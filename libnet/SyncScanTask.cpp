#include "SyncScanTask.h"

#if defined(_MSC_VER)
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <algorithm/AlgorithmHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif
#include <mutex>

#ifdef min
#undef min
#endif // min
#ifdef max
#undef max
#endif // min

#define TCP_SYN_LEAST_WAIT_PACKET_TIME (100*1000)
#define TCP_SYN_MAX_PACKET_SEND_AT_ONCE 50
#define TCP_SYN_MIN_INTERVAL_TIME_BTW_SEND_AND_WAIT 50 //the minial interval time between last wait responce and current send time
#define TCP_SYN_MAX_PACKET_EXPIRE_TIME (3*1000*1000)

/* TCP Options for TCP SYN probes: MSS 1460 */
#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4"
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS)-1)

using namespace TCPScan;

static ultra_scan_performance_vars perf;

static void init_ultra_timing_vals(ultra_timing_vals *timing, ultra_scan_performance_vars *perf, struct timeval *now)
{
    timing->cwnd = perf->host_initial_cwnd;
    timing->ssthresh = perf->initial_ssthresh;
    timing->num_replies_expected = 0;
    timing->num_replies_received = 0;
    timing->num_updates = 0;
    if (now) {
        timing->last_drop = *now;
    }
    else {
        gettimeofday(&timing->last_drop, NULL);
    }
}

static int mod_offset(int n, int min, int max)
{
    n = (n - min) % (max - min);
    if (n < 0)
        n += max - min;
    return n + min;
}

/* The try number or ping sequence number can be encoded into a TCP SEQ or ACK
field. This returns a 32-bit number which encodes both of these values along
with a simple checksum. Decoding is done by seq32_decode. */
static unsigned int seq32_encode(unsigned int seqmask, unsigned int trynum, unsigned int pingseq)
{
    unsigned int seq;
    unsigned short nfo;

    /* We'll let trynum and pingseq each be 8 bits. */
    nfo = (pingseq << 8) + trynum;
    /* Mirror the data to ensure it is reconstructed correctly. */
    seq = (nfo << 16) + nfo;
    /* Obfuscate it a little */
    seq = seq ^ seqmask;

    return seq;
}

/* Undoes seq32_encode. This extracts a try number and a port number from a
32-bit value. Returns true if the checksum is correct, false otherwise. */
static bool seq32_decode(unsigned int seqmask, unsigned int seq, unsigned int *trynum, unsigned int *pingseq) {
    if (trynum)
        *trynum = 0;
    if (pingseq)
        *pingseq = 0;

    /* Undo the mask xor. */
    seq = seq ^ seqmask;
    /* Check that both sides are the same. */
    if ((seq >> 16) != (seq & 0xFFFF))
        return false;

    if (trynum)
        *trynum = seq & 0xFF;
    if (pingseq)
        *pingseq = (seq & 0xFF00) >> 8;

    return true;
}

/* The try number or ping sequence number can be encoded in the source port
number. This returns a new port number that contains a try number or ping
sequence number encoded into the given port number. trynum and pingseq may
not both be non-zero. Decoding is done by sport_decode. */
static unsigned short sport_encode(unsigned short base_portno, unsigned int trynum, unsigned int pingseq) {
    unsigned short portno;

    portno = base_portno;
    if (pingseq > 0) {
        /* Encode the pingseq. trynum = 0. */
        portno += perf.tryno_cap + pingseq;
    }
    else {
        /* Encode the trynum. pingseq = 0. */
        portno += trynum;
    }

    return portno;
}

/* Undoes sport_encode. This extracts a try number and ping sequence number from
a port number given a "base" port number (the one given to
sport_encode). Returns true if the decoded values seem reasonable, false
otherwise. */
static bool sport_decode(unsigned short base_portno, unsigned short portno, unsigned int *trynum, unsigned int *pingseq) 
{
    unsigned int t;

    t = portno - base_portno;
    if (t > perf.tryno_cap + 256) {
        return false;
    }
    else if (t > perf.tryno_cap) {
        /* The ping sequence number was encoded. */
        if (pingseq)
            *pingseq = t - perf.tryno_cap;
        if (trynum)
            *trynum = 0;
    }
    else {
        /* The try number was encoded. */
        if (pingseq)
            *pingseq = 0;
        if (trynum)
            *trynum = t;
    }

    return true;
}

UltraProbe::UltraProbe()
{
    tryno = 0;
    timedout = false;
    retransmitted = false;
    memset(&sent, 0, sizeof(sent));
    memset(&prev_sent, 0, sizeof(prev_sent));
    memset(&mypspec, 0, sizeof(mypspec));
    memset(&IP, 0, sizeof(IP));
}

UltraProbe::~UltraProbe()
{

}

HostScanStats::HostScanStats()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    max_successful_tryno = 0;
    ports_finished = 0;
    num_probes_sent = 0;
    num_probes_active = 0;
    init_ultra_timing_vals(&timing, &perf, &now);
    probes_sent = 0;
    probes_sent_at_last_wait = 0;
    num_probes_waiting_retransmit = 0;
    last_wait = now;
    last_probe_sent = now;
    bench_tryno = 0;
    tryno_mayincrease = true;
    memset(&sdn, 0, sizeof(sdn));
    sdn.delayms = 0;
    sdn.last_boost = now;
    memset(&rld, 0, sizeof(rld));
    rld.max_tryno_sent = 0;
    rld.rld_waiting = false;
    rld.rld_waittime = now;
}

HostScanStats::~HostScanStats()
{

}

bool HostScanStats::SendOK(struct timeval *when)
{
    int recentsends;
    struct timeval now;
    gettimeofday(&now, NULL);

    /* In case it's not okay to send, arbitrarily say to check back in one
    second. */
    if (when) {
        TIMEVAL_MSEC_ADD(*when, now, 1000);
    }

    /* We need to stop sending if it has been a long time since
    the last wait responce*/
    recentsends = probes_sent - probes_sent_at_last_wait;
    if (recentsends > 0 ) {
        int to_ms = (int)std::max((int)(to.srtt * .75 / 1000), TCP_SYN_MIN_INTERVAL_TIME_BTW_SEND_AND_WAIT);
        if (TIMEVAL_MSEC_SUBTRACT(now, last_wait) > to_ms) {
            return false;
        }
    }

    /* There are good arguments for limiting the number of probes sent
    between waits even when we do get appropriate receive times.  For
    example, overflowing the pcap receive buffer with responses is no
    fun.  On one of my Linux boxes, it seems to hold about 113
    responses when I scan localhost.  And half of those are the @#$#
    sends being received.  I think I'll put a limit of 50 sends per
    wait */
    if (recentsends >= TCP_SYN_MAX_PACKET_SEND_AT_ONCE) {
        return false;
    }

    if (when) {
        *when = now;
    }
    return true;
}

void ultra_scan_performance_vars::Init()
{
    tryno_cap = MAX_RETRANSMISSIONS;
}

SyncScanTask::SyncScanTask(const std::vector<unsigned short> &ports, int src_ip, int dst_ip, char *src_mac, char *nxt_hop_mac, time_t time_out_ms, bool use_cwd)
    : pcap(src_ip)
{
    this->src_ip = src_ip;
    memcpy(this->src_mac, src_mac, 6);
    this->dst_ip = dst_ip;
    memcpy(this->dst_mac, nxt_hop_mac, 6);
    this->port_list.SetDefaultPortState(IPPROTO_TCP, PORT_FILTERED);
    this->port_list.AddProtocalPorts(IPPROTO_TCP, ports);
    this->ports = ports;
    this->next_dport_index = 0;
    this->seq_mask = AlgorithmHelper::GetRandomU32();
    this->time_out_ms = time_out_ms;
    IncrementBaseSrcPort();
    this->use_cwnd = use_cwd;
}

SyncScanTask::~SyncScanTask()
{

}

bool SyncScanTask::DoScan(PortList &list)
{
    /* Check we have at least one target*/
    if (dst_ip == 0 || src_ip == 0) {
        return false;
    }

    if (!this->BeginSniffer()) {
        return false;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    TIMEVAL_MSEC_ADD(this->time_out, now, (long)time_out_ms);

    while (stats.ports_finished != ports.size()) {
        DoOutstandingRetransmits();
        DoRetryStackRetransmits();
        DoNewProbes();
        WaitForResponses();
        UpdateProbesStats();
        if (Timeout() || Completed()) {
            break;
        }
    }
    
    list = this->port_list;
    return true;
}

bool SyncScanTask::SendOK(struct timeval *when)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    struct ultra_timing_vals tmng;
    std::vector<UltraProbe>::iterator probeI;
    struct timeval probe_to, earliest_to, sendTime;
    long tdiff;

    if (Timeout() || Completed()) {
        if (when) {
            *when = now;
        }
        return false;
    }

    if (stats.rld.rld_waiting) {
        if (TIMEVAL_AFTER(stats.rld.rld_waittime, now)) {
            if (when) {
                *when = stats.rld.rld_waittime;
            }
            return false;
        }
        else {
            if (when) {
                *when = now;
            }
            return true;
        }
    }

    if (stats.sdn.delayms) {
        if (TIMEVAL_MSEC_SUBTRACT(now, stats.last_probe_sent) < (int)stats.sdn.delayms) {
            if (when) {
                TIMEVAL_MSEC_ADD(*when, stats.last_probe_sent, stats.sdn.delayms);
            }
            return false;
        }
    }

    GetTiming(&tmng);
    if ((!use_cwnd || tmng.cwnd >= stats.num_probes_active + .5) && (FreshPortsLeft() || stats.num_probes_waiting_retransmit || !stats.retry_stack.empty())) {
        if (when) {
            *when = now;
        }
        return true;
    }

    if (!when) {
        return false;
    }

    TIMEVAL_MSEC_ADD(earliest_to, now, 10000);

    // Any timeouts coming up?
    for (probeI = stats.probes_outstanding.begin(); probeI != stats.probes_outstanding.end();
        probeI++) {
        if (!probeI->timedout) {
            TIMEVAL_MSEC_ADD(probe_to, probeI->sent, ProbeTimeout() / 1000);
            if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
                earliest_to = probe_to;
            }
        }
    }

    // Will any scan delay affect this?
    if (stats.sdn.delayms) {
        TIMEVAL_MSEC_ADD(sendTime, stats.last_probe_sent, stats.sdn.delayms);
        if (TIMEVAL_BEFORE(sendTime, now)) {
            sendTime = now;
        }
        tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);

        /* Timeouts previous to the sendTime requirement are pointless,
        and those later than sendTime are not needed if we can send a
        new packet at sendTime */
        if (tdiff < 0) {
            earliest_to = sendTime;
        }
        else {
            GetTiming(&tmng);
            if (tdiff > 0 && tmng.cwnd > stats.num_probes_active + .5) {
                earliest_to = sendTime;
            }
        }
    }

    *when = earliest_to;
    return false;
}

/* Returns the number of ports remaining to probe */
int SyncScanTask::FreshPortsLeft()
{
    return ports.size() - next_dport_index;
}

bool SyncScanTask::Timeout()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return TIMEVAL_SUBTRACT(this->time_out, now) < 0;
}

unsigned long SyncScanTask::ProbeTimeout()
{
    return stats.to.timeout;
}

unsigned long SyncScanTask::ProbeExpireTime(const UltraProbe &probe)
{
    return std::min(TCP_SYN_MAX_PACKET_EXPIRE_TIME, (int)ProbeTimeout() * 3);
}

bool SyncScanTask::Completed()
{
    /* If there are probes active or awaiting retransmission, we are not done. */
    if (stats.num_probes_active != 0 || stats.num_probes_waiting_retransmit != 0
        || !stats.probe_bench.empty() || !stats.retry_stack.empty()) {
        return false;
    }

    /* With other types of scan, we are done when there are no more ports to
    probe. */
    return FreshPortsLeft() == 0;
}

bool SyncScanTask::NextTimeout(struct timeval *when)
{
    struct timeval probe_to, earliest_to;
    std::vector<UltraProbe>::iterator probeI;
    bool firstgood = true;
    struct timeval now;
    gettimeofday(&now, NULL);

    memset(&probe_to, 0, sizeof(probe_to));
    memset(&earliest_to, 0, sizeof(earliest_to));

    for (probeI = stats.probes_outstanding.begin(); probeI != stats.probes_outstanding.end();
        probeI++) {
        if (!probeI->timedout) {
            TIMEVAL_ADD(probe_to, probeI->sent, ProbeTimeout());
            if (firstgood || TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
                earliest_to = probe_to;
                firstgood = false;
            }
        }
    }

    *when = (firstgood) ? now : earliest_to;
    return !firstgood;
}

std::vector<UltraProbe>::iterator SyncScanTask::DestroyOutstandingProbe(std::vector<UltraProbe>::iterator probeI)
{
    if (!probeI->timedout) {
        stats.num_probes_active--;
    }

    if (probeI->timedout && !probeI->retransmitted) {
        stats.num_probes_waiting_retransmit--;
    }

    return stats.probes_outstanding.erase(probeI);
}

void SyncScanTask::MarkProbeTimedout(std::vector<UltraProbe>::iterator probeI)
{
    probeI->timedout = true;
    stats.num_probes_active--;
    AdjustTiming(*probeI, NULL);
    stats.num_probes_waiting_retransmit++;
}

void SyncScanTask::AdjustTiming(const UltraProbe &probe, struct timeval *rcvdtime)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    stats.timing.num_replies_expected++;
    stats.timing.num_updates++;

    /* Notice a drop if
    1) We get a response to a retransmitted probe (meaning the first reply was
    dropped), or
    2) We got no response to a timing ping. */
    if (probe.tryno > 0 && rcvdtime != NULL) {
        // Drops often come in big batches, but we only want one decrease per batch.
        if (TIMEVAL_AFTER(probe.sent, stats.timing.last_drop)) {
            stats.timing.drop(stats.num_probes_active, &perf, &now);
        }
        if (TIMEVAL_AFTER(probe.sent, stats.timing.last_drop)) {
            stats.timing.drop_group(stats.num_probes_active, &perf, &now);
        }
    }
    /* If !probe->isPing() and rcvdtime == NULL, do nothing. */

    /* Increase the window for a positive reply. This can overlap with case (1)
    above. */
    if (rcvdtime != NULL) {
        stats.timing.ack(&perf, 1);
    }

    /* If packet drops are particularly bad, enforce a delay between
    packet sends (useful for cases such as UDP scan where responses
    are frequently rate limited by dest machines or firewalls) */

    /* First we decide whether this packet counts as a drop for send
    delay calculation purposes.  This statement means if (a ping since last boost failed, or the previous packet was both sent after the last boost and dropped) */
    if ((probe.tryno > 0 && rcvdtime && TIMEVAL_AFTER(probe.prev_sent, stats.sdn.last_boost))) {
        stats.sdn.dropped_resp_since_delay_changed++;
    }
    else if (rcvdtime) {
        stats.sdn.good_resp_since_delay_changed++;
    }

    /* Now change the send delay if necessary */
    unsigned int oldgood = stats.sdn.good_resp_since_delay_changed;
    unsigned int oldbad = stats.sdn.dropped_resp_since_delay_changed;
    double threshold = 0.30;
    if (oldbad > 10 && (oldbad / ((double)oldbad + oldgood) > threshold)) {
        BoostScanDelay();
    }
}

void SyncScanTask::AdjustTimeouts(const UltraProbe &probe, struct timeval *rcvdtime)
{
    if (rcvdtime == NULL)
        return;

    stats.to.adjust_timeouts2(&probe.sent, rcvdtime);
}

unsigned int SyncScanTask::NumProbesOutstanding()
{
    return stats.probes_outstanding.size();
}

std::vector<UltraProbe>::iterator SyncScanTask::MoveProbeToBench(std::vector<UltraProbe>::iterator &probeI)
{
    if (!stats.probe_bench.empty()){
        stats.bench_tryno = probeI->tryno;
        stats.probe_bench.reserve(128);
    }
    stats.probe_bench.push_back(probeI->pspec());
    stats.num_probes_waiting_retransmit--;
    return stats.probes_outstanding.erase(probeI);
}

void SyncScanTask::DismissBench()
{
    if (stats.probe_bench.empty()) {
        return;
    }
    while (!stats.probe_bench.empty()) {
        /* Nothing to do if !USI->ping_scan. ultrascan_port_pspec_update would
        allocate a Port object but we rely on the default port state to save
        memory. */
        stats.probe_bench.pop_back();
    }
    stats.bench_tryno = 0;
}

void SyncScanTask::RetransmitBench()
{
    if (stats.probe_bench.empty()) {
        return;
    }

    /* Move all contents of probe_bench to the end of retry_stack, updating retry_stack_tries accordingly */
    stats.retry_stack.insert(stats.retry_stack.end(), stats.probe_bench.begin(), stats.probe_bench.end());
    stats.retry_stack_tries.insert(stats.retry_stack_tries.end(), stats.probe_bench.size(), stats.bench_tryno);
    stats.probe_bench.erase(stats.probe_bench.begin(), stats.probe_bench.end());
    stats.bench_tryno = 0;
}

void SyncScanTask::GetTiming(struct ultra_timing_vals *tmng)
{
    /* Use the per-host value if a pingport has been found or very few probes
    have been sent */
    if (stats.num_probes_sent < 80) {
        *tmng = stats.timing;
        return;
    }

    /* Otherwise, use the global cwnd stats if it has sufficient responses */
    if (stats.timing.num_updates > 1) {
        *tmng = stats.timing;
        return;
    }

    /* Last resort is to use canned values */
    tmng->cwnd = perf.host_initial_cwnd;
    tmng->ssthresh = perf.initial_ssthresh;
    tmng->num_updates = 0;
    return;
}

unsigned int SyncScanTask::AllowedTryno()
{
    std::vector<UltraProbe>::iterator probeI;
    UltraProbe probe;
    bool allfinished = true;
    unsigned int maxval = 0;

    /* TODO: This should perhaps differ by scan type. */
    maxval = std::max(1, (int)stats.max_successful_tryno + 1);
    if (maxval > perf.tryno_cap) {
        maxval = perf.tryno_cap;
        stats.tryno_mayincrease = false; /* It never exceeds the cap */
    }

    /* Decide if the tryno can possibly increase.  */
    if (stats.tryno_mayincrease && stats.num_probes_active == 0 && FreshPortsLeft() == 0) {
        /* If every outstanding probe is timedout and at maxval, then no further
        retransmits are necessary. */
        for (probeI = stats.probes_outstanding.begin();
            probeI != stats.probes_outstanding.end(); probeI++) {
            probe = *probeI;
            if (!probe.retransmitted && probe.tryno < maxval) {
                /* Needs at least one more retransmit. */
                allfinished = false;
                break;
            }
        }
        if (allfinished) {
            stats.tryno_mayincrease = false;
        }
    }

    return maxval;
}

void SyncScanTask::BoostScanDelay()
{
    unsigned int maxAllowed = MAX_TCP_SCAN_DELAY;
    struct timeval now;
    gettimeofday(&now, NULL);

    if (stats.sdn.delayms == 0) {
        stats.sdn.delayms = 5; // In many cases, a pcap wait takes a minimum of 80ms, so this matters little :
    }
    else {
        stats.sdn.delayms = std::min((int)stats.sdn.delayms * 2, std::max((int)stats.sdn.delayms, 1000));
    }
    stats.sdn.delayms = std::min(stats.sdn.delayms, maxAllowed);
    stats.sdn.last_boost = now;
    stats.sdn.dropped_resp_since_delay_changed = 0;
    stats.sdn.good_resp_since_delay_changed = 0;
}

void SyncScanTask::IncrementBaseSrcPort()
{
    static unsigned short base_port = mod_offset(AlgorithmHelper::GetRandomU16(), 33000, 65536 - 256);
    static std::mutex base_port_lock;

    std::unique_lock<std::mutex> lock(base_port_lock);
    base_port = mod_offset(base_port + 256, 33000, 65536 - 256);
    this->base_sport = base_port;
}

bool SyncScanTask::BeginSniffer()
{
#if defined(_MSC_VER)
    char pcap_filter[2048];
    /* 20 IPv6 addresses is max (45 byte addy + 14 (" or src host ")) * 20 == 1180 */
    char dst_hosts[1200];
    int filterlen = 0;
    int len;

    if (!pcap.IsInit()) {
        return false;
    }

    pcap_filter[0] = '\0';

    len = snprintf(dst_hosts + filterlen, sizeof(dst_hosts) - filterlen, "src host %s", NetworkHelper::IPAddr2Str(dst_ip).c_str());
    filterlen += len;
    len = snprintf(dst_hosts + filterlen, sizeof(dst_hosts) - filterlen, ")");
    len = snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and tcp and (%s", NetworkHelper::IPAddr2Str(src_ip).c_str(), dst_hosts);
    if (pcap.PcapSetFilter(pcap_filter)) {
        return false;
    }
    return true;
#elif defined(__GNUC__)
    if (pcap.PcapSetTCPFilter(dst_ip)) {
        return false;
    }
    return true;
#endif
}

void SyncScanTask::DoOutstandingRetransmits()
{
    int retrans = 0; /* Number of retransmissions during a loop */
    unsigned int maxtries;
    struct timeval now;
    gettimeofday(&now, NULL);
    int prob_index = stats.probes_outstanding.size() - 1;

    do {
        retrans = 0;
        if (stats.num_probes_active == 0 && stats.num_probes_waiting_retransmit == 0) {
            continue;
        }
        if (!this->SendOK(NULL)) {
            continue;
        }
        maxtries = AllowedTryno();
        while (prob_index >= 0)
        {
            u_int cur_prob_index = prob_index--;
            UltraProbe &probe = *(stats.probes_outstanding.begin() + cur_prob_index);
            if (probe.timedout && !probe.retransmitted && maxtries > probe.tryno) {
                /* For rate limit detection, we delay the first time a new tryno
                is seen, as long as we are scanning at least 2 ports */
                if (probe.tryno + 1 > (int)stats.rld.max_tryno_sent && ports.size() > 1) {
                    stats.rld.max_tryno_sent = probe.tryno + 1;
                    stats.rld.rld_waiting = true;
                    TIMEVAL_MSEC_ADD(stats.rld.rld_waittime, now, 1000);
                }
                else {
                    stats.rld.rld_waiting = false;
                    SendIPScanProbe(probe.pspec(), probe.tryno + 1, &probe.sent);
                    (stats.probes_outstanding.begin() + cur_prob_index)->retransmitted = true;
                    stats.num_probes_waiting_retransmit--;
                    stats.num_probes_sent++;
                    stats.probes_sent++;
                    retrans++;
                }
                break; /* I only do one probe per host for now to spread load */
            }
        }
    } while (stats.SendOK(NULL) && retrans != 0);
}

void SyncScanTask::DoRetryStackRetransmits()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    bool unableToSend = false;
    while (!unableToSend && SendOK(NULL)) {
        if (!stats.retry_stack.empty() && SendOK(NULL)) {
            probespec pspec;
            unsigned char pspec_tries;
            stats.num_probes_sent++;
            stats.probes_sent++;

            pspec = stats.retry_stack.back();
            stats.retry_stack.pop_back();
            pspec_tries = stats.retry_stack_tries.back();
            stats.retry_stack_tries.pop_back();
            SendIPScanProbe(pspec, pspec_tries + 1, NULL);
        }
        else {
            unableToSend = true;
        }
    }
}

void SyncScanTask::DoNewProbes()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    bool unableToSend = false;
    while (!unableToSend && stats.SendOK(NULL) && next_dport_index<ports.size()) {
        if (FreshPortsLeft() && this->SendOK(NULL)) {
            probespec pspec;
            pspec.tcp.dport = ports[next_dport_index++];
            pspec.tcp.flags = TH_SYN;
            stats.num_probes_sent++;
            stats.probes_sent++;
            SendIPScanProbe(pspec, 0, NULL);
        }
        else {
            unableToSend = true;
        }
    }
}

void SyncScanTask::SendIPScanProbe(const probespec &pspec, unsigned char tryno, struct timeval *prev_sent)
{
    UltraProbe probe;
    unsigned int seq = 0;
    unsigned int ack = 0;
    unsigned short sport;
    unsigned short ipid = AlgorithmHelper::GetRandomU16();
    unsigned char *tcpops = NULL;
    unsigned short tcpopslen = 0;
    char *chunk = NULL;
    int chunklen = 0;

    sport = sport_encode(base_sport, tryno, 0);
    probe.tryno = tryno;
    /* Normally we encode the tryno and pingseq in the SEQ field, because that
    comes back (possibly incremented) in the ACK field of responses. But if
    our probe has the ACK flag set, the response reflects our own ACK number
    instead. */
    seq = seq32_encode(this->seq_mask, tryno, 0);

    if (pspec.tcp.flags & TH_SYN) {
        tcpops = (unsigned char *)TCP_SYN_PROBE_OPTIONS;
        tcpopslen = TCP_SYN_PROBE_OPTIONS_LEN;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    stats.last_probe_sent = now;
    SendTcpProbe(255, false, ipid, NULL, 0, sport, pspec.tcp.dport, seq, ack, 0, pspec.tcp.flags, 1024, 0, tcpops, tcpopslen, NULL, 0);
    probe.mypspec = pspec;
    probe.IP.ipid = ipid;
    probe.IP.tcp.seq = seq;
    probe.IP.tcp.sport = sport;
    probe.sent = now;
    if (prev_sent) {
        probe.prev_sent = *prev_sent;
    }
    stats.probes_outstanding.push_back(probe);
    stats.num_probes_active++;
}

int SyncScanTask::SendTcpProbe(
    int ttl, bool df, unsigned short ipid, unsigned char* ipopt, int ipoptlen,
    unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack,
    unsigned char reserved, unsigned char flags, unsigned short window, unsigned short urp,
    unsigned char *options, int optlen,
    char *data, unsigned short datalen)
{
    if (!pcap.IsInit()) {
        return -1;
    }

    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(IP_TOS_DEFAULT);
    ipv4->SetIdentification(ipid);
    if (df) {
        ipv4->SetDF();
    }
    ipv4->SetTTL(ttl);
    ipv4->SetNextProto(HEADER_TYPE_TCP);
    ipv4->SetDestinationAddress(dst_ip);
    ipv4->SetSourceAddress(src_ip);
    if (ipopt && ipoptlen > 0) {
        ipv4->SetOpts(ipopt, ipoptlen);
    }
    auto tcp = std::make_shared<TCPHeader>();
    ipv4->SetNext(tcp);
    tcp->SetSourcePort(sport);
    tcp->SetDestinationPort(dport);
    tcp->SetSeq(seq);
    tcp->SetAck(ack);
    tcp->SetReserved(reserved);
    tcp->SetFlags(flags);
    tcp->SetWindow(window);
    tcp->SetUrgPointer(urp);
    if (options && optlen > 0) {
        tcp->SetOptions(options, optlen);
    }
    if (data && datalen > 0) {
        auto raw_data = std::make_shared<RawData>();
        tcp->SetNext(raw_data);
        raw_data->StorePacket((unsigned char *)data, datalen);
    }
    tcp->SetHeaderLength();
    tcp->SetSum();
    ipv4->SetTotalLength();
    ipv4->SetHeaderLength();
    ipv4->SetSum();
    if (pcap.SendEthPacket(eth) == 0) {
        return 0;
    }
    return -1;
}

void SyncScanTask::WaitForResponses()
{
    struct timeval now;
    bool gotone;
    gettimeofday(&now, NULL);
    struct timeval stime = now; // the wait max time to
    stats.last_wait = now;
    stats.probes_sent_at_last_wait = stats.probes_sent;

    do {
        gotone = false;
        bool ggood = stats.SendOK(&stime);
        struct timeval lowhtime = { 0 };
        struct timeval tmptv;
        if (!ggood) {
                lowhtime = stime;
                if (NextTimeout(&tmptv)) {
                    if (TIMEVAL_SUBTRACT(tmptv, lowhtime) < 0) {
                        lowhtime = tmptv;
                    }
                }
                stime = lowhtime;
        }
        else {
            if (this->SendOK(&tmptv)) {
                lowhtime = tmptv;
            }
            else if (TIMEVAL_SUBTRACT(lowhtime, tmptv) > 0) {
                lowhtime = tmptv;
            }
        }
        if (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) < 0) {
            lowhtime = now;
        }
        stime = lowhtime;
        gotone = GetOneProbeResp(&stime);
    } while (gotone && stats.num_probes_active > 0);

    gettimeofday(&now, NULL);
    stats.last_wait = now;
}

bool SyncScanTask::GetOneProbeResp(struct timeval *stime)
{
    if (!pcap.IsInit()) {
        return false;
    }
    long to_usec;
    bool good_one = false;
    bool timedout = false;
    struct timeval now;
    std::shared_ptr<NetBase> packet;
    int new_state = PORT_UNKNOWN;
    bool adjust_timing = true;
    std::vector<UltraProbe>::iterator probeI;

    do
    {
        gettimeofday(&now, NULL);
        to_usec = TIMEVAL_SUBTRACT(*stime, now);
        if (to_usec < TCP_SYN_LEAST_WAIT_PACKET_TIME) {
            to_usec = TCP_SYN_LEAST_WAIT_PACKET_TIME;
        }
        int ret = this->pcap.GetOneReplayPacket(packet, to_usec / 1000);
        gettimeofday(&now, NULL);
        if ((ret || !packet) && TIMEVAL_SUBTRACT(*stime, now) < 0) {
            timedout = true;
            break;
        }
        if (ret || !packet) {
            continue;
        }
        if (TIMEVAL_SUBTRACT(now, *stime) > 200000) {
            /* While packets are still being received, I'll be generous and give
            an extra 1/5 sec.  But we have to draw the line somewhere */
            timedout = true;
        }

        std::shared_ptr<NetBase> tmp;
        IPv4Header *ipv4_header = NULL;
        TCPHeader *tcp_header = NULL;
        tmp = packet->ProtocalData(HEADER_TYPE_IPv4);
        if (!tmp) {
            continue;
        }
        ipv4_header = (IPv4Header *)tmp.get();
        if (!ipv4_header->Validate()) {
            continue;
        }
        if (ipv4_header->GetNextProto() != IPPROTO_TCP) {
            continue;
        }
        tmp = ipv4_header->Next();
        if (!tmp) {
           continue;
        }
        if (tmp->ProtocolId() != HEADER_TYPE_TCP) {
            continue;
        }
        tcp_header = (TCPHeader *)tmp.get();
        if (!tcp_header->Validate()) {
            continue;
        }
        probeI = stats.probes_outstanding.end();
        unsigned int listsz = NumProbesOutstanding();
        unsigned int probenum = 0;

        /* Find the probe that provoked this response. */
        for (probenum = 0; probenum < listsz && !good_one; probenum++) {
            probeI--;
            if (!TCPProbeMatch(*ipv4_header, *tcp_header, *probeI)) {
                continue;
            }

            /* Now that response has been matched to a probe, I interpret it */
            if ((tcp_header->GetFlags() & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                /* Yeah!  An open port */
                new_state = PORT_OPEN;
            }
            else if (tcp_header->GetFlags() & TH_RST) {
                new_state = PORT_CLOSED;
            }
            else if (tcp_header->GetFlags() & TH_SYN) {
                new_state = PORT_OPEN;
            }
            else {
                break;
            }
            good_one = true;
        }
    } while (!good_one && !timedout);

    if (good_one) {
        PortProbeUpdate(probeI, new_state, &now, adjust_timing);
    }
    return good_one;
}

bool SyncScanTask::TCPProbeMatch(IPv4Header &ipv4_header, TCPHeader &tcp_header, const UltraProbe &probe)
{
    const struct probespec_tcpdata *probedata;
    unsigned int tryno, pingseq;

    /* Ensure the connection info matches. */
    if (probe.dport() != tcp_header.GetSourcePort()
        || probe.sport() != tcp_header.GetDestinationPort()
        || src_ip != ipv4_header.GetDestinationAddress().s_addr) {
        return false;
    }

    tryno = 0;
    pingseq = 0;
    /* Get the values from the destination port (our source port). */
    sport_decode(base_sport, tcp_header.GetDestinationPort(), &tryno, &pingseq);

    /* Make sure that trynum and pingseq match the values in the probe. */
    if (!probe.CheckTryno(tryno)) {
        return false;
    }

    /* Make sure we are matching up the right kind of probe, otherwise just the
    ports, address, tryno, and pingseq can be ambiguous, between a SYN and an
    ACK probe during a -PS80 -PA80 scan for example. A SYN/ACK can only be
    matched to a SYN probe. */
    probedata = &probe.pspec().tcp;
    if ((tcp_header.GetFlags() & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)
        && !(probedata->flags & TH_SYN)) {
        return false;
    }

    /* Sometimes we get false results when scanning localhost with -p- because we
    scan localhost with src port = dst port and see our outgoing packet and
    think it is a response. */
    if (probe.dport() == probe.sport()
        && ipv4_header.GetDestinationAddress().s_addr == ipv4_header.GetSourceAddress().s_addr
        && probe.ipid() == ipv4_header.GetIdentification()) {
        return false;
    }

    return true;
}

/* This function is called when a new status is determined for a port.
the port in the probeI of host hss is now in newstate.  This
function needs to update timing information, other stats, and the
Nmap port state table as appropriate.  If rcvdtime is NULL or we got
unimportant packet, packet stats are not updated.  If you don't have an
UltraProbe list iterator, you may need to call ultrascan_port_psec_update()
instead. If adjust_timing_hint is false, packet stats are not
updated. */
void SyncScanTask::PortProbeUpdate(std::vector<UltraProbe>::iterator probeI, int newstate, struct timeval *rcvdtime, bool adjust_timing_hint)
{
    UltraProbe &probe = *probeI;
    const probespec &pspec = probe.pspec();

    PortPspecUpdate(pspec, newstate);

    AdjustTimeouts(probe, rcvdtime);

    /* Decide whether to adjust timing. We and together a bunch of conditions.
    First, don't adjust timing if adjust_timing_hint is false. */
    bool adjust_timing = adjust_timing_hint;

    /* If we got a response that meant "filtered", then it was an ICMP error.
    These are often rate-limited (RFC 1812) or generated by a different host.
    We only allow such responses to increase, not decrease, scanning speed by
    not considering drops (probe->tryno > 0), and we don't allow changing the
    ping probe to something that's likely to get dropped. */
    if (rcvdtime != NULL && newstate == PORT_FILTERED) {
        if (probe.tryno > 0) {
            adjust_timing = false;
        }
    }

    if (adjust_timing) {
        AdjustTiming(probe, rcvdtime);

        if (rcvdtime != NULL && probe.tryno > stats.max_successful_tryno) {
            /* We got a positive response to a higher tryno than we've seen so far. */
            stats.max_successful_tryno = probe.tryno;
            if (stats.max_successful_tryno > 3) {
                BoostScanDelay();
            }
        }
    }

    DestroyOutstandingProbe(probeI);
}

bool SyncScanTask::PortPspecUpdate(const probespec &pspec, int newstate)
{
    unsigned short portno = 0;
    unsigned char proto = 0;
    int oldstate = PORT_TESTING;
    /* Whether no response means a port is open */
    bool noresp_open_scan = false;

    proto = IPPROTO_TCP;
    portno = pspec.tcp.dport;
    if (port_list.PortIsDefault(portno, proto)) {
        oldstate = PORT_TESTING;
        stats.ports_finished++;
    }
    else {
        oldstate = port_list.GetPortState(portno, proto);
    }

    switch (oldstate) {
        /* TODO: I need more code here to determine when a state should
        be overridden, for example PORT_OPEN trumps PORT_FILTERED
        in a SYN scan, but not necessarily for UDP scan */
    case PORT_TESTING:
        /* Brand new port -- add it to the list */
        port_list.SetPortState(portno, proto, newstate);
        break;
    case PORT_OPEN:
        if (newstate != PORT_OPEN) {
            if (noresp_open_scan) {
                port_list.SetPortState(portno, proto, newstate);
            } /* Otherwise The old open takes precedence */
        }
        break;
    case PORT_CLOSED:
        if (newstate != PORT_CLOSED) {
            if (!noresp_open_scan && newstate != PORT_FILTERED) {
                port_list.SetPortState(portno, proto, newstate);
            }
        }
        break;
    case PORT_FILTERED:
        if (newstate != PORT_FILTERED) {
            if (!noresp_open_scan || newstate != PORT_OPEN) {
                port_list.SetPortState(portno, proto, newstate);
            }
        }
        break;
    case PORT_UNFILTERED:
        /* This could happen in an ACK scan if I receive a RST and then an
        ICMP filtered message.  I'm gonna stick with unfiltered in that
        case.  I'll change it if the new state is open or closed,
        though I don't expect that to ever happen */
        if (newstate == PORT_OPEN || newstate == PORT_CLOSED) {
            port_list.SetPortState(portno, proto, newstate);
        }
        break;
    case PORT_OPENFILTERED:
        if (newstate != PORT_OPENFILTERED) {
            port_list.SetPortState(portno, proto, newstate);
        }
        break;
    default:
        break;
    }

    return oldstate != newstate;
}

void SyncScanTask::UpdateProbesStats()
{
    std::vector<UltraProbe>::iterator probeI;
    unsigned int maxtries = 0;
    int expire_us = 0;
    struct timeval now = { 0 };
    gettimeofday(&now, NULL);

    maxtries = AllowedTryno();

    /* Should we dump everyone off the bench? */
    if (!stats.probe_bench.empty()) {
        if (maxtries == stats.bench_tryno && !stats.tryno_mayincrease) {
            /* We'll never need to retransmit these suckers!  So they can
            be treated as done */
            DismissBench();
        }
        else if (maxtries > stats.bench_tryno) {
            // These fellows may be retransmitted now that maxtries has increased
            RetransmitBench();
        }
    }

    for (probeI = stats.probes_outstanding.begin();
        probeI != stats.probes_outstanding.end();) {
        UltraProbe &probe = *probeI;
        expire_us = ProbeExpireTime(probe);
        if (!probe.timedout && TIMEVAL_SUBTRACT(now, probe.sent) > (long)ProbeTimeout()) {
            MarkProbeTimedout(probeI);
            /* Once we've timed out a probe, skip it for this round of processData.
            We don't want it to move to the bench or anything until the other
            functions have had a chance to see that it's timed out. In
            particular, timing out a probe may mean that the tryno can no longer
            increase, which would make the logic below incorrect. */
            probeI++;
            continue;
        }

        if (probe.timedout && !probe.retransmitted) {
            if (!stats.tryno_mayincrease && probe.tryno >= maxtries) {
                probeI = DestroyOutstandingProbe(probeI);
                continue;
            }
            else if (probe.tryno >= maxtries &&
                TIMEVAL_SUBTRACT(now, probe.sent) > expire_us) {
                /* Move it to the bench until it is needed (maxtries increases or is capped */
                probeI = MoveProbeToBench(probeI);
                continue;
            }
        }

        if (probe.timedout && probe.retransmitted &&
            TIMEVAL_SUBTRACT(now, probe.sent) > expire_us) {
            probeI = DestroyOutstandingProbe(probeI);
            continue;
        }
        probeI++;
    }
}