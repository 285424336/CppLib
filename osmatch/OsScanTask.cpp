#define WIN32_LEAN_AND_MEAN
#include "OsScanTask.h"
#if defined(_MSC_VER)
#include <Windows.h>
#include <algorithm\AlgorithmHelper.h>
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <algorithm/AlgorithmHelper.h>
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <math.h> 
#else
#error unsupported compiler
#endif
#include <mutex>
#include <iostream>
#include <thread>

#ifdef min
#undef min
#endif // min
#ifdef max
#undef max
#endif // min

#ifndef MOD_DIFF
#define MOD_DIFF(a,b) ((unsigned int) (std::min((unsigned int)(a) - (unsigned int ) (b), (unsigned int )(b) - (unsigned int) (a))))
#endif

/* Arithmatic difference modulo 2^16 */
#ifndef MOD_DIFF_USHORT
#define MOD_DIFF_USHORT(a,b) ((std::min((unsigned short)((unsigned short)(a) - (unsigned short ) (b)), (unsigned short) ((unsigned short )(b) - (unsigned short) (a)))))
#endif

static struct {
    unsigned char* val;
    int len;
} prbOpts[] = {
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00", 20 },
    { (unsigned char*) "\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80", 20 },
    { (unsigned char*) "\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 16 },
    { (unsigned char*) "\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 20 },
    { (unsigned char*) "\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00", 16 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01", 12 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { (unsigned char*) "\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 }
};

/* TCP Window sizes. Numbering is the same as for prbOpts[] */
unsigned short prbWindowSz[] = { 1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535 };
/* Global to store performance info */
static scan_performance_vars perf;

FingerPrintDB OsScanTask::db;
bool          OsScanTask::is_db_init = false;

bool OsScanTask::InitFPDB(const std::string &file_path)
{
    if (!is_db_init) {
        is_db_init = OsScanTask::db.InitFromFile(file_path);
    }
    return true;
}

bool OsScanTask::InitFPDBFromContent(const std::string &content)
{
    if (!is_db_init) {
        is_db_init = OsScanTask::db.InitFromContent(content);
    }
    return true;
}

OFProbe::OFProbe()
{
    type = OFP_UNSET;
    subid = 0;
    tryno = -1;
    retransmitted = false;
    memset(&sent, 0, sizeof(sent));
    memset(&prevSent, 0, sizeof(prevSent));
}

const char *OFProbe::TypeStr()
{
    switch (type) {
    case OFP_UNSET:
        return "OFP_UNSET";
    case OFP_TSEQ:
        return "OFP_TSEQ";
    case OFP_TOPS:
        return "OFP_TOPS";
    case OFP_TECN:
        return "OFP_TECN";
    case OFP_T1_7:
        return "OFP_T1_7";
    case OFP_TUDP:
        return "OFP_TUDP";
    case OFP_TICMP:
        return "OFP_TICMP";
    default:
        return "ERROR";
    }
}

OsScanStats::OsScanStats()
{
    distance = -1;
    distance_guess = -1;
    num_probes_sent = 0;
    send_delay_ms = OS_PROBE_DELAY;
    gettimeofday(&last_probe_sent, NULL);
    timing.cwnd = perf.host_initial_cwnd;
    timing.ssthresh = perf.initial_ssthresh; /* Will be reduced if any packets are dropped anyway */
    timing.num_replies_expected = 0;
    timing.num_replies_received = 0;
    timing.num_updates = 0;
    gettimeofday(&timing.last_drop, NULL);
    num_probes_active = 0;
    num_probes_sent = 0;
    num_probes_sent_at_last_round = 0;
    ReInitScanStats();
}

OsScanStats::~OsScanStats()
{

}

void OsScanStats::ReInitScanStats()
{
    fp = NULL;
    for (int i = 0; i < NUM_FPTESTS; i++) {
        fptests[i] = NULL;
    }
    for (int i = 0; i < 6; i++) {
        tops_AVs[i] = NULL;
        twin_AVs[i] = NULL;
    }
    memset(&si, 0, sizeof(si));
    for (int i = 0; i < NUM_SEQ_SAMPLES; i++) {
        ipid.tcp_ipids[i] = -1;
        ipid.tcp_closed_ipids[i] = -1;
        ipid.icmp_ipids[i] = -1;
    }
    lastipid = 0;
    memset(&seq_send_times, 0, sizeof(seq_send_times));
    twin_reply_num = 0;
    tops_reply_num = 0;
    stored_icmp_reply = -1;
    icmp_echo_reply = NULL;
    memset(&upi, 0, sizeof(upi));
}

double OsScanStats::TimingRatio()
{
    int msec_ideal = OS_SEQ_PROBE_DELAY * (NUM_SEQ_SAMPLES - 1);
    int msec_taken = TIMEVAL_MSEC_SUBTRACT(seq_send_times[NUM_SEQ_SAMPLES - 1], seq_send_times[0]);
    return (double)msec_taken / msec_ideal;
}

OsScanTask::OsScanTask(const Target &target, time_t time_out_ms):t(target), pcap(target.src_ip), stats(), probes_to_send(), probes_active()
{
    tcpPortBase = 33000 + (AlgorithmHelper::GetRandomU32() % 31000) + AlgorithmHelper::GetRandomU8();
    udpPortBase = 33000 + (AlgorithmHelper::GetRandomU32() % 31000) + AlgorithmHelper::GetRandomU8();
    this->time_out_ms = time_out_ms;
    ReInitScanSystem();
}

OsScanTask::~OsScanTask()
{

}

bool OsScanTask::BeginSniffer()
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

    len = snprintf(dst_hosts + filterlen, sizeof(dst_hosts) - filterlen, "src host %s", NetworkHelper::IPAddr2Str(t.dst_ip).c_str());
    filterlen += len;
    len = snprintf(dst_hosts + filterlen, sizeof(dst_hosts) - filterlen, ")))");
    len = snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and (icmp or (tcp and (%s", NetworkHelper::IPAddr2Str(t.src_ip).c_str(), dst_hosts);
    if (pcap.PcapSetFilter(pcap_filter)) {
        return false;
    }
    return true;
#elif defined(__GNUC__)
    if (pcap.PcapSetTCPOrICMPFilter(t.dst_ip)) {
        return false;
    }
    return true;
#endif
}

void OsScanTask::ReInitScanSystem()
{
    tcpSeqBase = AlgorithmHelper::GetRandomU32();
    tcpAck = AlgorithmHelper::GetRandomU32();
    tcpMss = 265;
    icmpEchoId = AlgorithmHelper::GetRandomU16();
    icmpEchoSeq = 295;
    udpttl = (TimeHelper::CurrentTimeStamp() % 14) + 51;
    if (t.is_direct) {
        stats.distance = 1;
        stats.distance_guess = 1;
    }
}

void OsScanTask::AddNewProbe(OFProbeType type, int subid)
{
    OFProbe probe;
    probe.type = type;
    probe.subid = subid;
    probes_to_send.push_back(probe);
}

std::vector<OFProbe>::iterator OsScanTask::GetActiveProbe(OFProbeType type, int subid)
{
    std::vector<OFProbe>::iterator probeI;
    for (probeI = probes_active.begin(); probeI != probes_active.end(); probeI++) {
        if (probeI->type == type && probeI->subid == subid) {
            break;
        }
    }
    return probeI;
}

unsigned int OsScanTask::NumProbesToSend()
{
    return probes_to_send.size();
}

unsigned int OsScanTask::NumProbesActive()
{
    return probes_active.size();
}

unsigned long OsScanTask::TimeProbeTimeout()
{
    if (t.to.srtt > 0) {
        /* We have at least one timing value to use.  Good enough, I suppose */
        return t.to.timeout;
    }
    else if (stats.to.srtt > 0) {
        /* OK, we'll use this one instead */
        return stats.to.timeout;
    }
    else {
        return t.to.timeout; /* It comes with a default */
    }
}

void OsScanTask::BuildSeqProbeList()
{
    int i;
    if (t.open_tcp_port == -1) {
        return;
    }
    for (i = 0; i < NUM_SEQ_SAMPLES; i++) {
        AddNewProbe(OFP_TSEQ, i);
    }
}

void OsScanTask::UpdateActiveSeqProbes()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    OFProbe probe;
    for (auto probeI = probes_active.begin(); probeI != probes_active.end();) {
        probe = *probeI;
        /* Is the probe timedout? */
        if (TIMEVAL_SUBTRACT(now, probe.sent) > (long)TimeProbeTimeout()) {
            probeI = probes_active.erase(probeI);
            stats.num_probes_active = NumProbesActive();
        }
        else {
            probeI++;
        }
    }
}

void OsScanTask::BuildTUIProbeList()
{
    int i;

    /* The order of these probes are important for ipid generation
    * algorithm test and should not be changed.
    *
    * At doSeqTests we sent 6 TSeq probes to generate 6 tcp replies,
    * and here we follow with 3 probes to generate 3 icmp replies. In
    * this way we can expect to get "good" IPid sequence.
    *
    * **** Should be done in a more elegant way. *****
    */

    /* ticmp */
    if (!stats.FP_TIcmp) {
        for (i = 0; i < 2; i++) {
            AddNewProbe(OFP_TICMP, i);
        }
    }

    /* tudp */
    if (!stats.FP_TUdp) {
        AddNewProbe(OFP_TUDP, 0);
    }

    if (t.open_tcp_port != -1) {
        /* tops/twin probes. We send the probe again if we didn't get a
        response by the corresponding seq probe. */
        if (!stats.FP_TOps || !stats.FP_TWin) {
            for (i = 0; i < 6; i++) {
                if (!stats.tops_AVs[i] || !stats.twin_AVs[i]) {
                    AddNewProbe(OFP_TOPS, i);
                }
            }
        }

        /* tecn */
        if (!stats.FP_TEcn) {
            AddNewProbe(OFP_TECN, 0);
        }

        /* t1_7: t1_t4 */
        for (i = 0; i < 4; i++) {
            if (!stats.fptests[FP_T1_7_OFF + i]) {
                AddNewProbe(OFP_T1_7, i);
            }
        }
    }

    /* t1_7: t5_t7 */
    for (i = 4; i < 7; i++) {
        if (!stats.fptests[FP_T1_7_OFF + i]) {
            AddNewProbe(OFP_T1_7, i);
        }
    }
}

void OsScanTask::UpdateActiveTUIProbes()
{
    struct timeval now;
    gettimeofday(&now, NULL);

    for (auto probeI = probes_active.begin(); probeI != probes_active.end();) {
        if (TIMEVAL_SUBTRACT(now, probeI->sent) > (long)TimeProbeTimeout()) {
            if (probeI->tryno >= 3) {
                /* The probe is expired. */
                probeI = probes_active.erase(probeI);
                stats.num_probes_active = NumProbesActive();
            }
            else {
                /* It is timedout, move it to the sendlist */
                probes_to_send.push_back(*probeI);
                probeI = probes_active.erase(probeI);
                stats.num_probes_active = NumProbesActive();
            }
        }
        else{
            probeI++;
        }
    }
}

void OsScanTask::SendNextProbe()
{
    std::vector<OFProbe >::iterator probeI;

    if (probes_to_send.empty()) {
        return;
    }

    probeI = probes_to_send.begin();

    switch (probeI->type) {
    case OFP_TSEQ:
        SendTSeqProbe(probeI->subid);
        break;
    case OFP_TOPS:
        SendTOpsProbe(probeI->subid);
        break;
    case OFP_TECN:
        SendTEcnProbe();
        break;
    case OFP_T1_7:
        SendT1_7Probe(probeI->subid);
        break;
    case OFP_TICMP:
        SendTIcmpProbe(probeI->subid);
        break;
    case OFP_TUDP:
        SendTUdpProbe(probeI->subid);
        break;
    default:
        break;
    }

    probeI->tryno++;
    if (probeI->tryno > 0) {
        /* This is a retransmission */
        probeI->retransmitted = true;
        probeI->prevSent = probeI->sent;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    probeI->sent = now;

    stats.last_probe_sent = now;
    stats.num_probes_sent++;

    probes_active.push_back(*probeI);
    probes_to_send.erase(probeI);
    stats.num_probes_active++;
}

bool OsScanTask::ProcessResp(const std::shared_ptr<NetBase> ip, struct timeval *rcvdtime)
{
    std::shared_ptr<NetBase> tmp;
    IPv4Header *ipv4_header = NULL;
    TCPHeader *tcp_header = NULL;
    ICMPv4Header *icmpv4_header = NULL;
    int testno = 0;
    bool is_pkt_useful = false;
    std::vector<OFProbe>::iterator probeI;

    if (!ip) {
        return false;
    }

    tmp = ip->ProtocalData(HEADER_TYPE_IPv4);
    if (!tmp) {
        return false;
    }
    ipv4_header = (IPv4Header *)tmp.get();
    if (!ipv4_header->Validate()) {
        return false;
    }

    if (ipv4_header->GetNextProto() == IPPROTO_TCP) {
        tmp = ipv4_header->Next();
        if (!tmp) {
            return false;
        }
        if (tmp->ProtocolId() != HEADER_TYPE_TCP) {
            return false;
        }
        tcp_header = (TCPHeader *)tmp.get();
        if (!tcp_header->Validate()) {
            return false;
        }
        testno = tcp_header->GetDestinationPort() - tcpPortBase;
        if (testno >= 0 && testno < NUM_SEQ_SAMPLES) {
            /* TSeq */
            is_pkt_useful = ProcessTSeqResp(*ipv4_header, *tcp_header, testno);
            if (is_pkt_useful) {
                stats.ipid.tcp_ipids[testno] = ipv4_header->GetIdentification();
                probeI = GetActiveProbe(OFP_TSEQ, testno);
            }
            /* Use the seq response to do other tests. We don't care if it
            * is useful for these tests.
            */
            if (testno == 0) {
                /* the first reply is used to do T1 */
                ProcessT1_7Resp(*ipv4_header, *tcp_header, 0);
            }
            if (testno < 6) {
                /* the 1th~6th replies are used to do TOps and TWin */
                ProcessTOpsResp(*tcp_header, testno);
                ProcessTWinResp(*tcp_header, testno);
            }
        }
        else if (testno >= NUM_SEQ_SAMPLES && testno < NUM_SEQ_SAMPLES + 6) {
            /* TOps/Twin */
            is_pkt_useful = ProcessTOpsResp(*tcp_header, testno - NUM_SEQ_SAMPLES);
            is_pkt_useful |= ProcessTWinResp(*tcp_header, testno - NUM_SEQ_SAMPLES);
            if (is_pkt_useful) {
                probeI = GetActiveProbe(OFP_TOPS, testno - NUM_SEQ_SAMPLES);
            }
        }
        else if (testno == NUM_SEQ_SAMPLES + 6) {
            /* TEcn */
            is_pkt_useful = ProcessTEcnResp(*ipv4_header, *tcp_header);
            if (is_pkt_useful) {
                probeI = GetActiveProbe(OFP_TECN, 0);
            }
        }
        else if (testno >= NUM_SEQ_SAMPLES + 7 && testno < NUM_SEQ_SAMPLES + 14) {
            is_pkt_useful = ProcessT1_7Resp(*ipv4_header, *tcp_header, testno - NUM_SEQ_SAMPLES - 7);
            if (is_pkt_useful) {
                probeI = GetActiveProbe(OFP_T1_7, testno - NUM_SEQ_SAMPLES - 7);

                /* Closed-port TCP IP ID sequence numbers (SEQ.CI). Uses T5, T6, and T7.
                T5 starts at NUM_SEQ_SAMPLES + 11. */
                if (testno >= NUM_SEQ_SAMPLES + 11 && testno < NUM_SEQ_SAMPLES + 14)
                    stats.ipid.tcp_closed_ipids[testno - (NUM_SEQ_SAMPLES + 11)] = ipv4_header->GetIdentification();
            }
        }
    }
    else if (ipv4_header->GetNextProto() == IPPROTO_ICMP) {
        tmp = ipv4_header->Next();
        if (!tmp) {
            return false;
        }
        if (tmp->ProtocolId() != HEADER_TYPE_ICMPv4) {
            return false;
        }
        icmpv4_header = (ICMPv4Header *)tmp.get();
        if (!icmpv4_header->Validate()) {
            return false;
        }

        if (icmpv4_header->GetType() == ICMP_ECHOREPLY) {
            testno = icmpv4_header->GetIdentifier() - icmpEchoId;
            if (testno == 0 || testno == 1) {
                is_pkt_useful = ProcessTIcmpResp(*ipv4_header, testno);
                if (is_pkt_useful) {
                    probeI = GetActiveProbe(OFP_TICMP, testno);
                }

                if (is_pkt_useful && probeI != probes_active.end() && !probeI->retransmitted) { /* Retransmitted ipid is useless. */
                    stats.ipid.icmp_ipids[testno] = ipv4_header->GetIdentification();
                }
            }
        }

        /* Is it a destination port unreachable? */
        if (icmpv4_header->GetType() == 3 && icmpv4_header->GetCode() == 3) {
            tmp = icmpv4_header->ProtocalDataBehind(HEADER_TYPE_IPv4);
            if (!tmp) {
                return false;
            }
            IPv4Header *ipv4_header_inner = (IPv4Header *)tmp.get();
            if (!ipv4_header_inner->Validate()) {
                return false;
            }
            is_pkt_useful = ProcessTUdpResp(*ipv4_header, *icmpv4_header, *ipv4_header_inner);
            if (is_pkt_useful) {
                probeI = GetActiveProbe(OFP_TUDP, 0);
            }
        }
    }

    if (is_pkt_useful && probeI != probes_active.end()) {
        if (rcvdtime) {
            AdjustTimes(*probeI, rcvdtime);
        }
        /* delete the probe. */
        probes_active.erase(probeI);
        stats.num_probes_active = NumProbesActive();
        return true;
    }

    return false;
}

/* Returns a guess about the original TTL based on an observed TTL value.
* This function assumes that the target from which we received the packet was
* less than 32 hops away. Also, note that although some systems use an
* initial TTL of 60, this function rounds that to 64, as both values
* cannot be reliably distinguished based on a simple observed hop count. */
int OsScanTask::GetDistanceGuessFromTTL(unsigned char ttl)
{
    if (ttl <= 32)
        return 32;
    else if (ttl <= 64)
        return 64;
    else if (ttl <= 128)
        return 128;
    else
        return 255;
}

bool OsScanTask::Timeout()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return TIMEVAL_SUBTRACT(this->time_out, now) < 0;
}

void OsScanTask::MakeFP()
{
    int i;
    AVal AV;
    std::vector<AVal>::iterator it;

    int ttl;

    if (!stats.FP_TSeq) {
        MakeTSeqFP();
    }

    if (!stats.FP_TOps) {
        MakeTOpsFP();
    }

    if (!stats.FP_TWin) {
        MakeTWinFP();
    }

    for (i = 3; i < NUM_FPTESTS; i++) {
        if (!stats.fptests[i] &&
            ((i >= 3 && i <= 7 && t.open_tcp_port != -1) ||
            (i >= 8 && i <= 10 && t.closed_tcp_port != -1) ||
                i >= 11)) {
            /* We create a Resp (response) attribute with value of N (no) because
            it is important here to note whether responses were or were not
            received */
            stats.fptests[i] = std::make_shared<FingerTest>();
            if (stats.fptests[i]) {
                AV.attribute = "R";
                AV.value = "N";
                stats.fptests[i]->results.emplace_back(AV);
                stats.fptests[i]->name = (i == 3) ? "ECN" : (i == 4) ? "T1" : (i == 5) ? "T2" : (i == 6) ? "T3" : (i == 7) ? "T4" : (i == 8) ? "T5" : (i == 9) ? "T6" : (i == 10) ? "T7" : (i == 11) ? "U1" : "IE";
            }
        }
        else if (stats.fptests[i]) {
            /* Replace TTL with initial TTL. */
            for (it = stats.fptests[i]->results.begin(); it != stats.fptests[i]->results.end(); it++) {
                if (strcmp(it->attribute, "T") == 0) {
                    /* Found TTL item. The value for this attribute is the
                    * received TTL encoded in decimal. We replace it with the
                    * initial TTL encoded in hex. */
                    ttl = atoi(it->value);

                    if (stats.distance_guess == -1) {
                        stats.distance_guess = GetDistanceGuessFromTTL(ttl) - ttl;
                    }

                    if (stats.distance != -1) {
                        /* We've gotten response for the UDP probe and thus have
                        the "true" hop count. Add the number of hops between
                        us and the target (hss->distance - 1) to the received
                        TTL to get the initial TTL. */
                        it->value = StringHelper::getstaticstring("%hX", ttl + stats.distance - 1);
                    }
                    else {
                        /* Guess the initial TTL value */
                        it->attribute = "TG";
                        it->value = StringHelper::getstaticstring("%hX", ttl);
                    }
                    break;
                }
            }
        }
    }

    /* Link them up. */
    stats.fp = std::make_shared<FingerPrint>();
    if (stats.fp) {
        for (i = 0; i < NUM_FPTESTS; i++) {
            if (stats.fptests[i] == NULL) {
                continue;
            }
            stats.fp->tests.push_back(*stats.fptests[i]);
        }
    }
}

bool OsScanTask::SendOK()
{
    if (stats.num_probes_sent - stats.num_probes_sent_at_last_round >= 50) {
        return false;
    }

    if (stats.timing.cwnd < stats.num_probes_active + 0.5) {
        return false;
    }
    return true;
}

bool OsScanTask::HostSendOK(struct timeval *when)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    std::vector<OFProbe>::iterator probeI;
    int packTime;
    struct timeval probe_to, earliest_to, sendTime;
    long tdiff;

    if (stats.send_delay_ms > 0) {
        packTime = TIMEVAL_MSEC_SUBTRACT(now, stats.last_probe_sent);
        if (packTime < (int)stats.send_delay_ms) {
            if (when) {
                TIMEVAL_MSEC_ADD(*when, stats.last_probe_sent, stats.send_delay_ms);
            }
            return false;
        }
    }

    if (stats.timing.cwnd >= (NumProbesActive() + 0.5)) {
        if (when) {
            *when = now;
        }
        return true;
    }

    if (!when) {
        return false;
    }

    TIMEVAL_MSEC_ADD(earliest_to, now, 10000);

    /* Any timeouts coming up? */
    for (probeI = probes_active.begin(); probeI != probes_active.end(); probeI++) {
        TIMEVAL_MSEC_ADD(probe_to, probeI->sent, TimeProbeTimeout() / 1000);
        if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
            earliest_to = probe_to;
        }
    }

    // Will any scan delay affect this?
    if (stats.send_delay_ms > 0) {
        TIMEVAL_MSEC_ADD(sendTime, stats.last_probe_sent, stats.send_delay_ms);
        if (TIMEVAL_MSEC_SUBTRACT(sendTime, now) < 0) {
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
            if (tdiff > 0 && stats.timing.cwnd > (NumProbesActive() + 0.5)) {
                earliest_to = sendTime;
            }
        }
    }

    *when = earliest_to;
    return false;
}

/* Check whether it is OK to send the next seq probe to the host. If
* not, fill param "when" with the time when it will be sendOK and return
* false; else, fill it with now and return true. */
bool OsScanTask::HostSeqSendOK(struct timeval *when)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    std::vector<OFProbe>::iterator probeI;
    int packTime = 0, maxWait = 0;
    struct timeval probe_to, earliest_to, sendTime;
    long tdiff;

    packTime = TIMEVAL_SUBTRACT(now, stats.last_probe_sent);

    /*
    * If the user insist a larger sendDelayMs, use it. But
    * the seq result may be inaccurate.
    */
    maxWait = std::max(OS_SEQ_PROBE_DELAY * 1000, (int)stats.send_delay_ms * 1000);
    if (packTime < maxWait) {
        if (when) {
            TIMEVAL_ADD(*when, stats.last_probe_sent, maxWait);
        }
        return false;
    }

    if (stats.timing.cwnd >= (NumProbesActive() + 0.5)) {
        if (when) {
            *when = now;
        }
        return true;
    }

    if (!when){
        return false;
    }

    /* max 10 sec to now*/
    TIMEVAL_MSEC_ADD(earliest_to, now, 10000);

    /* Any timeouts coming up? */
    for (probeI = probes_active.begin(); probeI != probes_active.end(); probeI++) {
        TIMEVAL_MSEC_ADD(probe_to, probeI->sent, TimeProbeTimeout() / 1000);
        if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
            earliest_to = probe_to;
        }
    }

    TIMEVAL_ADD(sendTime, stats.last_probe_sent, maxWait);
    if (TIMEVAL_SUBTRACT(sendTime, now) < 0) {
        sendTime = now;
    }

    tdiff = TIMEVAL_SUBTRACT(earliest_to, sendTime);
    /* Timeouts previous to the sendTime requirement are pointless,
    and those later than sendTime are not needed if we can send a
    new packet at sendTime */
    if (tdiff < 0) {
        earliest_to = sendTime;
    }
    else {
        if (tdiff > 0 && stats.timing.cwnd > (NumProbesActive() + 0.5)) {
            earliest_to = sendTime;
        }
    }

    *when = earliest_to;
    return false;
}

bool OsScanTask::NextTimeout(struct timeval *when)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timeval probe_to, earliest_to;
    std::vector<OFProbe>::iterator probeI;
    bool firstgood = true;

    memset(&probe_to, 0, sizeof(probe_to));
    memset(&earliest_to, 0, sizeof(earliest_to));

    for (probeI = probes_active.begin(); probeI != probes_active.end(); probeI++) {
        TIMEVAL_ADD(probe_to, probeI->sent, TimeProbeTimeout());
        if (firstgood || TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
            earliest_to = probe_to;
            firstgood = false;
        }
    }

    *when = (firstgood) ? now : earliest_to;
    return !firstgood;
}

void OsScanTask::AdjustTimes(const OFProbe &probe, struct timeval *rcvdtime)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    /* Adjust timing */
    if (rcvdtime) {
        t.to.adjust_timeouts2(&probe.sent, rcvdtime);
        stats.to.adjust_timeouts2(&probe.sent, rcvdtime);
    }

    stats.timing.num_replies_expected++;
    stats.timing.num_updates++;

    /* Notice a drop if
    1. We get a response to a retransmitted probe (meaning the first reply was
    dropped), or
    2. We get no response after a timeout (rcvdtime == NULL). */
    if (probe.tryno > 0 || rcvdtime == NULL) {
        if (TIMEVAL_AFTER(probe.sent, stats.timing.last_drop)) {
            stats.timing.drop(NumProbesActive(), &perf, &now);
        }
        if (TIMEVAL_AFTER(probe.sent, stats.timing.last_drop)) {
            stats.timing.drop_group(stats.num_probes_active, &perf, &now);
        }
    }

    /* Increase the window for a positive reply. This can overlap with case (1)
    above. */
    if (rcvdtime != NULL) {
        stats.timing.ack(&perf);
    }
}

void OsScanTask::SendTSeqProbe(int probeNo)
{
    if (t.open_tcp_port == -1) {
        return;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
        tcpPortBase + probeNo, t.open_tcp_port,
        tcpSeqBase + probeNo, tcpAck,
        0, TH_SYN, prbWindowSz[probeNo], 0,
        prbOpts[probeNo].val, prbOpts[probeNo].len, NULL, 0);
    stats.seq_send_times[probeNo] = now;
}

void OsScanTask::SendTOpsProbe(int probeNo)
{
    if (t.open_tcp_port == -1) {
        return;
    }

    SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
        tcpPortBase + NUM_SEQ_SAMPLES + probeNo, t.open_tcp_port,
        tcpSeqBase, tcpAck,
        0, TH_SYN, prbWindowSz[probeNo], 0,
        prbOpts[probeNo].val, prbOpts[probeNo].len, NULL, 0);
}

void OsScanTask::SendTEcnProbe()
{
    if (t.open_tcp_port == -1) {
        return;
    }

    SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
        tcpPortBase + NUM_SEQ_SAMPLES + 6, t.open_tcp_port,
        tcpSeqBase, 0,
        8, TH_CWR | TH_ECE | TH_SYN, prbWindowSz[6], 63477,
        prbOpts[6].val, prbOpts[6].len, NULL, 0);
}

void OsScanTask::SendT1_7Probe(int probeNo)
{
    int port_base = tcpPortBase + NUM_SEQ_SAMPLES + 7;
    switch (probeNo) {
    case 0: /* T1 */
            /* T1 is normally filled in by sendTSeqProbe so this case doesn't happen. In
            case all six Seq probes failed, this one will be re-sent. It is the same
            as the first probe sent by sendTSeqProbe. */
        if (t.open_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
            port_base, t.open_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_SYN, prbWindowSz[0], 0,
            prbOpts[0].val, prbOpts[0].len, NULL, 0);
        break;
    case 1: /* T2 */
        if (t.open_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, true, NULL, 0,
            port_base + 1, t.open_tcp_port,
            tcpSeqBase, tcpAck,
            0, 0, prbWindowSz[7], 0,
            prbOpts[7].val, prbOpts[7].len, NULL, 0);
        break;
    case 2: /* T3 */
        if (t.open_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
            port_base + 2, t.open_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_SYN | TH_FIN | TH_URG | TH_PSH, prbWindowSz[8], 0,
            prbOpts[8].val, prbOpts[8].len, NULL, 0);
        break;
    case 3: /* T4 */
        if (t.open_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, true, NULL, 0,
            port_base + 3, t.open_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_ACK, prbWindowSz[9], 0,
            prbOpts[9].val, prbOpts[9].len, NULL, 0);
        break;
    case 4: /* T5 */
        if (t.closed_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
            port_base + 4, t.closed_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_SYN, prbWindowSz[10], 0,
            prbOpts[10].val, prbOpts[10].len, NULL, 0);
        break;
    case 5: /* T6 */
        if (t.closed_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, true, NULL, 0,
            port_base + 5, t.closed_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_ACK, prbWindowSz[11], 0,
            prbOpts[11].val, prbOpts[11].len, NULL, 0);
        break;
    case 6: /* T7 */
        if (t.closed_tcp_port == -1) {
            return;
        }
        SendTcpProbe(DEFAULT_TCP_TTL, false, NULL, 0,
            port_base + 6, t.closed_tcp_port,
            tcpSeqBase, tcpAck,
            0, TH_FIN | TH_PSH | TH_URG, prbWindowSz[12], 0,
            prbOpts[12].val, prbOpts[12].len, NULL, 0);
    }
}

void OsScanTask::SendTUdpProbe(int probeNo)
{
    if (t.closed_udp_port == -1) {
        return;
    }
    SendClosedUdpProbe(udpttl, udpPortBase + probeNo, t.closed_udp_port);
}

void OsScanTask::SendTIcmpProbe(int probeNo)
{
    if (probeNo == 0) {
        SendIcmpEchoProbe(IP_TOS_DEFAULT,
            true, 9, icmpEchoId, icmpEchoSeq, 120);
    }
    else {
        SendIcmpEchoProbe(IP_TOS_RELIABILITY,
            false, 0, icmpEchoId + 1, icmpEchoSeq + 1, 150);
    }
}

bool OsScanTask::ProcessTSeqResp(const IPv4Header &ip, const TCPHeader &tcp, int replyNo)
{
    int seq_response_num; /* response # for sequencing */
    unsigned int timestamp = 0; /* TCP timestamp we receive back */

    if (stats.lastipid != 0 && ip.GetIdentification() == stats.lastipid) {
        /* Probably a duplicate -- this happens sometimes when scanning localhost */
        return false;
    }
    stats.lastipid = ip.GetIdentification();
    if (tcp.GetRST()) {
        return false;
    }

    if ((tcp.GetFlags() & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        /* We use the ACK value to match up our sent with rcv'd packets */
        seq_response_num = tcp.GetAck() - tcpSeqBase - 1;
        /* printf("seq_response_num = %d\treplyNo = %d\n", seq_response_num, replyNo); */

        if (seq_response_num != replyNo) {
            /* BzzT! Value out of range */
            seq_response_num = replyNo;
        }

        if (stats.si.seqs[seq_response_num] == 0) {
            /* New response found! */
            stats.si.responses++;
            stats.si.seqs[seq_response_num] = tcp.GetSeq(); /* TCP ISN */
            stats.si.ipids[seq_response_num] = ip.GetIdentification();
            std::vector<tcp_opt_t> opts = tcp.GetOption();
            bool found_ts = false;
            for (auto it = opts.begin(); it != opts.end(); it++) {
                if (it->type != TCPOPT_TSTAMP) {
                    continue;
                }
                if (!it->value || it->len < 10) {
                    continue;
                }
                timestamp = (int)ntohl(*(int*)(it->value));
                found_ts = true;
            }

            if (!found_ts) {
                stats.si.ts_seqclass = TS_SEQ_UNSUPPORTED;
            }
            else {
                if (timestamp == 0) {
                    stats.si.ts_seqclass = TS_SEQ_ZERO;
                }
            }
            stats.si.timestamps[seq_response_num] = timestamp;
            return true;
        }
    }

    return false;
}

bool OsScanTask::ProcessTOpsResp(const TCPHeader &tcp, int replyNo)
{
    char ops_buf[256];
    bool opsParseResult;

    if (stats.FP_TOps || stats.tops_AVs[replyNo]) {
        return false;
    }

    stats.tops_AVs[replyNo] = std::make_shared<AVal>();
    if (!stats.tops_AVs[replyNo]) {
        stats.tops_reply_num++;
        return false;
    }
    opsParseResult = GetTcpOptString(tcp, this->tcpMss, ops_buf, sizeof(ops_buf));

    if (!opsParseResult) {
        stats.tops_AVs[replyNo]->value = "";
    }

    stats.tops_AVs[replyNo]->value = StringHelper::getstaticstring(ops_buf);
    switch (replyNo) {
    case 0:
        stats.tops_AVs[replyNo]->attribute = "O1";
        break;
    case 1:
        stats.tops_AVs[replyNo]->attribute = "O2";
        break;
    case 2:
        stats.tops_AVs[replyNo]->attribute = "O3";
        break;
    case 3:
        stats.tops_AVs[replyNo]->attribute = "O4";
        break;
    case 4:
        stats.tops_AVs[replyNo]->attribute = "O5";
        break;
    case 5:
        stats.tops_AVs[replyNo]->attribute = "O6";
        break;
    }

    stats.tops_reply_num++;
    return true;
}

bool OsScanTask::ProcessTWinResp(const TCPHeader &tcp, int replyNo)
{
    if (stats.FP_TWin || stats.twin_AVs[replyNo]) {
        return false;
    }

    stats.twin_AVs[replyNo] = std::make_shared<AVal>();
    if (!stats.twin_AVs[replyNo]) {
        stats.twin_reply_num++;
        return false;
    }

    stats.twin_AVs[replyNo]->value = StringHelper::getstaticstring("%hX", tcp.GetWindow());

    switch (replyNo) {
    case 0:
        stats.twin_AVs[replyNo]->attribute = "W1";
        break;
    case 1:
        stats.twin_AVs[replyNo]->attribute = "W2";
        break;
    case 2:
        stats.twin_AVs[replyNo]->attribute = "W3";
        break;
    case 3:
        stats.twin_AVs[replyNo]->attribute = "W4";
        break;
    case 4:
        stats.twin_AVs[replyNo]->attribute = "W5";
        break;
    case 5:
        stats.twin_AVs[replyNo]->attribute = "W6";
        break;
    }

    stats.twin_reply_num++;
    return true;
}

bool OsScanTask::ProcessTEcnResp(const IPv4Header &ip, const TCPHeader &tcp)
{
    std::vector<AVal> AVs;
    AVal AV;
    char ops_buf[256];
    char quirks_buf[10];
    char *p;
    int numtests = 7;
    bool opsParseResult;

    if (stats.FP_TEcn) {
        return false;
    }

    /* Create the Avals */
    AVs.reserve(numtests);

    AV.attribute = "R";
    AV.value = "Y";
    AVs.push_back(AV);

    /* don't frag flag */
    AV.attribute = "DF";
    if (ip.GetDF()) {
        AV.value = "Y";
    }
    else {
        AV.value = "N";
    }
    AVs.push_back(AV);

    /* TTL */
    AV.attribute = "T";
    AV.value = StringHelper::getstaticstring("%d", ip.GetTTL());
    AVs.push_back(AV);

    /* TCP Window size */
    AV.attribute = "W";
    AV.value = StringHelper::getstaticstring("%hX", tcp.GetWindow());
    AVs.push_back(AV);

    /* Now for the TCP options ... */
    AV.attribute = "O";
    opsParseResult = GetTcpOptString(tcp, this->tcpMss, ops_buf, sizeof(ops_buf));

    if (!opsParseResult) {
        AV.value = "";
    }

    AV.value = StringHelper::getstaticstring(ops_buf);
    AVs.push_back(AV);

    /* Explicit Congestion Notification support test */
    AV.attribute = "CC";
    if (tcp.GetECE() && tcp.GetCWR()) {
        /* echo back */
        AV.value = "S";
    }
    else if (tcp.GetECE()) {
        /* support */
        AV.value = "Y";
    }
    else if (!tcp.GetCWR()) {
        /* not support */
        AV.value = "N";
    }
    else {
        AV.value = "O";
    }
    AVs.push_back(AV);

    /* TCP miscellaneous quirks test */
    AV.attribute = "Q";
    p = quirks_buf;
    if (tcp.GetReserved()) {
        /* Reserved field of TCP is not zero */
        *p++ = 'R';
    }
    if (!tcp.GetURG() && tcp.GetUrgPointer()) {
        /* URG pointer value when urg flag not set */
        *p++ = 'U';
    }
    *p = '\0';
    AV.value = StringHelper::getstaticstring(quirks_buf);
    AVs.push_back(AV);

    stats.FP_TEcn = std::make_shared<FingerTest>();
    if (stats.FP_TEcn) {
        stats.FP_TEcn->name = "ECN";
        stats.FP_TEcn->results = AVs;
    }
    return true;
}

bool OsScanTask::ProcessT1_7Resp(IPv4Header &ip, TCPHeader &tcp, int replyNo)
{
    std::vector<AVal> AVs;
    AVal AV;
    int numtests;
    int i;
    bool opsParseResult;
    int length;
    char flags_buf[10];
    char quirks_buf[10];
    char *p;

    if (stats.fptests[FP_T1_7_OFF + replyNo]) {
        return false;
    }

    if (replyNo == 0) {
        numtests = 8; /* T1 doesn't has 'Win', 'Ops' tests. */
    }
    else {
        numtests = 10;
    }

    /* Create the Avals */
    AVs.reserve(numtests);

    /* First we give the "response" flag to say we did actually receive
    a packet -- this way we won't match a template with R=N */
    AV.attribute = "R";
    AV.value = "Y";
    AVs.push_back(AV);

    /* Next we check whether the Don't Fragment bit is set */
    AV.attribute = "DF";
    if (ip.GetDF()) {
        AV.value = "Y";
    }
    else {
        AV.value = "N";
    }
    AVs.push_back(AV);

    /* TTL */
    AV.attribute = "T";
    AV.value = StringHelper::getstaticstring("%d", ip.GetTTL());
    AVs.push_back(AV);

    if (replyNo != 0) {
        /* Now we do the TCP Window size */
        AV.attribute = "W";
        AV.value = StringHelper::getstaticstring("%hX", tcp.GetWindow());
        AVs.push_back(AV);
    }

    /* Seq test values:
    Z   = zero
    A   = same as ack
    A+  = ack + 1
    O   = other
    */
    AV.attribute = "S";
    if (tcp.GetSeq() == 0) {
        AV.value = "Z";
    }
    else if (tcp.GetSeq() == tcpAck) {
        AV.value = "A";
    }
    else if (tcp.GetSeq() == tcpAck + 1) {
        AV.value = "A+";
    }
    else {
        AV.value = "O";
    }
    AVs.push_back(AV);

    /* ACK test values:
    Z   = zero
    S   = same as syn
    S+  = syn + 1
    O   = other
    */
    AV.attribute = "A";
    if (tcp.GetAck() == 0) {
        AV.value = "Z";
    }
    else if (tcp.GetAck() == tcpSeqBase) {
        AV.value = "S";
    }
    else if (tcp.GetAck() == tcpSeqBase + 1) {
        AV.value = "S+";
    }
    else {
        AV.value = "O";
    }
    AVs.push_back(AV);

    /* Flags. They must be in this order:
    E = ECN Echo
    U = Urgent
    A = Acknowledgement
    P = Push
    R = Reset
    S = Synchronize
    F = Final
    */
    struct {
        unsigned char flag;
        char c;
    } flag_defs[] = {
        { TH_ECE, 'E' },
        { TH_URG, 'U' },
        { TH_ACK, 'A' },
        { TH_PSH, 'P' },
        { TH_RST, 'R' },
        { TH_SYN, 'S' },
        { TH_FIN, 'F' },
    };
    AV.attribute = "F";
    p = flags_buf;
    for (i = 0; i < (int)(sizeof(flag_defs) / sizeof(flag_defs[0])); i++) {
        if (tcp.GetFlags() & flag_defs[i].flag)
            *p++ = flag_defs[i].c;
    }
    *p = '\0';
    AV.value = StringHelper::getstaticstring(flags_buf);
    AVs.push_back(AV);

    if (replyNo != 0) {
        char ops_buf[256];

        /* Now for the TCP options ... */
        AV.attribute = "O";
        opsParseResult = GetTcpOptString(tcp, this->tcpMss, ops_buf, sizeof(ops_buf));
        if (!opsParseResult) {
            AV.value = "";
        }

        AV.value = StringHelper::getstaticstring(ops_buf);
        AVs.push_back(AV);
    }

    /* Rst Data CRC32 */
    AV.attribute = "RD";
    length = (int)ip.GetTotalLength() - ip.GetHeaderLength() - tcp.GetHeaderLength();
    if (tcp.GetRST() && length>0 && tcp.Next()) {
        std::string data = tcp.Next()->AllData();
        AV.value = StringHelper::getstaticstring("%08lX", AlgorithmHelper::CRC32((unsigned char *)data.c_str(), data.size()));
    }
    else {
        AV.value = "0";
    }
    AVs.push_back(AV);

    /* TCP miscellaneous quirks test */
    AV.attribute = "Q";
    p = quirks_buf;
    if (tcp.GetReserved()) {
        /* Reserved field of TCP is not zero */
        *p++ = 'R';
    }
    if (!(tcp.GetURG()) && tcp.GetUrgPointer()) {
        /* URG pointer value when urg flag not set */
        *p++ = 'U';
    }
    *p = '\0';
    AV.value = StringHelper::getstaticstring(quirks_buf);
    AVs.push_back(AV);

    stats.fptests[FP_T1_7_OFF + replyNo] = std::make_shared<FingerTest>();
    if (stats.fptests[FP_T1_7_OFF + replyNo]) {
        stats.fptests[FP_T1_7_OFF + replyNo]->results = AVs;
        stats.fptests[FP_T1_7_OFF + replyNo]->name = (replyNo == 0) ? "T1" : (replyNo == 1) ? "T2" : (replyNo == 2) ? "T3" : (replyNo == 3) ? "T4" : (replyNo == 4) ? "T5" : (replyNo == 5) ? "T6" : "T7";
    }
    return true;
}

bool OsScanTask::ProcessTUdpResp(const IPv4Header &ip, const ICMPv4Header &icmp, IPv4Header &ip_inner)
{
    std::vector<AVal> AVs;
    AVal AV;
    int numtests = 10;
    unsigned short checksum;
    UDPHeader *udp_header;
    std::shared_ptr<NetBase> tmp;
    const unsigned char *datastart, *dataend;

    if (stats.FP_TUdp) {
        return false;
    }
    tmp = ip_inner.ProtocalDataBehind(HEADER_TYPE_UDP);
    if (!tmp) {
        return false;
    }
    udp_header = (UDPHeader *)tmp.get();
    /* The ports should match. */
    if (udp_header->GetSourcePort() != stats.upi.sport || udp_header->GetDestinationPort() != stats.upi.dport) {
        return false;
    }

    /* Create the Avals */
    AVs.reserve(numtests);

    /* First of all, if we got this far the response was yes */
    AV.attribute = "R";
    AV.value = "Y";
    AVs.push_back(AV);

    /* Also, we now know that the port we reached was closed */
    if (t.closed_udp_port == -1) {
        t.closed_udp_port = stats.upi.dport;
    }

    /* Now let us do an easy one, Don't fragment */
    AV.attribute = "DF";
    if (ip.GetDF()) {
        AV.value = "Y";
    }
    else {
        AV.value = "N";
    }
    AVs.push_back(AV);

    /* TTL */
    AV.attribute = "T";
    AV.value = StringHelper::getstaticstring("%d", ip.GetTTL());
    AVs.push_back(AV);

    /* Now we look at the IP datagram length that was returned, some
    machines send more of the original packet back than others */
    AV.attribute = "IPL";
    AV.value = StringHelper::getstaticstring("%hX", ip.GetTotalLength());
    AVs.push_back(AV);

    /* unused filed not zero in Destination Unreachable Message */
    AV.attribute = "UN";
    AV.value = StringHelper::getstaticstring("%hX", icmp.GetReserved());
    AVs.push_back(AV);

    /* OK, lets check the returned IP length, some systems @$@ this
    up */
    AV.attribute = "RIPL";
    if (ip_inner.GetTotalLength() == 328) {
        AV.value = "G";
    }
    else {
        AV.value = StringHelper::getstaticstring("%hX", ip_inner.GetTotalLength());
    }
    AVs.push_back(AV);

    /* This next test doesn't work on Solaris because the lamers
    overwrite our ip_id */
    /* Now lets see how they treated the ID we sent ... */
    AV.attribute = "RID";
    if (ip_inner.GetIdentification() == stats.upi.ipid) {
        AV.value = "G"; /* The good "expected" value */
    }
    else {
        AV.value = StringHelper::getstaticstring("%hX", ip_inner.GetIdentification());
    }
    AVs.push_back(AV);

    /* Let us see if the IP checksum we got back computes */

    AV.attribute = "RIPCK";
    /* Thanks to some machines not having struct ip member ip_sum we
    have to go with this BS */
    checksum = ip_inner.GetSum();
    if (checksum == 0) {
        AV.value = "Z";
    }
    else {
        ip_inner.SetSum();
        if (ip_inner.GetSum() == checksum) {
            AV.value = "G"; /* The "expected" good value */
        }
        else {
            AV.value = "I"; /* They modified it */
        }
        ip_inner.SetSum(checksum);
    }
    AVs.push_back(AV);

    /* UDP checksum */
    AV.attribute = "RUCK";
    if (udp_header->GetSum() == stats.upi.udpck) {
        AV.value = "G"; /* The "expected" good value */
    }
    else {
        AV.value = StringHelper::getstaticstring("%hX", ntohs(udp_header->GetSum()));
    }
    AVs.push_back(AV);

    /* Finally we ensure the data is OK */
    AV.attribute = "RUD";
    RawData *raw_data = NULL;
    tmp = udp_header->Next();
    if (!tmp) {
        AV.value = "G";
    }
    else if (tmp->ProtocolId() != HEADER_TYPE_RAW_DATA)
    {
        AV.value = "I"; /* They modified it */
    }
    else {
        raw_data = (RawData *)tmp.get();
        std::string data = raw_data->AllData();
        datastart = (const unsigned char*)data.c_str();
        dataend = (const unsigned char*)data.c_str() + data.size();
        while (datastart < dataend) {
            if (*datastart != stats.upi.patternbyte) {
                break;
            }
            datastart++;
        }
        if (datastart < dataend) {
            AV.value = "I"; /* They modified it */
        }
        else {
            AV.value = "G";
        }
    }
    AVs.push_back(AV);

    stats.FP_TUdp = std::make_shared<FingerTest>();
    if (stats.FP_TUdp) {
        stats.FP_TUdp->name = "U1";
        stats.FP_TUdp->results = AVs;
    }

    /* Count hop count */
    if (stats.distance == -1) {
        stats.distance = udpttl - ip_inner.GetTTL() + 1;
    }
    return true;
}

bool OsScanTask::ProcessTIcmpResp(IPv4Header &ip, int replyNo)
{
    std::vector<AVal> AVs;
    AVal AV;
    int numtests = 4;
    IPv4Header *ip1, *ip2;
    ICMPv4Header *icmp1, *icmp2;
    std::shared_ptr<NetBase> tmp;

    if (stats.FP_TIcmp) {
        return false;
    }

    if (!stats.icmp_echo_reply) {
        /* This is the first icmp reply we get, store it and return. */
        stats.icmp_echo_reply = ip.shared_from_this();
        stats.stored_icmp_reply = replyNo;
        return true;
    }
    else if (stats.stored_icmp_reply == replyNo) {
        /* This is a duplicated icmp reply. */
        return false;
    }

    /* Ok, now we get another reply. */
    if (stats.stored_icmp_reply == 0) {
        ip1 = (IPv4Header *)stats.icmp_echo_reply.get();
        ip2 = &ip;
    }
    else {
        ip1 = &ip;
        ip2 = (IPv4Header *)stats.icmp_echo_reply.get();
    }

    tmp = ip1->Next();
    if (!tmp) {
        return false;
    }
    if (tmp->ProtocolId() != HEADER_TYPE_ICMPv4) {
        return false;
    }
    icmp1 = (ICMPv4Header *)tmp.get();
    tmp = ip2->Next();
    if (!tmp) {
        return false;
    }
    if (tmp->ProtocolId() != HEADER_TYPE_ICMPv4) {
        return false;
    }
    icmp2 = (ICMPv4Header *)tmp.get();

    /* Create the Avals */
    AVs.reserve(numtests);

    AV.attribute = "R";
    AV.value = "Y";
    AVs.push_back(AV);

    /* DFI test values:
    * Y. Both set DF;
    * S. Both use the DF that the sender uses;
    * N. Both not set;
    * O. Other(both different with the sender, -_-b).
    */
    AV.attribute = "DFI";
    if (ip1->GetDF() && ip2->GetDF()) {
        /* both set */
        AV.value = "Y";
    }
    else if (ip1->GetDF() && !ip2->GetDF()) {
        /* echo back */
        AV.value = "S";
    }
    else if (!ip1->GetDF() && !ip2->GetDF()) {
        /* neither set */
        AV.value = "N";
    }
    else {
        AV.value = "O";
    }
    AVs.push_back(AV);

    /* TTL */

    AV.attribute = "T";
    AV.value = StringHelper::getstaticstring("%d", ip1->GetTTL());
    AVs.push_back(AV);

    /* ICMP Code value. Test values:
    * [Value]. Both set Code to the same value [Value];
    * S. Both use the Code that the sender uses;
    * O. Other.
    */
    AV.attribute = "CD";
    if (icmp1->GetCode() == icmp2->GetCode()) {
        if (icmp1->GetCode() == 0) {
            AV.value = "Z";
        }
        else {
            AV.value = StringHelper::getstaticstring("%hX", icmp1->GetCode());
        }
    }
    else if (icmp1->GetCode() == 9 && icmp2->GetCode() == 0) {
        AV.value = "S";
    }
    else {
        AV.value = "O";
    }
    AVs.push_back(AV);

    stats.FP_TIcmp = std::make_shared<FingerTest>();
    if (stats.FP_TIcmp) {
        stats.FP_TIcmp->name = "IE";
        stats.FP_TIcmp->results = AVs;
    }
    return true;
}

bool OsScanTask::GetTcpOptString(const TCPHeader &tcp, int mss, char *result, int maxlen)
{
    char *p, *q;
    unsigned short tmpshort;
    unsigned int tmpword;
    int length;
    int opcode;

    p = result;
    length = tcp.GetHeaderLength() - TCP_HEADER_LEN;
    std::string data = tcp.Data();
    q = ((char *)data.c_str()) + TCP_HEADER_LEN;

    /*
    * Example parsed result: M5B4ST11NW2
    *   MSS, Sack Permitted, Timestamp with both value not zero, Nop, WScale with value 2
    */

    /* Be aware of the max increment value for p in parsing,
    * now is 5 = strlen("Mxxxx") <-> MSS Option
    */
    while (length > 0 && (p - result) < (maxlen - 5)) {
        opcode = *q++;
        if (!opcode) { /* End of List */
            *p++ = 'L';
            length--;
        }
        else if (opcode == 1) { /* No Op */
            *p++ = 'N';
            length--;
        }
        else if (opcode == 2) { /* MSS */
            if (length < 4)
                break; /* MSS has 4 bytes */
            *p++ = 'M';
            q++;
            memcpy(&tmpshort, q, 2);
            snprintf(p,5,"%hX", ntohs(tmpshort));
            p += strlen(p); /* max movement of p is 4 (0xFFFF) */
            q += 2;
            length -= 4;
        }
        else if (opcode == 3) { /* Window Scale */
            if (length < 3)
                break; /* Window Scale option has 3 bytes */
            *p++ = 'W';
            q++;
            snprintf(p, length, "%hhX", *((unsigned char*)q));
            p += strlen(p); /* max movement of p is 2 (max WScale value is 0xFF) */
            q++;
            length -= 3;
        }
        else if (opcode == 4) { /* SACK permitted */
            if (length < 2)
                break; /* SACK permitted option has 2 bytes */
            *p++ = 'S';
            q++;
            length -= 2;
        }
        else if (opcode == 8) { /* Timestamp */
            if (length < 10)
                break; /* Timestamp option has 10 bytes */
            *p++ = 'T';
            q++;
            memcpy(&tmpword, q, 4);
            if (tmpword)
                *p++ = '1';
            else
                *p++ = '0';
            q += 4;
            memcpy(&tmpword, q, 4);
            if (tmpword)
                *p++ = '1';
            else
                *p++ = '0';
            q += 4;
            length -= 10;
        }
    }

    if (length > 0) {
        /* We could reach here for one of the two reasons:
        *  1. At least one option is not correct. (Eg. Should have 4 bytes but only has 3 bytes left).
        *  2. The option string is too long.
        */
        *result = '\0';
        return false;
    }

    *p = '\0';
    return true;
}

int OsScanTask::SendTcpProbe(
    int ttl, bool df, unsigned char* ipopt, int ipoptlen,
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
    eth->SetSrcMAC(t.src_mac, sizeof(t.src_mac));
    eth->SetDstMAC(t.dst_mac, sizeof(t.dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(IP_TOS_DEFAULT);
    ipv4->SetIdentification(AlgorithmHelper::GetRandomU16());
    if (df) {
        ipv4->SetDF();
    }
    ipv4->SetTTL(ttl);
    ipv4->SetNextProto(HEADER_TYPE_TCP);
    ipv4->SetDestinationAddress(t.dst_ip);
    ipv4->SetSourceAddress(t.src_ip);
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

int OsScanTask::SendIcmpEchoProbe(
    unsigned char tos, bool df, unsigned char pcode,
    unsigned short id, unsigned short seq, unsigned short datalen)
{
    if (!pcap.IsInit()) {
        return -1;
    }

    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(t.src_mac, sizeof(t.src_mac));
    eth->SetDstMAC(t.dst_mac, sizeof(t.dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(tos);
    ipv4->SetIdentification(AlgorithmHelper::GetRandomU16());
    if (df) {
        ipv4->SetDF();
    }
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_ICMPv4);
    ipv4->SetDestinationAddress(t.dst_ip);
    ipv4->SetSourceAddress(t.src_ip);
    auto icmpv4 = std::make_shared<ICMPv4Header>();
    ipv4->SetNext(icmpv4);
    icmpv4->SetType(ICMP_ECHO);
    icmpv4->SetCode(pcode);
    icmpv4->SetIdentifier(id);
    icmpv4->SetSequence(seq);
    icmpv4->SetSum();
    ipv4->SetTotalLength();
    ipv4->SetSum();
    if (pcap.SendEthPacket(eth) == 0) {
        return 0;
    }

    return -1;
}

int OsScanTask::SendClosedUdpProbe(int ttl, unsigned short sport, unsigned short dport)
{
    static unsigned char patternbyte = 0x43; /* character 'C' */
    static unsigned char data[300];
    static bool data_is_init = false;;
    static std::mutex data_init_lock;

    if (!pcap.IsInit()) {
        return -1;
    }

    {
        std::unique_lock<std::mutex> lock(data_init_lock);
        if (!data_is_init) {
            memset(data, patternbyte, sizeof(data));
            data_is_init = true;
        }
    }

    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(t.src_mac, sizeof(t.src_mac));
    eth->SetDstMAC(t.dst_mac, sizeof(t.dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(IPv4_DEFAULT_TOS);
    ipv4->SetIdentification(htons(0x1042));
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_UDP);
    ipv4->SetDestinationAddress(t.dst_ip);
    ipv4->SetSourceAddress(t.src_ip);
    auto udp = std::make_shared<UDPHeader>();
    ipv4->SetNext(udp);
    udp->SetSourcePort(sport);
    udp->SetDestinationPort(dport);
    auto raw_data = std::make_shared<RawData>();
    udp->SetNext(raw_data);
    raw_data->StorePacket(data, sizeof(data));
    udp->SetTotalLength();
    udp->SetSum();
    ipv4->SetHeaderLength();
    ipv4->SetTotalLength();
    ipv4->SetSum();
    stats.upi.ipck = ipv4->GetSum();
    stats.upi.iptl = ipv4->GetTotalLength();
    stats.upi.ipid = ipv4->GetIdentification();
    stats.upi.sport = sport;
    stats.upi.dport = dport;
    stats.upi.udpck = udp->GetSum();
    stats.upi.udplen = udp->GetTotalLength();
    stats.upi.patternbyte = patternbyte;
    stats.upi.target.s_addr = ipv4->GetDestinationAddress().s_addr;
    if (pcap.SendEthPacket(eth) == 0) {
        return 0;
    }

    return -1;
}

static unsigned int gcd_n_uint(int nvals, unsigned int *val) 
{
    unsigned int a, b, c;

    if (!nvals)
        return 1;
    a = *val;
    for (nvals--; nvals; nvals--) {
        b = *++val;
        if (a < b) {
            c = a;
            a = b;
            b = c;
        }
        while (b) {
            c = a % b;
            a = b;
            b = c;
        }
    }
    return a;
}

/* Calculate the distances between the ipids and write them
into the ipid_diffs array. If the sequence class can be determined
immediately, return it; otherwise return -1 */
static int get_diffs(unsigned int *ipid_diffs, int numSamples, unsigned int *ipids, int islocalhost)
{
    int i;
    bool allipideqz = true;

    if (numSamples < 2)
        return IPID_SEQ_UNKNOWN;

    for (i = 1; i < numSamples; i++) {
        if (ipids[i - 1] != 0 || ipids[i] != 0)
            allipideqz = false; /* All IP.ID values do *NOT* equal zero */

        ipid_diffs[i - 1] = ipids[i] - ipids[i - 1];

        /* Random */
        if (numSamples > 2 && ipid_diffs[i - 1] > 20000)
            return IPID_SEQ_RD;
    }

    if (allipideqz) {
        return IPID_SEQ_ZERO;
    }
    else {
        return -1;
    }

}

/* This function takes an array of "numSamples" IP IDs and analyzes
them to determine their sequence classification.  It returns
one of the IPID_SEQ_* classifications defined in nmap.h .  If the
function cannot determine the sequence, IPID_SEQ_UNKNOWN is returned.
This islocalhost argument is a boolean specifying whether these
numbers were generated by scanning localhost. */
static int identify_sequence(int numSamples, unsigned int *ipid_diffs, int islocalhost) 
{
    int i, j, k, l;

    if (islocalhost) {
        int allgto = 1; /* ALL diffs greater than one */

        for (i = 0; i < numSamples - 1; i++) {
            if (ipid_diffs[i] < 2) {
                allgto = 0; break;
            }
        }

        if (allgto) {
            for (i = 0; i < numSamples - 1; i++) {
                if (ipid_diffs[i] % 256 == 0) /* Stupid MS */
                    ipid_diffs[i] -= 256;
                else
                    ipid_diffs[i]--; /* Because on localhost the RST sent back use an IPID */
            }
        }
    }

    /* Constant */
    j = 1; /* j is a flag meaning "all differences seen are zero" */
    for (i = 0; i < numSamples - 1; i++) {
        if (ipid_diffs[i] != 0) {
            j = 0;
            break;
        }
    }
    if (j) {
        return IPID_SEQ_CONSTANT;
    }

    /* Random Positive Increments */
    for (i = 0; i < numSamples - 1; i++) {
        if (ipid_diffs[i] > 1000 &&
            (ipid_diffs[i] % 256 != 0 ||
            (ipid_diffs[i] % 256 == 0 && ipid_diffs[i] >= 25600))) {
            return IPID_SEQ_RPI;
        }
    }

    j = 1; /* j is a flag meaning "all differences seen are < 10" */
    k = 1; /* k is a flag meaning "all difference seen are multiples of 256 and
           * no greater than 5120" */
    l = 1; /* l is a flag meaning "all differences are multiples of 2" */
    for (i = 0; i < numSamples - 1; i++) {
        if (k && (ipid_diffs[i] > 5120 || ipid_diffs[i] % 256 != 0)) {
            k = 0;
        }

        if (l && ipid_diffs[i] % 2 != 0) {
            l = 0;
        }

        if (j && ipid_diffs[i] > 9) {
            j = 0;
        }
    }

    /* Broken Increment */
    if (k == 1) {
        return IPID_SEQ_BROKEN_INCR;
    }

    /* Incrementing by 2 */
    if (l == 1)
        return IPID_SEQ_INCR_BY_2;

    /* Incremental by 1 */
    if (j == 1)
        return IPID_SEQ_INCR;

    return IPID_SEQ_UNKNOWN;
}

/* Indentify the ipid sequence for 16-bit IPID values (IPv4) */
static int get_ipid_sequence_16(int numSamples, unsigned int *ipids, int islocalhost)
{
    int i;
    int ipid_seq = IPID_SEQ_UNKNOWN;
    unsigned int ipid_diffs[32];

    ipid_seq = get_diffs(ipid_diffs, numSamples, ipids, islocalhost);
    /* AND with 0xffff so that in case the 16 bit counter was
    * flipped over we still have a continuous sequence */
    for (i = 0; i < numSamples; i++) {
        ipid_diffs[i] = ipid_diffs[i] & 0xffff;
    }
    if (ipid_seq < 0) {
        return identify_sequence(numSamples, ipid_diffs, islocalhost);
    }
    else {
        return ipid_seq;
    }
}

/* Fill in a struct AVal with a value based on the IP ID sequence generation
class (one of the IPID_SEQ_* constants). If ipid_seqclass is such that the
test result should be omitted, the function returns NULL and doesn't modify
*av. Otherwise, it returns av after filling in the information. */
static AVal *make_aval_ipid_seq(AVal *av, const char *attribute,
    int ipid_seqclass, unsigned int ipids[NUM_SEQ_SAMPLES]) 
{
    switch (ipid_seqclass) {
    case IPID_SEQ_CONSTANT:
        av->value = StringHelper::getstaticstring("%X", ipids[0]);
        break;
    case IPID_SEQ_INCR_BY_2:
    case IPID_SEQ_INCR:
        av->value = "I";
        break;
    case IPID_SEQ_BROKEN_INCR:
        av->value = "BI";
        break;
    case IPID_SEQ_RPI:
        av->value = "RI";
        break;
    case IPID_SEQ_RD:
        av->value = "RD";
        break;
    case IPID_SEQ_ZERO:
        av->value = "Z";
        break;
    default:
        /* Signal to omit test result. */
        return NULL;
        break;
    }

    av->attribute = StringHelper::getstaticstring(attribute);
    return av;
}

void OsScanTask::MakeTSeqFP()
{
    int i, j;
    unsigned int seq_diffs[NUM_SEQ_SAMPLES];
    unsigned int ts_diffs[NUM_SEQ_SAMPLES];
    float seq_rates[NUM_SEQ_SAMPLES];
    unsigned long time_usec_diffs[NUM_SEQ_SAMPLES];
    double seq_stddev = 0;
    double seq_rate = 0;
    double seq_avg_rate = 0;
    double avg_ts_hz = 0.0; /* Avg. amount that timestamps incr. each second */
    unsigned int seq_gcd = 1;
    int tcp_ipid_seqclass; /* TCP IPID SEQ TYPE defines in nmap.h */
    int tcp_closed_ipid_seqclass; /* TCP IPID SEQ TYPE defines in nmap.h */
    int icmp_ipid_seqclass; /* ICMP IPID SEQ TYPE defines in nmap.h */
    int good_tcp_ipid_num, good_tcp_closed_ipid_num, good_icmp_ipid_num;
    int tsnewval = 0;

    std::vector<AVal> seq_AVs;
    AVal AV;

    /* Need 8 AVals for SP, GCD, ISR, TI, CI, II, SS, TS. */
    seq_AVs.reserve(8);

    /* Now we make sure there are no gaps in our response array ... */
    for (i = 0, j = 0; i < NUM_SEQ_SAMPLES; i++) {
        if (stats.si.seqs[i] != 0) /* We found a good one */ {
            if (j < i) {
                stats.si.seqs[j] = stats.si.seqs[i];
                stats.si.ipids[j] = stats.si.ipids[i];
                stats.si.timestamps[j] = stats.si.timestamps[i];
                stats.seq_send_times[j] = stats.seq_send_times[i];
            }
            if (j > 0) {
                seq_diffs[j - 1] = MOD_DIFF(stats.si.seqs[j], stats.si.seqs[j - 1]);

                ts_diffs[j - 1] = MOD_DIFF(stats.si.timestamps[j], stats.si.timestamps[j - 1]);
                time_usec_diffs[j - 1] = TIMEVAL_SUBTRACT(stats.seq_send_times[j], stats.seq_send_times[j - 1]);
                if (!time_usec_diffs[j - 1]) time_usec_diffs[j - 1]++; /* We divide by this later */
                                                                       /* Rate of ISN increase per second */
                seq_rates[j - 1] = (float)(seq_diffs[j - 1] * 1000000.0 / time_usec_diffs[j - 1]);
                seq_avg_rate += seq_rates[j - 1];
            }
            j++;
        } /* Otherwise nothing good in this slot to copy */
    }

    stats.si.responses = j; /* Just for assurance */

    /* Time to look at the TCP ISN predictability */
    if (stats.si.responses >= 4) {
        seq_avg_rate /= stats.si.responses - 1;
        seq_rate = seq_avg_rate;

        /* First calculate the GCD */
        seq_gcd = gcd_n_uint(stats.si.responses - 1, seq_diffs);

        if (!seq_gcd) {
            /* Constant ISN */
            seq_rate = 0;
            seq_stddev = 0;
            stats.si.index = 0;
        }
        else {

            /* Finally we take a binary logarithm, multiply by 8, and round
            * to get the final result */
            seq_rate = log(seq_rate) / log(2.0);
            seq_rate = (unsigned int)(seq_rate * 8 + 0.5);

            /* Normally we don't divide by gcd in computing the rate stddev
            * because otherwise we'll get an artificially low value about
            * 1/32 of the time if the responses all happen to be even.  On
            * the other hand, if a system inherently uses a large gcd such
            * as 64,000, we want to get rid of it.  So as a compromise, we
            * divide by the gcd if it is at least 9 */
            int div_gcd = 1;
            if (seq_gcd > 9)
                div_gcd = seq_gcd;

            for (i = 0; i < stats.si.responses - 1; i++) {
                double rtmp = seq_rates[i] / div_gcd - seq_avg_rate / div_gcd;
                seq_stddev += rtmp * rtmp;
            }

            /* We divide by ((numelements in seq_diffs) - 1), which is
            * (si.responses - 2), because that gives a better approx of
            * std. dev when you're only looking at a subset of whole
            * population. */
            seq_stddev /= stats.si.responses - 2;

            /* Next we need to take the square root of this value */
            seq_stddev = sqrt(seq_stddev);

            /* Finally we take a binary logarithm, multiply by 8, and round
            * to get the final result */
            if (seq_stddev <= 1)
                stats.si.index = 0;
            else {
                seq_stddev = log(seq_stddev) / log(2.0);
                stats.si.index = (int)(seq_stddev * 8 + 0.5);
            }
        }

        AV.attribute = "SP";
        AV.value = StringHelper::getstaticstring("%X", stats.si.index);
        seq_AVs.push_back(AV);
        AV.attribute = "GCD";
        AV.value = StringHelper::getstaticstring("%X", seq_gcd);
        seq_AVs.push_back(AV);
        AV.attribute = "ISR";
        AV.value = StringHelper::getstaticstring("%X", (unsigned int)seq_rate);
        seq_AVs.push_back(AV);
    }

    /* Now it is time to deal with IPIDs */
    good_tcp_ipid_num = 0;
    good_tcp_closed_ipid_num = 0;
    good_icmp_ipid_num = 0;

    for (i = 0; i < NUM_SEQ_SAMPLES; i++) {
        if (stats.ipid.tcp_ipids[i] != 0xffffffff) {
            if (good_tcp_ipid_num < i) {
                stats.ipid.tcp_ipids[good_tcp_ipid_num] = stats.ipid.tcp_ipids[i];
            }
            good_tcp_ipid_num++;
        }

        if (stats.ipid.tcp_closed_ipids[i] != 0xffffffff) {
            if (good_tcp_closed_ipid_num < i) {
                stats.ipid.tcp_closed_ipids[good_tcp_closed_ipid_num] = stats.ipid.tcp_closed_ipids[i];
            }
            good_tcp_closed_ipid_num++;
        }

        if (stats.ipid.icmp_ipids[i] != 0xffffffff) {
            if (good_icmp_ipid_num < i) {
                stats.ipid.icmp_ipids[good_icmp_ipid_num] = stats.ipid.icmp_ipids[i];
            }
            good_icmp_ipid_num++;
        }
    }

    if (good_tcp_ipid_num >= 3) {
        tcp_ipid_seqclass = get_ipid_sequence_16(good_tcp_ipid_num, stats.ipid.tcp_ipids, false);
    }
    else {
        tcp_ipid_seqclass = IPID_SEQ_UNKNOWN;
    }
    /* Only print open tcp ipid seqclass in the final report. */
    stats.si.ipid_seqclass = tcp_ipid_seqclass;

    if (good_tcp_closed_ipid_num >= 2) {
        tcp_closed_ipid_seqclass = get_ipid_sequence_16(good_tcp_closed_ipid_num, stats.ipid.tcp_closed_ipids, false);
    }
    else {
        tcp_closed_ipid_seqclass = IPID_SEQ_UNKNOWN;
    }

    if (good_icmp_ipid_num >= 2) {
        icmp_ipid_seqclass = get_ipid_sequence_16(good_icmp_ipid_num, stats.ipid.icmp_ipids, false);
    }
    else {
        icmp_ipid_seqclass = IPID_SEQ_UNKNOWN;
    }

    /* This fills in TI=Z or something like that. */
    if (make_aval_ipid_seq(&AV, "TI", tcp_ipid_seqclass, stats.ipid.tcp_ipids) != NULL)
        seq_AVs.push_back(AV);
    if (make_aval_ipid_seq(&AV, "CI", tcp_closed_ipid_seqclass, stats.ipid.tcp_closed_ipids) != NULL)
        seq_AVs.push_back(AV);
    if (make_aval_ipid_seq(&AV, "II", icmp_ipid_seqclass, stats.ipid.icmp_ipids) != NULL)
        seq_AVs.push_back(AV);

    /* SS: Shared IP ID sequence boolean */
    if ((tcp_ipid_seqclass == IPID_SEQ_INCR ||
        tcp_ipid_seqclass == IPID_SEQ_BROKEN_INCR ||
        tcp_ipid_seqclass == IPID_SEQ_RPI) &&
        (icmp_ipid_seqclass == IPID_SEQ_INCR ||
            icmp_ipid_seqclass == IPID_SEQ_BROKEN_INCR ||
            icmp_ipid_seqclass == IPID_SEQ_RPI)) {
        /* Both are incremental. Thus we have "SS" test. Check if they
        are in the same sequence. */
        AV.attribute = "SS";
        unsigned int avg = (stats.ipid.tcp_ipids[good_tcp_ipid_num - 1] - stats.ipid.tcp_ipids[0]) / (good_tcp_ipid_num - 1);
        if (stats.ipid.icmp_ipids[0] < stats.ipid.tcp_ipids[good_tcp_ipid_num - 1] + 3 * avg) {
            AV.value = "S";
        }
        else {
            AV.value = "O";
        }
        seq_AVs.push_back(AV);
    }

    /* Now we look at TCP Timestamp sequence prediction */
    /* Battle plan:
    1) Compute average increment counts per second of peer, and variance in incr. per second, saving in avg_ts_hz var
    2) If any are 0, set to constant
    3) If variance is high, set to random incr. [ skip for now ]
    4) if ~10/second, set to appropriate thing
    5) Same with ~100/sec
    */
    if (stats.si.ts_seqclass == TS_SEQ_UNKNOWN && stats.si.responses >= 2) {
        time_t uptime = 0;
        avg_ts_hz = 0.0;
        for (i = 0; i < stats.si.responses - 1; i++) {
            double dhz;

            dhz = (double)ts_diffs[i] / (time_usec_diffs[i] / 1000000.0);
            avg_ts_hz += dhz / (stats.si.responses - 1);
        }

        if (avg_ts_hz > 0 && avg_ts_hz < 5.66) { /* relatively wide range because sampling time so short and frequency so slow */
            stats.si.ts_seqclass = TS_SEQ_2HZ;
            uptime = stats.si.timestamps[0] / 2;
        }
        else if (avg_ts_hz > 70 && avg_ts_hz < 150) {
            stats.si.ts_seqclass = TS_SEQ_100HZ;
            uptime = stats.si.timestamps[0] / 100;
        }
        else if (avg_ts_hz > 724 && avg_ts_hz < 1448) {
            stats.si.ts_seqclass = TS_SEQ_1000HZ;
            uptime = stats.si.timestamps[0] / 1000;
        }
        else if (avg_ts_hz > 0) {
            stats.si.ts_seqclass = TS_SEQ_OTHER_NUM;
            uptime = stats.si.timestamps[0] / (unsigned int)(0.5 + avg_ts_hz);
        }

        if (uptime > 63072000) {
            /* Up 2 years?  Perhaps, but they're probably lying. */
            uptime = 0;
        }
        stats.si.lastboot = stats.seq_send_times[0].tv_sec - uptime;
    }

    switch (stats.si.ts_seqclass) {

    case TS_SEQ_ZERO:
        AV.attribute = "TS";
        AV.value = "0";
        seq_AVs.push_back(AV);
        break;
    case TS_SEQ_2HZ:
    case TS_SEQ_100HZ:
    case TS_SEQ_1000HZ:
    case TS_SEQ_OTHER_NUM:
    {
        AV.attribute = "TS";

        /* Here we "cheat" a little to make the classes correspond more
        closely to common real-life frequencies (particularly 100)
        which aren't powers of two. */
        if (avg_ts_hz <= 5.66) {
            /* 1 would normally range from 1.4 - 2.82, but we expand that
            to 0 - 5.66, so we won't ever even get a value of 2.  Needs
            to be wide because our test is so fast that it is hard to
            match slow frequencies exactly.  */
            tsnewval = 1;
        }
        else if (avg_ts_hz > 70 && avg_ts_hz <= 150) {
            /* mathematically 7 would be 90.51 - 181, but we change to 70-150 to
            better align with common freq 100 */
            tsnewval = 7;
        }
        else if (avg_ts_hz > 150 && avg_ts_hz <= 350) {
            /* would normally be 181 - 362.  Now aligns better with 200 */
            tsnewval = 8;
        }
        else {
            /* Do a log base2 rounded to nearest int */
            tsnewval = (unsigned int)(0.5 + log(avg_ts_hz) / log(2.0));
        }

        AV.value = StringHelper::getstaticstring("%X", tsnewval);
        seq_AVs.push_back(AV);
        break;
    }
    case TS_SEQ_UNSUPPORTED:
        AV.attribute = "TS";
        AV.value = "U";
        seq_AVs.push_back(AV);
        break;
    }

    /* Now generate the SEQ line of the fingerprint if there are any test results
    in seq_AVs. */
    if (!seq_AVs.empty()) {
        stats.FP_TSeq = std::make_shared<FingerTest>();
        if (stats.FP_TSeq) {
            stats.FP_TSeq->name = "SEQ";
            stats.FP_TSeq->results = seq_AVs;
        }
    }
}

void OsScanTask::MakeTOpsFP()
{
    std::vector<AVal> AVs;
    int i, n;

    if (stats.tops_reply_num != 6) {
        return;
    }

    for (n = 0; n < 6; n++) {
        if (!stats.tops_AVs[n]) {
            break;
        }
    }
    if (n < 6) {
        return;
    }

    AVs.reserve(n);

    for (i = 0; i < n; i++) {
        AVs.push_back(*stats.tops_AVs[i]);
    }

    stats.FP_TOps = std::make_shared<FingerTest>();
    if (stats.FP_TOps) {
        stats.FP_TOps->results = AVs;
        stats.FP_TOps->name = "OPS";
    }
}

void OsScanTask::MakeTWinFP()
{
    std::vector<AVal> AVs;
    int i, n;

    if (stats.twin_reply_num != 6) {
        return;
    }

    for (n = 0; n < 6; n++) {
        if (!stats.twin_AVs[n]) {
            break;
        }
    }
    if (n < 6) {
        return;
    }

    AVs.reserve(n);

    for (i = 0; i < n; i++) {
        AVs.push_back(*stats.twin_AVs[i]);
    }

    stats.FP_TWin = std::make_shared<FingerTest>();
    if (stats.FP_TWin) {
        stats.FP_TWin->results = AVs;
        stats.FP_TWin->name = "WIN";
    }
}

void OsScanTask::DoSeqTests()
{
    int numProbesLeft = 0;
    int timeToSleep = 0;
    struct timeval now;
    unsigned int unableToSend = 0;  /* # of times in a row that hosts were unable to send probe */
    unsigned int expectReplies = 0;
    struct timeval rcvdtime;
    struct timeval stime = this->time_out;
    struct timeval tmptv;
    bool thisHostGood = false;
    long to_usec = 0;
    bool goodResponse = false;
    bool timedout = false;

    memset(&tmptv, 0, sizeof(tmptv));

    this->BuildSeqProbeList();
    do {
        if (timeToSleep > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(timeToSleep));
        }

        expectReplies = 0;
        unableToSend = 0;

        /* Send a seq probe to each host. */
        while (unableToSend < 1 && this->SendOK()) {
            if (this->NumProbesToSend() > 0 && this->HostSeqSendOK(NULL)) {
                this->SendNextProbe();
                expectReplies++;
                unableToSend = 0;
            }
            else {
                unableToSend++;
            }
        }

        this->stats.num_probes_sent_at_last_round = this->stats.num_probes_sent;

        /* Count the pcap wait time. */
        if (!this->SendOK()) {
            gettimeofday(&now, NULL);
            TIMEVAL_MSEC_ADD(stime, now, 1000);
            if (this->NextTimeout(&tmptv)) {
                if (TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
                    stime = tmptv;
                }
            }
        }
        else {
            thisHostGood = this->HostSeqSendOK(&tmptv);
            if (thisHostGood) {
                stime = tmptv;
            }
            else if (TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
                stime = tmptv;
            }
        }

        do {
            gettimeofday(&now, NULL);
            to_usec = TIMEVAL_SUBTRACT(stime, now);
            if (to_usec < 2000) {
                to_usec = 2000;
            }

            std::shared_ptr<NetBase> packet;
            if (!this->pcap.GetOneReplayPacket(packet, to_usec / 1000)) {
                gettimeofday(&rcvdtime, NULL);
                goodResponse = this->ProcessResp(packet, &rcvdtime);
                if (goodResponse) {
                    expectReplies--;
                }
            }
            gettimeofday(&now, NULL);
            if (TIMEVAL_SUBTRACT(now, stime) > 200000) {
                /* While packets are still being received, I'll be generous and give
                an extra 1/5 sec.  But we have to draw the line somewhere */
                timedout = true;
            }
        } while (!timedout && expectReplies > 0);

        numProbesLeft = 0;
        this->UpdateActiveSeqProbes();
        numProbesLeft += this->NumProbesToSend();
        numProbesLeft += this->NumProbesActive();

        gettimeofday(&now, NULL);
        if (expectReplies == 0) {
            timeToSleep = TIMEVAL_SUBTRACT(stime, now);
        }
        else {
            timeToSleep = 0;
        }
    } while (numProbesLeft > 0 && !Timeout());
}

void OsScanTask::DoTUITests()
{
    unsigned int unableToSend = 0;  /* # of times in a row that hosts were unable to send probe */
    unsigned int expectReplies = 0;
    long to_usec = 0;
    int timeToSleep = 0;
    unsigned int bytes = 0;
    struct timeval now;
    struct timeval rcvdtime;
    struct timeval stime = this->time_out;
    struct timeval tmptv;
    bool timedout = false;
    bool thisHostGood = false;
    bool goodResponse = false;
    int numProbesLeft = 0;

    memset(&tmptv, 0, sizeof(tmptv));

    this->BuildTUIProbeList();
    do {
        if (timeToSleep > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(timeToSleep));
        }

        expectReplies = 0;
        unableToSend = 0;

        /* Send a seq probe to each host. */
        while (unableToSend < 1 && this->SendOK()) {
            if (this->NumProbesToSend() > 0 && this->HostSendOK(NULL)) {
                this->SendNextProbe();
                expectReplies++;
                unableToSend = 0;
            }
            else {
                unableToSend++;
            }
        }

        this->stats.num_probes_sent_at_last_round = this->stats.num_probes_sent;

        /* Count the pcap wait time. */
        if (!this->SendOK()) {
            gettimeofday(&now, NULL);
            TIMEVAL_MSEC_ADD(stime, now, 1000);
            if (this->NextTimeout(&tmptv)) {
                if (TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
                    stime = tmptv;
                }
            }
        }
        else {
            thisHostGood = this->HostSendOK(&tmptv);
            if (thisHostGood) {
                stime = tmptv;
            }
            else if (TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
                stime = tmptv;
            }
        }

        do {
            gettimeofday(&now, NULL);
            to_usec = TIMEVAL_SUBTRACT(stime, now);
            if (to_usec < 2000) {
                to_usec = 2000;
            }

            std::shared_ptr<NetBase> packet;
            if (!this->pcap.GetOneReplayPacket(packet, to_usec / 1000)) {
                gettimeofday(&rcvdtime, NULL);
                goodResponse = this->ProcessResp(packet, &rcvdtime);
                if (goodResponse) {
                    expectReplies--;
                }
            }
            gettimeofday(&now, NULL);
            if (TIMEVAL_SUBTRACT(now, stime) > 200000) {
                /* While packets are still being received, I'll be generous and give
                an extra 1/5 sec.  But we have to draw the line somewhere */
                timedout = true;
            }
        } while (!timedout && expectReplies > 0);

        numProbesLeft = 0;
        this->UpdateActiveTUIProbes();
        numProbesLeft += this->NumProbesToSend();
        numProbesLeft += this->NumProbesActive();

        gettimeofday(&now, NULL);
        if (expectReplies == 0) {
            timeToSleep = TIMEVAL_SUBTRACT(stime, now);
        }
        else {
            timeToSleep = 0;
        }
    } while (numProbesLeft > 0 && !Timeout());
}

#define OS_SCAN_MAX_TRY_NUM 10

int OsScanTask::OsScan(FingerPrintResults &result)
{
    static const u_int max_try_num = 10;
    if (!is_db_init) {
        return -1;
    }

    /* Check we have at least one target*/
    if (t.dst_ip == 0) {
        return -2;
    }

    if (!BeginSniffer()) {
        return -3;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    TIMEVAL_MSEC_ADD(this->time_out, now, (long)time_out_ms);
    FingerPrintResults fpr_result[OS_SCAN_MAX_TRY_NUM];
    u_int round = 0;

    while (round++ < OS_SCAN_MAX_TRY_NUM) {
        stats.ReInitScanStats();
        ReInitScanSystem();
        DoSeqTests();
        DoTUITests();
        MakeFP();
        fpr_result[round - 1] = db.MatchFingerprint(*stats.fp);
        fpr_result[round - 1].fp = stats.fp;
        if (Timeout()) {
            break;
        }
        if (fpr_result[round-1].overall_results == OSSCAN_SUCCESS
            && fpr_result[round-1].num_perfect_matches > 0) {
            break;
        }
        if (round > 2) {
            continue;
        }
    }

    double bestacc = 0;
    int bestaccidx = 0;
    for (u_int i = 0; i < round; i++) {
        if (fpr_result[i].overall_results == OSSCAN_SUCCESS &&
            fpr_result[i].matches.size() > 0 &&
            fpr_result[i].matches[0].first > bestacc) {
            bestacc = fpr_result[i].matches[0].first;
            bestaccidx = i;
            if (fpr_result[i].num_perfect_matches) {
                break;
            }
        }
    }
    result = fpr_result[bestaccidx];
    return 0;
}