#ifndef OS_SCAN_TASK__H_INCLUDED
#define OS_SCAN_TASK__H_INCLUDED

#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#include <libnet\IPv4Header.h>
#include <libnet\ICMPv4Header.h>
#include <libnet\TCPHeader.h>
#include <libnet\UDPHeader.h>
#include <libnet\PcapHelper.h>
#include <libnet\RawData.h>
#include <libnet\EthernetHeader.h>
#include <libnet\timing.h>
#elif defined(__GNUC__)
#include <time/TimeHelper.h>
#include <libnet/IPv4Header.h>
#include <libnet/ICMPv4Header.h>
#include <libnet/TCPHeader.h>
#include <libnet/UDPHeader.h>
#include <libnet/PcapHelper.h>
#include <libnet/RawData.h>
#include <libnet/EthernetHeader.h>
#include <libnet/timing.h>
#else
#error unsupported compiler
#endif
#include "FingerPrintDB.h"

#define DEFAULT_TCP_TTL 255

/******************************************************************************
* CONSTANT DEFINITIONS                                                       *
******************************************************************************/

#define NUM_FPTESTS    13

/* The number of tries we normally do.  This may be increased if
the target looks like a good candidate for fingerprint submission, or fewer
if the user gave the --max-os-tries option */
#define STANDARD_OS2_TRIES 2

// The minimum (and target) amount of time to wait between probes
// sent to a single host, in milliseconds.
#define OS_PROBE_DELAY 25

// The target amount of time to wait between sequencing probes sent to
// a single host, in milliseconds.  The ideal is 500ms because of the
// common 2Hz timestamp frequencies.  Less than 500ms and we might not
// see any change in the TS counter (and it gets less accurate even if
// we do).  More than 500MS and we risk having two changes (and it
// gets less accurate even if we have just one).  So we delay 100MS
// between probes, leaving 500MS between 1st and 6th.
#define OS_SEQ_PROBE_DELAY 100

/* How many syn packets do we send to TCP sequence a host? */
#define NUM_SEQ_SAMPLES 6

/* TCP Timestamp Sequence */
#define TS_SEQ_UNKNOWN 0
#define TS_SEQ_ZERO 1 /* At least one of the timestamps we received back was 0 */
#define TS_SEQ_2HZ 2
#define TS_SEQ_100HZ 3
#define TS_SEQ_1000HZ 4
#define TS_SEQ_OTHER_NUM 5
#define TS_SEQ_UNSUPPORTED 6 /* System didn't send back a timestamp */

#define IPID_SEQ_UNKNOWN 0
#define IPID_SEQ_INCR 1  /* simple increment by one each time */
#define IPID_SEQ_BROKEN_INCR 2 /* Stupid MS -- forgot htons() so it
counts by 256 on little-endian platforms */
#define IPID_SEQ_RPI 3 /* Goes up each time but by a "random" positive
increment */
#define IPID_SEQ_RD 4 /* Appears to select IPID using a "random" distributions (meaning it can go up or down) */
#define IPID_SEQ_CONSTANT 5 /* Contains 1 or more sequential duplicates */
#define IPID_SEQ_ZERO 6 /* Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this) */
#define IPID_SEQ_INCR_BY_2 7 /* simple increment by two each time */

#define OS_SCAN_HOST_TIME_OUT_MS 3000

/******************************************************************************
* TYPE AND STRUCTURE DEFINITIONS                                             *
******************************************************************************/

struct seq_info {
    int responses;
    int ts_seqclass;
    int ipid_seqclass;
    unsigned int seqs[NUM_SEQ_SAMPLES];
    unsigned int timestamps[NUM_SEQ_SAMPLES];
    int index;
    unsigned short ipids[NUM_SEQ_SAMPLES];
    time_t lastboot; /* 0 means unknown */
};

/* Different kinds of Ipids. */
struct ipid_info {
    unsigned int tcp_ipids[NUM_SEQ_SAMPLES];
    unsigned int tcp_closed_ipids[NUM_SEQ_SAMPLES];
    unsigned int icmp_ipids[NUM_SEQ_SAMPLES];
};

struct udpprobeinfo {
    unsigned short iptl;
    unsigned short ipid;
    unsigned short ipck;
    unsigned short sport;
    unsigned short dport;
    unsigned short udpck;
    unsigned short udplen;
    unsigned char patternbyte;
    struct in_addr target;
};

typedef enum {
    OFP_UNSET,
    OFP_TSEQ,
    OFP_TOPS,
    OFP_TECN,
    OFP_T1_7,
    OFP_TICMP,
    OFP_TUDP
}OFProbeType;

class Target
{
    friend class OsScanTask;
public:
    /*open tcp port at dst device*/
    int open_tcp_port;
    /*closed tcp port at dst device*/
    int closed_tcp_port;
    /*closed udp port at dst device*/
    int closed_udp_port;
    /*local eth ip*/
    int src_ip;
    /*local eth mac*/
    unsigned char src_mac[6];
    /*dst eth ip*/
    int dst_ip;
    /*dst eth mac or next hop mac, it will be used to fill the eth packet*/
    unsigned char dst_mac[6];
    /*if dst device is direct connect to us*/
    bool is_direct;

private:
    timeout_info to; //dst rtt info, not must
};

class OFProbe 
{
    friend class OsScanTask;
    /** Represents an OS detection probe. It does not contain the actual packet
    * that is sent to the target but contains enough information to generate
    * it (such as the probe type and its subid). It also stores timing
    * information. */
public:
    OFProbe();
    /* The literal string for the current probe type. */
    const char *TypeStr();

private:
    /* Type of the probe: for what os fingerprinting test? */
    OFProbeType type;
    /* Subid of this probe to separate different tcp/udp/icmp. */
    int subid;
    /* Try (retransmission) number of this probe */
    int tryno;
    /* A packet may be timedout for a while before being retransmitted
    due to packet sending rate limitations */
    bool retransmitted;
    /* the probe send time */
    struct timeval sent;
    /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
    struct timeval prevSent;
};

/* These are statistics for the whole group of Targets */
class OsScanStats 
{
    friend class OsScanTask;
public:
    OsScanStats();
    ~OsScanStats();

private:
    /*int the default value of OsScanStats*/
    void ReInitScanStats();
    /*returns the amount of time taken between sending 1st tseq probe and the last one.*/
    double TimingRatio();

private:
    /*store the send seq info*/
    struct seq_info si;
    /*store probe ipid info*/
    struct ipid_info ipid;
    /* distance, distance_guess: hop count between us and the target.
    *
    * Possible values of distance:
    *   0: when scan self;
    *   1: when scan a target on the same network segment;
    * >=1: not self, not same network and nmap has got the icmp reply to the U1 probe.
    *  -1: none of the above situations.
    *
    * Possible values of distance_guess:
    *  -1: nmap fails to get a valid ttl by all kinds of probes.
    * >=1: a guessing value based on ttl. */
    int distance;
    int distance_guess;

    /* Delay between two probes.    */
    unsigned int send_delay_ms;
    /* When the last probe is sent. */
    struct timeval last_probe_sent;
    /* used to control send probe rate */
    struct ultra_timing_vals timing;    
    /* rtt/timeout info                */
    timeout_info to;    
    /* Total number of active probes   */
    int num_probes_active; 
    /* Number of probes sent total. */
    int num_probes_sent;
    /* Number of probes sent at last round. */
    int num_probes_sent_at_last_round;

    /* Fingerprint of this target.*/
    std::shared_ptr<FingerPrint> fp;
    std::shared_ptr<FingerTest> fptests[NUM_FPTESTS];
#define FP_TSeq  fptests[0]
#define FP_TOps  fptests[1]
#define FP_TWin  fptests[2]
#define FP_TEcn  fptests[3]
#define FP_T1_7_OFF 4
#define FP_T1    fptests[4]
#define FP_T2    fptests[5]
#define FP_T3    fptests[6]
#define FP_T4    fptests[7]
#define FP_T5    fptests[8]
#define FP_T6    fptests[9]
#define FP_T7    fptests[10]
#define FP_TUdp  fptests[11]
#define FP_TIcmp fptests[12]
    std::shared_ptr<AVal> tops_AVs[6]; /* 6 AVs of TOps */
    std::shared_ptr<AVal> twin_AVs[6]; /* 6 AVs of TWin */

    /* The following are variables to store temporary results
    * during the os fingerprinting process of this host. */
    unsigned short lastipid;
    struct timeval seq_send_times[NUM_SEQ_SAMPLES];
    /* how many TWin replies are received. */
    int twin_reply_num; 
    /* how many TOps replies are received. Actually it is the same with TOpsReplyNum. */
    int tops_reply_num; 
    /* To store one of the two icmp replies */
    std::shared_ptr<NetBase> icmp_echo_reply; 
    /* Which one of the two icmp replies is stored*/
    int stored_icmp_reply; 
    /* info of the udp probe we sent */
    struct udpprobeinfo upi; 
};

class OsScanTask
{
public:
    /**
    *init fingerprint db resource, you must call InitFPDB* first and just once
    */
    static bool InitFPDB(const std::string &file_path);
    /**
    *init fingerprint db resource from content, you must call InitFPDB* first and just once
    */
    static bool InitFPDBFromContent(const std::string &content);

public:
    OsScanTask(const Target &t, time_t time_out_ms = OS_SCAN_HOST_TIME_OUT_MS);
    ~OsScanTask();
    /**
    *start scan
    *FingerPrintResults(out): the result of this scan
    *return 0 for success, other for failed
    */
    int OsScan(FingerPrintResults &result);

private:
    /**
    *(Re)Initialize the parameters that will be used during the scan.
    */
    void ReInitScanSystem();
    /**
    *Begine to sniffer the data 
    */
    bool BeginSniffer();
    /**
    *Send TCP Sync seq probe useing differnt win size and option and then get responce
    */
    void DoSeqTests();
    /**
    *Send TCP UDP ICMP probe and then get responce
    */
    void DoTUITests();

    /*
    *Build TCP Sync seq probe to send list
    */
    void BuildSeqProbeList();
    /*
    *Update TCP Sync seq probe in active list, remove which is timeout
    */
    void UpdateActiveSeqProbes();
    /*
    *Build TCP UDP ICMP probe to send list
    */
    void BuildTUIProbeList();
    /** 
    *Update TCP Sync seq probe in active list,
    * remove which is timeout and retrans more than 3 times, 
    * move which is timeout but retrans more than 3 times to send list
    */
    void UpdateActiveTUIProbes();
    /**
    *Get the probe count that need to send
    */
    unsigned int NumProbesToSend();
    /**
    *Get the probe count that waiting for response
    */
    unsigned int NumProbesActive();
    /**
    *Add new probe to send list
    */
    void AddNewProbe(OFProbeType type, int subid);
    /**
    *Get an active probe from active probe list identified by probe type
    *and subid.  
    */
    std::vector<OFProbe>::iterator GetActiveProbe(OFProbeType type, int subid);
    /** 
    *Returns false, if can not send any other probe, need to wait
    */
    bool SendOK();
    /**
    *Check whether can send next TCP Sync seq probe. If can not, fill _when_ with the
    * time when it can send
    */
    bool HostSeqSendOK(struct timeval *when);
    /**
    *Check whether can send TCP UDP ICMP probe. If can not, fill _when_ with the
    * time when it can send 
    */
    bool HostSendOK(struct timeval *when);
    /**
    *Get the earliest timeout time of all probe that has send out
    *return false if no probe has send
    */
    bool NextTimeout(struct timeval *when);
    /* 
    *How long I am willing to wait for a probe response
    *before considering it timed out.
    *return in MICROseconds.  */
    unsigned long TimeProbeTimeout();
    /** 
    *Adjust various timing variables based on pcket rece.
    */
    void AdjustTimes(const OFProbe &probe, struct timeval *rcvdtime);
    /**
    *Get the distance guess from responce ttl
    */
    int GetDistanceGuessFromTTL(unsigned char ttl);
    /**
    *check if this task is timeout
    */
    bool Timeout();

    /************************down is the send probe functions************************/
    /* Send the next probe in the probe list*/
    void SendNextProbe();
    /* Probe send functions. */
    void SendTSeqProbe(int probeNo);
    void SendTOpsProbe(int probeNo);
    void SendTEcnProbe();
    void SendT1_7Probe(int probeNo);
    void SendTUdpProbe(int probeNo);
    void SendTIcmpProbe(int probeNo);
    /* Generic sending functions used by the above probe functions. */
    int SendTcpProbe(int ttl, bool df, unsigned char* ipopt, int ipoptlen, unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack,
        unsigned char reserved, unsigned char flags, unsigned short window, unsigned short urp, unsigned char *options, int optlen, char *data, unsigned short datalen);
    int SendIcmpEchoProbe(unsigned char tos, bool df, unsigned char pcode, unsigned short id, unsigned short seq, unsigned short datalen);
    int SendClosedUdpProbe(int ttl, unsigned short sport, unsigned short dport);

    /************************down is the recv probe responce functions************************/
    /* Process one response. If the response is useful, return true. */
    bool ProcessResp(const std::shared_ptr<NetBase> ipv4_header, struct timeval *rcvdtime);
    /* Response process functions. */
    bool ProcessTSeqResp(const IPv4Header &ip, const TCPHeader &tcp, int replyNo);
    bool ProcessTOpsResp(const TCPHeader &tcp, int replyNo);
    bool ProcessTWinResp(const TCPHeader &tcp, int replyNo);
    bool ProcessTEcnResp(const IPv4Header &ip, const TCPHeader &tcp);
    bool ProcessT1_7Resp(IPv4Header &ip, TCPHeader &tcp, int replyNo);
    bool ProcessTUdpResp(const IPv4Header &ip, const ICMPv4Header &icmp, IPv4Header &ip_inner);
    bool ProcessTIcmpResp(IPv4Header &ip, int replyNo);
    bool GetTcpOptString(const TCPHeader &tcp, int mss, char *result, int maxlen);

    /************************down is the make all probe fingerprint functions************************/
    /* Make up the fingerprint. */
    void MakeFP();
    /* Make Finger Print functions. */
    void MakeTSeqFP();
    void MakeTOpsFP();
    void MakeTWinFP();

private:
    Target t; //target info which need to scan
    PcapHelper pcap; //pcap handle used to send recv packet
    time_t time_out_ms; //time out time for this task
    struct timeval time_out; //time out time for this task
    OsScanStats stats; //scan stats which store the scan progress result
    std::vector<OFProbe> probes_to_send; //list need to be send
    std::vector<OFProbe> probes_active; //list ready to send
    unsigned int tcpSeqBase; //seq value used in TCP probes
    unsigned int tcpAck; //ack value used in TCP probes
    int tcpMss; //TCP MSS value used in TCP probes
    int udpttl; //TTL value used in the UDP probe
    unsigned short icmpEchoId; //ICMP Echo Identifier value for ICMP probes
    unsigned short icmpEchoSeq; //ICMP Echo Sequence value used in ICMP probes
    int tcpPortBase; //source port number in TCP probes, different probes will use an arbitrary offset value of it.
    int udpPortBase; //source port number in UDP probes, different probes will use an arbitrary offset value of it.

private:
    static FingerPrintDB db; //fingerprint db which used to match fingerprint and get the finger match
    static bool is_db_init; //if fingerprint db is init
};

#endif
