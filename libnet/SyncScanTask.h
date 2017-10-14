#ifndef SYNC_SCAN_TASK__H_INCLUDED
#define SYNC_SCAN_TASK__H_INCLUDED

#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#include <libnet\PcapHelper.h>
#include <libnet\IPv4Header.h>
#include <libnet\ICMPv4Header.h>
#include <libnet\TCPHeader.h>
#include <libnet\UDPHeader.h>
#include <libnet\RawData.h>
#include <libnet\EthernetHeader.h>
#elif defined(__GNUC__)
#include <time/TimeHelper.h>
#include <libnet/PcapHelper.h>
#include <libnet/IPv4Header.h>
#include <libnet/ICMPv4Header.h>
#include <libnet/TCPHeader.h>
#include <libnet/UDPHeader.h>
#include <libnet/RawData.h>
#include <libnet/EthernetHeader.h>
#else
#error unsupported compiler
#endif
#include "PortList.h"
#include "timing.h"

namespace TCPScan
{
    struct probespec_tcpdata {
        unsigned short dport; //tcp dst port
        unsigned char flags; //tcp flags
    };

    typedef struct probespec {
        struct probespec_tcpdata tcp; // TCP dst info
    } probespec;

    struct IPExtraProbeData_tcp {
        unsigned short sport; //tcp src port
        unsigned int seq; //tcp send seq
    };

    struct IPExtraProbeData {
        unsigned int ipid; // ip identify
        struct IPExtraProbeData_tcp tcp; // tcp src data
    };

    class UltraProbe 
    {
        /* 
        *Used to store the probe info that has send
        */
        friend class SyncScanTask;
    public:
        UltraProbe();
        ~UltraProbe();

        // source port used 
        unsigned short sport() const
        {
            return IP.tcp.sport;
        }
        // destination port used 
        unsigned short dport() const 
        {
            return mypspec.tcp.dport;
        }
        // ip identify
        unsigned int ipid() const 
        {
            return IP.ipid;
        }
        //tcp seq
        unsigned int tcpseq() const
        {
            return IP.tcp.seq;
        }

        /* Get general details about the probe */
        const probespec& pspec() const 
        {
            return mypspec;
        }

        /* Returns true if the given tryno and pingseq match those within this probe. */
        bool CheckTryno(unsigned int tryno) const
        {
            return tryno == this->tryno;
        }

    private:
        unsigned char tryno; // Retransmission number of this probe, 
        bool timedout; // If probe is timeout
        bool retransmitted; // If probe is retransmitted, every will and only will generate one retransmit probe, the new probe prev_sent is set with current probe's sent, and tryno is set with current probe's tryno+1
        struct timeval sent; //the send time
        struct timeval prev_sent; //Time the previous probe was sent if have retry
        probespec mypspec; //probe tcp dst info
        IPExtraProbeData IP; //probe IP&TCP src info
    };

    struct send_delay_nfo 
    {
        unsigned int delayms; // Milliseconds to delay between probes, used to choose delay
        struct timeval last_boost; // last time of increase to delayms
        unsigned int good_resp_since_delay_changed; // packet recv success( no retry) count after delay change
        unsigned int dropped_resp_since_delay_changed; // packet recv success( need retry )count after delay change
    };

    struct rate_limit_detection_nfo 
    {
        unsigned int max_tryno_sent; // the max tryno we have sent so far, then need to wait 1 sec
        bool rld_waiting; // is need to wait
        struct timeval rld_waittime; // the time that we need to wait reach
    };

    class HostScanStats 
    {
        friend class SyncScanTask;
    public:
        HostScanStats();
        ~HostScanStats();
        /**
        *check if it is Ok to send next probe, if false, when can we send
        */
        bool SendOK(struct timeval *when);

    private:
        std::vector<UltraProbe> probes_outstanding; //probes sent out, need wait for responce, include retransmit probe
        std::vector<probespec> probe_bench; // probe retry number meet the current maximum tryno, and can ot try now, will add to this probe, if max tryno increase, will move to retry_stack
        unsigned int bench_tryno; // the tryno of probes in the bench list
        std::vector<probespec> retry_stack; //when max tryno increase, the probe_bench list will move to retry_stack, the these probe will be retransmit
        std::vector<unsigned char> retry_stack_tries; //probe in retry_stack current tryno
        bool tryno_mayincrease; //if tryno can increase, if can not, timeout probe who retry match max tryno will move to probe_bench an wait it to be true
        int ports_finished; // The number of ports that have been determined stat
        unsigned int max_successful_tryno; // The highest retry count in all port probe
        int num_probes_sent; // Number of port probes, include retry count
        int num_probes_active; // Total of probes outstanding (active), timeout probe is not active, but can still in outstanding
        struct ultra_timing_vals timing; // Getting the current time w/o
        timeout_info to; // Group-wide packet rtt/timeout info
        int probes_sent; // probes sent count in total.
        int probes_sent_at_last_wait; // probes sent count in total at last time.
        unsigned int num_probes_waiting_retransmit; //timeout and wait to retransmit probe count
        struct timeval last_wait; //last wait for responce time
        struct timeval last_probe_sent; // last probe send time
        struct send_delay_nfo sdn; // used to choose send delay
        struct rate_limit_detection_nfo rld; // used to contry retry rate
    };

#ifndef MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS 10    /* 11 probes to port at maximum */
#endif
#ifndef MAX_TCP_SCAN_DELAY
#define MAX_TCP_SCAN_DELAY 1000
#endif
#define SYNC_SCAN_HOST_TIME_OUT_MS 3000

    /* A few extra performance tuning parameters specific to ultra_scan. */
    class ultra_scan_performance_vars : public scan_performance_vars
    {
    public:
        ultra_scan_performance_vars()
        {
            Init();
        }

    public:
        unsigned int tryno_cap; // The maximum retry number allowed

    private:
        void Init();
    };

    class SyncScanTask
    {
    public:
        SyncScanTask(const std::vector<unsigned short> &ports, int src_ip, int dst_ip, char *src_mac, char *nxt_hop_mac, time_t time_out_ms = SYNC_SCAN_HOST_TIME_OUT_MS, bool use_cwd = false);
        ~SyncScanTask();
        bool DoScan(PortList &list);
       
    private:
        /** 
        *Returns the number of ports remaining to probe
        */
        int FreshPortsLeft(); 
        /**
        *Returns the number of probes_outstanding
        */
        unsigned int NumProbesOutstanding();
        /* 
        *Mark an outstanding probe as timedout.  
        */
        void MarkProbeTimedout(std::vector<UltraProbe>::iterator probeI);
        /* 
        *Removes a probe from probes_outstanding 
        */
        std::vector<UltraProbe>::iterator DestroyOutstandingProbe(std::vector<UltraProbe>::iterator probeI);
        /**
        *Move probee from probes_outstanding ro bench
        */
        std::vector<UltraProbe>::iterator MoveProbeToBench(std::vector<UltraProbe>::iterator &probeI);
        /* 
        *Dismiss all probe attempts on bench 
        */
        void DismissBench();
        /* 
        *Move all members of bench to retry_stack for probe retransmission 
        */
        void RetransmitBench();


        /* determine whether any probes may be sent. Returns true if they can be sent immediately.  If when is non-NULL,
        *it is filled with the next possible time that probes can be sent
        */
        bool SendOK(struct timeval *tv);
        /**
        *check if this task is timeout 
        */
        bool Timeout();
        /* How long I am currently willing to wait for a probe response
        *before considering it timed out.  Uses the host values from
        *target if they are available, otherwise from gstats.
        *return in MICROseconds.  */
        unsigned long ProbeTimeout();
        /* 
        *How long I'll wait until completely giving up on a probe.
        *Timedout probes are often marked as such (and sometimes
        *considered a drop), but kept in the list juts in case they come
        *really late.  But after probeExpireTime(), I don't waste time
        *keeping them around. 
        *return in MICROseconds 
        */
        unsigned long ProbeExpireTime(const UltraProbe &probe);
        /**
        *Whether or not the scan has completed
        */
        bool Completed();
        /**
        *If there are probe in probes_outstanding timeouts, fills in when with the time of
        *the earliest one and returns true.  Otherwise returns false and
        *puts now in when. 
        */
        bool NextTimeout(struct timeval *when);
        /**
        *Adjust various timing variables based on pcket recv.
        */
        void AdjustTiming(const UltraProbe &probe, struct timeval *rcvdtime);
        /**
        *Adjust rtt based on probe recv time
        */
        void AdjustTimeouts(const UltraProbe &probe, struct timeval *rcvdtime);
        /** 
        *This function provides the proper cwnd and ssthresh to use.
        */
        void GetTiming(struct ultra_timing_vals *tmng);

        /**
        *gives the maximum try number (try numbers start at zero and increments for each retransmission) that may be used, based on
        *the scan type, observed network reliability, timing mode, etc.
        */
        unsigned int AllowedTryno();
        /** 
        *Boost the scan delay, usually because too many packet drops were detected. 
        */
        void BoostScanDelay();
        /**
        *increase base src port every task
        */
        void IncrementBaseSrcPort();
        /**
        *start sniffer what used to recv responce probe
        */
        bool BeginSniffer();

        /************************down is the send probe functions************************/
        /**
        *retransmit probe in probes_outstanding who need and can retransmit
        */
        void DoOutstandingRetransmits();
        /**
        *send probes in retry_stack
        */
        void DoRetryStackRetransmits();
        /**
        *send probes of specify who have not been sent
        */
        void DoNewProbes();
        /**
        *send specify scan probe 
        */
        void SendIPScanProbe(const probespec &pspec, unsigned char tryno, struct timeval *prev_sent);
        /**
        *send tcp probe out
        */
        int SendTcpProbe(
            int ttl, bool df, unsigned short ipid, unsigned char* ipopt, int ipoptlen,
            unsigned short sport, unsigned short dport, unsigned int seq, unsigned int ack,
            unsigned char reserved, unsigned char flags, unsigned short window, unsigned short urp,
            unsigned char *options, int optlen,
            char *data, unsigned short datalen);

        /************************down recv probe responce functions************************/
        /**
        *wait for probes responce until timeout
        */
        void WaitForResponses();
        /**
        *get one valid responce of send out probe
        */
        bool GetOneProbeResp(struct timeval *stime);
        /**
        *check if the tcp responce is match the probe
        */
        bool TCPProbeMatch(IPv4Header &ipv4_header, TCPHeader &tcp_header, const UltraProbe &probe);
        /**
        *update probe port stat, and probe stat
        */
        void PortProbeUpdate(std::vector<UltraProbe>::iterator probeI, int newstate, struct timeval *rcvdtime, bool adjust_timing_hint);
        /**
        *update probe port stat
        */
        bool PortPspecUpdate(const probespec &pspec, int newstate);

        /************************down end done one round************************/
        /**
        *update probes stats, check if need move to bench or can retransmit
        */
        void UpdateProbesStats();

    private:
        int src_ip; //local eth ip used to send packet
        unsigned char src_mac[6];//local eth mac
        int dst_ip; //dst eth ip
        unsigned char dst_mac[6]; //dst eth mac or next hop mac, it will be used to fill the eth packet
        std::vector<unsigned short> ports; //ports need to scan
        time_t time_out_ms; //time out time for this task
        struct timeval time_out; //time out time for this task
        unsigned int seq_mask; // sequence mask used to encode sequence numbers
        unsigned short base_sport; // base port used as the base src port
        u_int next_dport_index; //Index of the next dst port to send in the ports vector
        PcapHelper pcap; //pcap handle used to send recv packet
        PortList port_list; //ports to store result
        HostScanStats stats; //stats of scan 
        bool use_cwnd; //use cwnd to limit prob outside
    };
}
#endif