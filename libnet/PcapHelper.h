#ifndef PCAP_HELPER_H_INCLUDED
#define PCAP_HELPER_H_INCLUDED

#include "NetBase.h"
#include <mutex>

#if defined(_MSC_VER)
#ifndef WPCAP
#define WPCAP
#endif // !1
#include <pcap.h>
#elif defined(__GNUC__)
#include <network/NetworkInfoHelper.h>
#endif

#define PCAP_DEFAULT_IO_TIMEOUT 3000   //ms
#define PCAP_NETMASK_UNKNOWN	0xffffffff

class PcapHelper
{
public:
    PcapHelper(struct in_addr eth_ip, size_t max_size=BUFSIZ, time_t time_out=PCAP_DEFAULT_IO_TIMEOUT);
    PcapHelper(u_int eth_ip, size_t max_size = BUFSIZ, time_t time_out = PCAP_DEFAULT_IO_TIMEOUT);
    ~PcapHelper();
    int PcapSelect(struct timeval *timeout);
    int PcapSelect(long usecs);
    bool IsInit();
    int PcapInit();
    void PcapUnInit();
#if defined(_MSC_VER)
    int PcapSetFilter(const char *filter);
#elif defined(__GNUC__)
    int PcapSetFilter(struct sock_filter *filter, int filter_size);
    int PcapSetTCPFilter(int dst_ip, unsigned short src_port = 0, unsigned short dst_port = 0);
    int PcapSetTCPOrICMPFilter(int dst_ip, unsigned short src_port = 0, unsigned short dst_port = 0);
    int PcapSetUDPFilter(int dst_ip, unsigned short src_port = 0, unsigned short dst_port = 0);
    int PcapSetUDPOrICMPFilter(int dst_ip, unsigned short src_port = 0, unsigned short dst_port = 0);
#endif
    int SendEthPacket(std::shared_ptr<NetBase> head);
    int GetOneReplayPacket(std::shared_ptr<NetBase> &head);
    int GetOneReplayPacket(std::shared_ptr<NetBase> &head, time_t time_out);

private:
#if defined(_MSC_VER)
    pcap_if_t *PcapGetSpecifyDevice(pcap_if_t *alldevs);
#endif

private:
#if defined(_MSC_VER)
    pcap_t *m_pcap_handle;
#elif defined(__GNUC__)
    int m_raw_sock;
    NetworkInfoHelper::AdaptInfo m_adapt;
#endif
    struct in_addr m_eth_ip;
    size_t  m_max_size;
    time_t  m_time_out;

private:
    static std::mutex init_lock;
};

#endif
