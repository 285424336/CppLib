#include "PcapHelper.h"
#include "PacketParser.h"
#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#elif defined(__GNUC__)
#include <unistd.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <sys/time.h>
#include <string.h>
#include <net/route.h>
#include <time/TimeHelper.h>
#include <poll.h>
#else
#error unsupported compiler
#endif

std::mutex PcapHelper::init_lock;

PcapHelper::PcapHelper(struct in_addr eth_ip, size_t max_size, time_t time_out) 
    : m_eth_ip(eth_ip), m_max_size(max_size), m_time_out(time_out)
{
#if defined(_MSC_VER)
    m_pcap_handle = NULL,
#endif
    PcapInit();
}

PcapHelper::PcapHelper(u_int eth_ip, size_t max_size , time_t time_out)
    : m_eth_ip(), m_max_size(max_size), m_time_out(time_out)
{
#if defined(_MSC_VER)
    m_pcap_handle = NULL,
#endif
    m_eth_ip.s_addr = eth_ip;
    PcapInit();
}

PcapHelper::~PcapHelper() 
{
    PcapUnInit();
}

bool PcapHelper::IsInit()
{
#if defined(_MSC_VER)
    return m_pcap_handle != NULL;
#elif defined(__GNUC__)
    return (m_raw_sock!=-1)&&(m_adapt.index!=-1);
#endif
}

int PcapHelper::PcapInit()
{
    if (this->IsInit()) {
        return 0;
    }

#if defined(_MSC_VER)
    HANDLE pcapMutex = CreateMutex(NULL, 0, TEXT("Global\\DnetPcapHangAvoidanceMutex"));
    DWORD wait = WaitForSingleObject(pcapMutex, INFINITE);
    pcap_if_t *alldevs = NULL, *d = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    int res = 0;

    res = pcap_findalldevs(&alldevs, errbuf);
    if (res == -1 || alldevs == NULL) {
        return -1;
    }

    d = PcapGetSpecifyDevice(alldevs);
    if (d == NULL) {
        pcap_freealldevs(alldevs);
        return -2;
    }

    errbuf[0] = 0;
    pcap_t *handle = pcap_open_live(d->name, m_max_size, true, (int)m_time_out, errbuf);
    if (handle == NULL) {
        pcap_freealldevs(alldevs);
        return -3;
    }
    pcap_freealldevs(alldevs);
    if (wait == WAIT_ABANDONED || wait == WAIT_OBJECT_0) {
        ReleaseMutex(pcapMutex);
    }
    CloseHandle(pcapMutex);

    pcap_setmintocopy(handle, 1);
    m_pcap_handle = handle;

#elif defined(__GNUC__)
    std::unique_lock<std::mutex> lock(init_lock);

    m_raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_raw_sock == -1) {
        return -1;
    }

    struct timeval recv_time_out = { 0 };
    recv_time_out.tv_usec = 1 * 1000;
    if (setsockopt(m_raw_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)) != 0)
    {
        close(m_raw_sock);
        m_raw_sock = -1;
        return -2;
    }

    struct timeval  send_time_out = { 0 };
    send_time_out.tv_usec = 1 * 1000;
    if (setsockopt(m_raw_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)) != 0)
    {
        close(m_raw_sock);
        m_raw_sock = -1;
        return -3;
    }

    if (m_eth_ip.s_addr) 
    {
        m_adapt = NetworkInfoHelper::GetNetworkInfoByIp(m_eth_ip.s_addr, false).adapt_info;
    }
#endif
    return 0;
}

#if defined(_MSC_VER)
pcap_if_t *PcapHelper::PcapGetSpecifyDevice(pcap_if_t *alldevs)
{
    pcap_if_t *d = NULL;
    pcap_addr_t *a = NULL;

    for (d = alldevs; d != NULL; d = d->next) {
        for (a = d->addresses; a; a = a->next) {
            switch (a->addr->sa_family) {
            case AF_INET:
                if (((struct sockaddr_in *)a->addr)->sin_addr.s_addr == m_eth_ip.s_addr) {
                    return d;
                }
                break;
            case AF_INET6:
                break;
            default:
                break;
            }
        }
    }
    return NULL;
}
#endif

void PcapHelper::PcapUnInit()
{
    if (this->IsInit()) {
#if defined(_MSC_VER)
        pcap_close(m_pcap_handle);
        m_pcap_handle = NULL;
#elif defined(__GNUC__)
        close(m_raw_sock);
        m_raw_sock = -1;
#endif
    }
}

int PcapHelper::PcapSelect(struct timeval *timeout)
{
    int ret = -1;
    if (!this->IsInit()) {
        return -1;
    }

#if defined(_MSC_VER)
    DWORD msec_timeout = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    HANDLE event = pcap_getevent(m_pcap_handle);
    DWORD result = WaitForSingleObject(event, msec_timeout);
    switch (result) {
    case WAIT_OBJECT_0:
        ret = 1;
        break;
    case WAIT_TIMEOUT:
        ret = 0;
        break;
    case WAIT_FAILED:
        ret = -2;
        break;
    default:
        ret = -3;
        break;
    }
    return ret;
#elif defined(__GNUC__)
    struct pollfd fdSet;
    fdSet.fd = m_raw_sock;
    fdSet.events = POLLIN;
    int msec_timeout = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    int nRet = poll(&fdSet, 1 , msec_timeout);
    if (nRet == 0)
    {
        return 0;
    }
    else if (nRet == -1)
    {
        return -1;
    }

    if (fdSet.revents & POLLIN)
    {
        return 1;
    }
    return -2;
#endif
}

int PcapHelper::PcapSelect(long usecs)
{
    struct timeval tv;

    tv.tv_sec = usecs / 1000000;
    tv.tv_usec = usecs % 1000000;

    return this->PcapSelect(&tv);
}

#if defined(_MSC_VER)
int PcapHelper::PcapSetFilter(const char *filter)
{
    if (!this->IsInit()) {
        return -1;
    }

    struct bpf_program fcode;
    if (pcap_compile(m_pcap_handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        return -2;
    }

    //set the filter
    if (pcap_setfilter(m_pcap_handle, &fcode)<0) {
        return -3;
    }

    pcap_freecode(&fcode);
    return 0;
}
#elif defined(__GNUC__)
int PcapHelper::PcapSetFilter(struct sock_filter *filter, int filter_size)
{
    if (!this->IsInit()) {
        return -1;
    }

    struct sock_fprog fprog;
    fprog.filter = filter;
    fprog.len = filter_size;
    int iRet = setsockopt(m_raw_sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
    if (iRet == -1)
    {
        return -2;
    }
    return 0;
}

int PcapHelper::PcapSetTCPFilter(int dst_ip, unsigned short src_port_r, unsigned short dst_port_r)
{
    static struct sock_filter tcp_all_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 7, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 5, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 3, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 1, 0x00000006 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_src_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 12, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 10, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 8, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 12, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 10, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 8, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_src_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 14, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 12, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 10, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 8, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 6, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 3, 0x00000002 },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_filter *sock_f = NULL;
    u_int len = 0;
    unsigned short src_port = dst_port_r;
    unsigned short dst_port = src_port_r;

    if (!src_port && !dst_port) {
        len = sizeof(tcp_all_port_filter) / sizeof(tcp_all_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_all_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_all_port_filter, sizeof(tcp_all_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
    }
    else if (src_port && !dst_port) {
        len = sizeof(tcp_src_port_filter) / sizeof(tcp_src_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_src_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_src_port_filter, sizeof(tcp_src_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(src_port);
    }
    else if (!src_port && dst_port) {
        len = sizeof(tcp_dst_port_filter) / sizeof(tcp_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_dst_port_filter, sizeof(tcp_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(dst_port);
    }
    else {
        len = sizeof(tcp_src_dst_port_filter) / sizeof(tcp_src_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_src_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_src_dst_port_filter, sizeof(tcp_src_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(dst_port);
        sock_f[14].k = (int)htons(src_port);
    }
    int ret = PcapSetFilter(sock_f, len);
    delete[]sock_f;
    return ret;
}

int PcapHelper::PcapSetTCPOrICMPFilter(int dst_ip, unsigned short src_port_r, unsigned short dst_port_r)
{
    static struct sock_filter tcp_all_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 8, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 6, 0xc0a80101 },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 4, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 1, 0, 0x00000001 },
        { 0x15, 0, 1, 0x00000006 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_src_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 13, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 11, 0xc0a80101 },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 9, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 6, 0, 0x00000001 },
        { 0x15, 0, 6, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 13, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 11, 0xc0a80101 },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 9, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 6, 0, 0x00000001 },
        { 0x15, 0, 6, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter tcp_src_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 15, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 13, 0xc0a80101 },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 11, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 8, 0, 0x00000001 },
        { 0x15, 0, 8, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 6, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 3, 0x00000001 },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_filter *sock_f = NULL;
    u_int len = 0;
    unsigned short src_port = dst_port_r;
    unsigned short dst_port = src_port_r;

    if (!src_port && !dst_port) {
        len = sizeof(tcp_all_port_filter) / sizeof(tcp_all_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_all_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_all_port_filter, sizeof(tcp_all_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
    }
    else if (src_port && !dst_port) {
        len = sizeof(tcp_src_port_filter) / sizeof(tcp_src_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_src_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_src_port_filter, sizeof(tcp_src_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(src_port);
    }
    else if (!src_port && dst_port) {
        len = sizeof(tcp_dst_port_filter) / sizeof(tcp_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_dst_port_filter, sizeof(tcp_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(dst_port);
    }
    else {
        len = sizeof(tcp_src_dst_port_filter) / sizeof(tcp_src_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(tcp_src_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, tcp_src_dst_port_filter, sizeof(tcp_src_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(dst_port);
        sock_f[15].k = (int)htons(src_port);
    }
    int ret = PcapSetFilter(sock_f, len);
    delete[]sock_f;
    return ret;
}

int PcapHelper::PcapSetUDPFilter(int dst_ip, unsigned short src_port_r, unsigned short dst_port_r)
{
    static struct sock_filter udp_all_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 7, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 5, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 3, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 1, 0x00000011 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_src_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 12, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 10, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 8, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 12, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 10, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 8, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_src_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 14, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 12, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 10, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 8, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 6, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 3, 0x00000002 },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_filter *sock_f = NULL;
    u_int len = 0;
    unsigned short src_port = dst_port_r;
    unsigned short dst_port = src_port_r;

    if (!src_port && !dst_port) {
        len = sizeof(udp_all_port_filter) / sizeof(udp_all_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_all_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_all_port_filter, sizeof(udp_all_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
    }
    else if (src_port && !dst_port) {
        len = sizeof(udp_src_port_filter) / sizeof(udp_src_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_src_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_src_port_filter, sizeof(udp_src_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(src_port);
    }
    else if (!src_port && dst_port) {
        len = sizeof(udp_dst_port_filter) / sizeof(udp_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_dst_port_filter, sizeof(udp_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(dst_port);
    }
    else {
        len = sizeof(udp_src_dst_port_filter) / sizeof(udp_src_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_src_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_src_dst_port_filter, sizeof(udp_src_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[12].k = (int)htons(dst_port);
        sock_f[14].k = (int)htons(src_port);
    }
    int ret = PcapSetFilter(sock_f, len);
    delete[]sock_f;
    return ret;
}

int PcapHelper::PcapSetUDPOrICMPFilter(int dst_ip, unsigned short src_port_r, unsigned short dst_port_r)
{
    static struct sock_filter udp_all_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 8, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 6, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 4, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 1, 0, 0x00000011 },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_src_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 13, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 11, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 9, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 6, 0, 0x00000001 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 13, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 11, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 9, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 6, 0, 0x00000001 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    static struct sock_filter udp_src_dst_port_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 15, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x15, 0, 13, 0xc0a801ff },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 0, 11, 0xc0a80101 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 8, 0, 0x00000001 },
        { 0x15, 0, 8, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 6, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 3, 0x00000002 },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 1, 0x00000001 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_filter *sock_f = NULL;
    u_int len = 0;
    unsigned short src_port = dst_port_r;
    unsigned short dst_port = src_port_r;
    if (!src_port && !dst_port) {
        len = sizeof(udp_all_port_filter) / sizeof(udp_all_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_all_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_all_port_filter, sizeof(udp_all_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
    }
    else if (src_port && !dst_port) {
        len = sizeof(udp_src_port_filter) / sizeof(udp_src_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_src_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_src_port_filter, sizeof(udp_src_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(src_port);
    }
    else if (!src_port && dst_port) {
        len = sizeof(udp_dst_port_filter) / sizeof(udp_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_dst_port_filter, sizeof(udp_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(dst_port);
    }
    else {
        len = sizeof(udp_src_dst_port_filter) / sizeof(udp_src_dst_port_filter[0]);
        sock_f = (struct sock_filter *)new (std::nothrow) char[sizeof(udp_src_dst_port_filter)];
        if (sock_f == NULL) {
            return -1;
        }
        memcpy(sock_f, udp_src_dst_port_filter, sizeof(udp_src_dst_port_filter));
        sock_f[3].k = htonl(dst_ip);
        sock_f[5].k = htonl(m_eth_ip.s_addr);
        sock_f[13].k = (int)htons(dst_port);
        sock_f[14].k = (int)htons(src_port);
    }
    int ret = PcapSetFilter(sock_f, len);
    delete[]sock_f;
    return ret;
}

#endif

int PcapHelper::SendEthPacket(std::shared_ptr<NetBase> head)
{
    if (!this->IsInit()) {
        return -1;
    }

    if (!head) {
        return -2;
    }

    if (head->ProtocolId() != HEADER_TYPE_ETHERNET) {
        return -3;
    }

    std::string data = head->AllData();
#if defined(_MSC_VER)
    if (pcap_sendpacket(m_pcap_handle, (const u_char *)data.c_str(), data.size()) != 0)
    {
        return -4;
    }
#elif defined(__GNUC__)
    struct sockaddr_ll saddr_ll = { 0 };
    saddr_ll.sll_ifindex = m_adapt.index;
    saddr_ll.sll_family = AF_PACKET;
    if (sendto(m_raw_sock, (const u_char *)data.c_str(), data.size(), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll)) == -1)
    {
        return -4;
    }
#endif
    return 0;
}

int PcapHelper::GetOneReplayPacket(std::shared_ptr<NetBase> &head)
{
    return GetOneReplayPacket(head, this->m_time_out);
}

int PcapHelper::GetOneReplayPacket(std::shared_ptr<NetBase> &head, time_t time_out)
{
    if (!this->IsInit()) {
        return -1;
    }
#if defined(_MSC_VER)
    if (pcap_datalink(m_pcap_handle) != DLT_EN10MB) {
        return -2;
    }

    if (time_out == 0)
    {
        time_out = m_time_out;
    }

    if (time_out == 0)
    {
        time_out = PCAP_DEFAULT_IO_TIMEOUT;
    }

    unsigned char *p = NULL;
    struct pcap_pkthdr pack_head;
    int rc, nonblock;
    nonblock = pcap_getnonblock(m_pcap_handle, NULL);
    if (nonblock != 0) {
        return -3;
    }
    rc = pcap_setnonblock(m_pcap_handle, 1, NULL);
    if (rc != 0) {
        return -4;
    }
    p = (unsigned char*)pcap_next(m_pcap_handle, &pack_head);
    rc = pcap_setnonblock(m_pcap_handle, nonblock, NULL);
    struct timeval tv_start, tv_end;
    time_t time_left = time_out * 1000;
    gettimeofday(&tv_start, NULL);
    if (p == NULL) {
        /* Nonblocking pcap_next didn't get anything. */
        do
        {
            rc = this->PcapSelect((long)time_left);
            if (rc == 0) {
                return -5;
            }

            if (rc != 1) {
                return -6;
            }
            p = (unsigned char*)pcap_next(m_pcap_handle, &pack_head);
            if (p)
            {
                head = PacketParser::ParsePacketRaw(p, pack_head.caplen, true);
                if (head == NULL) {
                    p = NULL;
                }
                else if (!head->PacketValidate()) {
                    p = NULL;
                }
            }

            gettimeofday(&tv_end, NULL);
            time_left -= TIMEVAL_SUBTRACT(tv_end, tv_start);
        } while (p==NULL && time_left>0);
    }
    else {
        head = PacketParser::ParsePacketRaw(p, pack_head.caplen, true);
        if (head == NULL) {
            p = NULL;
        }
        else if (!head->PacketValidate()) {
            p = NULL;
        }
    }

    if (p == NULL) {
        return -7;
    }
#elif defined(__GNUC__)
    if (time_out == 0)
    {
        time_out = m_time_out;
    }

    if (time_out == 0)
    {
        time_out = PCAP_DEFAULT_IO_TIMEOUT;
    }

    unsigned char *p = (unsigned char *)new (std::nothrow) char[m_max_size];
    if (p == NULL)
    {
        return -2;
    }
    int rc = 0;
    int szRecv = recv(m_raw_sock, p, m_max_size, 0);
    struct timeval tv_start, tv_end;
    time_t time_left = time_out * 1000;
    gettimeofday(&tv_start, NULL);
    if (szRecv < 0) {
        do
        {
            rc = this->PcapSelect((long)time_left);
            if (rc == 0) {
                delete[]p;
                return -3;
            }

            if (rc != 1) {
                delete[]p;
                return -4;
            }
            szRecv = recv(m_raw_sock, p, m_max_size, 0);
            if (szRecv > 0)
            {
                head = PacketParser::ParsePacketRaw(p, szRecv, true);
                if (head == NULL) {
                    szRecv = -1;
                }
                else if (!head->PacketValidate()) {
                    szRecv = -1;
                }
            }

            gettimeofday(&tv_end, NULL);
            time_left -= TIMEVAL_SUBTRACT(tv_end, tv_start);
        } while (szRecv<0 && time_left>0);
    }
    else {
        head = PacketParser::ParsePacketRaw(p, szRecv, true);
        if (head == NULL) {
            szRecv = -1;
        }
        else if (!head->PacketValidate()) {
            szRecv = -1;
        }
    }

    if (szRecv < 0) {
        delete[]p;
        return -5;
    }
    delete[]p;
#endif
    return 0;
}