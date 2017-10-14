#ifndef SOCKET_HELPER_H_INCLUDED
#define SOCKET_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <WS2tcpip.h>
#include <Mstcpip.h>
#pragma comment(lib,"ws2_32.lib")
#elif defined(__GNUC__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <linux/sockios.h> 
#include <netinet/in.h>
#include <sys/types.h>  
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h> 
#else
#error unsupported compiler
#endif
#include <string>
#include <mutex>

#define SOCKET_DEFALUT_RECV_TIMEOUT 3000
#define SOCKET_DEFALUT_SEND_TIMEOUT 3000
#define SOCKET_DEFALUT_TLL 255

#if defined(_MSC_VER)
#elif defined(__GNUC__)
typedef int SOCKET;
#else
#error unsupported compiler
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (SOCKET)(~0)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

class SocketHelper
{
public:
    /**
    *get the last socket error
    */
    static int GetLastSocketError()
    {
#if defined(_MSC_VER)
        return ::WSAGetLastError();
#elif defined(__GNUC__)
        return errno;
#else
#error unsupported compiler
#endif
    }

public:
    //constructor
    SocketHelper() : m_sock(-1), m_is_init(false), m_fail_result(0)
    {
    }
    //copy constructor is not support
    SocketHelper(const SocketHelper&) = delete;
    //move constructor
    SocketHelper(SocketHelper&& mv)
    {
        this->m_sock = mv.m_sock;
        this->m_is_init = mv.m_is_init;
        this->m_fail_result = mv.m_fail_result;
        mv.m_sock = -1;
        mv.m_is_init = false;
    }
    //copy assign operator is not support
    SocketHelper& operator=(const SocketHelper&) = delete;
    //move assign
    SocketHelper& operator=(SocketHelper&& mv)
    {
        this->m_sock = mv.m_sock;
        this->m_is_init = mv.m_is_init;
        this->m_fail_result = mv.m_fail_result;
        mv.m_sock = -1;
        mv.m_is_init = false;
        return *this;
    }
    //destructor
    virtual ~SocketHelper() 
    { 
    }
    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(const std::string &src_ip) = 0;
    /**
    *init the sock, after init, you can use GetSock to listen|connect|send|recv
    */
    virtual bool Init() = 0;
    /**
    *uninit the sock and release the resource
    */
    virtual void UnInit() = 0;
    /**
    *check if the socket is valid
    */
    virtual bool IsValid() { return m_sock == -1 ? false : true; }
    /**
    *get the socket, note you must not clost the socket handle, the object will clost it when destruct or you cal uninit
    */
    virtual SOCKET GetSocket() { return m_sock; }
    /**
    *get the last error of socket operation
    */
    virtual int LastError() { return m_fail_result; }
protected:
    /**
    *ready for socket environment
    */
    static int SocketEvnStartUp()
    {
#if defined(_MSC_VER)
        WSADATA wsd;
        return ::WSAStartup(MAKEWORD(2, 2), &wsd);
#elif defined(__GNUC__)
        return 0;
#else
#error unsupported compiler
#endif
    }
    /**
    *clean socket environment
    */
    static void SocketEvnCleanUp()
    {
#if defined(_MSC_VER)
        WSACleanup();
#elif defined(__GNUC__)
        return;
#else
#error unsupported compiler
#endif
    }
    /**
    *create socket
    */
    static SOCKET CreateSocket(int af, int type, int protocal)
    {
#if defined(_MSC_VER)
        return WSASocket(af, type, protocal, NULL, 0, WSA_FLAG_OVERLAPPED);
#elif defined(__GNUC__)
        return socket(af, type, protocal);
#else
#error unsupported compiler
#endif
    }
    /**
    *clost socket socket
    */
    static void CloseSocket(SOCKET &sock)
    {
#if defined(_MSC_VER)
        ::closesocket(sock);
        sock = -1;
#elif defined(__GNUC__)
        close(sock);
        sock = -1;
#else
#error unsupported compiler
#endif
    }

protected:
    bool    m_is_init;
    SOCKET  m_sock;
    int     m_fail_result;
};

class SocketV4Helper : public SocketHelper
{
public:
    //constructor
    SocketV4Helper(u_int src_ip, u_short src_port, int type = SOCK_DGRAM, int protocal = 0, bool is_broadcast = false
        , bool is_multicast = false, u_int multi_ip = 0, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT, int is_multi_loop = 1)
        :SocketHelper(), m_src_ip(src_ip), m_src_port(src_port), m_type(type), m_protocal(protocal), m_is_broadcast(is_broadcast)
        , m_is_multicast(is_multicast), m_multi_ip(multi_ip), m_ttl(ttl), m_send_tm_out(send_tm_out)
        , m_recv_tm_out(recv_tm_out), m_is_multi_loop(is_multi_loop)
    {}
    //copy constructor is not support
    SocketV4Helper(const SocketV4Helper&) = delete;
    //move constructor
    SocketV4Helper(SocketV4Helper&& mv):SocketHelper(std::move(mv))
    {
        this->m_src_ip = mv.m_src_ip;
        this->m_src_port = mv.m_src_port;
        this->m_type = mv.m_type;
        this->m_protocal = mv.m_protocal;
        this->m_is_broadcast = mv.m_is_broadcast;
        this->m_is_multicast = mv.m_is_multicast;
        this->m_multi_ip = mv.m_multi_ip;
        this->m_ttl = mv.m_ttl;
        this->m_send_tm_out = mv.m_send_tm_out;
        this->m_recv_tm_out = mv.m_recv_tm_out;
    }
    //copy assign operator is not support
    SocketV4Helper& operator=(const SocketV4Helper&) = delete;
    //move assign
    SocketV4Helper& operator=(SocketV4Helper&& mv)
    {
        SocketHelper::operator=(std::move(mv));
        this->m_src_ip = mv.m_src_ip;
        this->m_src_port = mv.m_src_port;
        this->m_type = mv.m_type;
        this->m_protocal = mv.m_protocal;
        this->m_is_broadcast = mv.m_is_broadcast;
        this->m_is_multicast = mv.m_is_multicast;
        this->m_multi_ip = mv.m_multi_ip;
        this->m_ttl = mv.m_ttl;
        this->m_send_tm_out = mv.m_send_tm_out;
        this->m_recv_tm_out = mv.m_recv_tm_out;
        return *this;
    }
    //destructor
    virtual ~SocketV4Helper() 
    { 
        this->UnInit();
    }

    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(const std::string &src_ip)
    {
        in_addr result = { 0 };
        inet_pton(AF_INET, src_ip.c_str(), (void *)&result);
        this->ResetSrcIp(result.s_addr);
    }
    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(u_int src_ip)
    {
        m_src_ip = src_ip;
    }
    /**
    *init the sock, after init, you can use GetSock to listen|connect|send|recv
    */
    virtual bool Init()
    {
        if (m_is_init) return true;

        if (SocketEvnStartUp() != 0)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!InitSock())
        {
            SocketEvnCleanUp();
            return false;
        }

        m_is_init = true;
        return true;
    }
    /**
    *uninit the sock and release the resource
    */
    virtual void UnInit()
    {
        if (!m_is_init) {
            return;
        }
        if (m_sock != -1)
        {
            if (m_is_multicast)
            {
                ip_mreq mreq = { 0 };
                mreq.imr_multiaddr.s_addr = m_multi_ip;
                mreq.imr_interface.s_addr = m_src_ip;
                setsockopt(m_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
            }
            CloseSocket(m_sock);
        }
        SocketEvnCleanUp();
        m_is_init = false;
    }
    /**
    *swap to object content
    */
    virtual void swap(SocketV4Helper& right)
    {
        if (this == &right) return;
        SocketV4Helper tmp(std::move(*this));
        *this = std::move(right);
        right = std::move(tmp);
    }

protected:
    virtual bool InitSock()
    {
        m_sock = CreateSocket(AF_INET, m_type, m_protocal);
        if (m_sock == INVALID_SOCKET)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!SetSockOptions())
        {
            CloseSocket(m_sock);
            return false;
        }

        sockaddr_in bind_sock = { 0 };
        bind_sock.sin_family = AF_INET;
        bind_sock.sin_port = m_src_port;
        bind_sock.sin_addr.s_addr = m_src_ip;
        if (bind(m_sock, (struct sockaddr*)&bind_sock, sizeof(bind_sock)) == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }

        return true;
    }

    virtual bool SetSockOptions()
    {
        static int true_val = 1;
        static int false_val = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&true_val, sizeof(true_val)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

#if defined(_MSC_VER)
        u_int recv_time_out = m_recv_tm_out;
#elif defined(__GNUC__)
        struct timeval recv_time_out = { 0 };
        recv_time_out.tv_sec  = m_recv_tm_out/1000;
        recv_time_out.tv_usec = m_recv_tm_out%1000*1000;
#else
#error unsupported compiler
#endif
        if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

#if defined(_MSC_VER)
        u_int send_time_out = m_send_tm_out;
#elif defined(__GNUC__)
        struct timeval send_time_out = { 0 };
        send_time_out.tv_sec = m_send_tm_out / 1000;
        send_time_out.tv_usec = m_send_tm_out % 1000 * 1000;
#else
#error unsupported compiler
#endif
        if (setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (m_is_broadcast)
        {
            if (setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, (char*)&true_val, sizeof(true_val)))
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
        }

        if (m_is_multicast)
        {
            if (setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&m_ttl, sizeof(m_ttl)) != 0)
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
            if (setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&m_is_multi_loop, sizeof(m_is_multi_loop)) != 0)
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
        }
        else
        {
            if (setsockopt(m_sock, IPPROTO_IP, IP_TTL, (char *)&m_ttl, sizeof(m_ttl)))
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
        }

        if (m_is_multicast)
        {
            ip_mreq mreq = { 0 };
            mreq.imr_multiaddr.s_addr = m_multi_ip;
            mreq.imr_interface.s_addr = m_src_ip;
            if (setsockopt(m_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq)) != 0)
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
        }

        return true;
    }

protected:
    u_int   m_src_ip;
    u_short m_src_port;
    int     m_type;
    int     m_protocal;
    bool    m_is_broadcast;
    bool    m_is_multicast;
    u_int   m_multi_ip;
    int     m_is_multi_loop;
    u_int   m_ttl;
    u_int   m_send_tm_out;
    u_int   m_recv_tm_out;
};

class RawSocket : public SocketV4Helper
{
public:
    RawSocket(u_int src_ip, int protocal = 0, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketV4Helper(src_ip, 0, SOCK_RAW, protocal, false, false, 0, ttl, send_tm_out, recv_tm_out){}

protected:
    virtual bool InitSock()
    {
        m_sock = CreateSocket(AF_INET, m_type, m_protocal);
        if (m_sock == INVALID_SOCKET)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!SetSockOptions())
        {
            CloseSocket(m_sock);
            return false;
        }

#if defined(_MSC_VER)
        sockaddr_in bind_sock = { 0 };
        bind_sock.sin_family = AF_INET;
        bind_sock.sin_port = m_src_port;
        bind_sock.sin_addr.s_addr = m_src_ip;
        if (bind(m_sock, (struct sockaddr*)&bind_sock, sizeof(bind_sock)) == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }

        DWORD dwValue = 1;
        if (ioctlsocket(m_sock, SIO_RCVALL, &dwValue) != 0)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }
#elif defined(__GNUC__)
        int fd = m_sock, intrface;
        struct ifreq buf[40] = { { 0 } };
        struct ifconf ifc;

        ifc.ifc_len = sizeof buf;
        ifc.ifc_buf = (caddr_t)buf;
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }

        intrface = ifc.ifc_len / sizeof(struct ifreq);
        while (intrface-- > 0)
        {
            if (ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))
            {
                continue;
            }
            
            if (((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr.s_addr != m_src_ip)
            {
                continue;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, buf[intrface].ifr_name, strlen(buf[intrface].ifr_name) + 1);
            if (ioctl(fd, SIOCGIFFLAGS, &ifr))
            {
                m_fail_result = GetLastSocketError();
                CloseSocket(m_sock);
                return false;
            }
            ifr.ifr_flags |= IFF_PROMISC;
            if (ioctl(fd, SIOCSIFFLAGS, &ifr))
            {
                m_fail_result = GetLastSocketError();
                CloseSocket(m_sock);
                return false;
            }
            break;
        }
#else
#error unsupported compiler
#endif
        return true;
    }
};

class BroadcastSocket : public SocketV4Helper
{
public:
    BroadcastSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketV4Helper(src_ip, src_port, SOCK_DGRAM, 0, true, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

class MulticastSocket : public SocketV4Helper
{
public:
    MulticastSocket(u_int src_ip, u_short src_port, u_int multi_ip, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT, int is_multi_loop = 1)
        : SocketV4Helper(src_ip, src_port, SOCK_DGRAM, 0, false, true, multi_ip, ttl, send_tm_out, recv_tm_out, is_multi_loop) {}
};

class UDPSocket : public SocketV4Helper
{
public:
    UDPSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketV4Helper(src_ip, src_port, SOCK_DGRAM, 0, false, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

class TCPSocket : public SocketV4Helper
{
public:
    TCPSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketV4Helper(src_ip, src_port, SOCK_STREAM, 0, false, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

/**
*swap left with rignht
*/
inline void swap(SocketV4Helper &left, SocketV4Helper &right)
{
    left.swap(right);
}

class SocketV6Helper : public SocketHelper
{
public:
    //constructor
    SocketV6Helper(const std::string &src_ip, u_short src_port, int type = SOCK_DGRAM, int protocal = 0
        , bool is_multicast = false, const std::string &multi_ip = 0, u_int if_index = 0
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT, int is_multi_loop = 1)
        :SocketHelper(), m_if_index(if_index), m_src_port(src_port), m_type(type), m_protocal(protocal)
        , m_is_multicast(is_multicast), m_send_tm_out(send_tm_out)
        , m_recv_tm_out(recv_tm_out), m_is_multi_loop(is_multi_loop)
    {
        if (!src_ip.empty())
        {
            memset(&m_src_ip, 0, sizeof(m_src_ip));
            inet_pton(AF_INET6, src_ip.c_str(), (void *)&m_src_ip);
        }
        else
        {
            m_src_ip = in6addr_any;
        }
        memset(&m_multi_ip, 0, sizeof(m_multi_ip));
        inet_pton(AF_INET6, multi_ip.c_str(), (void *)&m_multi_ip);
    }
    //copy constructor is not support
    SocketV6Helper(const SocketV6Helper&) = delete;
    //move constructor
    SocketV6Helper(SocketV6Helper&& mv):SocketHelper(std::move(mv))
    {
        this->m_src_ip = mv.m_src_ip;
        this->m_src_port = mv.m_src_port;
        this->m_type = mv.m_type;
        this->m_protocal = mv.m_protocal;
        this->m_is_multicast = mv.m_is_multicast;
        this->m_multi_ip = mv.m_multi_ip;
        this->m_if_index = mv.m_if_index;
        this->m_send_tm_out = mv.m_send_tm_out;
        this->m_recv_tm_out = mv.m_recv_tm_out;
    }
    //copy assign operator is not support
    SocketV6Helper& operator=(const SocketV6Helper&) = delete;
    //move assign
    SocketV6Helper& operator=(SocketV6Helper&& mv)
    {
        SocketHelper::operator=(std::move(mv));
        this->m_src_ip = mv.m_src_ip;
        this->m_src_port = mv.m_src_port;
        this->m_type = mv.m_type;
        this->m_protocal = mv.m_protocal;
        this->m_is_multicast = mv.m_is_multicast;
        this->m_multi_ip = mv.m_multi_ip;
        this->m_if_index = mv.m_if_index;
        this->m_send_tm_out = mv.m_send_tm_out;
        this->m_recv_tm_out = mv.m_recv_tm_out;
        return *this;
    }
    //destructor
    virtual ~SocketV6Helper()
    {
        this->UnInit();
    }

    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(const std::string &src_ip)
    {
        in6_addr result = { 0 };
        inet_pton(AF_INET6, src_ip.c_str(), (void *)&result);
        this->ResetSrcIp(result);
    }
    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(in6_addr src_ip)
    {
        m_src_ip = src_ip;
    }
    /**
    *init the sock, after init, you can use GetSock to listen|connect|send|recv
    */
    virtual bool Init()
    {
        if (m_is_init) return true;

        if (SocketEvnStartUp() != 0)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!InitSock())
        {
            SocketEvnCleanUp();
            return false;
        }

        m_is_init = true;
        return true;
    }
    /**
    *uninit the sock and release the resource
    */
    virtual void UnInit()
    {
        if (!m_is_init) {
            return;
        }
        if (m_sock != -1)
        {
            if (m_is_multicast)
            {
                ipv6_mreq mreq = { 0 };
                mreq.ipv6mr_multiaddr = m_multi_ip;
                mreq.ipv6mr_interface = m_if_index;
                setsockopt(m_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
            }
            CloseSocket(m_sock);
        }
        SocketEvnCleanUp();
        m_is_init = false;
    }
    /**
    *swap to object content
    */
    virtual void swap(SocketV6Helper& right)
    {
        if (this == &right) return;
        SocketV6Helper tmp(std::move(*this));
        *this = std::move(right);
        right = std::move(tmp);
    }

protected:
    virtual bool InitSock()
    {
        m_sock = CreateSocket(AF_INET6, m_type, m_protocal);
        if (m_sock == INVALID_SOCKET)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!SetSockOptions())
        {
            CloseSocket(m_sock);
            return false;
        }

        sockaddr_in6 bind_sock = { 0 };
        bind_sock.sin6_family = AF_INET6;
        bind_sock.sin6_port = m_src_port;
        bind_sock.sin6_addr = m_src_ip; ///in6addr_any
        if (bind(m_sock, (struct sockaddr*)&bind_sock, sizeof(bind_sock)) == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }

        return true;
    }

    virtual bool SetSockOptions()
    {
        static int true_val = 1;
        static int false_val = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&true_val, sizeof(true_val)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

#if defined(_MSC_VER)
        u_int recv_time_out = m_recv_tm_out;
#elif defined(__GNUC__)
        struct timeval recv_time_out = { 0 };
        recv_time_out.tv_sec = m_recv_tm_out / 1000;
        recv_time_out.tv_usec = m_recv_tm_out % 1000 * 1000;
#else
#error unsupported compiler
#endif
        if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

#if defined(_MSC_VER)
        u_int send_time_out = m_send_tm_out;
#elif defined(__GNUC__)
        struct timeval send_time_out = { 0 };
        send_time_out.tv_sec = m_send_tm_out / 1000;
        send_time_out.tv_usec = m_send_tm_out % 1000 * 1000;
#else
#error unsupported compiler
#endif
        if (setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)))
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (m_is_multicast)
        {
            if (setsockopt(m_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&m_is_multi_loop, sizeof(m_is_multi_loop)) != 0)
            {
                m_fail_result = GetLastSocketError();
                return false;
            }

            ipv6_mreq mreq = { 0 };
            mreq.ipv6mr_multiaddr = m_multi_ip;
            mreq.ipv6mr_interface = m_if_index;// m_if_ip;
            if (setsockopt(m_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq)) != 0)
            {
                m_fail_result = GetLastSocketError();
                return false;
            }
        }

        return true;
    }

protected:
    in6_addr   m_src_ip; //bind src ip
    u_short m_src_port; //bind src port
    int     m_type; //socket type
    int     m_protocal; //socket protocal
    bool    m_is_multicast; //is use multi packet
    in6_addr   m_multi_ip; //multi ip to add
    u_int   m_if_index; //eth index used to send or recv multi packet
    int     m_is_multi_loop; //is use loop
    u_int   m_send_tm_out;
    u_int   m_recv_tm_out;
};

class MulticastSocketV6 : public SocketV6Helper
{
public:
    MulticastSocketV6(u_short src_port, const std::string &multi_ip, u_int if_index, u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT, int is_multi_loop = 1)
     : SocketV6Helper("", src_port, SOCK_DGRAM, 0, true, multi_ip, if_index, send_tm_out, recv_tm_out, is_multi_loop)
    {}

    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(const std::string &src_ip)
    {
        this->SocketV6Helper::ResetSrcIp(src_ip);
        return;
    }
    /**
    *reset the src ip, you should do this before init
    */
    virtual void ResetSrcIp(in6_addr src_ip)
    {
        this->SocketV6Helper::ResetSrcIp(src_ip);
        return;
    }
    /**
    *reset the multicast eth to send or recv packet, you should do this before init
    */
    virtual void ResetSrcIp(u_int if_index)
    {
        m_if_index = if_index;
    }
};

class RawSocketV6 : public SocketV6Helper
{
public:
    RawSocketV6(const std::string &src_ip, int protocal = 0
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketV6Helper(src_ip, 0, SOCK_RAW, protocal, false, "", 0, send_tm_out, recv_tm_out) {}
protected:
    virtual bool InitSock()
    {
        m_sock = CreateSocket(AF_INET6, m_type, m_protocal);
        if (m_sock == INVALID_SOCKET)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!SetSockOptions())
        {
            CloseSocket(m_sock);
            return false;
        }

#if defined(_MSC_VER)
        sockaddr_in6 bind_sock = { 0 };
        bind_sock.sin6_family = AF_INET6;
        bind_sock.sin6_port = m_src_port;
        bind_sock.sin6_addr = m_src_ip; ///in6addr_any
        if (bind(m_sock, (struct sockaddr*)&bind_sock, sizeof(bind_sock)) == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }

        DWORD dwValue = 1;
        if (ioctlsocket(m_sock, SIO_RCVALL, &dwValue) != 0)
        {
            m_fail_result = GetLastSocketError();
            CloseSocket(m_sock);
            return false;
        }
#elif defined(__GNUC__)
        struct ifaddrs *ifa, *p;
        int family;
        char address[200];

        if (getifaddrs(&ifa)) {
            return false;
        }

        bool ret = false;
        for (p = ifa; p != NULL; p = p->ifa_next) {
            if (p->ifa_addr == NULL) {
                continue;
            }
            family = p->ifa_addr->sa_family;
            /* Just check IPv6 address */
            if (family != AF_INET6) {
                continue;
            }
            if (memcmp(&((struct sockaddr_in6 *)(p->ifa_addr))->sin6_addr, &m_src_ip, sizeof(m_src_ip))) {
                continue;
            }
            if (p->ifa_name == NULL) {
                break;
            }
            struct ifreq ifr;
            strncpy(ifr.ifr_name, p->ifa_name, strlen(p->ifa_name) + 1);
            if (ioctl(m_sock, SIOCGIFFLAGS, &ifr))
            {
                m_fail_result = GetLastSocketError();
                CloseSocket(m_sock);
                break;
            }
            ifr.ifr_flags |= IFF_PROMISC;
            if (ioctl(m_sock, SIOCSIFFLAGS, &ifr))
            {
                m_fail_result = GetLastSocketError();
                CloseSocket(m_sock);
                break;
            }
            ret = true;
            break;
        }
        freeifaddrs(ifa);
        if (!ret) {
            return false;
        }
#else
#error unsupported compiler
#endif
        return true;
    }

};

/**
*swap left with rignht
*/
inline void swap(SocketV6Helper &left, SocketV6Helper &right)
{
    left.swap(right);
}

#endif