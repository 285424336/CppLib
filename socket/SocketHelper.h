#ifndef SOCKET_HELPER_H_INCLUDED
#define SOCKET_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#elif defined(__GNUC__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
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
    //constructor
    SocketHelper(u_int src_ip, u_short src_port, int type = SOCK_DGRAM, int protocal = 0, bool is_broadcast = false
        , bool is_multicast = false, u_int multi_ip = 0, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        :m_src_ip(src_ip), m_src_port(src_port), m_type(type), m_protocal(protocal), m_is_broadcast(is_broadcast)
        , m_is_multicast(is_multicast), m_multi_ip(multi_ip), m_ttl(ttl), m_send_tm_out(send_tm_out)
        , m_recv_tm_out(recv_tm_out), m_sock(-1), m_is_init(false), m_fail_result(0)
    {}
    //copy constructor is not support
    SocketHelper(const SocketHelper&) = delete;
    //move constructor
    SocketHelper(SocketHelper&& mv)
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
        this->m_sock = mv.m_sock;
        this->m_is_init = mv.m_is_init;
        this->m_fail_result = mv.m_fail_result;
        mv.m_sock = -1;
        mv.m_is_init = false;
        return *this;
    }
    //destructor
    virtual ~SocketHelper() { UnInit(); }
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
        if (!m_is_init) return;
        if (m_sock != -1) CloseSocket(m_sock);
        SocketEvnCleanUp();
        m_is_init = false;
    }
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
    /**
    *swap to object content
    */
    virtual void swap(SocketHelper& right)
    {
        if (this == &right) return;
        SocketHelper tmp(std::move(*this));
        *this = std::move(right);
        right = std::move(tmp);
    }

private:
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

private:
    u_int   m_src_ip;
    u_short m_src_port;
    int     m_type;
    int     m_protocal;
    bool    m_is_broadcast;
    bool    m_is_multicast;
    u_int   m_multi_ip;
    u_int   m_ttl;
    u_int   m_send_tm_out;
    u_int   m_recv_tm_out;
    SOCKET  m_sock;
    bool    m_is_init;
protected:
    int     m_fail_result;
};

class RawSocket : public SocketHelper
{
public:
    RawSocket(u_int src_ip, int protocal = 0, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketHelper(src_ip, 0, SOCK_RAW, protocal, false, false, 0, ttl, send_tm_out, recv_tm_out){}
};

class BroadcastSocket : public SocketHelper
{
public:
    BroadcastSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketHelper(src_ip, src_port, SOCK_DGRAM, 0, true, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

class MulticastSocket : public SocketHelper
{
public:
    MulticastSocket(u_int src_ip, u_short src_port, u_int multi_ip, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketHelper(src_ip, src_port, SOCK_DGRAM, 0, false, true, multi_ip, ttl, send_tm_out, recv_tm_out) {}
};

class UDPSocket : public SocketHelper
{
public:
    UDPSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketHelper(src_ip, src_port, SOCK_DGRAM, 0, false, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

class TCPSocket : public SocketHelper
{
public:
    TCPSocket(u_int src_ip, u_short src_port, u_int ttl = SOCKET_DEFALUT_TLL
        , u_int send_tm_out = SOCKET_DEFALUT_SEND_TIMEOUT, u_int recv_tm_out = SOCKET_DEFALUT_RECV_TIMEOUT)
        : SocketHelper(src_ip, src_port, SOCK_STREAM, 0, false, false, 0, ttl, send_tm_out, recv_tm_out) {}
};

/**
*swap left with rignht
*/
inline void swap(SocketHelper &left, SocketHelper &right)
{
    left.swap(right);
}
#endif