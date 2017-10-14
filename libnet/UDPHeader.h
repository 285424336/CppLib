#ifndef UDP_HEADER_H_INCLUDED
#define UDP_HEADER_H_INCLUDED

#include "TransportLayerHeader.h"

#define UDP_HEADER_LEN 8

/* Default header values */
#define UDP_DEFAULT_SPORT 53
#define UDP_DEFAULT_DPORT 53

#define UDP_SERIA_NAME_SRC_PORT "src_port"
#define UDP_SERIA_NAME_DST_PORT "dst_port"
#define UDP_SERIA_NAME_TOTAL_LEN "total_len"
#define UDP_SERIA_NAME_CHECK_SUM "check_sum"

#pragma pack(push,1)
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct udp_hdr {
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_ulen;
    unsigned short uh_sum;
}udp_hdr_t;
#pragma pack(pop)

class UDPHeader : public TransportLayerHeader
{
public:
    UDPHeader();
    ~UDPHeader();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    void SetSourcePort(unsigned short p);
    unsigned short GetSourcePort() const;

    void SetDestinationPort(unsigned short p);
    unsigned short GetDestinationPort() const;

    void SetTotalLength();
    void SetTotalLength(unsigned short l);
    unsigned short GetTotalLength() const;

    void SetSum();
    void SetSum(unsigned short s);
    unsigned short GetSum() const;

private:
    udp_hdr_t h;
};


#endif