#ifndef IPV4_HEADER_H_INCLUDED
#define IPV4_HEADER_H_INCLUDED

#include "NetBase.h"
#include <vector>

#define IP_RF 0x8000               /* Reserved fragment flag         */
#define IP_DF 0x4000               /* Don't fragment flag            */
#define IP_MF 0x2000               /* More fragments flag            */
#define IP_OFFMASK 0x1fff          /* Mask for fragmenting bits      */
#define IP_HEADER_LEN 20           /* Length of the standard header  */
#define MAX_IP_OPTIONS_LEN 40      /* Max Length for IP Options      */

/*
* Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
*/
#define IP_TOS_DEFAULT		0x00	/* default */
#define IP_TOS_LOWDELAY		0x10	/* low delay */
#define IP_TOS_THROUGHPUT	0x08	/* high throughput */
#define IP_TOS_RELIABILITY	0x04	/* high reliability */
#define IP_TOS_LOWCOST		0x02	/* low monetary cost - XXX */
#define IP_TOS_ECT		0x02	/* ECN-capable transport */
#define IP_TOS_CE		0x01	/* congestion experienced */

/*
* IP precedence (high 3 bits of ip_tos), hopefully unused
*/
#define IP_TOS_PREC_ROUTINE		0x00
#define IP_TOS_PREC_PRIORITY		0x20
#define IP_TOS_PREC_IMMEDIATE		0x40
#define IP_TOS_PREC_FLASH		0x60
#define IP_TOS_PREC_FLASHOVERRIDE	0x80
#define IP_TOS_PREC_CRITIC_ECP		0xa0
#define IP_TOS_PREC_INTERNETCONTROL	0xc0
#define IP_TOS_PREC_NETCONTROL		0xe0

/* Ip option types*/
#define IP_OPTION_TYPE_EOL  0
#define IP_OPTION_TYPE_NOP  1
#define IP_OPTION_TYPE_RR   7
#define IP_OPTION_TYPE_TS   68
#define IP_OPTION_TYPE_LSRR 131
#define IP_OPTION_TYPE_SSRR 137

/* Default header values */
#define IPv4_DEFAULT_TOS      0
#define IPv4_DEFAULT_ID       0
#define IPv4_DEFAULT_TTL      64
#define IPv4_DEFAULT_PROTO    6 /* TCP */

#define IPV4_SERIA_NAME_VERSION "version"
#define IPV4_SERIA_NAME_HEADER_LENGTH "head_len"
#define IPV4_SERIA_NAME_TOS "tos"
#define IPV4_SERIA_NAME_TOTAL_LENGTH "total_len"
#define IPV4_SERIA_NAME_ID "id"
#define IPV4_SERIA_NAME_FRAG_OFF "frag_off"
#define IPV4_SERIA_NAME_RF "rf"
#define IPV4_SERIA_NAME_DF "df"
#define IPV4_SERIA_NAME_MF "mf"
#define IPV4_SERIA_NAME_TTL "ttl"
#define IPV4_SERIA_NAME_PROTOCAL "protocal"
#define IPV4_SERIA_NAME_CHECKSUM "checksum"
#define IPV4_SERIA_NAME_DST_IP "dst_ip"
#define IPV4_SERIA_NAME_SRC_IP "src_ip"
#define IPV4_SERIA_NAME_OPT "options"
#define IPV4_SERIA_NAME_OPT_TYPE "type"
#define IPV4_SERIA_NAME_OPT_NAME "name"
#define IPV4_SERIA_NAME_OPT_NAME_EOL  "eol"
#define IPV4_SERIA_NAME_OPT_NAME_NOP  "nop"
#define IPV4_SERIA_NAME_OPT_NAME_RR   "rr"
#define IPV4_SERIA_NAME_OPT_NAME_TS   "ts"
#define IPV4_SERIA_NAME_OPT_NAME_LSRR "lsrr"
#define IPV4_SERIA_NAME_OPT_NAME_SSRR "ssrr"
#define IPV4_SERIA_NAME_OPT_NAME_UNKNOWN "unknown"
#define IPV4_SERIA_NAME_OPT_OFFSET "offset"
#define IPV4_SERIA_NAME_OPT_FLAG "flag"
#define IPV4_SERIA_NAME_OPT_DATA   "data"

#pragma pack(push,1)
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct ipv4_hdr 
{
#ifdef _BIG_ENDIAN
    unsigned char ip_v : 4;                     /* Version                        */
    unsigned char ip_hl : 4;                    /* Header length                  */
#else
    unsigned char ip_hl : 4;                    /* Header length                  */
    unsigned char ip_v : 4;                     /* Version                        */
#endif
    unsigned char ip_tos;                       /* Type of service                */
    unsigned short ip_len;                      /* Total length                   */
    unsigned short ip_id;                       /* Identification                 */
    unsigned short ip_off;                      /* Fragment offset field          */
    unsigned char ip_ttl;                       /* Time to live                   */
    unsigned char ip_p;                         /* Protocol                       */
    unsigned short ip_sum;                      /* Checksum                       */
    struct in_addr ip_src;                      /* Source IP address              */
    struct in_addr ip_dst;                      /* Destination IP address         */
    unsigned char options[MAX_IP_OPTIONS_LEN];  /* IP Options                   */
}ipv4_hdr_t;
#pragma pack(pop)

class IPv4Header : public NetBase 
{
public:
    static std::string GenerateRouteOpts(bool is_record_route = true, bool is_strict = false, const std::vector<struct in_addr> &addrs = std::vector<struct in_addr>());
    static std::string GenerateTimestampOpts(bool is_need_addr = false);

public:
    IPv4Header();
    ~IPv4Header();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    bool Validate() const;
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    /* IP version */
    void SetVersion();
    unsigned char GetVersion() const;
    /* Header Length */
    void SetHeaderLength();
    void SetHeaderLength(unsigned char l);
    unsigned char GetHeaderLength() const;
    /* Type of Service */
    void SetTOS(unsigned char v);
    unsigned char GetTOS() const;
    /* Total length of the datagram */
    void SetTotalLength();
    void SetTotalLength(unsigned short l);
    unsigned short GetTotalLength() const;
    /* Identification value */
    void SetIdentification(unsigned short i = 0);
    unsigned short GetIdentification() const;
    /* Fragment Offset */
    void SetFragOffset(unsigned short f = 0);
    unsigned short GetFragOffset() const;
    /* Flags */
    void SetRF();
    void UnsetRF();
    bool GetRF() const;
    void SetDF();
    void UnsetDF();
    bool GetDF() const;
    void SetMF();
    void UnsetMF();
    bool GetMF() const;
    /* Time to live */
    void SetTTL(unsigned char t = IPv4_DEFAULT_TTL);
    unsigned char GetTTL() const;
    /* Next protocol */
    void SetNextProto(unsigned char p = IPv4_DEFAULT_PROTO);
    unsigned char GetNextProto() const;
    /* Checksum */
    void SetSum();
    void SetSum(unsigned short s);
    unsigned short GetSum() const;
    /* Destination IP */
    void SetDestinationAddress(struct in_addr d);
    void SetDestinationAddress(int d);
    struct in_addr GetDestinationAddress() const;
    /* Source IP */
    void SetSourceAddress(struct in_addr d);
    void SetSourceAddress(int d);
    struct in_addr GetSourceAddress() const;
    /* IP Options */
    bool SetOpts(const unsigned char *opts_buff, unsigned int opts_len);
    std::string GetOpts() const;
    size_t GetOptsLen() const;
    Json::Value OptSerialize() const;
    bool OptUnSerialize(const Json::Value &in);

private:
    ipv4_hdr_t h;
    size_t ipoptlen; /**< Length of IP options */
};

#endif