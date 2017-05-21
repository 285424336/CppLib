#ifndef MDNS_HELPER_H_INCLUDED
#define MDNS_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#include <json\json.h>
#elif defined(__GNUC__)
#include <json/json.h>
#include <socket/SocketHelper.h>
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <vector>
#include <set>
#include <map>
#include <functional>
#include <mutex>

#ifndef offsetof
#define offsetof(s,m) ((size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))
#endif // !offsetof

struct DNSHeader;
namespace DNSQueryBody
{
    struct tc;
}
namespace DNSResponceBody
{
    struct tctd;
};

#define MDNS_RECV_TIMEOUT 2000
#define MDNS_SEND_TIMEOUT 1000
#define MDNS_TYPE_IS_PTR(byte_a) ((0XC0&(char)(byte_a))==(0XC0))
#define MDNS_QUERY_BUFSIZE 2048
#define MDNS_RESPONCE_BUFSIZE 2048
#define MDNS_QUERY_PACK_MINI_SIZE (sizeof(struct DNSHeader)+sizeof(struct DNSQueryBody::tc))
#define MDNS_RESPONCE_PACK_MINI_SIZE (sizeof(struct DNSHeader)+sizeof(struct DNSResponceBody::tctd))

#pragma pack(push,1)
#define MDNS_MCAST_ADDR "224.0.0.251"
#define MDNS_MCAST_ADDR_INT 0XE00000FB 
#define MDNS_MCAST_PORT 5353

#define DNS_RECODE_TYPE_RECODE_NAME 0   //fake type, just for map name
#define DNS_RECODE_TYPE_A           1   
#define DNS_RECODE_TYPE_AAAA        28    
#define DNS_RECODE_TYPE_AFSDB       18    
#define DNS_RECODE_TYPE_APL         42    
#define DNS_RECODE_TYPE_CAA         257   
#define DNS_RECODE_TYPE_CDNSKEY     60   
#define DNS_RECODE_TYPE_CDS         59   
#define DNS_RECODE_TYPE_CERT        37   
#define DNS_RECODE_TYPE_CNAME       5   
#define DNS_RECODE_TYPE_DHCID       49   
#define DNS_RECODE_TYPE_DLV         32769   
#define DNS_RECODE_TYPE_DNSKEY      48   
#define DNS_RECODE_TYPE_DS          43   
#define DNS_RECODE_TYPE_IPSECKEY    45
#define DNS_RECODE_TYPE_KEY         25   
#define DNS_RECODE_TYPE_KX          36    
#define DNS_RECODE_TYPE_LOC         29  
#define DNS_RECODE_TYPE_MX          15   
#define DNS_RECODE_TYPE_NAPTR       35   
#define DNS_RECODE_TYPE_NS          2   
#define DNS_RECODE_TYPE_NSEC        47  
#define DNS_RECODE_TYPE_NSEC3       50  
#define DNS_RECODE_TYPE_NSEC3PARAM  51   
#define DNS_RECODE_TYPE_PTR         12   
#define DNS_RECODE_TYPE_RRSIG       46   
#define DNS_RECODE_TYPE_RP          17  
#define DNS_RECODE_TYPE_SIG         24   
#define DNS_RECODE_TYPE_SOA         6    
#define DNS_RECODE_TYPE_SRV         33  
#define DNS_RECODE_TYPE_SSHFP       44   
#define DNS_RECODE_TYPE_TA          32768  
#define DNS_RECODE_TYPE_TKEY        249  
#define DNS_RECODE_TYPE_TLSA        52  
#define DNS_RECODE_TYPE_TSIG        250   
#define DNS_RECODE_TYPE_TXT         16    
#define DNS_RECODE_TYPE_URI         256   
#define DNS_RECODE_TYPE_DNAME       39
#define DNS_RECODE_TYPE_ANY         255
#define DNS_RECODE_TYPE_AXFR        252
#define DNS_RECODE_TYPE_IXFR        251
#define DNS_RECODE_TYPE_OPT         41

struct DNSHeader
{
    unsigned short id;
#ifdef _BIG_ENDIAN
    union
    {
        unsigned short flags;
        struct {
            unsigned short flag_qr : 1;
            unsigned short flag_opcode : 4;
            unsigned short flag_aa : 1;
            unsigned short flag_tc : 1;
            unsigned short flag_rd : 1;
            unsigned short flag_ra : 1;
            unsigned short flag_z : 3;
            unsigned short flag_rcode : 4;
        }flag_in;
    }flag;
#else
    union
    {
        unsigned short flags;
        struct {
            unsigned short flag_rcode : 4;
            unsigned short flag_z : 3;
            unsigned short flag_ra : 1;
            unsigned short flag_rd : 1;
            unsigned short flag_tc : 1;
            unsigned short flag_aa : 1;
            unsigned short flag_opcode : 4;
            unsigned short flag_qr : 1;
        }flag_in;
    }flag;
#endif
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

namespace DNSQueryBody
{
    struct name
    {
        unsigned char  *qname; //variable len, end with 0
    };
    struct tc
    {
        unsigned short qtype;
        unsigned short qclass;
    };
};

struct RecuName
{
#ifdef _BIG_ENDIAN
    union
    {
        unsigned short name;
        struct {
            unsigned short flag : 2;
            unsigned short off  : 14;
        }name_in;
    }name;
#else
    union
    {
        unsigned short name;
        struct {
            unsigned short off  : 14;
            unsigned short flag : 2;
        }name_in;
    }name;
#endif
};

namespace DNSResponceBody
{
    struct name
    {
        unsigned char  *rname; //variable len, end with 0
    };
    struct tctd
    {
        unsigned short rtype;
        unsigned short rclass;
        unsigned int   rttl;
        unsigned short rdlen;
    };
    struct data
    {
        unsigned char  *rdata; //rdlen len
    };
};

struct DNSResponceData_Ptr
{
    unsigned char  domain_name; //variable len, end with 0
};

struct DNSResponceData_Text
{
    unsigned char  text_len;
    unsigned char  text; //variable len, end with 0
};

struct DNSResponceData_Srv
{
    unsigned short priority;
    unsigned short weight;
    unsigned short port;
    unsigned char  target; //variable len, end with 0
};

#pragma pack(pop)

class MDNSHelper : public MulticastSocket
{
public:
    typedef std::map<int, std::function<bool(const char *, int, int, int, Json::Value &)>> TypeDataOpType;

public:
    explicit MDNSHelper(u_int src_ip = INADDR_ANY, u_short src_port = 0):MulticastSocket(src_ip, src_port, htonl(MDNS_MCAST_ADDR_INT)){}
    ~MDNSHelper(){}
    bool SendMDNSRequest(const std::string &server);
    bool RecvNextMDNSResponce(std::string &from_ip, Json::Value &info);

public:
    static DNSHeader GetMDNSQueryHeader();
    static sockaddr_in GetMDNSSockaddr();
    static TypeDataOpType RegistTypeDataOp();
    static bool CheckMDNSDataValidity(char *data, int size);
    static bool DealMDNSData(Json::Value &info, char *data, int size);

private:
    static bool GeneraterMDNSQueryPacket(const std::string &server, char *buf, size_t &size);
    static bool EncodeDotStr(const std::string &type, char *byte, size_t &size);
    static bool DecodeDotStr(std::string &type, const char *packet, int size, int &deal_off);
    static bool ParseMdnsPtrdata(const char *data, int size, int pos, int len, Json::Value &names);
    static bool ParseMdnsTextdata(const char *data, int size, int pos, int len, Json::Value &names);
    static bool ParseMdnsSrvdata(const char *data, int size, int pos, int len, Json::Value &names);

private:
    static sockaddr_in m_mdns_addr;
    static TypeDataOpType m_mdns_type_data_op;
};

#endif