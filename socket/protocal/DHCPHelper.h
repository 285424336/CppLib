
#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#else
#error unsupported compiler
#endif

typedef struct
{
    std::string chaddr;
    std::string hostname;
    std::string	ciaddr;
    std::string siaddr;
} DhcpParseResult;

class DHCPHelper : public RawSocket
{
public:
#define ETH_HDR_LEN			14
#define IPV4_HDR_LEN        20
#define UDP_HDR_LEN         8

#define DHCP_CHADDR_LEN			16
#define DHCP_SNAME_LEN			64
#define DHCP_FILE_LEN			128
#define DHCP_VEND_LEN			312	//for bootp, it's fidex to 64, for DHCP, it's vary from 64-312
#define DHCP_MAGIC_COOKIE		0x63825363

    /*ethernet header*/
    typedef struct eth_header
    {
        unsigned char h_dest[6];
        unsigned char h_source[6];
        unsigned short h_proto;	/*packet type ID field*/
    } eth_header;

    /*ip header*/
    typedef  struct ip_header
    {
# if __BYTE_ORDER == __LITTLE_ENDIAN  
        unsigned char ihl : 4;
        unsigned char version : 4;
#else
        /* __BYTE_ORDER == __BIG_ENDIAN */
        unsigned char version : 4;
        unsigned char ihl : 4;
#endif   
        unsigned char tos;
        unsigned short tot_len;
        unsigned short id;
        unsigned short frag_off;
        unsigned char  ttl;
        unsigned char  protocol;
        unsigned short check;
        unsigned int   saddr;
        unsigned int   daddr;
    } ip_header;

    typedef struct ipv6_header {
        unsigned int  first_4;			/* Version(4 bits)¡BTraffic class(8 bits)¡BFlow label(20 bits)*/
        unsigned short  payload_len;
        unsigned char   next_hdr;
        unsigned char   hop_limit;
        unsigned char   saddr[16];  /* 16 */
        unsigned char   daddr[16];  /* 16 */
    }ipv6_header;

    /*udp header*/
    typedef struct  udp_header
    {
        unsigned short uh_sport;
        unsigned short uh_dport;
        unsigned short uh_ulen;
        unsigned short uh_sum;
    } udp_header;

    /*dhcp header*/
    typedef struct dhcp_packet_t {
        unsigned char		opcode;
        unsigned char		htype;
        unsigned char		hlen;
        unsigned char		hops;
        unsigned int	    xid;	/* 4 */
        unsigned short	    secs;	/* 8 */
        unsigned short	    flags;
        unsigned int	    ciaddr;	/* 12 */
        unsigned int	    yiaddr;	/* 16 */
        unsigned int	    siaddr;	/* 20 */
        unsigned int	    giaddr;	/* 24 */
        unsigned char		chaddr[DHCP_CHADDR_LEN]; /* 28 */
        unsigned char		sname[DHCP_SNAME_LEN]; /* 44 */
        unsigned char		file[DHCP_FILE_LEN]; /* 108 */
        unsigned int	    option_format; /* 236 */
        unsigned char		options[DHCP_VEND_LEN];
    } dhcp_packet_t;

    typedef struct dhcp_option_t {
        unsigned char		code;
        unsigned char		length;
    } dhcp_option_t;

    enum dhcp_option_code
    {
        DHCP_OPTION_HOSTNAME = 12,
        DHCP_OPTION_REQUESTED_IP = 50,
        DHCP_OPTION_SERVER_ID = 54
    };
public:
    DHCPHelper();
    ~DHCPHelper();

public:
    static bool DhcpRequestPackCheck(const char *buf, int buf_len);
    static void ParseDhcpData(const char *dhcp, int len, DhcpParseResult &res);

private:
    static bool DhcpPackCheck(const char *buf, int buf_len);
    static unsigned char* GetOptionEntityFromDHCPPkt(const dhcp_packet_t *_packet, int _sizetPacketSize, dhcp_option_code _opCode);
    static unsigned char GetOptionEntityLen(const unsigned char* _ptrOptionEntity);
};