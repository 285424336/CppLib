#ifndef ICMPV4_HEADER_H_INCLUDED
#define ICMPV4_HEADER_H_INCLUDED

#include "NetBase.h"
#include <vector>

#define ICMP_ECHOREPLY               0     /* Echo reply                     */
#define ICMP_UNREACH                 3     /* Destination unreachable:       */
#define    ICMP_UNREACH_NET            0   /*  --> Bad network               */
#define    ICMP_UNREACH_HOST           1   /*  --> Bad host                  */
#define    ICMP_UNREACH_PROTOCOL       2   /*  --> Bad protocol              */
#define    ICMP_UNREACH_PORT           3   /*  --> Bad port                  */
#define    ICMP_UNREACH_NEEDFRAG       4   /*  --> DF flag caused pkt drop   */
#define    ICMP_UNREACH_SRCFAIL        5   /*  --> Source route failed       */
#define    ICMP_UNREACH_NET_UNKNOWN    6   /*  --> Unknown network           */
#define    ICMP_UNREACH_HOST_UNKNOWN   7   /*  --> Unknown host              */
#define    ICMP_UNREACH_ISOLATED       8   /*  --> Source host isolated      */
#define    ICMP_UNREACH_NET_PROHIB     9   /*  --> Prohibited access         */
#define    ICMP_UNREACH_HOST_PROHIB    10  /*  --> Prohibited access         */
#define    ICMP_UNREACH_TOSNET         11  /*  --> Bad TOS for network       */
#define    ICMP_UNREACH_TOSHOST        12  /*  --> Bad TOS for host          */
#define    ICMP_UNREACH_COMM_PROHIB    13  /*  --> Prohibited communication  */
#define    ICMP_UNREACH_HOSTPRECEDENCE 14  /*  --> Host precedence violation */
#define    ICMP_UNREACH_PRECCUTOFF     15  /*  --> Precedence cutoff         */
#define ICMP_SOURCEQUENCH            4     /* Source Quench.                 */
#define ICMP_REDIRECT                5     /* Redirect:                      */
#define    ICMP_REDIRECT_NET           0   /*  --> For the network           */
#define    ICMP_REDIRECT_HOST          1   /*  --> For the host              */
#define    ICMP_REDIRECT_TOSNET        2   /*  --> For the TOS and network   */
#define    ICMP_REDIRECT_TOSHOST       3   /*  --> For the TOS and host      */
#define ICMP_ECHO                    8     /* Echo request                   */
#define ICMP_ROUTERADVERT            9     /* Router advertisement           */
#define    ICMP_ROUTERADVERT_MOBILE    16  /* Used by mobile IP agents       */
#define ICMP_ROUTERSOLICIT           10    /* Router solicitation            */
#define ICMP_TIMXCEED                11    /* Time exceeded:                 */
#define    ICMP_TIMXCEED_INTRANS       0   /*  --> TTL==0 in transit         */
#define    ICMP_TIMXCEED_REASS         1   /*  --> TTL==0 in reassembly      */
#define ICMP_PARAMPROB               12    /* Parameter problem              */
#define    ICMM_PARAMPROB_POINTER      0   /*  --> Pointer shows the problem */
#define    ICMP_PARAMPROB_OPTABSENT    1   /*  --> Option missing            */
#define    ICMP_PARAMPROB_BADLEN       2   /*  --> Bad datagram length       */
#define ICMP_TSTAMP                  13    /* Timestamp request              */
#define ICMP_TSTAMPREPLY             14    /* Timestamp reply                */
#define ICMP_INFO                    15    /* Information request            */
#define ICMP_INFOREPLY               16    /* Information reply              */
#define ICMP_MASK                    17    /* Address mask request           */
#define ICMP_MASKREPLY               18    /* Address mask reply             */
#define ICMP_TRACEROUTE              30    /* Traceroute                     */
#define    ICMP_TRACEROUTE_SUCCESS     0   /*  --> Dgram sent to next router */
#define    ICMP_TRACEROUTE_DROPPED     1   /*  --> Dgram was dropped         */
#define ICMP_DOMAINNAME              37    /* Domain name request            */
#define ICMP_DOMAINNAMEREPLY         38    /* Domain name reply              */
#define ICMP_SECURITYFAILURES        40    /* Security failures              */

#define ICMP_STD_HEADER_LEN 8
#define ICMP_MAX_PAYLOAD_LEN 1500
#define MAX_ROUTER_ADVERT_ENTRIES (((ICMP_MAX_PAYLOAD_LEN-4)/8)-1)

#define ICMPV4_SERIA_NAME_TYPE "type"
#define ICMPV4_SERIA_NAME_CODE "code"
#define ICMPV4_SERIA_NAME_INFO "info"
#define ICMPV4_SERIA_NAME_CHECKSUM "checksum"
#define ICMPV4_SERIA_NAME_ID "id"
#define ICMPV4_SERIA_NAME_SEQ "seq"
#define ICMPV4_SERIA_NAME_UNUSED "unused"
#define ICMPV4_SERIA_NAME_ADDR "addr"
#define ICMPV4_SERIA_NAME_ADDR_NUM "addr_num"
#define ICMPV4_SERIA_NAME_ADDR_LEN "addr_len"
#define ICMPV4_SERIA_NAME_LIFE_TIME "lief_time"
#define ICMPV4_SERIA_NAME_ADDRS "addrs"
#define ICMPV4_SERIA_NAME_PARA_POINTER "para_pointer"
#define ICMPV4_SERIA_NAME_ORIG_TIMESTAMP "orgi_timestamp"
#define ICMPV4_SERIA_NAME_RECV_TIMESTAMP "recv_timestamp"
#define ICMPV4_SERIA_NAME_TRANS_TIMESTAMP "trans_timestamp"
#define ICMPV4_SERIA_NAME_MASK "mask"
#define ICMPV4_SERIA_NAME_OUTHOPS "outhops"
#define ICMPV4_SERIA_NAME_RETHOPS "rethops"
#define ICMPV4_SERIA_NAME_SPEED "speed"
#define ICMPV4_SERIA_NAME_MTU "mtu"
#define ICMPV4_SERIA_NAME_RESERVED "reserved"
#define ICMPV4_SERIA_NAME_POINTER "pointer"
#define ICMPV4_SERIA_NAME_OTHER_DATA "other_data"
#pragma pack(push,1)
/**********************************************************************/
/* COMMON ICMPv4 packet HEADER                                        */
/**********************************************************************/
/* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Message Body                          +
|                                                               | */
typedef struct icmpv4_hdr {
    unsigned char type;                     /* ICMP Message Type                 */
    unsigned char code;                     /* ICMP Message Code                 */
    unsigned short checksum;                /* Checksum                          */
    unsigned char data[ICMP_MAX_PAYLOAD_LEN];
}icmpv4_hdr_t;

/**********************************************************************/
/* ICMPv4 MESSAGE SPECIFIC HEADERS                                    */
/**********************************************************************/

/* Destination Unreachable Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             unused                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_dest_unreach_msg {
    unsigned int unused;
    //u8 original_dgram[?];
}icmp4_dest_unreach_msg_t;

/* Time Exceeded Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             unused                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_time_exceeded_msg {
    unsigned int unused;
    //u8 original_dgram[?];
}icmp4_time_exceeded_msg_t;

/* Parameter Problem Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Pointer    |                   unused                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  */

typedef struct icmp4_parameter_problem_msg {
    unsigned char pointer;
    unsigned char unused[3];
    //u8 original_dgram[?];
}icmp4_parameter_problem_msg_t;

/* Source Quench Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             unused                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_source_quench_msg {
    unsigned int unused;
    //u8 original_dgram[?];
}icmp4_source_quench_msg_t;

/* Redirect Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Gateway Internet Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_redirect_msg {
    struct in_addr gateway_address;
    //u8 original_dgram[?];
}icmp4_redirect_msg_t;

/* Echo Request/Reply Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data ...
+-+-+-+-+-                                                        */
typedef struct icmp4_echo_msg {
    unsigned short identifier;
    unsigned short sequence;
    //u8 data[?];
}icmp4_echo_msg_t;

/* Timestamp Request/Reply Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |      Code     |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Originate Timestamp                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Receive Timestamp                                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Transmit Timestamp                                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_timestamp_msg {
    unsigned short identifier;
    unsigned short sequence;
    unsigned int originate_ts;
    unsigned int receive_ts;
    unsigned int transmit_ts;
}icmp4_timestamp_msg_t;

/* Information Request/Reply Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |      Code     |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_information_msg {
    unsigned short identifier;
    unsigned short sequence;
}icmp4_information_msg_t;

/* ICMP Router Advertisement Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Num Addrs   |Addr Entry Size|           Lifetime            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[1]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[1]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[2]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[2]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               .                               |
|                               .                               |
|                               .                               | */
typedef struct icmp4_router_advert_entry {
    struct in_addr router_addr;
    unsigned int preference_level;
}icmp4_router_advert_entry_t;

typedef struct icmp4_router_advert_msg {
    unsigned char num_addrs;
    unsigned char addr_entry_size;
    unsigned short lifetime;
    icmp4_router_advert_entry_t adverts[MAX_ROUTER_ADVERT_ENTRIES];
}icmp4_router_advert_msg_t;

/* ICMP Router Solicitation Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_router_solicit_msg {
    unsigned int reserved;
}icmp4_router_solicit_msg_t;

/* ICMP Security Failures Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved            |          Pointer              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~     Original Internet Headers + 64 bits of Payload            ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_security_failures_msg {
    unsigned short reserved;
    unsigned short pointer;
    //u8 original_headers[?];
}icmp4_security_failures_msg_t;

/* ICMP Address Mask Request/Reply Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |      Code     |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |       Sequence Number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Address Mask                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_address_mask_msg {
    unsigned short identifier;
    unsigned short sequence;
    struct in_addr address_mask;
}icmp4_address_mask_msg_t;

/* ICMP Traceroute Message
+---------------+---------------+---------------+---------------+
|     Type      |     Code      |           Checksum            |
+---------------+---------------+---------------+---------------+
|           ID Number           |            unused             |
+---------------+---------------+---------------+---------------+
|      Outbound Hop Count       |       Return Hop Count        |
+---------------+---------------+---------------+---------------+
|                       Output Link Speed                       |
+---------------+---------------+---------------+---------------+
|                        Output Link MTU                        |
+---------------+---------------+---------------+---------------+ */
typedef struct icmp4_traceroute_msg {
    unsigned short id_number;
    unsigned short unused;
    unsigned short outbound_hop_count;
    unsigned short return_hop_count;
    unsigned int output_link_speed;
    unsigned int output_link_mtu;
}icmp4_traceroute_msg_t;

/* ICMP Domain Name Request Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
typedef struct icmp4_domain_name_request_msg {
    unsigned short identifier;
    unsigned short sequence;
}icmp4_domain_name_request_msg_t;

/* ICMP Domain Name Reply Message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Time-To-Live                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Names ...
+-+-+-+-+-+-+-+-                                                  */
typedef struct icmp4_domain_name_reply_msg {
    unsigned short identifier;
    unsigned short sequence;
    unsigned short ttl; /* Signed! */
    unsigned char names[ICMP_MAX_PAYLOAD_LEN - 8];
}icmp4_domain_name_reply_msg_t;
#pragma pack(pop)

class ICMPv4Header : public NetBase 
{
public:
    /* PacketElement:: Mandatory methods */
    ICMPv4Header();
    ~ICMPv4Header();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    bool Validate() const;
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    /* ICMP Type */
    void SetType(unsigned char val);
    unsigned char GetType() const;
    bool ValidateType() const;
    bool ValidateType(unsigned char val) const;
    /* ICMP Code */
    void SetCode(unsigned char c);
    unsigned char GetCode() const;
    bool ValidateCode() const;
    bool ValidateCode(unsigned char type, unsigned char code) const;
    /* Checksum */
    void SetSum();
    void SetSum(unsigned short s);
    unsigned short GetSum() const;

    /* set the raw data of after the common head*/
    void SetRawData(size_t off_data, const unsigned char *buf, size_t len);
    void SetRawData(size_t off_data, const std::string &data);

    /* Unused and reserved fields */
    bool SetUnused(unsigned int val);
    unsigned int GetUnused() const;
    bool SetReserved(unsigned int val);
    unsigned int GetReserved() const;

    /* Redirect */
    bool SetGatewayAddress(struct in_addr ipaddr);
    struct in_addr GetGatewayAddress() const;

    /* Parameter problem */
    bool SetParameterPointer(unsigned char val);
    unsigned char GetParameterPointer() const;

    /* Router advertisement */
    unsigned char GetNumAddresses() const;
    bool SetAddrEntrySize(unsigned char val = 2);
    unsigned char GetAddrEntrySize() const;
    bool SetLifetime(unsigned short val);
    unsigned short GetLifetime() const;
    bool AddRouterAdvEntry(struct in_addr raddr, unsigned int pref);
    std::vector<icmp4_router_advert_entry_t> GetRouterAdvEntries() const;

    /* Echo/Timestamp/Mask */
    bool SetIdentifier(unsigned short val);
    unsigned short GetIdentifier() const;
    bool SetSequence(unsigned short val);
    unsigned short GetSequence() const;

    /* Timestamp only */
    bool SetOriginateTimestamp(unsigned int t);
    unsigned int GetOriginateTimestamp() const;
    bool SetReceiveTimestamp(unsigned int t);
    unsigned int GetReceiveTimestamp() const;
    bool SetTransmitTimestamp(unsigned int t);
    unsigned int GetTransmitTimestamp() const;

    /* Mask only */
    bool SetAddressMask(struct in_addr mask);
    struct in_addr GetAddressMask() const;

    /* Security Failures */
    bool SetSecurityPointer(unsigned short val);
    unsigned short GetSecurityPointer() const;

    /* Traceroute */
    bool SetIDNumber(unsigned short val);
    unsigned short GetIDNumber() const;
    bool SetOutboundHopCount(unsigned short val);
    unsigned short GetOutboundHopCount() const;
    bool SetReturnHopCount(unsigned short val);
    unsigned short GetReturnHopCount() const;
    bool SetOutputLinkSpeed(unsigned int val);
    unsigned int GetOutputLinkSpeed() const;
    bool SetOutputLinkMTU(unsigned int val);
    unsigned int GetOutputLinkMTU() const;

    /* Misc */
    size_t GetICMPMinHeaderLengthFromType(unsigned char type) const;
    std::string Type2String(int type, int code) const;
    bool IsErrorMsg() const;

private:
    bool SetNumAddresses(unsigned char val);

private:
    /* Main data structure */
    icmpv4_hdr_t h;

    /* Helper pointers */
    icmp4_dest_unreach_msg_t         *h_du;
    icmp4_time_exceeded_msg_t        *h_te;
    icmp4_parameter_problem_msg_t    *h_pp;
    icmp4_source_quench_msg_t        *h_sq;
    icmp4_redirect_msg_t             *h_r;
    icmp4_echo_msg_t                 *h_e;
    icmp4_timestamp_msg_t            *h_t;
    icmp4_information_msg_t          *h_i;
    icmp4_router_advert_msg_t        *h_ra;
    icmp4_router_solicit_msg_t       *h_rs;
    icmp4_security_failures_msg_t    *h_sf;
    icmp4_address_mask_msg_t         *h_am;
    icmp4_traceroute_msg_t           *h_trc;
    icmp4_domain_name_request_msg_t  *h_dn;
    icmp4_domain_name_reply_msg_t    *h_dnr;

    /* Internal counts */
    unsigned char routeradventries;
}; /* End of class ICMPv4Header */

#endif