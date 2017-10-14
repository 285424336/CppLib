#ifndef NET_BASE_H_INCLUDED
#define NET_BASE_H_INCLUDED

#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <json\json.h>
#pragma comment(lib, "ws2_32.lib")
#elif defined(__GNUC__)
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <json/json.h>
#else
#error unsupported compiler
#endif

#include <string>
#include <memory>
#include <map>

#define HEADER_TYPE_IPv6_HOPOPT   0  /* IPv6 Hop-by-Hop Option                */
#define HEADER_NAME_IPv6_HOPOPT   "ipv6_hopopt"
#define HEADER_TYPE_ICMPv4        1  /* ICMP Internet Control Message         */
#define HEADER_NAME_ICMPv4        "icmpv4"
#define HEADER_TYPE_IGMP          2  /* IGMP Internet Group Management        */
#define HEADER_NAME_IGMP          "igmp"
#define HEADER_TYPE_IPv4          4  /* IPv4 IPv4 encapsulation               */
#define HEADER_NAME_IPv4          "ipv4"
#define HEADER_TYPE_TCP           6  /* TCP Transmission Control              */
#define HEADER_NAME_TCP           "tcp"
#define HEADER_TYPE_EGP           8  /* EGP Exterior Gateway Protocol         */
#define HEADER_NAME_EGP           "egp"
#define HEADER_TYPE_UDP           17 /* UDP User Datagram                     */
#define HEADER_NAME_UDP           "udp"
#define HEADER_TYPE_IPv6          41 /* IPv6 IPv6 encapsulation               */
#define HEADER_NAME_IPv6          "ipv6"
#define HEADER_TYPE_IPv6_ROUTE    43 /* IPv6-Route Routing Header for IPv6    */
#define HEADER_NAME_IPv6_ROUTE    "ipv6_router"
#define HEADER_TYPE_IPv6_FRAG     44 /* IPv6-Frag Fragment Header for IPv6    */
#define HEADER_NAME_IPv6_FRAG     "ipv6_frag"
#define HEADER_TYPE_GRE           47 /* GRE General Routing Encapsulation     */
#define HEADER_NAME_GRE           "gre"
#define HEADER_TYPE_ESP           50 /* ESP Encap Security Payload            */
#define HEADER_NAME_ESP           "esp"
#define HEADER_TYPE_AH            51 /* AH Authentication Header              */
#define HEADER_NAME_AH            "ah"
#define HEADER_TYPE_ICMPv6        58 /* IPv6-ICMP ICMP for IPv6               */
#define HEADER_NAME_ICMPv6        "icmpv6"
#define HEADER_TYPE_IPv6_NONXT    59 /* IPv6-NoNxt No Next Header for IPv6    */
#define HEADER_NAME_IPv6_NONXT    "ipv6_nonxt"
#define HEADER_TYPE_IPv6_OPTS     60 /* IPv6-Opts IPv6 Destination Options    */
#define HEADER_NAME_IPv6_OPTS     "ipv6_opts"
#define HEADER_TYPE_EIGRP         88 /* EIGRP                                 */
#define HEADER_NAME_EIGRP         "eigrp"
#define HEADER_TYPE_ETHERNET      97 /* Ethernet                              */
#define HEADER_NAME_ETHERNET      "ethernet"
#define HEADER_TYPE_L2TP         115 /* L2TP Layer Two Tunneling Protocol     */
#define HEADER_NAME_L2TP         "l2tp"
#define HEADER_TYPE_SCTP         132 /* SCTP Stream Control Transmission P.   */
#define HEADER_NAME_SCTP         "sctp"
#define HEADER_TYPE_IPv6_MOBILE  135 /* Mobility Header                       */
#define HEADER_NAME_IPv6_MOBILE  "ipv6_mobile"
#define HEADER_TYPE_MPLS_IN_IP   137 /* MPLS-in-IP                            */
#define HEADER_NAME_MPLS_IN_IP   "mpls_in_ip"
#define HEADER_TYPE_ARP         2054 /* ARP Address Resolution Protocol       */
#define HEADER_NAME_ARP         "arp"
#define HEADER_TYPE_ICMPv6_OPTION 9997 /* ICMPv6 option                       */
#define HEADER_NAME_ICMPv6_OPTION "icmpv6_option"
#define HEADER_TYPE_NEP         9998 /* Nping Echo Protocol                   */
#define HEADER_NAME_NEP         "nep"
#define HEADER_TYPE_RAW_DATA    9999 /* Raw unknown data                      */
#define HEADER_NAME_RAW_DATA    "raw_data"

#define SERIA_NAME_PROTOCOL_ID    "protocal_id"
#define SERIA_NAME_PROTOCOL_DATA  "protocal_data"
#define SERIA_NAME_PROTOCOL_NAME  "protocal_name"

class NetBase : public std::enable_shared_from_this<NetBase>
{
public:
    NetBase();
    NetBase(const NetBase&) = delete;
    NetBase(const NetBase&&) = delete;
    NetBase& operator=(const NetBase&) = delete;
    NetBase& operator=(const NetBase&&) = delete;

    virtual ~NetBase();
    /**
    *get current header protocal id, child should implacment the func.
    */
    virtual int ProtocolId() const = 0;
    /**
    *serialize the data to the json value.
    */
    virtual Json::Value Serialize() const = 0;
    /**
    *unserialize the json value to data.
    */
    virtual bool UnSerialize(const Json::Value &in) = 0;
    /**
    *store raw packet from the buf.
    *buf(in): raw data
    *len(in): data len
    *return true if success
    */
    virtual bool StorePacket(const unsigned char *buf, size_t len) = 0;
    /**
    *is current data valid
    */
    virtual bool Validate() const;
    /**
    *is total packet valid
    */
    virtual bool PacketValidate();
    /**
    *get a copy of the raw data of current data, child should implacment the func.
    */
    virtual std::string Data() const = 0;
    /**
    *get current data len.
    */
    virtual size_t Len() const;
    /**
    *get a copy of the raw data of current header and its down layer.
    */
    virtual std::string AllData() const;
    /**
    *get current header together with down layer headers len.
    */
    virtual size_t AllLen() const;
    /**
    *get next data, may be null
    */
    virtual std::shared_ptr<NetBase> Next() const;
    /**
    *get prev data, may be null
    */
    virtual std::shared_ptr<NetBase> Prev() const;
    /**
    *get the head data in current chain
    */
    virtual std::shared_ptr<NetBase> Head();
    /**
    *get the tail data in current chain
    */
    virtual std::shared_ptr<NetBase> Tail();
    /**
    *set the next data
    *n(in): next data
    *return the next data
    */
    virtual std::shared_ptr<NetBase> SetNext(std::shared_ptr<NetBase> n);
    /**
    *get the json string of all data after this layer include this layer
    */
    virtual std::string Repr() const;
    /**
    *unparse the Json data
    *in(in): the json data
    *return a shared point to the parsed json data
    */
    template <typename T>
    static std::shared_ptr<NetBase> UnParse(const Json::Value &in) {
        std::shared_ptr<NetBase> tmp = std::make_shared<T>();
        if (!tmp) {
            return std::shared_ptr<NetBase>();
        }
        if (!tmp->UnSerialize(in)) {
            return std::shared_ptr<NetBase>();
        }
        return tmp;
    }
    /**
    *get the specify protocal id data in chain, it search from the head
    */
    virtual std::shared_ptr<NetBase> ProtocalData(int protocal_id);
    /**
    *get the specify protocal id data in chain, it search from current
    */
    virtual std::shared_ptr<NetBase> ProtocalDataBehind(int protocal_id);

protected:
    /**
    *set the prev data
    *n(in): prev data
    *return the prev data
    */
    virtual std::shared_ptr<NetBase>  SetPrev(std::shared_ptr<NetBase> n);

protected:
    size_t length; /** current packet length */
    std::shared_ptr<NetBase> next; /** next PacketElement (next proto header) */
    std::weak_ptr<NetBase> prev; /** prev PacketElement (previous proto header) */

protected:
    static std::map<int, std::string> protocal_id_name_map;
    static std::map<std::string, int> protocal_name_id_map;
    static bool init;
    static bool InitStatic();
};
#endif
