#ifndef ICMPV6_HELPER_H_INCLUDED
#define ICMPV6_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#include <algorithm/AlgorithmHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <mutex>
#include <future>

#undef __flexarr
#if defined(__GNUC__) && ((__GNUC__ > 2) || (__GNUC__ == 2 && __GNUC_MINOR__ >= 97))
/* GCC 2.97 supports C99 flexible array members.  */
# define __flexarr	[]
#else
# ifdef __GNUC__
#  define __flexarr	[0]
# else
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#   define __flexarr	[]
#  elif defined(_MSC_VER)
/* MS VC++ -- using [] works but gives a "nonstandard extension" warning */
#   define __flexarr	[1]
#  else
/* Some other non-C99 compiler. Approximate with [1]. */
#   define __flexarr	[1]
#  endif
# endif
#endif

#define ICMPV6_HDR_LEN	4	/* base ICMPv6 header length */

#ifndef __GNUC__
#ifndef __attribute__
# define __attribute__(x)
#endif
# pragma pack(1)
#endif

/*
* ICMPv6 header
*/
struct icmpv6_hdr {
    unsigned char		icmpv6_type;	/* type of message, see below */
    unsigned char		icmpv6_code;	/* type sub code */
    unsigned short   	icmpv6_cksum;	/* ones complement cksum of struct */
};

/*
* Types (icmpv6_type) and codes (icmpv6_code) -
* http://www.iana.org/assignments/icmpv6-parameters
*/
#define		ICMPV6_CODE_NONE	0		/* for types without codes */
#define ICMPV6_UNREACH		1		/* dest unreachable, codes: */
#define		ICMPV6_UNREACH_NOROUTE		0	/* no route to dest */
#define		ICMPV6_UNREACH_PROHIB		1	/* admin prohibited */
#define		ICMPV6_UNREACH_SCOPE		2	/* beyond scope of source address */
#define		ICMPV6_UNREACH_ADDR		3	/* address unreach */
#define		ICMPV6_UNREACH_PORT		4	/* port unreach */
#define		ICMPV6_UNREACH_FILTER_PROHIB	5	/* src failed ingress/egress policy */
#define		ICMPV6_UNREACH_REJECT_ROUTE	6	/* reject route */
#define ICMPV6_TIMEXCEED	3		/* time exceeded, code: */
#define		ICMPV6_TIMEXCEED_INTRANS	0	/* hop limit exceeded in transit */
#define		ICMPV6_TIMEXCEED_REASS		1	/* fragmetn reassembly time exceeded */
#define ICMPV6_PARAMPROBLEM	4		/* parameter problem, code: */
#define 	ICMPV6_PARAMPROBLEM_FIELD	0	/* erroneous header field encountered */
#define 	ICMPV6_PARAMPROBLEM_NEXTHEADER	1	/* unrecognized Next Header type encountered */
#define 	ICMPV6_PARAMPROBLEM_OPTION	2	/* unrecognized IPv6 option encountered */
#define ICMPV6_ECHO		128		/* echo request */
#define ICMPV6_ECHOREPLY	129		/* echo reply */
/*
* Neighbor discovery types (RFC 4861)
*/
#define	ICMPV6_NEIGHBOR_SOLICITATION	135
#define	ICMPV6_NEIGHBOR_ADVERTISEMENT	136

#define	ICMPV6_INFOTYPE(type) (((type) & 0x80) != 0)

/*
* Echo message data
*/
struct icmpv6_msg_echo {
    unsigned short	icmpv6_id;
    unsigned short	icmpv6_seq;
    unsigned char	icmpv6_data __flexarr;	/* optional data */
};

/* Neighbor solicitation or advertisement (single hardcoded option).
RFC 4861, sections 4.3 and 4.4. */
struct icmpv6_msg_nd {
    unsigned int icmpv6_flags;
    in6_addr	icmpv6_target;
    unsigned char icmpv6_option_type;
    unsigned char icmpv6_option_length;
    unsigned char icmpv6_mac[6];
};

/*
* ICMPv6 message union
*/
union icmpv6_msg {
    struct icmpv6_msg_echo	   echo;	/* ICMPV6_ECHO{REPLY} */
    struct icmpv6_msg_nd	   nd;		/* ICMPV6_NEIGHBOR_{SOLICITATION,ADVERTISEMENT} */
};

#ifndef __GNUC__
# pragma pack()
#endif

#define icmpv6_pack_hdr(hdr, type, code) do {				\
	struct icmpv6_hdr *icmpv6_pack_p = (struct icmpv6_hdr *)(hdr);	\
	icmpv6_pack_p->icmpv6_type = type; icmpv6_pack_p->icmpv6_code = code;	\
} while (0)

#define icmpv6_pack_hdr_echo(hdr, type, code, id, seq, data, len) do {	\
	struct icmpv6_msg_echo *echo_pack_p = (struct icmpv6_msg_echo *)\
		((unsigned char *)(hdr) + ICMPV6_HDR_LEN);			\
	icmpv6_pack_hdr(hdr, type, code);				\
	echo_pack_p->icmpv6_id = htons(id);				\
	echo_pack_p->icmpv6_seq = htons(seq);				\
	memcpy(echo_pack_p->icmpv6_data, data, len);			\
} while (0)

#define icmpv6_pack_hdr_ns_mac(hdr, targetip, srcmac) do {		\
	struct icmpv6_msg_nd *nd_pack_p = (struct icmpv6_msg_nd *)	\
		((unsigned char *)(hdr) + ICMPV6_HDR_LEN);			\
	icmpv6_pack_hdr(hdr, ICMPV6_NEIGHBOR_SOLICITATION, 0);		\
	nd_pack_p->icmpv6_flags = 0;					\
	memcpy(&nd_pack_p->icmpv6_target, &(targetip), 16);	\
	nd_pack_p->icmpv6_option_type = 1;				\
	nd_pack_p->icmpv6_option_length = 1;				\
	memcpy(&nd_pack_p->icmpv6_mac, &(srcmac), 6);	\
} while (0)

class ICMPV6Helper : public RawSocketV6
{
public:
    /**
    *eth_ip: which eth you want to bind to send upnp multcast, empty for all eth
    */
    explicit ICMPV6Helper(const std::string &src_ip) : RawSocketV6(src_ip, IPPROTO_ICMPV6, 1000, 1000), is_dn_listern_start(false){}
    virtual ~ICMPV6Helper() 
    {
        if (nd_listen_thread) {
            nd_listen_thread->join();
        }
    }
    /**
    *get mac from ipv6 address
    *dst_mac(out): mac of the dst
    *len(in): dst_mac buf len
    *src_mac(in): src_mac
    *dst(in): ipv6 dst ip
    *time_out(in): timeout of this func
    */
    bool DoND(u_char *dst_mac, u_int len, const u_char *src_mac, const std::string &dst, time_t time_out = 3000);
    /**
    *ip: ip of device
    *mac: mac of device
    *return false to exit the listern
    */
    typedef bool(*NDListernCallback)(const in6_addr &ip, u_char *mac);
    /**
    *start to listern nd packet and get the result
    */
    bool StartNDListern(NDListernCallback callback);
    /**
    *stop listern nd packet
    */
    void StopNDListern();
    /**
    *check if the ip is same as the bind ip
    */
    bool IsBindIp(const in6_addr &addr);

private:
    bool is_dn_listern_start;
    std::shared_ptr<std::thread> nd_listen_thread;
};

#endif
