#ifndef PORT_LIST__H_INCLUDED
#define PORT_LIST__H_INCLUDED

#if defined(_MSC_VER)
#include <libnet\NetBase.h>
#elif defined(__GNUC__)
#include <libnet/NetBase.h>
#else
#error unsupported compiler
#endif
#include <vector>

/* port states */
#define PORT_UNKNOWN 0
#define PORT_CLOSED 1
#define PORT_OPEN 2
#define PORT_FILTERED 3
#define PORT_TESTING 4
#define PORT_FRESH 5
#define PORT_UNFILTERED 6
#define PORT_OPENFILTERED 7 /* Like udp/fin/xmas/null/ipproto scan with no response */
#define PORT_CLOSEDFILTERED 8 /* Idle scan */
#define PORT_HIGHEST_STATE 9 /* ***IMPORTANT -- BUMP THIS UP WHEN STATES ARE ADDED *** */

#define TCPANDUDP IPPROTO_MAX
#define TRANSPORT_MAX_NUM 65536

class Port 
{
    friend class PortList;
public:
    Port()
    {
        portno = 0;
        proto = 0;
        state = 0;
        is_default_stat = true;
    }

    unsigned short port()
    {
        return portno;
    }

private:
    unsigned short portno; //local byte
    unsigned char proto; //protocal
    unsigned char state;
    bool          is_default_stat;
};


/* Needed enums to address some arrays. This values
* should never be used directly. Use INPROTO2PORTLISTPROTO macro */
enum portlist_proto {	// PortList Protocols
    PORTLIST_PROTO_TCP = 0,
    PORTLIST_PROTO_UDP = 1,
    PORTLIST_PROTO_MAX
};

#define INPROTO2PORTLISTPROTO(p)		\
  ((p)==IPPROTO_TCP ? PORTLIST_PROTO_TCP : PORTLIST_PROTO_UDP)

#define PORTLISTPROTO2INPROTO(p)		\
  ((p)==PORTLIST_PROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP )

class PortList 
{
public:
    PortList();
    ~PortList();
    /**
    *Set the protocal port default stat, when you call InitializePortMap, the default stat will be used
    */
    void SetDefaultPortState(unsigned char protocol, int state);
    /* add ports that will be scanned for each protocol. */
    void AddProtocalPorts(int protocol, std::vector<unsigned short> ports);
    /* add port that will be scanned for each protocol. */
    void AddProtocalPort(int protocol, unsigned short portno);
    /* del port */
    void DelProtocalPort(unsigned short portno, unsigned char protocol);
    /* set port stat */
    void SetPortState(unsigned short portno, unsigned char protocol, int state);
    /* reset port to default stat */
    void ReSetPortState(unsigned short portno, unsigned char protocol);
    /* get the port default stat */
    int GetPortState(unsigned short portno, unsigned char protocol);
    /* if port in default stat */
    bool PortIsDefault(unsigned short portno, unsigned char protocol);
    /** 
    *A function for iterating through the ports 
    *next(out): next port
    *cur(in): if is null, will find from begin, otherwise find from this port
    *allowed_protocol(in): IPPROTO_TCP or IPPROTO_UDP or TCPANDUDP
    *allowed_state(in): port stat, 0 for all stat
    *return true for success
    */
    bool NextPort(Port &next, const Port *cur, int allowed_protocol, int allowed_state);
    /**
    *get all the port specify
    *allowed_protocol(in): IPPROTO_TCP or IPPROTO_UDP or TCPANDUDP
    *allowed_state(in): port stat, 0 for all stat
    *return all ports satisfy
    */
    std::vector<unsigned short> GetPorts(int allowed_protocol, int allowed_state);
    /* Get number of ports in this state. This a sum for protocols. */
    int GetStateCounts(int state) const;
    /* Get number of ports in this state for requested protocol. */
    int GetStateCounts(int protocol, int state) const;
    /* Get number of ports in protocol. */
    int GetPortsCounts(int protocol) const;
    /* Get number of ports. */
    int GetPortsCounts() const;

private:
    /*port map, first is port no, second is the index of port_map_rev*/
    std::map<unsigned short, unsigned short> port_map[PORTLIST_PROTO_MAX];
    /*store ports*/
    std::vector<Port> port_map_rev[PORTLIST_PROTO_MAX];
    /* Number of ports in each state per each protocol. */
    int state_counts_proto[PORTLIST_PROTO_MAX][PORT_HIGHEST_STATE];
    /*store port default stat*/
    Port default_port_state[PORTLIST_PROTO_MAX];
};

#endif
