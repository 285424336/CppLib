
#include "PortList.h"

PortList::PortList()
{
}

PortList::~PortList()
{
}

void PortList::SetDefaultPortState(unsigned char protocol, int state)
{
    if (state >= PORT_HIGHEST_STATE) {
        return;
    }

    int proto = INPROTO2PORTLISTPROTO(protocol);
    default_port_state[proto].state = state;
    default_port_state[proto].proto = protocol;
}

void PortList::AddProtocalPorts(int protocol, std::vector<unsigned short> ports)
{
    for (auto it = ports.begin(); it != ports.end(); it++) {
        AddProtocalPort(protocol, *it);
    }
}

void PortList::AddProtocalPort(int protocol, unsigned short portno)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);
    if (port_map[proto].find(portno) != port_map[proto].end()) {
        return;
    }
    int index = port_map_rev[proto].size();
    Port p = default_port_state[proto];
    port_map[proto][portno] = index;
    p.portno = portno;
    port_map_rev[proto].emplace_back(p);
    state_counts_proto[proto][p.state]++;
}

void PortList::DelProtocalPort(unsigned short portno, unsigned char protocol)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);
    if (port_map[proto].find(portno) != port_map[proto].end()) {
        return;
    }
    Port &p = port_map_rev[proto][port_map[proto][portno]];
    state_counts_proto[proto][p.state]--;
    port_map_rev[proto].erase(port_map_rev[proto].begin() + port_map[proto][portno]);
    port_map[proto].erase(portno);
}

void PortList::SetPortState(unsigned short portno, unsigned char protocol, int state)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);

    if (state >= PORT_HIGHEST_STATE) {
        return;
    }

    if (port_map[proto].find(portno) != port_map[proto].end()) {
        AddProtocalPort(protocol, portno);
    }

    Port &p = port_map_rev[proto][port_map[proto][portno]];
    state_counts_proto[proto][p.state]--;
    state_counts_proto[proto][state]++;
    p.state = state;
    p.is_default_stat = false;
}

void PortList::ReSetPortState(unsigned short portno, unsigned char protocol)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);

    if (port_map[proto].find(portno) != port_map[proto].end()) {
        AddProtocalPort(protocol, portno);
        return;
    }
    Port &p = port_map_rev[proto][port_map[proto][portno]];
    state_counts_proto[proto][p.state]--;
    state_counts_proto[proto][default_port_state[proto].state]++;
    p.state = default_port_state[proto].state;
    p.is_default_stat = true;
}

int PortList::GetPortState(unsigned short portno, unsigned char protocol)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);
    if (port_map[proto].find(portno) != port_map[proto].end()) {
        return default_port_state[proto].state;
    }
    Port &p = port_map_rev[proto][port_map[proto][portno]];
    return p.state;
}

bool PortList::PortIsDefault(unsigned short portno, unsigned char protocol)
{
    int proto = INPROTO2PORTLISTPROTO(protocol);
    if (port_map[proto].find(portno) != port_map[proto].end()) {
        return true;
    }
    Port &p = port_map_rev[proto][port_map[proto][portno]];
    return p.is_default_stat;
}

bool PortList::NextPort(Port &next, const Port *cur, int allowed_protocol, int allowed_state)
{
    int proto;
    unsigned short mapped_pno;

    if (cur) {
        if (cur->proto != allowed_protocol && allowed_protocol != TCPANDUDP) {
            return false;
        }
        proto = INPROTO2PORTLISTPROTO(cur->proto);
        if (port_map[proto].find(cur->portno) == port_map[proto].end()) {
            return false;
        }
        mapped_pno = port_map[proto][cur->portno];
        mapped_pno++;
    }
    else {
        if (allowed_protocol == TCPANDUDP) {
            proto = INPROTO2PORTLISTPROTO(IPPROTO_TCP);
        }
        else {
            proto = INPROTO2PORTLISTPROTO(allowed_protocol);
        }
        mapped_pno = 0;
    }

    if ((size_t)mapped_pno < port_map_rev[proto].size()) {
        for (auto it = port_map_rev[proto].begin() + mapped_pno; it != port_map_rev[proto].end(); it++) {
            if (allowed_state == 0 || (*it).state == allowed_state) {
                next = *it;
                return true;
            }
        }
    }

    /* if all protocols, than after TCP search UDP*/
    if (!cur && allowed_protocol == TCPANDUDP) {
        return NextPort(next, NULL, IPPROTO_UDP, allowed_state);
    }

    if (cur && allowed_protocol == TCPANDUDP) {
        if (cur->proto == IPPROTO_TCP) {
            return NextPort(next, NULL, IPPROTO_UDP, allowed_state);
        }
    }

    return false;
}

std::vector<unsigned short> PortList::GetPorts(int allowed_protocol, int allowed_state)
{
    std::vector<unsigned short> r;
    Port port;
    if (NextPort(port, NULL, allowed_protocol, allowed_state)) {
        r.emplace_back(port.port());
        while (NextPort(port, &port, allowed_protocol, allowed_state))
        {
            r.emplace_back(port.port());
        }
    }
    return r;
}

int PortList::GetStateCounts(int protocol, int state) const
{
    return state_counts_proto[INPROTO2PORTLISTPROTO(protocol)][state];
}

int PortList::GetStateCounts(int state) const
{
    int sum = 0, proto;
    for (proto = 0; proto < PORTLIST_PROTO_MAX; proto++)
        sum += GetStateCounts(PORTLISTPROTO2INPROTO(proto), state);
    return(sum);
}

int PortList::GetPortsCounts(int protocol) const
{
    return port_map_rev[INPROTO2PORTLISTPROTO(protocol)].size();
}

int PortList::GetPortsCounts() const
{
    int sum = 0, proto;
    for (proto = 0; proto < PORTLIST_PROTO_MAX; proto++)
        sum += GetPortsCounts(PORTLISTPROTO2INPROTO(proto));
    return(sum);
}