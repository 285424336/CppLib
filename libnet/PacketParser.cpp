#include "PacketParser.h"
#include "EthernetHeader.h"
#include "ArpHeader.h"
#include "IPv4Header.h"
#include "ICMPv4Header.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include "RawData.h"

#define LINK_LAYER         2
#define NETWORK_LAYER      3
#define TRANSPORT_LAYER    4
#define APPLICATION_LAYER  5
#define EXTHEADERS_LAYER   6

PacketParser::PacketParser()
{

}

PacketParser::~PacketParser()
{

}

std::shared_ptr<NetBase> PacketParser::ParsePacketRaw(const unsigned char *pkt, size_t pktlen, bool eth_included)
{
    const unsigned char*curr_pkt = pkt; /* Pointer to current part of the packet   */
    size_t curr_pktlen = pktlen;        /* Remaining packet length                 */
    int next_layer = 0;                 /* Next header type to process             */
    int expected = 0;                   /* Next protocol expected, if not error    */
    std::shared_ptr<NetBase> curr;
    std::shared_ptr<NetBase> head;
    std::shared_ptr<NetBase> next_header;

    if (eth_included) {
        next_layer = LINK_LAYER;
        expected = HEADER_TYPE_ETHERNET;
    }
    else {
        next_layer = NETWORK_LAYER;
        expected = 0;
    }

    while (curr_pktlen > 0) {
        if (next_layer == LINK_LAYER) {
            if (expected == HEADER_TYPE_ETHERNET) {
                std::shared_ptr<EthernetHeader> eth_header = std::make_shared<EthernetHeader>();
                if (!eth_header) {
                    return head;
                }
                if (!eth_header->StorePacket(curr_pkt, curr_pktlen)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                /* Determine next header type */
                switch (eth_header->GetEtherType()) {
                case ETHTYPE_IPV4:
                    expected = HEADER_TYPE_IPv4;
                    next_layer = NETWORK_LAYER;
                    break;
                case ETHTYPE_ARP:
                    next_layer = LINK_LAYER;
                    expected = HEADER_TYPE_ARP;
                    break;
                default:
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    break;
                }
                next_header = eth_header;
            }
            else if (expected == HEADER_TYPE_ARP) {
                std::shared_ptr<ArpHeader> arp_header = std::make_shared<ArpHeader>();
                if (!arp_header) {
                    return head;
                }
                if (!arp_header->StorePacket(curr_pkt, curr_pktlen)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                next_header = arp_header;
            }
            else {
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                continue;
            }
        }
        else if (next_layer == NETWORK_LAYER) {
            std::shared_ptr<IPv4Header> ipv4_header = std::make_shared<IPv4Header>();
            if (!ipv4_header) {
                return head;
            }
            if (!ipv4_header->StorePacket(curr_pkt, curr_pktlen)) {
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                continue;
            }
            if (!ipv4_header->Validate()) {
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                continue;
            }
            /* Determine next header type */
            switch (ipv4_header->GetNextProto()) {
            case HEADER_TYPE_ICMPv4:
                next_layer = TRANSPORT_LAYER;
                expected = HEADER_TYPE_ICMPv4;
                break;
            case HEADER_TYPE_IPv4: /* IP in IP */
                next_layer = NETWORK_LAYER;
                expected = HEADER_TYPE_IPv4;
                break;
            case HEADER_TYPE_TCP:
                next_layer = TRANSPORT_LAYER;
                expected = HEADER_TYPE_TCP;
                break;
            case HEADER_TYPE_UDP:
                next_layer = TRANSPORT_LAYER;
                expected = HEADER_TYPE_UDP;
                break;
            default:
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                break;
            }
            next_header = ipv4_header;
        }
        else if (next_layer == TRANSPORT_LAYER) {
            if (expected == HEADER_TYPE_TCP) {
                std::shared_ptr<TCPHeader> tcp_header = std::make_shared<TCPHeader>();
                if (!tcp_header) {
                    return head;
                }
                if (!tcp_header->StorePacket(curr_pkt, curr_pktlen)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                if (!tcp_header->Validate()) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                next_header = tcp_header;
            }
            else if (expected == HEADER_TYPE_UDP) {
                std::shared_ptr<UDPHeader> udp_header = std::make_shared<UDPHeader>();
                if (!udp_header) {
                    return head;
                }
                if (!udp_header->StorePacket(curr_pkt, curr_pktlen)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                next_header = udp_header;
            }
            else if (expected == HEADER_TYPE_ICMPv4) {
                std::shared_ptr<ICMPv4Header> icmpv4_header = std::make_shared<ICMPv4Header>();
                if (!icmpv4_header) {
                    return head;
                }
                if (!icmpv4_header->StorePacket(curr_pkt, curr_pktlen)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                if (!icmpv4_header->Validate()) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    continue;
                }
                switch (icmpv4_header->GetType()) {
                case ICMP_UNREACH:
                case ICMP_TIMXCEED:
                case ICMP_PARAMPROB:
                case ICMP_SOURCEQUENCH:
                case ICMP_REDIRECT:
                    icmpv4_header->StorePacket(curr_pkt, ICMP_STD_HEADER_LEN);
                    next_layer = NETWORK_LAYER;
                    expected = HEADER_TYPE_IPv4;
                    break;
                default:
                    expected = HEADER_TYPE_RAW_DATA;
                    next_layer = APPLICATION_LAYER;
                    break;
                }
                next_header = icmpv4_header;
            }
            else {
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                continue;
            }
        }
        else { // next_layer==APPLICATION_LAYER
            /* If we get here it is possible that the packet is ARP but
            * we have no access to the original Ethernet header. We
            * determine if this header is ARP by checking its size
            * and checking for some common values. */

            std::shared_ptr<ArpHeader> arp_header = std::make_shared<ArpHeader>();
            if (!arp_header) {
                return head;
            }
            if (arp_header->StorePacket(curr_pkt, curr_pktlen) &&
                  (arp_header->GetHardwareType() == HDR_ETH10MB) &&
                  (arp_header->GetProtocolType() == 0x0800) &&
                  (arp_header->GetHwAddrLen() == ETH_ADDRESS_LEN) &&
                  (arp_header->GetProtoAddrLen() == IPv4_ADDRESS_LEN)) {
                    next_layer = APPLICATION_LAYER;
                    expected = HEADER_TYPE_RAW_DATA;
                    next_header = arp_header;
            }
            else {
                std::shared_ptr<RawData> raw_data = std::make_shared<RawData>();
                if (!raw_data) {
                    return head;
                }
                if (!raw_data->StorePacket(curr_pkt, curr_pktlen)) {
                    return head;
                }
                next_layer = APPLICATION_LAYER;
                expected = HEADER_TYPE_RAW_DATA;
                next_header = raw_data;
            }
        }
        if (curr) {
            curr->SetNext(next_header);
        }
        curr = next_header;
        if (!head) {
            head = curr;
        }
        curr_pkt += next_header->Len();
        curr_pktlen -= next_header->Len();
    }

    return head;
}

std::shared_ptr<NetBase> PacketParser::ParsePacketJson(const Json::Value &in)
{
    std::shared_ptr<NetBase> head;
    if (!in.isArray()) {
        return head;
    }

    std::shared_ptr<NetBase> r;
    for (Json::ArrayIndex i = 0; i < in.size(); i++) {
        if (!in[i].isMember(SERIA_NAME_PROTOCOL_ID) || !in[i][SERIA_NAME_PROTOCOL_ID].isInt()) {
            continue;
        }
        if (!in[i].isMember(SERIA_NAME_PROTOCOL_DATA) || !in[i][SERIA_NAME_PROTOCOL_DATA].isObject()) {
            continue;
        }
        int type = in[i][SERIA_NAME_PROTOCOL_ID].asInt();
        std::shared_ptr<NetBase> tmp;
        switch (type) {
        case HEADER_TYPE_ETHERNET:
        {
            tmp = NetBase::UnParse<EthernetHeader>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_ARP:
        {
            tmp = NetBase::UnParse<ArpHeader>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_IPv4:
        {
            tmp = NetBase::UnParse<IPv4Header>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_ICMPv4:
        {
            tmp = NetBase::UnParse<ICMPv4Header>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_UDP:
        {
            tmp = NetBase::UnParse<UDPHeader>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_TCP:
        {
            tmp = NetBase::UnParse<TCPHeader>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        case HEADER_TYPE_RAW_DATA:
        {
            tmp = NetBase::UnParse<RawData>(in[i][SERIA_NAME_PROTOCOL_DATA]);
            break;
        }
        default:
            break;
        }
        if (tmp) {
            if (r) {
                r->SetNext(tmp);
            }
            r = tmp;
        }
        if (!head) {
            head = r;
        }
    }

    return head;
}

std::shared_ptr<NetBase> PacketParser::ParsePacketString(const std::string &in)
{
    std::shared_ptr<NetBase> packet_chain;
    Json::Value root;
    Json::Reader reader;
    if (reader.parse(in, root)) {
        packet_chain = PacketParser::ParsePacketJson(root);
    }
    return packet_chain;
}

bool PacketParser::IsResponse(std::shared_ptr<NetBase> sent, std::shared_ptr<NetBase> rcvd)
{
    if (!sent || !rcvd) {
        return false;
    }

    /* If any of the packets is encapsulated in an Ethernet frame, strip the
    * link layer header before proceeding with the matching process. */
    if (sent->ProtocolId() == HEADER_TYPE_ETHERNET) {
        sent = sent->Next();
        if (!sent) {
            return false;
        }
    }

    if (rcvd->ProtocolId() == HEADER_TYPE_ETHERNET) {
        rcvd = rcvd->Next();
        if (!rcvd) {
            return false;
        }
    }

    /* Make sure both packets have the same network layer */
    if (rcvd->ProtocolId() != sent->ProtocolId()) {
        return false;
    }

    /* The packet could be ARP */
    if (rcvd->ProtocolId() == HEADER_TYPE_ARP) {
        ArpHeader *sent_arp = (ArpHeader *)sent.get();
        ArpHeader *rcvd_arp = (ArpHeader *)rcvd.get();
        switch (sent_arp->GetOpCode()) {
        case OP_ARP_REQUEST:
            if (rcvd_arp->GetOpCode() == OP_ARP_REPLY) {
                if ((sent_arp->GetTargetIP().s_addr == rcvd_arp->GetSenderIP().s_addr) &&
                    (sent_arp->GetSenderIP().s_addr == rcvd_arp->GetTargetIP().s_addr)) {
                    return true;
                }
            }
            return false;
            break;
            /* We only support ARP, not RARP or other weird stuff. Also, if
            * we didn't send a request, then we don't expect any response */
        case OP_RARP_REQUEST:
        case OP_DRARP_REQUEST:
        case OP_INARP_REQUEST:
        default:
            return false;
            break;

        }
        return false;
    }

    /* The packet is IPv4 */
    if (rcvd->ProtocolId() != HEADER_TYPE_IPv4)
    {
        return false;
    }

    /* Handle the network layer with a more specific class */
    IPv4Header *rcvd_ip = (IPv4Header *)rcvd.get();
    IPv4Header *sent_ip = (IPv4Header *)sent.get();

    /* Ensure the packet comes from the host we sent the probe to */
    in_addr rcv_src_addr = rcvd_ip->GetSourceAddress();
    in_addr send_dst_addr = sent_ip->GetDestinationAddress();
    if (memcmp(&rcv_src_addr, &send_dst_addr, 4) != 0) {
        return false;
    }

    /* Ensure the received packet is destined to us */
    in_addr rcv_dst_addr = rcvd_ip->GetDestinationAddress();
    in_addr send_src_addr = sent_ip->GetSourceAddress();
    if (memcmp(&rcv_dst_addr, &send_src_addr, 4) != 0) {
        return false;
    }

    std::shared_ptr<NetBase> send_layer;
    std::shared_ptr<NetBase> recv_layer;
    if (!recv_layer) {
        recv_layer = rcvd->ProtocalData(HEADER_TYPE_UDP);
    }
    if (!recv_layer) {
        recv_layer = rcvd->ProtocalData(HEADER_TYPE_TCP);
    }
    if (!recv_layer) {
        recv_layer = rcvd->ProtocalData(HEADER_TYPE_ICMPv4);
    }
    if (!send_layer) {
        send_layer = sent->ProtocalData(HEADER_TYPE_UDP);
    }
    if (!send_layer) {
        send_layer = sent->ProtocalData(HEADER_TYPE_TCP);
    }
    if (!send_layer) {
        send_layer = sent->ProtocalData(HEADER_TYPE_ICMPv4);
    }

    if (!send_layer || !recv_layer) {
        return false;
    }

    /* If we get here it means that both packets have a proper layer4 protocol
    * header. Now we have to check which type are they and see if a probe-response
    * relation can be established. */
    if (send_layer->ProtocolId() == HEADER_TYPE_ICMPv4) {

        /* Make sure received packet is ICMP (we only expect ICMP responses for
        * ICMP probes) */
        if (recv_layer->ProtocolId() != HEADER_TYPE_ICMPv4) {
            return false;
        }

        /* Check if the received ICMP is an error message. We don't care which kind
        * of error message it is. The only important thing is that error messages
        * contain a copy of the original datagram, and that's what we want to
        * match against the sent probe. */
        ICMPv4Header *icmpv4_rcvd_header = (ICMPv4Header *)recv_layer.get();
        if (icmpv4_rcvd_header->IsErrorMsg()) {
            std::shared_ptr<NetBase> iperror = recv_layer->Next();

            /* ICMP error message must contain the original datagram */
            if (!iperror) {
                return false;
            }

            /* The first header must be IP */
            if (iperror->ProtocolId() != HEADER_TYPE_IPv4) {
                return false;
            }

            IPv4Header *iperror_ptr = (IPv4Header *)iperror.get();
            /* Source and destination addresses must match the probe's */
            in_addr err_src_addr = iperror_ptr->GetSourceAddress();
            in_addr send_src_addr = sent_ip->GetSourceAddress();
            if (memcmp(&err_src_addr, &send_src_addr, 4) != 0) {
                return false;
            }
            in_addr err_dst_addr = iperror_ptr->GetDestinationAddress();
            in_addr send_dst_addr = sent_ip->GetDestinationAddress();
            if (memcmp(&err_dst_addr, &send_dst_addr, 4) != 0) {
                return false;
            }

            /* So far we've verified that the ICMP error contains an IP datagram that matches
            * what we sent. Now, let's find the upper layer ICMP header (skip extension
            * headers until we find ICMP) */
            std::shared_ptr<NetBase> recv_inner_icmpv4 = iperror->Next();
            while (recv_inner_icmpv4 != NULL) {
                if (recv_inner_icmpv4->ProtocolId() == HEADER_TYPE_ICMPv4) {
                    break;
                }
                recv_inner_icmpv4 = recv_inner_icmpv4->Next();
            }
            if (recv_inner_icmpv4 == NULL) {
                return false;
            }

            ICMPv4Header *sent_icmpv4_ptr = (ICMPv4Header *)send_layer.get();
            ICMPv4Header *recv_inner_icmpv4_ptr = (ICMPv4Header *)recv_inner_icmpv4.get();
            /* Make sure ICMP type and code match  */
            if (sent_icmpv4_ptr->GetType() != recv_inner_icmpv4_ptr->GetType()) {
                return false;
            }
            if (sent_icmpv4_ptr->GetCode() != recv_inner_icmpv4_ptr->GetCode()) {
                return false;
            }
            switch (sent_icmpv4_ptr->GetType()) {
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TSTAMP:
            case ICMP_TSTAMPREPLY:
            case ICMP_INFO:
            case ICMP_INFOREPLY:
            case ICMP_MASK:
            case ICMP_MASKREPLY:
            case ICMP_DOMAINNAME:
            case ICMP_DOMAINNAMEREPLY:
                /* Check the message identifier and sequence number */
                if (sent_icmpv4_ptr->GetIdentifier() != recv_inner_icmpv4_ptr->GetIdentifier()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetSequence() != recv_inner_icmpv4_ptr->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_ROUTERADVERT:
                /* Check only the main fields, no need to parse the whole list
                * of addresses (maybe we didn't even get enough octets to
                * check that). */
                if (sent_icmpv4_ptr->GetNumAddresses() != recv_inner_icmpv4_ptr->GetNumAddresses()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetAddrEntrySize() != recv_inner_icmpv4_ptr->GetAddrEntrySize()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetLifetime() != recv_inner_icmpv4_ptr->GetLifetime()) {
                    return false;
                }
                break;

            case ICMP_ROUTERSOLICIT:
                /* Here we do not have much to compare, so we just test that
                * the reserved field contains the same value, usually zero. */
                if (sent_icmpv4_ptr->GetReserved() != recv_inner_icmpv4_ptr->GetReserved()) {
                    return false;
                }
                break;

            case ICMP_UNREACH:
            case ICMP_SOURCEQUENCH:
            case ICMP_TIMXCEED:
                /* For these we cannot guarantee that the received ICMP error
                * packet included data beyond the inner ICMP header, so we just
                * assume that they are a match to the sent probe. (We shouldn't
                * really be sending ICMP error messages and expect ICMP error
                * responses that contain our ICMP error messages, should we?
                * Well, even if we do, there is a good chance we are able to match
                * those responses with the original probe) */
                break;

            case ICMP_REDIRECT:
                if (sent_icmpv4_ptr->GetGatewayAddress().s_addr != recv_inner_icmpv4_ptr->GetGatewayAddress().s_addr) {
                    return false;
                }
                break;

            case ICMP_PARAMPROB:
                if (sent_icmpv4_ptr->GetParameterPointer() != recv_inner_icmpv4_ptr->GetParameterPointer()) {
                    return false;
                }
                break;

            case ICMP_TRACEROUTE:
                if (sent_icmpv4_ptr->GetIDNumber() != recv_inner_icmpv4_ptr->GetIDNumber()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetOutboundHopCount() != recv_inner_icmpv4_ptr->GetOutboundHopCount()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetOutputLinkSpeed() != recv_inner_icmpv4_ptr->GetOutputLinkSpeed()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetOutputLinkMTU() != recv_inner_icmpv4_ptr->GetOutputLinkMTU()) {
                    return false;
                }
                break;

            case ICMP_SECURITYFAILURES:
                /* Check the pointer and the reserved field */
                if (sent_icmpv4_ptr->GetSecurityPointer() != recv_inner_icmpv4_ptr->GetSecurityPointer()) {
                    return false;
                }
                if (sent_icmpv4_ptr->GetReserved() != recv_inner_icmpv4_ptr->GetReserved()) {
                    return false;
                }
                break;

            default:
                /* Do not match ICMP types we don't know about */
                return false;
                break;
            }
        }
        else { /* Received ICMP is informational. */

               /* If we get here it means that we received an informational ICMPv6
               * message. So now we have to check if the received message is the
               * expected reply to the probe we sent (like an Echo reply for an Echo
               * request, etc). */
            ICMPv4Header *sent_icmp4 = (ICMPv4Header *)send_layer.get();
            ICMPv4Header *rcvd_icmp4 = (ICMPv4Header *)recv_layer.get();

            switch (sent_icmp4->GetType()) {

            case ICMP_ECHOREPLY:
                /* We don't expect replies to Echo replies. */
                return false;
                break;

            case ICMP_UNREACH:
            case ICMP_SOURCEQUENCH:
            case ICMP_REDIRECT:
            case ICMP_TIMXCEED:
            case ICMP_PARAMPROB:
                /* Nodes are not supposed to respond to error messages, so
                * we don't expect any replies. */
                return false;
                break;

            case ICMP_ECHO:
                /* For Echo request, we expect echo replies  */
                if (rcvd_icmp4->GetType() != ICMP_ECHOREPLY) {
                    return false;
                }
                /* And we expect the ID and sequence number of the reply to
                * match the ID and seq of the request. */
                if (sent_icmp4->GetIdentifier() != rcvd_icmp4->GetIdentifier()) {
                    return false;
                }
                if (sent_icmp4->GetSequence() != rcvd_icmp4->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_ROUTERSOLICIT:
                /* For ICMPv4 router solicitations, we expect router advertisements.
                * We don't validate anything else because in IPv4 any advert that
                * comes from the host we sent the solicitation to can be
                * considered a response. */
                if (rcvd_icmp4->GetType() != ICMP_ROUTERADVERT) {
                    return false;
                }
                break;

            case ICMP_ROUTERADVERT:
                /* We don't expect responses to advertisements */
                return false;
                break;

            case ICMP_TSTAMP:
                /* For Timestampt requests, we expect timestamp replies  */
                if (rcvd_icmp4->GetType() != ICMP_TSTAMPREPLY) {
                    return false;
                }
                /* And we expect the ID and sequence number of the reply to
                * match the ID and seq of the request. */
                if (sent_icmp4->GetIdentifier() != rcvd_icmp4->GetIdentifier()) {
                    return false;
                }
                if (sent_icmp4->GetSequence() != rcvd_icmp4->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_TSTAMPREPLY:
                /* We do not expect responses to timestamp replies */
                return false;
                break;

            case ICMP_INFO:
                /* For Information requests, we expect Information replies  */
                if (rcvd_icmp4->GetType() != ICMP_INFOREPLY) {
                    return false;
                }
                /* And we expect the ID and sequence number of the reply to
                * match the ID and seq of the request. */
                if (sent_icmp4->GetIdentifier() != rcvd_icmp4->GetIdentifier()) {
                    return false;
                }
                if (sent_icmp4->GetSequence() != rcvd_icmp4->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_INFOREPLY:
                /* We do not expect responses to Information replies */
                return false;
                break;

            case ICMP_MASK:
                /* For Netmask requests, we expect Netmask replies  */
                if (rcvd_icmp4->GetType() != ICMP_MASKREPLY) {
                    return false;
                }
                /* And we expect the ID and sequence number of the reply to
                * match the ID and seq of the request. */
                if (sent_icmp4->GetIdentifier() != rcvd_icmp4->GetIdentifier()) {
                    return false;
                }
                if (sent_icmp4->GetSequence() != rcvd_icmp4->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_MASKREPLY:
                /* We do not expect responses to netmask replies */
                return false;
                break;

            case ICMP_TRACEROUTE:
                /* We don't expect replies to a traceroute message as it is
                * sent as a response to an IP datagram that contains the
                * IP traceroute option. Also, note that this function does
                * not take this into account when processing IPv4 datagrams
                * so if we receive an ICMP_TRACEROUTE we'll not be able
                * to match it with the original IP datagram. */
                return false;
                break;

            case ICMP_DOMAINNAME:
                /* For Domain Name requests, we expect Domain Name replies  */
                if (rcvd_icmp4->GetType() != ICMP_DOMAINNAMEREPLY) {
                    return false;
                }
                /* And we expect the ID and sequence number of the reply to
                * match the ID and seq of the request. */
                if (sent_icmp4->GetIdentifier() != rcvd_icmp4->GetIdentifier()) {
                    return false;
                }
                if (sent_icmp4->GetSequence() != rcvd_icmp4->GetSequence()) {
                    return false;
                }
                break;

            case ICMP_DOMAINNAMEREPLY:
                /* We do not expect replies to DN replies */
                return false;
                break;

            case ICMP_SECURITYFAILURES:
                /* Nodes are not expected to send replies to this message, as it
                * is an ICMP error. */
                return false;
                break;
            }
        }
    }
    else if (send_layer->ProtocolId() == HEADER_TYPE_TCP || send_layer->ProtocolId() == HEADER_TYPE_UDP) {

        /* Both are TCP or both UDP */
        if (send_layer->ProtocolId() == recv_layer->ProtocolId()) {

            TransportLayerHeader *send_trans_header = (TransportLayerHeader *)send_layer.get();
            TransportLayerHeader *recv_trans_header = (TransportLayerHeader *)recv_layer.get();
            /* Probe source port must equal response target port */
            if (send_trans_header->GetSourcePort() != recv_trans_header->GetDestinationPort()) {
                return false;
            }
            /* Probe target port must equal response source port */
            if (recv_trans_header->GetSourcePort() != send_trans_header->GetDestinationPort()) {
                return false;
            }

            /* If we sent TCP or UDP and got ICMP in response, we need to find a copy of our packet in the
            * ICMP payload, providing it is an ICMP error message. */
        }
        else if (recv_layer->ProtocolId() == HEADER_TYPE_ICMPv4) {

            ICMPv4Header *rcvd_icmp4 = (ICMPv4Header *)recv_layer.get();
            /* We only expect ICMP error messages */
            if (!rcvd_icmp4->IsErrorMsg()) {
                return false;
            }

            /* Let's validate the original header */
            std::shared_ptr<NetBase> iperror = recv_layer->Next();

            /* ICMP error message must contain the original datagram */
            if (!iperror) {
                return false;
            }

            /* The first header must be IP */
            if (iperror->ProtocolId() != HEADER_TYPE_IPv4) {
                return false;
            }

            IPv4Header *inner_ip_error = (IPv4Header *)iperror.get();
            /* Source and destination addresses must match the probe's (NATs are
            * supposed to rewrite them too, so this should be OK) */
            in_addr err_src_addr = inner_ip_error->GetSourceAddress();
            in_addr send_src_addr = sent_ip->GetSourceAddress();
            if (memcmp(&err_src_addr, &send_src_addr, 4) != 0) {
                return false;
            }
            in_addr err_dst_addr = inner_ip_error->GetDestinationAddress();
            in_addr send_dst_addr = sent_ip->GetDestinationAddress();
            if (memcmp(&err_dst_addr, &send_dst_addr, 4) != 0) {
                return false;
            }

            /* So far we've verified that the ICMP error contains an IP datagram that matches
            * what we sent. Now, let's find the upper layer protocol (skip extension
            * headers and the like until we find some transport protocol). */
            std::shared_ptr<NetBase> inner_trans_error = iperror->Next();
            while (inner_trans_error != NULL) {
                if (inner_trans_error->ProtocolId() == HEADER_TYPE_UDP || inner_trans_error->ProtocolId() == HEADER_TYPE_TCP) {
                    break;
                }
                inner_trans_error = inner_trans_error->Next();
            }
            if (!inner_trans_error) {
                return false;
            }

            TransportLayerHeader *inner_trans_error_ptr = (TransportLayerHeader *)inner_trans_error.get();
            TransportLayerHeader *send_trans_header = (TransportLayerHeader *)send_layer.get();
            /* Now make sure we see the same port numbers */
            if (inner_trans_error_ptr->GetSourcePort() != send_trans_header->GetSourcePort()) {
                return false;
            }
            if (inner_trans_error_ptr->GetDestinationPort() != send_trans_header->GetDestinationPort()) {
                return false;
            }
        }
        else {
            return false;
        }
    }
    else {
        /* We sent a layer 4 other than ICMP, ICMPv6, TCP, or UDP. We return false
        * as we cannot match responses for protocols we don't understand */
        return false;
    }

    return true;
}