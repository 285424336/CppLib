#ifndef PACKET_PARSE_H_INCLUDED
#define PACKET_PARSE_H_INCLUDED

#include "NetBase.h"

class PacketParser
{
public:
    /**
    *unparse the packet which is raw data
    *pkt(in): raw packet data
    *pktlen(in): packet data
    *eth_included(in): if data include eth data
    *return the head of the packet chain
    */
    static std::shared_ptr<NetBase> ParsePacketRaw(const unsigned char *pkt, size_t pktlen, bool eth_included = false);
    /**
    *unparse the packet which is show in json, it must be an json array
    *in(in): packet json data
    *return the head of the packet chain
    */
    static std::shared_ptr<NetBase> ParsePacketJson(const Json::Value &in);
    /**
    *unparse the packet which is show in json string, the json string must be an json array, mostly generate by NetBase::Repr
    *in(in): packet json data string
    *return the head of the packet chain
    */
    static std::shared_ptr<NetBase> ParsePacketString(const std::string &in);
    /**
    *check if the recv data is a responce of a sent data
    *sent(in): sent data
    *rcvd(in): recv data
    *return true if it is a responce, the following is the condition of return true:
    *ARP REPLAY
    *ICMP RESPONCE OF TCP OR UDE OR ICMP
    *TCP RESPONCE
    *UDP RESPONCE
    */
    static bool IsResponse(std::shared_ptr<NetBase> sent, std::shared_ptr<NetBase> rcvd);

public:
    PacketParser();
    ~PacketParser();

};

#endif