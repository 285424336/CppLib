#include "UDPHeader.h"
#include "IPv4Header.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif

UDPHeader::UDPHeader() : TransportLayerHeader()
{
    this->Reset();
}

UDPHeader::~UDPHeader()
{

}

void UDPHeader::Reset()
{
    this->length = UDP_HEADER_LEN;
    this->SetSourcePort(UDP_DEFAULT_SPORT);
    this->SetDestinationPort(UDP_DEFAULT_DPORT);
    this->SetTotalLength();
    this->h.uh_sum = 0;
}

int UDPHeader::ProtocolId() const
{
    return HEADER_TYPE_UDP;
}

std::string UDPHeader::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool UDPHeader::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len<UDP_HEADER_LEN) {
        return false;
    }

    this->length = UDP_HEADER_LEN;
    memcpy(&(this->h), buf, UDP_HEADER_LEN);
    return true;
}

void UDPHeader::SetSourcePort(unsigned short p)
{
    this->h.uh_sport = htons(p);
}

unsigned short UDPHeader::GetSourcePort() const
{
    return htons(this->h.uh_sport);
}

void UDPHeader::SetDestinationPort(unsigned short p)
{
    this->h.uh_dport = htons(p);
}

unsigned short UDPHeader::GetDestinationPort() const
{
    return htons(this->h.uh_dport);
}

void UDPHeader::SetTotalLength()
{
    this->h.uh_ulen = htons((unsigned short)this->AllLen());
}

void UDPHeader::SetTotalLength(unsigned short l)
{
    this->h.uh_ulen = htons(l);
}

unsigned short UDPHeader::GetTotalLength() const
{
    return htons(this->h.uh_ulen);
}

void UDPHeader::SetSum()
{
    std::shared_ptr<NetBase> ip_header = this->ProtocalData(HEADER_TYPE_IPv4);
    if (!ip_header) {
        return;
    }
    IPv4Header *header = (IPv4Header *)ip_header.get();
    this->h.uh_sum = 0;
    std::string all_data = this->AllData();
    this->h.uh_sum = NetworkHelper::ComputerTcpOUdpSum(header->GetSourceAddress(), header->GetDestinationAddress(), false, all_data.c_str(), (unsigned short)all_data.size());
}

void UDPHeader::SetSum(unsigned short s)
{
    this->h.uh_sum = s;
}

unsigned short UDPHeader::GetSum() const
{
    return this->h.uh_sum;
}

Json::Value UDPHeader::Serialize() const
{
    Json::Value root;

    root[UDP_SERIA_NAME_SRC_PORT] = (int)this->GetSourcePort();
    root[UDP_SERIA_NAME_DST_PORT] = (int)this->GetDestinationPort();
    root[UDP_SERIA_NAME_TOTAL_LEN] = (int)this->GetTotalLength();
    unsigned short sum = this->GetSum();
    root[UDP_SERIA_NAME_CHECK_SUM] = "0x" + StringHelper::byte2basestr((const unsigned char *)&sum, sizeof(sum), "", StringHelper::hex, 2);
    return root;
}

bool UDPHeader::UnSerialize(const Json::Value &in)
{
    if (in.isMember(UDP_SERIA_NAME_SRC_PORT) && in[UDP_SERIA_NAME_SRC_PORT].isInt()) {
        this->SetSourcePort(in[UDP_SERIA_NAME_SRC_PORT].asInt());
    }

    if (in.isMember(UDP_SERIA_NAME_DST_PORT) && in[UDP_SERIA_NAME_DST_PORT].isInt()) {
        this->SetDestinationPort(in[UDP_SERIA_NAME_DST_PORT].asInt());
    }

    if (in.isMember(UDP_SERIA_NAME_TOTAL_LEN) && in[UDP_SERIA_NAME_TOTAL_LEN].isInt()) {
        this->SetTotalLength(in[UDP_SERIA_NAME_TOTAL_LEN].asInt());
    }

    if (in.isMember(UDP_SERIA_NAME_CHECK_SUM) && in[UDP_SERIA_NAME_CHECK_SUM].isString()) {
        unsigned short sum = 0;
        std::string data = in[UDP_SERIA_NAME_CHECK_SUM].asString();
        const std::string *hexdata = &data;
        std::string tmpdata;
        if ((data.find("0x") != std::string::npos) || (data.find("0X") != std::string::npos)) {
            tmpdata = std::string(data, 2);
            hexdata = &tmpdata;
        }
        if (StringHelper::hex2byte(*hexdata, (char *)&sum, sizeof(sum))) {
            this->SetSum(sum);
        }
    }

    return true;
}