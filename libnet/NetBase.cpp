
#include "NetBase.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#else
#error unsupported compiler
#endif

static std::pair<int, std::string> id_name_list[] = {
    { HEADER_TYPE_IPv6_HOPOPT,HEADER_NAME_IPv6_HOPOPT },
    { HEADER_TYPE_ICMPv4,HEADER_NAME_ICMPv4 },
    { HEADER_TYPE_IGMP,HEADER_NAME_IGMP },
    { HEADER_TYPE_IPv4,HEADER_NAME_IPv4 },
    { HEADER_TYPE_TCP,HEADER_NAME_TCP },
    { HEADER_TYPE_EGP,HEADER_NAME_EGP },
    { HEADER_TYPE_UDP,HEADER_NAME_UDP },
    { HEADER_TYPE_IPv6,HEADER_NAME_IPv6 },
    { HEADER_TYPE_IPv6_ROUTE,HEADER_NAME_IPv6_ROUTE },
    { HEADER_TYPE_IPv6_FRAG,HEADER_NAME_IPv6_FRAG },
    { HEADER_TYPE_GRE,HEADER_NAME_GRE },
    { HEADER_TYPE_ESP,HEADER_NAME_ESP },
    { HEADER_TYPE_AH,HEADER_NAME_AH },
    { HEADER_TYPE_ICMPv6,HEADER_NAME_ICMPv6 },
    { HEADER_TYPE_IPv6_NONXT,HEADER_NAME_IPv6_NONXT },
    { HEADER_TYPE_IPv6_OPTS,HEADER_NAME_IPv6_OPTS },
    { HEADER_TYPE_EIGRP,HEADER_NAME_EIGRP },
    { HEADER_TYPE_ETHERNET,HEADER_NAME_ETHERNET },
    { HEADER_TYPE_L2TP,HEADER_NAME_L2TP },
    { HEADER_TYPE_SCTP,HEADER_NAME_SCTP },
    { HEADER_TYPE_IPv6_MOBILE,HEADER_NAME_IPv6_MOBILE },
    { HEADER_TYPE_MPLS_IN_IP,HEADER_NAME_MPLS_IN_IP },
    { HEADER_TYPE_ARP,HEADER_NAME_ARP },
    { HEADER_TYPE_ICMPv6_OPTION,HEADER_NAME_ICMPv6_OPTION },
    { HEADER_TYPE_NEP,HEADER_NAME_NEP },
    { HEADER_TYPE_RAW_DATA,HEADER_NAME_RAW_DATA },
};

std::map<int, std::string> NetBase::protocal_id_name_map;
std::map<std::string, int> NetBase::protocal_name_id_map;
bool NetBase::init = NetBase::InitStatic();

bool NetBase::InitStatic()
{
    for (auto pair : id_name_list) {
        protocal_id_name_map[pair.first] = pair.second;
        protocal_name_id_map[pair.second] = pair.first;
    }
    return true;
}

NetBase::NetBase() : length(0), next(NULL), prev()
{

}

NetBase::~NetBase()
{

}

size_t NetBase::Len() const
{
    return this->length;
}

std::string NetBase::AllData() const
{
    std::string ourbuf = this->Data();
    if (this->next) {
        ourbuf += this->next->AllData();
    }
    return ourbuf;
}

size_t NetBase::AllLen() const
{
    if (this->next) {
        return this->length + this->next->AllLen();
    }
    return this->length;
}

bool NetBase::Validate() const
{
    return true;
}

bool NetBase::PacketValidate()
{
    std::shared_ptr<NetBase> cur = this->Head();
    while (cur)
    {
        if (!cur->Validate())
        {
            return false;
        }
        cur = cur->Next();
    }
    return true;
}

std::shared_ptr<NetBase> NetBase::Next() const
{
    return this->next;
}

std::shared_ptr<NetBase> NetBase::Prev() const
{
    if (this->prev.expired()) {
        return NULL;
    }
    return std::shared_ptr<NetBase>(this->prev);
}

std::shared_ptr<NetBase> NetBase::Head()
{
    std::shared_ptr<NetBase> head = shared_from_this();
    while (!head->prev.expired()) {
        head = std::shared_ptr<NetBase>(head->prev);
    }
    return head;
}

std::shared_ptr<NetBase> NetBase::Tail()
{
    std::shared_ptr<NetBase> tail = shared_from_this();
    while (tail->next) {
        tail = tail->next;
    }
    return tail;
}

std::shared_ptr<NetBase> NetBase::SetNext(std::shared_ptr<NetBase> n)
{
    if (this->next) {
        this->next->prev.reset();
    }
    this->next = n;
    if (this->next) {
        next->SetPrev(shared_from_this());
    }
    return this->next;
}

std::shared_ptr<NetBase>  NetBase::SetPrev(std::shared_ptr<NetBase> n)
{
    if (!this->prev.expired()) {
        std::shared_ptr<NetBase>(this->prev)->next = NULL;
    }
    this->prev = n;
    return std::shared_ptr<NetBase>(this->prev);
}

std::string NetBase::Repr() const
{
    Json::Value root(Json::arrayValue);
    Json::Value head;
    head[SERIA_NAME_PROTOCOL_ID] = ProtocolId();
    head[SERIA_NAME_PROTOCOL_NAME] = protocal_id_name_map[ProtocolId()];
    head[SERIA_NAME_PROTOCOL_DATA] = Serialize();
    root.append(head);
    std::shared_ptr<NetBase> p = Next();
    while (p) {
        Json::Value tmp;
        tmp[SERIA_NAME_PROTOCOL_ID] = p->ProtocolId();
        tmp[SERIA_NAME_PROTOCOL_NAME] = protocal_id_name_map[p->ProtocolId()];
        tmp[SERIA_NAME_PROTOCOL_DATA] = p->Serialize();
        root.append(tmp);
        p = p->Next();
    }
    return root.toStyledString();
}

std::shared_ptr<NetBase> NetBase::ProtocalData(int protocal_id)
{
    std::shared_ptr<NetBase> r;
    std::shared_ptr<NetBase> p = this->Head();
    while (p) {
        if (p->ProtocolId() == protocal_id) {
            r = p;
            break;
        }
        p = p->Next();
    }
    return r;
}

std::shared_ptr<NetBase> NetBase::ProtocalDataBehind(int protocal_id)
{
    std::shared_ptr<NetBase> r;
    std::shared_ptr<NetBase> p = shared_from_this();
    while (p) {
        if (p->ProtocolId() == protocal_id) {
            r = p;
            break;
        }
        p = p->Next();
    }
    return r;
}