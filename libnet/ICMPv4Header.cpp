
#include "ICMPv4Header.h"
#include <algorithm>
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <algorithm/AlgorithmHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif

#ifdef min
#undef min
#endif // min
#ifdef max
#undef max
#endif // min

ICMPv4Header::ICMPv4Header() : NetBase()
{
    this->Reset();
}

ICMPv4Header::~ICMPv4Header()
{

}

void ICMPv4Header::Reset()
{
    memset(&this->h, 0, sizeof(icmpv4_hdr_t));
    h_du = (icmp4_dest_unreach_msg_t        *)this->h.data;
    h_te = (icmp4_time_exceeded_msg_t       *)this->h.data;
    h_pp = (icmp4_parameter_problem_msg_t   *)this->h.data;
    h_sq = (icmp4_source_quench_msg_t       *)this->h.data;
    h_r = (icmp4_redirect_msg_t            *)this->h.data;
    h_e = (icmp4_echo_msg_t                *)this->h.data;
    h_t = (icmp4_timestamp_msg_t           *)this->h.data;
    h_i = (icmp4_information_msg_t         *)this->h.data;
    h_ra = (icmp4_router_advert_msg_t       *)this->h.data;
    h_rs = (icmp4_router_solicit_msg_t      *)this->h.data;
    h_sf = (icmp4_security_failures_msg_t   *)this->h.data;
    h_am = (icmp4_address_mask_msg_t        *)this->h.data;
    h_trc = (icmp4_traceroute_msg_t          *)this->h.data;
    h_dn = (icmp4_domain_name_request_msg_t *)this->h.data;
    h_dnr = (icmp4_domain_name_reply_msg_t   *)this->h.data;
    this->routeradventries = 0;
}

int ICMPv4Header::ProtocolId() const
{
    return HEADER_TYPE_ICMPv4;
}

std::string ICMPv4Header::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool ICMPv4Header::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len < ICMP_STD_HEADER_LEN) {
        return false;
    }
    int stored_len = std::min((int)(ICMP_MAX_PAYLOAD_LEN + 4), (int)len);
    this->length = stored_len;
    memcpy(&(this->h), buf, stored_len);
    this->routeradventries = 0;
    if (GetType() == ICMP_ROUTERADVERT) {
        this->routeradventries = this->GetNumAddresses();
    }
    return true;
}

bool ICMPv4Header::Validate() const
{
    size_t min_head_length = this->GetICMPMinHeaderLengthFromType(this->GetType());
    if (this->length < min_head_length) {
        return false;
    }
    if (!this->ValidateType()) {
        return false;
    }
    if (!this->ValidateCode()) {
        return false;
    }
    return true;
}

void ICMPv4Header::SetType(unsigned char val)
{
    this->h.type = val;
    this->length = this->GetICMPMinHeaderLengthFromType(val);
}

unsigned char ICMPv4Header::GetType() const
{
    return this->h.type;
}

bool ICMPv4Header::ValidateType() const
{
    return this->ValidateType(this->h.type);
}

bool ICMPv4Header::ValidateType(unsigned char val) const
{
    switch (val) {
    case ICMP_ECHOREPLY:
    case ICMP_UNREACH:
    case ICMP_SOURCEQUENCH:
    case ICMP_REDIRECT:
    case ICMP_ECHO:
    case ICMP_ROUTERADVERT:
    case ICMP_ROUTERSOLICIT:
    case ICMP_TIMXCEED:
    case ICMP_PARAMPROB:
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
    case ICMP_INFO:
    case ICMP_INFOREPLY:
    case ICMP_MASK:
    case ICMP_MASKREPLY:
    case ICMP_TRACEROUTE:
    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
        return true;
        break;

    default:
        return false;
        break;
    }
    return false;
}

void ICMPv4Header::SetCode(unsigned char c)
{
    this->h.code = c;
}

unsigned char ICMPv4Header::GetCode() const
{
    return this->h.code;
}

bool ICMPv4Header::ValidateCode() const
{
    return this->ValidateCode(this->h.type, this->h.code);
}

bool ICMPv4Header::ValidateCode(unsigned char type, unsigned char code) const
{
    switch (type) {
    case ICMP_ECHOREPLY:
        return true;
        break;

    case ICMP_UNREACH:
        switch (code) {
        case ICMP_UNREACH_NET:
        case ICMP_UNREACH_HOST:
        case ICMP_UNREACH_PROTOCOL:
        case ICMP_UNREACH_PORT:
        case ICMP_UNREACH_NEEDFRAG:
        case ICMP_UNREACH_SRCFAIL:
        case ICMP_UNREACH_NET_UNKNOWN:
        case ICMP_UNREACH_HOST_UNKNOWN:
        case ICMP_UNREACH_ISOLATED:
        case ICMP_UNREACH_NET_PROHIB:
        case ICMP_UNREACH_HOST_PROHIB:
        case ICMP_UNREACH_TOSNET:
        case ICMP_UNREACH_TOSHOST:
        case ICMP_UNREACH_COMM_PROHIB:
        case ICMP_UNREACH_HOSTPRECEDENCE:
        case ICMP_UNREACH_PRECCUTOFF:
            return true;
        }
        break;

    case ICMP_REDIRECT:
        switch (code) {
        case ICMP_REDIRECT_NET:
        case ICMP_REDIRECT_HOST:
        case ICMP_REDIRECT_TOSNET:
        case ICMP_REDIRECT_TOSHOST:
            return true;
        }
        break;

    case ICMP_ROUTERADVERT:
        switch (code) {
        case 0:
        case ICMP_ROUTERADVERT_MOBILE:
            return true;
        }
        break;

    case ICMP_TIMXCEED:
        switch (code) {
        case ICMP_TIMXCEED_INTRANS:
        case ICMP_TIMXCEED_REASS:
            return true;
        }
        break;

    case ICMP_PARAMPROB:
        switch (code) {
        case ICMM_PARAMPROB_POINTER:
        case ICMP_PARAMPROB_OPTABSENT:
        case ICMP_PARAMPROB_BADLEN:
            return true;
        }
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
    case ICMP_INFO:
    case ICMP_INFOREPLY:
    case ICMP_MASK:
    case ICMP_MASKREPLY:
    case ICMP_ROUTERSOLICIT:
    case ICMP_SOURCEQUENCH:
    case ICMP_ECHO:
        return true;
        break;

    case ICMP_TRACEROUTE:
        switch (code) {
        case ICMP_TRACEROUTE_SUCCESS:
        case ICMP_TRACEROUTE_DROPPED:
            return true;
        }
        break;

    default:
        return false;
        break;
    }
    return false;
}

void ICMPv4Header::SetSum()
{
    this->h.checksum = 0;
    std::string data = this->AllData();
    this->h.checksum = AlgorithmHelper::CheckSum((const unsigned char*)data.c_str(), data.size());
}

void ICMPv4Header::SetSum(unsigned short s)
{
    this->h.checksum = s;
}

unsigned short ICMPv4Header::GetSum() const
{
    return this->h.checksum;
}

void ICMPv4Header::SetRawData(size_t off_data, const unsigned char *buf, size_t len)
{
    if (off_data > ICMP_MAX_PAYLOAD_LEN) {
        return;
    }
    size_t store_len = std::min(ICMP_MAX_PAYLOAD_LEN - off_data, len);
    memcpy(this->h.data + off_data, buf, store_len);
    this->length = 4 + off_data + store_len;
}

void ICMPv4Header::SetRawData(size_t off_data, const std::string &data)
{
    unsigned char buf[ICMP_MAX_PAYLOAD_LEN];

    const std::string *hexdata = &data;
    std::string tmpdata;
    if ((data.find("0x") != std::string::npos) || (data.find("0X") != std::string::npos)) {
        tmpdata = std::string(data, 2);
        hexdata = &tmpdata;
    }
    if (!StringHelper::hex2byte(*hexdata, (char *)buf, sizeof(buf))) {
        return;
    }
    this->SetRawData(off_data, buf, hexdata->size() / 2);
}

bool ICMPv4Header::SetUnused(unsigned int val)
{
    return this->SetReserved(val);
}

unsigned int ICMPv4Header::GetUnused() const
{
    return this->GetReserved();
}

bool ICMPv4Header::SetReserved(unsigned int val)
{
    unsigned int aux32 = 0;
    unsigned char *auxpnt = (unsigned char *)&aux32;

    switch (this->h.type) {
    case ICMP_UNREACH:
        this->h_du->unused = htonl(val);
        break;
    case ICMP_TIMXCEED:
        this->h_te->unused = htonl(val);
        break;
    case ICMP_PARAMPROB:
        /* The reserved field in Parameter Problem messages is only
        * 24-bits long so we convert the supplied value to big endian and
        * use only the 24 least significant bits. */
        aux32 = htonl(val);
        this->h_pp->unused[0] = auxpnt[1];
        this->h_pp->unused[1] = auxpnt[2];
        this->h_pp->unused[2] = auxpnt[3];
        break;

    case ICMP_SOURCEQUENCH:
        this->h_sq->unused = htonl(val);
        break;

    case ICMP_ROUTERSOLICIT:
        this->h_rs->reserved = htonl(val);
        break;

    case ICMP_SECURITYFAILURES:
        /* The reserved field in Security failure messages is only
        * 16-bits long so we cast it to u16 first (callers are not supposed to
        * pass values higher than 2^16) */
        this->h_sf->reserved = htons((unsigned short)val);
        break;

    case ICMP_TRACEROUTE:
        /* The reserved field in Traceroute messages is only
        * 16-bits long so we cast it to u16 first (callers are not supposed to
        * pass values higher than 2^16) */
        this->h_trc->unused = htons((unsigned short)val);
        break;

    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetReserved() const
{
    unsigned int aux32 = 0;
    unsigned char *auxpnt = (unsigned char *)&aux32;

    switch (this->h.type) {

    case ICMP_UNREACH:
        return ntohl(this->h_du->unused);
        break;

    case ICMP_TIMXCEED:
        return ntohl(this->h_te->unused);
        break;

    case ICMP_PARAMPROB:
        /* The unused field in Parameter Problem messages is only
        * 24-bits long so we extract the stored value and convert it to host
        * byte order. */
        auxpnt[0] = 0;
        auxpnt[1] = this->h_pp->unused[0];
        auxpnt[2] = this->h_pp->unused[1];
        auxpnt[3] = this->h_pp->unused[2];
        return ntohl(aux32);
        break;

    case ICMP_SOURCEQUENCH:
        return ntohl(this->h_sq->unused);
        break;

    case ICMP_ROUTERSOLICIT:
        return ntohl(this->h_rs->reserved);
        break;

    case ICMP_SECURITYFAILURES:
        /* The unused field in Security Failures messages is only
        * 16-bits long so we extract the stored value and cast it to an u32 in
        * host byte order */
        return (unsigned int)ntohs(h_sf->reserved);
        break;

    case ICMP_TRACEROUTE:
        /* The reserved field in Traceroute messages is only
        * 16-bits long so we extract the stored value and cast it to an u32 in
        * host byte order */
        return (unsigned int)ntohs(h_trc->unused);
        break;

    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetGatewayAddress(struct in_addr ipaddr)
{
    if (ICMP_REDIRECT != this->GetType()) {
        return false;
    }
    this->h_r->gateway_address = ipaddr;
    return true;
}

struct in_addr ICMPv4Header::GetGatewayAddress() const
{
    if (ICMP_REDIRECT != this->GetType()) {
        return in_addr{ 0 };
    }
    return this->h_r->gateway_address;
}

bool ICMPv4Header::SetParameterPointer(unsigned char val)
{
    if (ICMP_PARAMPROB != this->GetType()) {
        return false;
    }
    this->h_pp->pointer = val;
    return true;
}

unsigned char ICMPv4Header::GetParameterPointer() const
{
    if (ICMP_PARAMPROB != this->GetType()) {
        return 0;
    }
    return this->h_pp->pointer;
}

bool ICMPv4Header::SetNumAddresses(unsigned char val)
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return false;
    }
    this->h_ra->num_addrs = val;
    return true;
}

unsigned char ICMPv4Header::GetNumAddresses() const
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return 0;
    }
    return this->h_ra->num_addrs;
}

bool ICMPv4Header::SetAddrEntrySize(unsigned char val)
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return false;
    }
    this->h_ra->addr_entry_size = val;
    return true;
}

unsigned char ICMPv4Header::GetAddrEntrySize() const
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return 0;
    }
    return this->h_ra->addr_entry_size;
}

bool ICMPv4Header::SetLifetime(unsigned short val)
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return false;
    }
    this->h_ra->lifetime = htons(val);
    return true;
}

unsigned short ICMPv4Header::GetLifetime() const
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return 0;
    }
    return this->h_ra->lifetime;
}

bool ICMPv4Header::AddRouterAdvEntry(struct in_addr raddr, unsigned int pref)
{
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return false;
    }
    if (this->routeradventries >= MAX_ROUTER_ADVERT_ENTRIES) {
        return false;
    }
    this->h_ra->adverts[this->routeradventries].router_addr = raddr;
    this->h_ra->adverts[this->routeradventries].preference_level = pref;
    this->routeradventries++; /* Update internal entry count */
    this->SetNumAddresses(this->routeradventries); /* Update number of addresses */
    this->length += 8;        /* Update total length of the ICMP packet */
    return true;
}

std::vector<icmp4_router_advert_entry_t> ICMPv4Header::GetRouterAdvEntries() const
{
    std::vector<icmp4_router_advert_entry_t> r;
    if (ICMP_ROUTERADVERT != this->GetType()) {
        return r;
    }
    size_t pos = 0;
    for (pos = 0; pos < this->h_ra->num_addrs; pos++)
    {
        r.emplace_back(icmp4_router_advert_entry_t{ this->h_ra->adverts[pos].router_addr,  this->h_ra->adverts[pos].preference_level });
    }
    return r;
}

bool ICMPv4Header::SetIdentifier(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        h_e->identifier = htons(val);
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        h_t->identifier = htons(val);
        break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        h_i->identifier = htons(val);
        break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        h_am->identifier = htons(val);
        break;

    case ICMP_DOMAINNAME:
        h_dn->identifier = htons(val);
        break;

    case ICMP_DOMAINNAMEREPLY:
        h_dnr->identifier = htons(val);
        break;

    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetIdentifier() const
{
    switch (this->h.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        return ntohs(h_e->identifier);
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return ntohs(h_t->identifier);
        break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        return ntohs(h_i->identifier);
        break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        return ntohs(h_am->identifier);
        break;

    case ICMP_DOMAINNAME:
        return ntohs(h_dn->identifier);
        break;

    case ICMP_DOMAINNAMEREPLY:
        return ntohs(h_dnr->identifier);
        break;

    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetSequence(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        h_e->sequence = htons(val);
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        h_t->sequence = htons(val);
        break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        h_i->sequence = htons(val);
        break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        h_am->sequence = htons(val);
        break;

    case ICMP_DOMAINNAME:
        h_dn->sequence = htons(val);
        break;

    case ICMP_DOMAINNAMEREPLY:
        h_dnr->sequence = htons(val);
        break;

    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetSequence() const
{
    switch (this->h.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        return ntohs(h_e->sequence);
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return ntohs(h_t->sequence);
        break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        return ntohs(h_i->sequence);
        break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        return ntohs(h_am->sequence);
        break;

    case ICMP_DOMAINNAME:
        return ntohs(h_dn->sequence);
        break;

    case ICMP_DOMAINNAMEREPLY:
        return ntohs(h_dnr->sequence);
        break;

    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetOriginateTimestamp(unsigned int t)
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        this->h_t->originate_ts = htonl(t);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetOriginateTimestamp() const
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return htonl(this->h_t->originate_ts);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetReceiveTimestamp(unsigned int t)
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        this->h_t->receive_ts = htonl(t);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetReceiveTimestamp() const
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return htonl(this->h_t->receive_ts);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetTransmitTimestamp(unsigned int t)
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        this->h_t->transmit_ts = htonl(t);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetTransmitTimestamp() const
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return htonl(this->h_t->transmit_ts);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetAddressMask(struct in_addr mask)
{
    switch (this->h.type) {
    case ICMP_MASK:
    case ICMP_MASKREPLY:
        this->h_am->address_mask = mask;
        break;
    default:
        return false;
        break;
    }
    return true;
}

struct in_addr ICMPv4Header::GetAddressMask() const
{
    switch (this->h.type) {
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return this->h_am->address_mask;
        break;
    default:
        return in_addr{ 0 };
        break;
    }
    return in_addr{ 0 };
}

bool ICMPv4Header::SetSecurityPointer(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_SECURITYFAILURES:
        this->h_sf->pointer = htons(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetSecurityPointer() const
{
    switch (this->h.type) {
    case ICMP_SECURITYFAILURES:
        return ntohs(this->h_sf->pointer);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetIDNumber(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        h_trc->id_number = htons(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetIDNumber() const
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        return htons(h_trc->id_number);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetOutboundHopCount(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        h_trc->outbound_hop_count = htons(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetOutboundHopCount() const
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        return htons(h_trc->outbound_hop_count);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetReturnHopCount(unsigned short val)
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        h_trc->return_hop_count = htons(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned short ICMPv4Header::GetReturnHopCount() const
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        return htons(h_trc->return_hop_count);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetOutputLinkSpeed(unsigned int val)
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        h_trc->output_link_speed = htonl(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetOutputLinkSpeed() const
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        return ntohl(h_trc->output_link_speed);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

bool ICMPv4Header::SetOutputLinkMTU(unsigned int val)
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        h_trc->output_link_mtu = htonl(val);
        break;
    default:
        return false;
        break;
    }
    return true;
}

unsigned int ICMPv4Header::GetOutputLinkMTU() const
{
    switch (this->h.type) {
    case ICMP_TRACEROUTE:
        return ntohl(h_trc->output_link_mtu);
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

size_t ICMPv4Header::GetICMPMinHeaderLengthFromType(unsigned char type) const
{
    switch (type) {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
        return 8; /* (+ optional data) */
        break;

    case ICMP_UNREACH:
        return 8; /* (+ payload) */
        break;

    case ICMP_SOURCEQUENCH:
        return 8; /* (+ payload) */
        break;

    case ICMP_REDIRECT:
        return 8; /* (+ payload) */
        break;

    case ICMP_ROUTERADVERT:
        return 8; /* (+ value of NumAddr field * 8 ) */
        break;

    case ICMP_ROUTERSOLICIT:
        return 8;
        break;

    case ICMP_TIMXCEED:
        return 8; /* (+ payload) */
        break;

    case ICMP_PARAMPROB:
        return 8; /* (+ payload) */
        break;

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        return 20;
        break;

    case ICMP_INFO:
    case ICMP_INFOREPLY:
        return 8;
        break;

    case ICMP_MASK:
    case ICMP_MASKREPLY:
        return 12;
        break;

    case ICMP_TRACEROUTE:
        return 20;
        break;

    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
        return 8;
        break;

        /* Packets with non RFC-Compliant types will be represented as
        an 8-byte ICMP header, just like the types that don't include
        additional info (time exceeded, router solicitation, etc)  */
    default:
        return 8;
        break;
    }
    return 8;
}

std::string ICMPv4Header::Type2String(int type, int code) const
{
    switch (type) {
    case ICMP_ECHOREPLY:
        return "Echo reply";
        break;

    case ICMP_UNREACH:
        switch (code) {
        case ICMP_UNREACH_NET: return "Network unreachable"; break;
        case ICMP_UNREACH_HOST: return "Host unreachable"; break;
        case ICMP_UNREACH_PROTOCOL: return "Protocol unreachable"; break;
        case ICMP_UNREACH_PORT: return "Port unreachable"; break;
        case ICMP_UNREACH_NEEDFRAG: return "Fragmentation required"; break;
        case ICMP_UNREACH_SRCFAIL: return "Source route failed"; break;
        case ICMP_UNREACH_NET_UNKNOWN: return "Destination network unknown"; break;
        case ICMP_UNREACH_HOST_UNKNOWN: return "Destination host unknown"; break;
        case ICMP_UNREACH_ISOLATED: return "Source host isolated"; break;
        case ICMP_UNREACH_NET_PROHIB: return "Network prohibited"; break;
        case ICMP_UNREACH_HOST_PROHIB: return "Host prohibited"; break;
        case ICMP_UNREACH_TOSNET: return "Network unreachable for TOS"; break;
        case ICMP_UNREACH_TOSHOST: return "Host unreachable for TOS"; break;
        case ICMP_UNREACH_COMM_PROHIB: return "Communication prohibited"; break;
        case ICMP_UNREACH_HOSTPRECEDENCE: return "Precedence violation"; break;
        case ICMP_UNREACH_PRECCUTOFF: return "Precedence cutoff"; break;
        default: return "Destination unreachable (unknown code)"; break;
        } /* End of ICMP Code switch */
        break;

    case ICMP_SOURCEQUENCH:
        return "Source quench";
        break;

    case ICMP_REDIRECT:
        switch (code) {
        case ICMP_REDIRECT_NET: return "Redirect for network"; break;
        case ICMP_REDIRECT_HOST: return "Redirect for host"; break;
        case ICMP_REDIRECT_TOSNET: return "Redirect for TOS and network"; break;
        case ICMP_REDIRECT_TOSHOST: return "Redirect for TOS and host"; break;
        default: return "Redirect (unknown code)"; break;
        }
        break;

    case ICMP_ECHO:
        return "Echo request";
        break;

    case ICMP_ROUTERADVERT:
        switch (code) {
        case ICMP_ROUTERADVERT_MOBILE: return "Router advertisement (Mobile Agent Only)"; break;
        default: return "Router advertisement"; break;
        }
        break;

    case ICMP_ROUTERSOLICIT:
        return "Router solicitation";
        break;

    case ICMP_TIMXCEED:
        switch (code) {
        case ICMP_TIMXCEED_INTRANS: return "TTL=0 during transit"; break;
        case ICMP_TIMXCEED_REASS: return "Reassembly time exceeded"; break;
        default: return "TTL exceeded (unknown code)"; break;
        }
        break;

    case ICMP_PARAMPROB:
        switch (code) {
        case ICMM_PARAMPROB_POINTER: return "Parameter problem (pointer indicates error)"; break;
        case ICMP_PARAMPROB_OPTABSENT: return "Parameter problem (option missing)"; break;
        case ICMP_PARAMPROB_BADLEN: return "Parameter problem (bad length)"; break;
        default: return "Parameter problem (unknown code)"; break;
        }
        break;

    case ICMP_TSTAMP:
        return "Timestamp request";
        break;

    case ICMP_TSTAMPREPLY:
        return "Timestamp reply";
        break;

    case ICMP_INFO:
        return "Information request";
        break;

    case ICMP_INFOREPLY:
        return "Information reply";
        break;

    case ICMP_MASK:
        return "Address mask request ";
        break;

    case ICMP_MASKREPLY:
        return "Address mask reply";
        break;

    case ICMP_TRACEROUTE:
        return "Traceroute";
        break;

    case ICMP_DOMAINNAME:
        return "Domain name request";
        break;

    case ICMP_DOMAINNAMEREPLY:
        return "Domain name reply";
        break;

    case ICMP_SECURITYFAILURES:
        return "Security failures";
        break;

    default:
        return "Unknown ICMP type";
        break;
    } /* End of ICMP Type switch */
    return "Unknown ICMP type";
}

bool ICMPv4Header::IsErrorMsg() const
{
    switch (this->GetType()) {
    case ICMP_UNREACH:
    case ICMP_TIMXCEED:
    case ICMP_PARAMPROB:
    case ICMP_SOURCEQUENCH:
    case ICMP_REDIRECT:
    case ICMP_SECURITYFAILURES:
        return true;
        break;
    default:
        return false;
        break;
    }
    return false;
}

Json::Value ICMPv4Header::Serialize() const
{
    Json::Value root;

    root[ICMPV4_SERIA_NAME_TYPE] = (int)this->GetType();
    root[ICMPV4_SERIA_NAME_CODE] = (int)this->GetCode();
    root[ICMPV4_SERIA_NAME_INFO] = this->Type2String(this->GetType(), this->GetCode());
    unsigned short sum = this->GetSum();
    root[ICMPV4_SERIA_NAME_CHECKSUM] = "0x" + StringHelper::byte2basestr((const unsigned char *)&sum, sizeof(sum), "", StringHelper::hex, 2);
    switch (this->GetType()) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_INFO:
    case ICMP_INFOREPLY:
    {
        root[ICMPV4_SERIA_NAME_ID] = (int)this->GetIDNumber();
        root[ICMPV4_SERIA_NAME_SEQ] = (int)this->GetSequence();
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
        break;
    }

    case ICMP_UNREACH:
    case ICMP_SOURCEQUENCH:
    case ICMP_ROUTERSOLICIT:
    {
        root[ICMPV4_SERIA_NAME_UNUSED] = (int)this->GetUnused();
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
        break;
    }

    case ICMP_REDIRECT:
    {
        in_addr addr = this->GetGatewayAddress();
        root[ICMPV4_SERIA_NAME_ADDR] = StringHelper::byte2basestr((const unsigned char *)&addr, 4, ".", StringHelper::dec);
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
        break;
    }

    case ICMP_ROUTERADVERT:
    {
        root[ICMPV4_SERIA_NAME_ADDR_NUM] = (int)this->GetNumAddresses();
        root[ICMPV4_SERIA_NAME_ADDR_LEN] = (int)this->GetAddrEntrySize();
        root[ICMPV4_SERIA_NAME_LIFE_TIME] = (int)this->GetLifetime();
        root[ICMPV4_SERIA_NAME_ADDRS] = Json::Value(Json::arrayValue);
        auto v = this->GetRouterAdvEntries();
        for (auto addr : v)
        {
            Json::Value tmp(Json::arrayValue);
            tmp.append(StringHelper::byte2basestr((const unsigned char *)&addr.router_addr.s_addr, 4, ".", StringHelper::dec));
            tmp.append(StringHelper::byte2basestr((const unsigned char *)&addr.preference_level, 4, ".", StringHelper::dec));
            root[ICMPV4_SERIA_NAME_ADDRS].append(tmp);
        }
        break;
    }

    case ICMP_PARAMPROB:
    {
        root[ICMPV4_SERIA_NAME_PARA_POINTER] = (int)this->GetParameterPointer();
        root[ICMPV4_SERIA_NAME_UNUSED] = (int)this->GetUnused();
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
        break;
    }

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
    {
        root[ICMPV4_SERIA_NAME_ID] = (int)this->GetIDNumber();
        root[ICMPV4_SERIA_NAME_SEQ] = (int)this->GetSequence();
        root[ICMPV4_SERIA_NAME_ORIG_TIMESTAMP] = (int)this->GetOriginateTimestamp();
        root[ICMPV4_SERIA_NAME_RECV_TIMESTAMP] = (int)this->GetReceiveTimestamp();
        root[ICMPV4_SERIA_NAME_TRANS_TIMESTAMP] = (int)this->GetTransmitTimestamp();
        break;
    }

    case ICMP_MASK:
    case ICMP_MASKREPLY:
    {
        root[ICMPV4_SERIA_NAME_ID] = (int)this->GetIDNumber();
        root[ICMPV4_SERIA_NAME_SEQ] = (int)this->GetSequence();
        in_addr addr = this->GetAddressMask();
        root[ICMPV4_SERIA_NAME_MASK] = StringHelper::byte2basestr((const unsigned char *)&addr, 4, ".", StringHelper::dec);
        break;
    }

    case ICMP_TRACEROUTE:
    {
        root[ICMPV4_SERIA_NAME_ID] = (int)this->GetIDNumber();
        root[ICMPV4_SERIA_NAME_UNUSED] = (int)this->GetUnused();
        root[ICMPV4_SERIA_NAME_OUTHOPS] = (int)this->GetOutboundHopCount();
        root[ICMPV4_SERIA_NAME_RETHOPS] = (int)this->GetReturnHopCount();
        root[ICMPV4_SERIA_NAME_SPEED] = (int)this->GetOutputLinkSpeed();
        root[ICMPV4_SERIA_NAME_MTU] = (int)this->GetOutputLinkMTU();
        break;
    }

    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
    {
        root[ICMPV4_SERIA_NAME_ID] = (int)this->GetIDNumber();
        root[ICMPV4_SERIA_NAME_SEQ] = (int)this->GetSequence();
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
    }
        /* TODO: print TTL and domain names in replies */
        // UNIMPLEMENTED
        break;

    case ICMP_SECURITYFAILURES:
    {
        root[ICMPV4_SERIA_NAME_RESERVED] = (int)this->GetReserved();
        root[ICMPV4_SERIA_NAME_POINTER] = (int)this->GetSecurityPointer();
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data + 4, this->length - 4 - 4, "", StringHelper::hex, 2);
        break;
    }
    default:
        root[ICMPV4_SERIA_NAME_OTHER_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->h.data, this->length - 4, "", StringHelper::hex, 2);
        break;
    }
    return root;
}

bool ICMPv4Header::UnSerialize(const Json::Value &in)
{
    int type = 0;
    if (in.isMember(ICMPV4_SERIA_NAME_TYPE) && in[ICMPV4_SERIA_NAME_TYPE].isInt()) {
        type = in[ICMPV4_SERIA_NAME_TYPE].asInt();
        this->SetType(type);
    }
    else {
        return false;
    }

    if (in.isMember(ICMPV4_SERIA_NAME_CHECKSUM) && in[ICMPV4_SERIA_NAME_CHECKSUM].isString()) {
        unsigned short sum = 0;
        std::string data = in[ICMPV4_SERIA_NAME_CHECKSUM].asString();
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

    switch (type)
    {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_INFO:
    case ICMP_INFOREPLY:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ID) && in[ICMPV4_SERIA_NAME_ID].isInt()) {
            this->SetIDNumber(in[ICMPV4_SERIA_NAME_ID].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_SEQ) && in[ICMPV4_SERIA_NAME_SEQ].isInt()) {
            this->SetSequence(in[ICMPV4_SERIA_NAME_SEQ].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }
        break;
    }

    case ICMP_UNREACH:
    case ICMP_SOURCEQUENCH:
    case ICMP_ROUTERSOLICIT:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_UNUSED) && in[ICMPV4_SERIA_NAME_UNUSED].isInt()) {
            this->SetUnused(in[ICMPV4_SERIA_NAME_UNUSED].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }
        break;
    }

    case ICMP_REDIRECT:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ADDR) && in[ICMPV4_SERIA_NAME_ADDR].isString()) {
            struct in_addr addr = NetworkHelper::IPStr2Addr(in[ICMPV4_SERIA_NAME_ADDR].asString());
            this->SetGatewayAddress(addr);
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }
        break;
    }

    case ICMP_ROUTERADVERT:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ADDR_NUM) && in[ICMPV4_SERIA_NAME_ADDR_NUM].isInt()) {
            this->SetNumAddresses(in[ICMPV4_SERIA_NAME_ADDR_NUM].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_ADDR_LEN) && in[ICMPV4_SERIA_NAME_ADDR_LEN].isInt()) {
            this->SetAddrEntrySize(in[ICMPV4_SERIA_NAME_ADDR_LEN].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_LIFE_TIME) && in[ICMPV4_SERIA_NAME_LIFE_TIME].isInt()) {
            this->SetAddrEntrySize(in[ICMPV4_SERIA_NAME_LIFE_TIME].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_ADDRS) && in[ICMPV4_SERIA_NAME_ADDRS].isArray()) {
            for (Json::ArrayIndex i = 0; i < in[ICMPV4_SERIA_NAME_ADDRS].size(); i++) {
                if (in[ICMPV4_SERIA_NAME_ADDRS][i].isArray() && in[ICMPV4_SERIA_NAME_ADDRS][i].size() == 2) {
                    if (in[ICMPV4_SERIA_NAME_ADDRS][i][0].isString() && in[ICMPV4_SERIA_NAME_ADDRS][i][1].isString()) {
                        struct in_addr router_addr = NetworkHelper::IPStr2Addr(in[ICMPV4_SERIA_NAME_ADDRS][i][0].asString());
                        struct in_addr preference_level = NetworkHelper::IPStr2Addr(in[ICMPV4_SERIA_NAME_ADDRS][i][1].asString());
                        this->AddRouterAdvEntry(router_addr, preference_level.s_addr);
                    }
                }
            }

        }
        break;
    }

    case ICMP_PARAMPROB:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_PARA_POINTER) && in[ICMPV4_SERIA_NAME_PARA_POINTER].isInt()) {
            this->SetParameterPointer(in[ICMPV4_SERIA_NAME_PARA_POINTER].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_UNUSED) && in[ICMPV4_SERIA_NAME_UNUSED].isInt()) {
            this->SetUnused(in[ICMPV4_SERIA_NAME_UNUSED].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }
        break;
    }

    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ID) && in[ICMPV4_SERIA_NAME_ID].isInt()) {
            this->SetIDNumber(in[ICMPV4_SERIA_NAME_ID].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_SEQ) && in[ICMPV4_SERIA_NAME_SEQ].isInt()) {
            this->SetSequence(in[ICMPV4_SERIA_NAME_SEQ].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_ORIG_TIMESTAMP) && in[ICMPV4_SERIA_NAME_ORIG_TIMESTAMP].isInt()) {
            this->SetOriginateTimestamp(in[ICMPV4_SERIA_NAME_ORIG_TIMESTAMP].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_RECV_TIMESTAMP) && in[ICMPV4_SERIA_NAME_RECV_TIMESTAMP].isInt()) {
            this->SetReceiveTimestamp(in[ICMPV4_SERIA_NAME_RECV_TIMESTAMP].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_TRANS_TIMESTAMP) && in[ICMPV4_SERIA_NAME_TRANS_TIMESTAMP].isInt()) {
            this->SetTransmitTimestamp(in[ICMPV4_SERIA_NAME_TRANS_TIMESTAMP].asInt());
        }
        break;
    }

    case ICMP_MASK:
    case ICMP_MASKREPLY:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ID) && in[ICMPV4_SERIA_NAME_ID].isInt()) {
            this->SetIDNumber(in[ICMPV4_SERIA_NAME_ID].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_SEQ) && in[ICMPV4_SERIA_NAME_SEQ].isInt()) {
            this->SetSequence(in[ICMPV4_SERIA_NAME_SEQ].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_MASK) && in[ICMPV4_SERIA_NAME_MASK].isString()) {
            struct in_addr addr = NetworkHelper::IPStr2Addr(in[ICMPV4_SERIA_NAME_MASK].asString());
            this->SetAddressMask(addr);
        }
        break;
    }

    case ICMP_TRACEROUTE:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ID) && in[ICMPV4_SERIA_NAME_ID].isInt()) {
            this->SetIDNumber(in[ICMPV4_SERIA_NAME_ID].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_UNUSED) && in[ICMPV4_SERIA_NAME_UNUSED].isInt()) {
            this->SetUnused(in[ICMPV4_SERIA_NAME_UNUSED].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OUTHOPS) && in[ICMPV4_SERIA_NAME_OUTHOPS].isInt()) {
            this->SetOutboundHopCount(in[ICMPV4_SERIA_NAME_OUTHOPS].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_RETHOPS) && in[ICMPV4_SERIA_NAME_RETHOPS].isInt()) {
            this->SetReturnHopCount(in[ICMPV4_SERIA_NAME_RETHOPS].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_SPEED) && in[ICMPV4_SERIA_NAME_SPEED].isInt()) {
            this->SetOutputLinkSpeed(in[ICMPV4_SERIA_NAME_SPEED].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_MTU) && in[ICMPV4_SERIA_NAME_MTU].isInt()) {
            this->SetOutputLinkMTU(in[ICMPV4_SERIA_NAME_MTU].asInt());
        }
        break;
    }

    case ICMP_DOMAINNAME:
    case ICMP_DOMAINNAMEREPLY:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_ID) && in[ICMPV4_SERIA_NAME_ID].isInt()) {
            this->SetIDNumber(in[ICMPV4_SERIA_NAME_ID].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_SEQ) && in[ICMPV4_SERIA_NAME_SEQ].isInt()) {
            this->SetSequence(in[ICMPV4_SERIA_NAME_SEQ].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }   
    }
    /* TODO: print TTL and domain names in replies */
    // UNIMPLEMENTED
    break;

    case ICMP_SECURITYFAILURES:
    {
        if (in.isMember(ICMPV4_SERIA_NAME_RESERVED) && in[ICMPV4_SERIA_NAME_RESERVED].isInt()) {
            this->SetReserved(in[ICMPV4_SERIA_NAME_RESERVED].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_POINTER) && in[ICMPV4_SERIA_NAME_POINTER].isInt()) {
            this->SetSecurityPointer(in[ICMPV4_SERIA_NAME_POINTER].asInt());
        }
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(4, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }   
        break;
    }
    default:
        if (in.isMember(ICMPV4_SERIA_NAME_OTHER_DATA) && in[ICMPV4_SERIA_NAME_OTHER_DATA].isString()) {
            this->SetRawData(0, in[ICMPV4_SERIA_NAME_OTHER_DATA].asString());
        }   
        break;
    }

    return true;
}