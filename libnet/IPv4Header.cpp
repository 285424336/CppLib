#include "IPv4Header.h"
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

IPv4Header::IPv4Header() : NetBase()
{
    this->Reset();
}

IPv4Header::~IPv4Header()
{

}

void IPv4Header::Reset()
{
    memset(&this->h, 0, sizeof(this->h));
    this->ipoptlen = 0;
    this->length = IP_HEADER_LEN;   /* Initial value 20. This will be incremented if options are used */
    this->SetVersion();
    this->SetHeaderLength();
    this->SetTOS(IPv4_DEFAULT_TOS);
    this->SetIdentification(IPv4_DEFAULT_ID);
    this->SetTTL(IPv4_DEFAULT_TTL);
    this->SetNextProto(IPv4_DEFAULT_PROTO);
    this->SetTotalLength();
}

int IPv4Header::ProtocolId() const
{
    return HEADER_TYPE_IPv4;
}

std::string IPv4Header::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool IPv4Header::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len<IP_HEADER_LEN) {
        return false;
    }
    ipv4_hdr_t *hdr = (ipv4_hdr_t *)buf;
    size_t stored_len = hdr->ip_hl * 4;
    if (stored_len>len || stored_len<IP_HEADER_LEN) {
        return false;
    }
    this->length = stored_len;
    this->ipoptlen = stored_len - IP_HEADER_LEN;
    memcpy(&(this->h), buf, stored_len);
    return true;
}

bool IPv4Header::Validate() const
{
    if (this->GetVersion() != 4) {
        return false;
    }
    else if (this->GetHeaderLength() < IP_HEADER_LEN) {
        return false;
    }
    else if (this->GetHeaderLength() != this->length) {
        return false;
    }
    else if (this->GetTotalLength() < this->GetHeaderLength()) {
        return false;
    }
    return true;
}

void IPv4Header::SetVersion()
{
    this->h.ip_v = 4;
}

unsigned char IPv4Header::GetVersion() const
{
    return this->h.ip_v;
}

void IPv4Header::SetHeaderLength()
{
    this->h.ip_hl = this->length / 4;
}

void IPv4Header::SetHeaderLength(unsigned char l)
{
    this->h.ip_hl = l / 4;
}

unsigned char IPv4Header::GetHeaderLength() const
{
    return this->h.ip_hl * 4;
}

void IPv4Header::SetTOS(unsigned char v)
{
    this->h.ip_tos = v;
}

unsigned char IPv4Header::GetTOS() const
{
    return this->h.ip_tos;
}

void IPv4Header::SetTotalLength()
{
    this->h.ip_len = htons((unsigned short)this->AllLen());
}

void IPv4Header::SetTotalLength(unsigned short l)
{
    this->h.ip_len = htons(l);
}

unsigned short IPv4Header::GetTotalLength() const
{
    return htons(this->h.ip_len);
}

void IPv4Header::SetIdentification(unsigned short i)
{
    this->h.ip_id = htons(i);
}

unsigned short IPv4Header::GetIdentification() const
{
    return htons(this->h.ip_id);
}

void IPv4Header::SetFragOffset(unsigned short f)
{
    this->h.ip_off = htons(f);
}

unsigned short IPv4Header::GetFragOffset() const
{
    return htons(this->h.ip_off);
}

void IPv4Header::SetRF()
{
    this->h.ip_off |= htons(IP_RF);
}

void IPv4Header::UnsetRF()
{
    this->h.ip_off &= ~htons(IP_RF);
}

bool IPv4Header::GetRF() const
{
    return (htons(this->h.ip_off) & IP_RF) ? true : false;
}

void IPv4Header::SetDF()
{
    this->h.ip_off |= htons(IP_DF);
}

void IPv4Header::UnsetDF()
{
    this->h.ip_off &= ~htons(IP_DF);
}

bool IPv4Header::GetDF() const
{
    return (htons(this->h.ip_off) & IP_DF) ? true : false;
}

void IPv4Header::SetMF()
{
    this->h.ip_off |= htons(IP_MF);
}

void IPv4Header::UnsetMF()
{
    this->h.ip_off &= ~htons(IP_MF);
}

bool IPv4Header::GetMF() const
{
    return (htons(this->h.ip_off) & IP_MF) ? true : false;
}

void IPv4Header::SetTTL(unsigned char t)
{
    this->h.ip_ttl = t;
}

unsigned char IPv4Header::GetTTL() const
{
    return this->h.ip_ttl;
}

void IPv4Header::SetNextProto(unsigned char p)
{
    this->h.ip_p = p;
}

unsigned char IPv4Header::GetNextProto() const
{
    return this->h.ip_p;
}

void IPv4Header::SetSum()
{
    this->h.ip_sum = 0;
    this->h.ip_sum = AlgorithmHelper::CheckSum((const unsigned char*)&this->h, this->length);
}

void IPv4Header::SetSum(unsigned short s)
{
    this->h.ip_sum = s;
}

unsigned short IPv4Header::GetSum() const
{
    return this->h.ip_sum;
}

void IPv4Header::SetDestinationAddress(struct in_addr d)
{
    this->h.ip_dst = d;
}

void IPv4Header::SetDestinationAddress(int d)
{
    this->h.ip_dst.s_addr = d;
}

struct in_addr IPv4Header::GetDestinationAddress() const
{
    return this->h.ip_dst;
}

void IPv4Header::SetSourceAddress(struct in_addr d)
{
    this->h.ip_src = d;
}

void IPv4Header::SetSourceAddress(int d)
{
    this->h.ip_src.s_addr = d;
}

struct in_addr IPv4Header::GetSourceAddress() const
{
    return this->h.ip_src;
}

bool IPv4Header::SetOpts(const unsigned char *opts_buff, unsigned int opts_len)
{
    if (opts_buff==NULL || opts_len==0) {
        return false;
    }
    unsigned int ip_opt_len = std::min(MAX_IP_OPTIONS_LEN, (int)opts_len);
    memcpy((unsigned char *)&(this->h)+ IP_HEADER_LEN, opts_buff, ip_opt_len);
    this->length = this->length - this->ipoptlen + ip_opt_len;
    this->ipoptlen = ip_opt_len;
    this->SetHeaderLength();
    this->SetTotalLength();
    return true;
}

std::string IPv4Header::GetOpts() const
{
    return std::string((char *)&this->h + IP_HEADER_LEN, this->ipoptlen);
}

size_t IPv4Header::GetOptsLen() const
{
    return this->ipoptlen;
}

std::string IPv4Header::GenerateRouteOpts(bool is_record_route, bool is_strict, const std::vector<struct in_addr> &addrs)
{
    unsigned char buf[MAX_IP_OPTIONS_LEN] = { 0 };
    size_t len = 0;
    unsigned char *route_opt_len = NULL;
    buf[len++] = IP_OPTION_TYPE_NOP;
    if (is_record_route) {
        buf[len++] = IP_OPTION_TYPE_RR;
        route_opt_len = &buf[len++];
        *route_opt_len = 39;
        buf[len++] = 4;
        len = MAX_IP_OPTIONS_LEN;
        return std::string((char *)buf, len);
    }
    buf[len++] = is_strict ? IP_OPTION_TYPE_SSRR : IP_OPTION_TYPE_LSRR;
    route_opt_len = &buf[len++];
    *route_opt_len = 3;
    buf[len++] = 4;
    for (struct in_addr addr :addrs) {
        if (len >= (MAX_IP_OPTIONS_LEN - 4)) {
            break;
        }
        memcpy(&buf[len], &addr.s_addr, 4);
        len += 4;
        *route_opt_len += 4;
    }
    memset(&buf[len], 0, 4);
    len += 4;
    *route_opt_len += 4;
    return std::string((char *)buf, len);
}

std::string IPv4Header::GenerateTimestampOpts(bool is_need_addr)
{
    unsigned char buf[MAX_IP_OPTIONS_LEN] = { 0 };
    size_t len = 0;
    unsigned char *route_opt_len = NULL;
    buf[len++] = IP_OPTION_TYPE_TS;
    route_opt_len = &buf[len++];
    *route_opt_len = is_need_addr ? 36 : 40; //4 addr/time pair or 9 time
    buf[len++] = 5;
    buf[len++] = is_need_addr ? 1 : 0;
    len = *route_opt_len;
    return std::string((char *)buf, len);
}

Json::Value IPv4Header::OptSerialize() const
{
    Json::Value root(Json::arrayValue);
    if (this->ipoptlen == 0) {
        return root;
    }
    const unsigned char *ipopt = (unsigned char *)&this->h + IP_HEADER_LEN;
    int option_type = -1;// option type
    size_t option_len = 0; // option length
    size_t option_sta = 0;	// option start offset base data
    size_t option_end = 0;	// option end offset base data
    size_t pt = 0;		// current offset base data

    while (pt < this->ipoptlen) {
        if (option_type == -1) {
            //choose option type
            option_sta = pt;
            option_type = ipopt[pt++];
            if (option_type != IP_OPTION_TYPE_EOL && option_type != IP_OPTION_TYPE_NOP) {
                if (pt >= this->ipoptlen) { //error option
                    return Json::Value(Json::arrayValue);
                }
                option_len = ipopt[pt++];
                if (option_len < 2) { //error option
                    return Json::Value(Json::arrayValue);
                }
                if ((option_sta + option_len) > this->ipoptlen) { //error option
                    return Json::Value(Json::arrayValue);
                }
                option_end = option_sta + option_len;
            }
        }
        switch (option_type) {
        case IP_OPTION_TYPE_EOL:	// IPOPT_END
        {
            Json::Value tmp;
            tmp[IPV4_SERIA_NAME_OPT_TYPE] = (int)option_type;
            tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_EOL;
            root.append(tmp);
            option_type = -1;
            break;
        }
        case IP_OPTION_TYPE_NOP:	// IPOPT_NOP
        {
            Json::Value tmp;
            tmp[IPV4_SERIA_NAME_OPT_TYPE] = (int)option_type;
            tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_NOP;
            root.append(tmp);
            option_type = -1;
            break;            
        }
        case IP_OPTION_TYPE_LSRR:	// IPOPT_LSRR	-> Loose Source and Record Route
        case IP_OPTION_TYPE_SSRR:	// IPOPT_SSRR	-> Strict Source and Record Route
        case IP_OPTION_TYPE_RR:	// IPOPT_RR	-> Record Route
        {
            int option_off = 0; // option offset
            if (option_len < 3 || ((option_len-3) % 4 != 0)) { //error option
                return Json::Value(Json::arrayValue);
            }
            Json::Value tmp;
            tmp[IPV4_SERIA_NAME_OPT_TYPE] = (int)option_type;
            if (option_type == IP_OPTION_TYPE_LSRR) {
                tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_LSRR;
            }
            else if (option_type == IP_OPTION_TYPE_SSRR) {
                tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_SSRR;
            }
            else {
                tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_RR;
            }
            option_off = (int)ipopt[pt++];
            if (option_off % 4 != 0 || option_off < 4 || (option_off - 1) > (int)option_len ) { //error option
                return Json::Value(Json::arrayValue);
            }
            tmp[IPV4_SERIA_NAME_OPT_OFFSET] = option_off;
            tmp[IPV4_SERIA_NAME_OPT_DATA] = Json::Value(Json::arrayValue);
            for (; (pt - option_sta) < option_len; pt = pt + 4) {
                tmp[IPV4_SERIA_NAME_OPT_DATA].append(StringHelper::byte2basestr((const unsigned char *)&ipopt[pt], 4, ".", StringHelper::dec));
            }
            root.append(tmp);
            option_type = -1;
            break;
        }
        case IP_OPTION_TYPE_TS:	// IPOPT_TS	-> Internet Timestamp
        {
            int option_off = 0; // option offset
            if (option_len < 4 || ((option_len - 4) % 4 != 0)) { //error option
                return Json::Value(Json::arrayValue);
            }
            Json::Value tmp;
            tmp[IPV4_SERIA_NAME_OPT_TYPE] = (int)option_type;
            tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_TS;
            option_off = (int)ipopt[pt++];
            if (option_off % 4 != 1 || option_off < 5 || (option_off - 1) > (int)option_len) { //error option
                return Json::Value(Json::arrayValue);
            }
            tmp[IPV4_SERIA_NAME_OPT_OFFSET] = option_off;
            int option_fl = 0;  // option flag
            option_fl = (int)ipopt[pt++];
            if ((option_fl & 0x0C) || (option_fl & 0x03) == 2) { //error option
                return Json::Value(Json::arrayValue);
            }
            tmp[IPV4_SERIA_NAME_OPT_FLAG] = option_fl;
            option_fl &= 0x03;
            if (option_fl && ((option_len - 4) % 8 != 0)) { //error option
                return Json::Value(Json::arrayValue);
            }
            if (option_fl && (option_off % 8 != 5)) { //error option
                return Json::Value(Json::arrayValue);
            }
            tmp[IPV4_SERIA_NAME_OPT_DATA] = Json::Value(Json::arrayValue);
            for (; (pt - option_sta) < option_len; pt = pt + 4) {
                Json::Value data;
                if (option_fl) {
                    data.append(StringHelper::byte2basestr((const unsigned char *)&ipopt[pt], 4, ".", StringHelper::dec));
                    pt = pt + 4;
                }
                data.append((int)htonl(*(int *)&ipopt[pt]));
                tmp[IPV4_SERIA_NAME_OPT_DATA].append(data);
            }
            root.append(tmp);
            option_type = -1;
            break;
        }
        default:
        {
            Json::Value tmp;
            tmp[IPV4_SERIA_NAME_OPT_TYPE] = (int)option_type;
            tmp[IPV4_SERIA_NAME_OPT_NAME] = IPV4_SERIA_NAME_OPT_NAME_UNKNOWN;
            tmp[IPV4_SERIA_NAME_OPT_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)&ipopt[pt], option_len - 2, "", StringHelper::hex, 2);
            pt += option_len - 2;
            root.append(tmp);
            option_type = -1;
            break;
        }
        }
    }
    return root;
}

bool IPv4Header::OptUnSerialize(const Json::Value &in)
{
    if (!in.isArray()) {
        return false;
    }
    unsigned char *ipopt = (unsigned char *)&this->h + IP_HEADER_LEN;
    this->length = IP_HEADER_LEN;
    this->ipoptlen = 0;
    for (Json::ArrayIndex i = 0; i < in.size(); i++) {
        if (!in[i].isMember(IPV4_SERIA_NAME_OPT_TYPE) || !in[i][IPV4_SERIA_NAME_OPT_TYPE].isInt()) {
            continue;
        }
        int type = in[i][IPV4_SERIA_NAME_OPT_TYPE].asInt();
        switch (type) {
        case IP_OPTION_TYPE_EOL:
        case IP_OPTION_TYPE_NOP:
            if (this->ipoptlen + 1 > MAX_IP_OPTIONS_LEN) {
                return false;
            }
            ipopt[this->ipoptlen++] = type;
            break;
        case IP_OPTION_TYPE_RR:
        case IP_OPTION_TYPE_LSRR:
        case IP_OPTION_TYPE_SSRR:
        {
            size_t start = this->ipoptlen;
            if (this->ipoptlen + 3 > MAX_IP_OPTIONS_LEN) {
                return false;
            }
            ipopt[this->ipoptlen++] = type;
            unsigned char *len = &ipopt[this->ipoptlen++];
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_OFFSET) && in[i][IPV4_SERIA_NAME_OPT_OFFSET].isInt()) {
                ipopt[this->ipoptlen++] = in[i][IPV4_SERIA_NAME_OPT_OFFSET].asInt();
            }
            else {
                ipopt[this->ipoptlen++] = 4;
            }
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_DATA) && in[i][IPV4_SERIA_NAME_OPT_DATA].isArray()) {
                for (Json::ArrayIndex j = 0; j < in[i][IPV4_SERIA_NAME_OPT_DATA].size(); j++) {
                    if (!in[i][IPV4_SERIA_NAME_OPT_DATA][j].isString()) {
                        continue;
                    }
                    if (this->ipoptlen + 4 > MAX_IP_OPTIONS_LEN) {
                        return false;
                    }
                    struct in_addr addr = NetworkHelper::IPStr2Addr(in[i][IPV4_SERIA_NAME_OPT_DATA][j].asString());
                    *(int*)&ipopt[this->ipoptlen] = addr.s_addr;
                    this->ipoptlen += 4;
                }
            }
            *len = (unsigned char)(this->ipoptlen - start);
            break;
        }
        case IP_OPTION_TYPE_TS:
        {
            size_t start = this->ipoptlen;
            if (this->ipoptlen + 4 > MAX_IP_OPTIONS_LEN) {
                return false;
            }
            ipopt[this->ipoptlen++] = type;
            unsigned char *len = &ipopt[this->ipoptlen++];
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_OFFSET) && in[i][IPV4_SERIA_NAME_OPT_OFFSET].isInt()) {
                ipopt[this->ipoptlen++] = in[i][IPV4_SERIA_NAME_OPT_OFFSET].asInt();
            }
            else {
                ipopt[this->ipoptlen++] = 4;
            }
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_FLAG) && in[i][IPV4_SERIA_NAME_OPT_FLAG].isInt()) {
                ipopt[this->ipoptlen++] = in[i][IPV4_SERIA_NAME_OPT_FLAG].asInt();
            }
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_DATA) && in[i][IPV4_SERIA_NAME_OPT_DATA].isArray()) {
                for (Json::ArrayIndex j = 0; j < in[i][IPV4_SERIA_NAME_OPT_DATA].size(); j++) {
                    if (!in[i][IPV4_SERIA_NAME_OPT_DATA][j].isArray() || in[i][IPV4_SERIA_NAME_OPT_DATA][j].size()>2) {
                        continue;
                    }
                    if (in[i][IPV4_SERIA_NAME_OPT_DATA][j].size() == 1) {
                        if (!in[i][IPV4_SERIA_NAME_OPT_DATA][j][0].isInt()) {
                            continue;
                        }
                        if (this->ipoptlen + 4 > MAX_IP_OPTIONS_LEN) {
                            return false;
                        }
                        ipopt[this->ipoptlen] = (int)htonl(in[i][IPV4_SERIA_NAME_OPT_DATA][j][0].asInt());
                        this->ipoptlen += 4;
                    }
                    else if (in[i][IPV4_SERIA_NAME_OPT_DATA][j].size() == 2) {
                        if (!in[i][IPV4_SERIA_NAME_OPT_DATA][j][0].isString() || !in[i][IPV4_SERIA_NAME_OPT_DATA][j][1].isInt()) {
                            continue;
                        }
                        if (this->ipoptlen + 8 > MAX_IP_OPTIONS_LEN) {
                            return false;
                        }
                        struct in_addr addr = NetworkHelper::IPStr2Addr(in[i][IPV4_SERIA_NAME_OPT_DATA][j][0].asString());
                        *(int *)&ipopt[this->ipoptlen] = addr.s_addr;
                        *(int *)&ipopt[this->ipoptlen+4] = (int)htonl(in[i][IPV4_SERIA_NAME_OPT_DATA][j][1].asInt());
                        this->ipoptlen += 8;
                    }
                }
            }

            *len = (unsigned char)(this->ipoptlen - start);
            break;
        }
        default:
        {
            size_t start = this->ipoptlen;
            if (this->ipoptlen + 2 > MAX_IP_OPTIONS_LEN) {
                return false;
            }
            ipopt[this->ipoptlen++] = type;
            unsigned char *len = &ipopt[this->ipoptlen++];
            if (in[i].isMember(IPV4_SERIA_NAME_OPT_DATA) && in[i][IPV4_SERIA_NAME_OPT_DATA].isString()) {
                unsigned char buf[MAX_IP_OPTIONS_LEN];
                std::string data = in[i][IPV4_SERIA_NAME_OPT_DATA].asString();
                const std::string *hexdata = &data;
                std::string tmpdata;
                if ((data.find("0x") != std::string::npos) || (data.find("0X") != std::string::npos)) {
                    tmpdata = std::string(data, 2);
                    hexdata = &tmpdata;
                }
                if (StringHelper::hex2byte(*hexdata, (char *)buf, sizeof(buf))) {
                    if ((this->ipoptlen + hexdata->size() / 2) > MAX_IP_OPTIONS_LEN) {
                        return false;
                    }
                    memcpy(&ipopt[this->ipoptlen], buf, hexdata->size() / 2);
                    this->ipoptlen += hexdata->size() / 2;
                }
            }

            *len = (unsigned char)(this->ipoptlen - start);
            break;
        }
        }
    }

    this->length += this->ipoptlen;
    return true;
}

Json::Value IPv4Header::Serialize() const
{
    Json::Value root;

    root[IPV4_SERIA_NAME_VERSION] = (int)this->GetVersion();
    root[IPV4_SERIA_NAME_HEADER_LENGTH] = (int)this->GetHeaderLength();
    root[IPV4_SERIA_NAME_TOS] = (int)this->GetTOS();
    root[IPV4_SERIA_NAME_TOTAL_LENGTH] = (int)this->GetTotalLength();
    root[IPV4_SERIA_NAME_ID] = (int)this->GetIdentification();
    root[IPV4_SERIA_NAME_FRAG_OFF] = (int)(this->GetFragOffset() & 0x1FFF);
    root[IPV4_SERIA_NAME_RF] = this->GetRF();
    root[IPV4_SERIA_NAME_DF] = this->GetDF();
    root[IPV4_SERIA_NAME_MF] = this->GetMF();
    root[IPV4_SERIA_NAME_TTL] = (int)this->GetTTL();
    root[IPV4_SERIA_NAME_PROTOCAL] = (int)this->GetNextProto();
    unsigned short sum = this->GetSum();
    root[IPV4_SERIA_NAME_CHECKSUM] = "0x" + StringHelper::byte2basestr((const unsigned char *)&sum, sizeof(sum), "", StringHelper::hex, 2);
    in_addr dst_addr = this->GetDestinationAddress();
    root[IPV4_SERIA_NAME_DST_IP] = StringHelper::byte2basestr((const unsigned char *)&dst_addr, 4, ".", StringHelper::dec);
    in_addr src_addr = this->GetSourceAddress();
    root[IPV4_SERIA_NAME_SRC_IP] = StringHelper::byte2basestr((const unsigned char *)&src_addr, 4, ".", StringHelper::dec);
    root[IPV4_SERIA_NAME_OPT] = this->OptSerialize();
    return root;
}

bool IPv4Header::UnSerialize(const Json::Value &in)
{
    if (in.isMember(IPV4_SERIA_NAME_VERSION) && in[IPV4_SERIA_NAME_VERSION].isInt()) {
        this->SetVersion();
    }

    if (in.isMember(IPV4_SERIA_NAME_HEADER_LENGTH) && in[IPV4_SERIA_NAME_HEADER_LENGTH].isInt()) {
        this->SetHeaderLength(in[IPV4_SERIA_NAME_HEADER_LENGTH].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_TOS) && in[IPV4_SERIA_NAME_TOS].isInt()) {
        this->SetTOS(in[IPV4_SERIA_NAME_TOS].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_TOTAL_LENGTH) && in[IPV4_SERIA_NAME_TOTAL_LENGTH].isInt()) {
        this->SetTotalLength(in[IPV4_SERIA_NAME_TOTAL_LENGTH].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_ID) && in[IPV4_SERIA_NAME_ID].isInt()) {
        this->SetIdentification(in[IPV4_SERIA_NAME_ID].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_FRAG_OFF) && in[IPV4_SERIA_NAME_FRAG_OFF].isInt()) {
        this->SetFragOffset(in[IPV4_SERIA_NAME_FRAG_OFF].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_RF) && in[IPV4_SERIA_NAME_RF].isBool()) {
        if (in[IPV4_SERIA_NAME_RF].asBool()) {
            this->SetRF();
        }
        else {
            this->UnsetRF();
        }
    }

    if (in.isMember(IPV4_SERIA_NAME_DF) && in[IPV4_SERIA_NAME_DF].isBool()) {
        if (in[IPV4_SERIA_NAME_DF].asBool()) {
            this->SetDF();
        }
        else {
            this->UnsetDF();
        }
    }

    if (in.isMember(IPV4_SERIA_NAME_MF) && in[IPV4_SERIA_NAME_MF].isBool()) {
        if (in[IPV4_SERIA_NAME_MF].asBool()) {
            this->SetMF();
        }
        else {
            this->UnsetMF();
        }
    }

    if (in.isMember(IPV4_SERIA_NAME_TTL) && in[IPV4_SERIA_NAME_TTL].isInt()) {
        this->SetTTL(in[IPV4_SERIA_NAME_TTL].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_PROTOCAL) && in[IPV4_SERIA_NAME_PROTOCAL].isInt()) {
        this->SetNextProto(in[IPV4_SERIA_NAME_PROTOCAL].asInt());
    }

    if (in.isMember(IPV4_SERIA_NAME_CHECKSUM) && in[IPV4_SERIA_NAME_CHECKSUM].isString()) {
        unsigned short sum = 0;
        std::string data = in[IPV4_SERIA_NAME_CHECKSUM].asString();
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

    if (in.isMember(IPV4_SERIA_NAME_DST_IP) && in[IPV4_SERIA_NAME_DST_IP].isString()) {
        struct in_addr addr = NetworkHelper::IPStr2Addr(in[IPV4_SERIA_NAME_DST_IP].asString());
        this->SetDestinationAddress(addr);
    }

    if (in.isMember(IPV4_SERIA_NAME_SRC_IP) && in[IPV4_SERIA_NAME_SRC_IP].isString()) {
        struct in_addr addr = NetworkHelper::IPStr2Addr(in[IPV4_SERIA_NAME_SRC_IP].asString());
        this->SetSourceAddress(addr);
    }

    if (in.isMember(IPV4_SERIA_NAME_OPT) && in[IPV4_SERIA_NAME_OPT].isArray()) {
        this->OptUnSerialize(in[IPV4_SERIA_NAME_OPT]);
    }

    return true;
}