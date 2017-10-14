#include "TCPHeader.h"
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

std::map<int, TCPHeader::OptParse> TCPHeader::optparse = TCPHeader::InitOptParse();
std::map<int, TCPHeader::OptUnParse> TCPHeader::optunparse = TCPHeader::InitOptUnParse();

std::map<int, TCPHeader::OptParse> TCPHeader::InitOptParse()
{
    std::map<int, TCPHeader::OptParse> r;
    r[TCPOPT_NOOP] = NopOptParse;
    r[TCPOPT_MSS] = MssOptParse;
    r[TCPOPT_WSCALE] = WinScaleOptParse;
    r[TCPOPT_SACKOK] = SackPermOptParse;
    r[TCPOPT_SACK] = SackOptParse;
    r[TCPOPT_TSTAMP] = TimestampOptParse;
    return r;
}

std::map<int, TCPHeader::OptUnParse> TCPHeader::InitOptUnParse()
{
    std::map<int, TCPHeader::OptUnParse> r;
    r[TCPOPT_NOOP] = NopOptUnParse;
    r[TCPOPT_MSS] = MssOptUnParse;
    r[TCPOPT_WSCALE] = WinScaleOptUnParse;
    r[TCPOPT_SACKOK] = SackPermOptUnParse;
    r[TCPOPT_SACK] = SackOptUnParse;
    r[TCPOPT_TSTAMP] = TimestampOptUnParse;
    return r;
}

TCPHeader::TCPHeader() : TransportLayerHeader()
{
    this->Reset();
}

TCPHeader::~TCPHeader()
{

}

void TCPHeader::Reset()
{
    memset(&this->h, 0, sizeof(tcp_hdr_t));
    this->length = TCP_HEADER_LEN; /* Initial value 20. This will be incremented if options are used */
    this->tcpoptlen = 0;
    this->SetSourcePort(TCP_DEFAULT_SPORT);
    this->SetDestinationPort(TCP_DEFAULT_DPORT);
    this->SetSeq(TCP_DEFAULT_SEQ);
    this->SetAck(TCP_DEFAULT_ACK);
    this->SetFlags(TCP_DEFAULT_FLAGS);
    this->SetWindow(TCP_DEFAULT_WIN);
    this->SetUrgPointer(TCP_DEFAULT_URP);
    this->SetHeaderLength();
}

int TCPHeader::ProtocolId() const
{
    return HEADER_TYPE_TCP;
}

std::string TCPHeader::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool TCPHeader::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len<TCP_HEADER_LEN) {
        return false;
    }
    tcp_hdr_t *hdr = (tcp_hdr_t *)buf;
    size_t stored_len = hdr->th_off * 4;
    if (stored_len>len || stored_len<TCP_HEADER_LEN) {
        return false;
    }
    this->length = stored_len;
    this->tcpoptlen = stored_len - TCP_HEADER_LEN;
    memcpy(&(this->h), buf, stored_len);
    return true;
}

bool TCPHeader::Validate() const
{
    if (this->GetHeaderLength() < TCP_HEADER_LEN) {
        return false;
    }
    else if (this->GetHeaderLength() != this->length) {
        return false;
    }
    return true;
}

void TCPHeader::SetSourcePort(unsigned short p)
{
    this->h.th_sport = htons(p);
}

unsigned short TCPHeader::GetSourcePort() const
{
    return htons(this->h.th_sport);
}

void TCPHeader::SetDestinationPort(unsigned short p)
{
    this->h.th_dport = htons(p);
}

unsigned short TCPHeader::GetDestinationPort() const
{
    return htons(this->h.th_dport);
}

void TCPHeader::SetSeq(unsigned int p)
{
    this->h.th_seq = htonl(p);
}

unsigned int TCPHeader::GetSeq() const
{
    return htonl(this->h.th_seq);
}

void TCPHeader::SetAck(unsigned int p)
{
    this->h.th_ack = htonl(p);
}

unsigned int TCPHeader::GetAck() const
{
    return ntohl(this->h.th_ack);
}

void TCPHeader::SetHeaderLength()
{
    this->h.th_off = this->length / 4;
}

void TCPHeader::SetHeaderLength(unsigned char l)
{
    this->h.th_off = l / 4;
}

unsigned char TCPHeader::GetHeaderLength() const
{
    return this->h.th_off * 4;
}

void TCPHeader::SetReserved(unsigned char r)
{
    this->h.th_x2 = r;
}

unsigned char TCPHeader::GetReserved() const
{
    return this->h.th_x2;
}

void TCPHeader::SetFlags(unsigned char f)
{
    this->h.th_flags = f;
}

unsigned char TCPHeader::GetFlags() const
{
    return this->h.th_flags;
}

unsigned short TCPHeader::GetFlags16() const
{
    unsigned short field = ntohs(*(unsigned short *)(((unsigned char *)&this->h) + 12));
    /* Erase the contents of the data offset field */
    field = field & 0x0FFF;
    return field;
}

void TCPHeader::SetCWR()
{
    this->h.th_flags |= TH_CWR;
}

void TCPHeader::UnsetCWR()
{
    this->h.th_flags ^= TH_CWR;
}

bool TCPHeader::GetCWR() const
{
    return (this->h.th_flags & TH_CWR) ? true : false;
}

void TCPHeader::SetECE()
{
    this->h.th_flags |= TH_ECN;
}

void TCPHeader::UnsetECE()
{
    this->h.th_flags ^= TH_ECN;
}

bool TCPHeader::GetECE() const
{
    return (this->h.th_flags & TH_ECN) ? true : false;
}

void TCPHeader::SetECN()
{
    this->h.th_flags |= TH_ECN;
}

void TCPHeader::UnsetECN()
{
    this->h.th_flags ^= TH_ECN;
}

bool TCPHeader::GetECN() const
{
    return (this->h.th_flags & TH_ECN) ? true : false;
}

void TCPHeader::SetURG()
{
    this->h.th_flags |= TH_URG;
}

void TCPHeader::UnsetURG()
{
    this->h.th_flags ^= TH_URG;
}

bool TCPHeader::GetURG() const
{
    return (this->h.th_flags & TH_URG) ? true : false;
}

void TCPHeader::SetACK()
{
    this->h.th_flags |= TH_ACK;
}

void TCPHeader::UnsetACK()
{
    this->h.th_flags ^= TH_ACK;
}

bool TCPHeader::GetACK() const
{
    return (this->h.th_flags & TH_ACK) ? true : false;
}

void TCPHeader::SetPSH()
{
    this->h.th_flags |= TH_PSH;
}

void TCPHeader::UnsetPSH()
{
    this->h.th_flags ^= TH_PSH;
}

bool TCPHeader::GetPSH() const
{
    return (this->h.th_flags & TH_PSH) ? true : false;
}

void TCPHeader::SetRST()
{
    this->h.th_flags |= TH_RST;
}

void TCPHeader::UnsetRST()
{
    this->h.th_flags ^= TH_RST;
}

bool TCPHeader::GetRST() const
{
    return (this->h.th_flags & TH_RST) ? true : false;
}

void TCPHeader::SetSYN()
{
    this->h.th_flags |= TH_SYN;
}

void TCPHeader::UnsetSYN()
{
    this->h.th_flags ^= TH_SYN;
}

bool TCPHeader::GetSYN() const
{
    return (this->h.th_flags & TH_SYN) ? true : false;
}

void TCPHeader::SetFIN()
{
    this->h.th_flags |= TH_FIN;
}

void TCPHeader::UnsetFIN()
{
    this->h.th_flags ^= TH_FIN;
}

bool TCPHeader::GetFIN() const
{
    return this->h.th_flags & TH_FIN;
}

void TCPHeader::SetWindow(unsigned short p)
{
    this->h.th_win = htons(p);
}

unsigned short TCPHeader::GetWindow() const
{
    return htons(this->h.th_win);
}

void TCPHeader::SetUrgPointer(unsigned short l)
{
    this->h.th_urp = htons(l);
}

unsigned short TCPHeader::GetUrgPointer() const
{
    return htons(this->h.th_urp);
}

void TCPHeader::SetSum()
{
    std::shared_ptr<NetBase> ip_header = this->ProtocalData(HEADER_TYPE_IPv4);
    if (!ip_header) {
        return;
    }
    IPv4Header *header = (IPv4Header *)ip_header.get();
    this->h.th_sum = 0;
    std::string all_data = this->AllData();
    this->h.th_sum = NetworkHelper::ComputerTcpOUdpSum(header->GetSourceAddress(), header->GetDestinationAddress(), true, all_data.c_str(), (unsigned short)all_data.size());
}

void TCPHeader::SetSum(unsigned short s)
{
    this->h.th_sum = s;
}

unsigned short TCPHeader::GetSum() const
{
    return this->h.th_sum;
}

void TCPHeader::SetOptions(const unsigned char *optsbuff, size_t optslen)
{
    if (optsbuff == NULL && optslen == 0) {
        this->tcpoptlen = 0;
        this->length = TCP_HEADER_LEN;
        memset(this->h.options, 0, MAX_TCP_OPTIONS_LEN);
        this->SetHeaderLength();
        return;
    }
    else if (optsbuff == NULL || optslen == 0 || optslen>MAX_TCP_OPTIONS_LEN) {
        return;
    }
    else {
        memcpy(this->h.options, optsbuff, optslen);
        this->tcpoptlen = optslen;
        this->length = TCP_HEADER_LEN + optslen;
        this->SetHeaderLength();
        return;
    }
}

std::vector<tcp_opt_t> TCPHeader::GetOption() const
{
    std::vector<tcp_opt_t> r;
    if (!this->tcpoptlen) {
        return r;
    }

    tcp_opt_t *curr_opt = NULL;
    unsigned char *curr_pnt = (unsigned char *)this->h.options;
    size_t bytes_left = this->tcpoptlen;
    while (bytes_left) {
        curr_opt = (tcp_opt_t *)curr_pnt;
        switch (curr_opt->type) {
            /* EOL or NOOP
            +-+-+-+-+-+-+-+-+
            |       X       |
            +-+-+-+-+-+-+-+-+  */
        case TCPOPT_EOL:
            return r;
        case TCPOPT_NOOP:
        {
            tcp_opt_t result;
            result.type = curr_opt->type;
            result.len = 1;
            result.value = NULL;
            r.emplace_back(result);
            curr_pnt++; /* Skip one octet */
            bytes_left--;
            break;
        }
        default:
        {
            if (bytes_left < curr_opt->len) {
                return r;
            }
            tcp_opt_t result;
            result.type = curr_opt->type;
            result.len = curr_opt->len;
            result.value = (unsigned char *)curr_pnt + 2;
            r.emplace_back(result);
            curr_pnt += curr_opt->len;
            bytes_left -= curr_opt->len;
            break;
        }
        }
    }
    return r;
}

std::string TCPHeader::Optcode2Str(unsigned char optcode)
{
    switch (optcode) {
    case TCPOPT_EOL:
        return "EOL";
    case TCPOPT_NOOP:
        return "NOOP";
    case TCPOPT_MSS:
        return "MSS";
    case TCPOPT_WSCALE:
        return "WScale";
    case TCPOPT_SACKOK:
        return "SAckOK";
    case TCPOPT_SACK:
        return "SAck";
    case TCPOPT_ECHOREQ:
        return "EchoReq";
    case TCPOPT_ECHOREP:
        return "EchoRep";
    case TCPOPT_TSTAMP:
        return "TStamp";
    case TCPOPT_POCP:
        return "POCP";
    case TCPOPT_POSP:
        return "POSP";
    case TCPOPT_CC:
        return "CC";
    case TCPOPT_CCNEW:
        return "CC.NEW";
    case TCPOPT_CCECHO:
        return "CC.ECHO";
    case TCPOPT_ALTCSUMREQ:
        return "AltSumReq";
    case TCPOPT_ALTCSUMDATA:
        return "AltSumData";
    case TCPOPT_MD5:
        return "MD5";
    case TCPOPT_SCPS:
        return "SCPS";
    case TCPOPT_SNACK:
        return "SNAck";
    case TCPOPT_QSRES:
        return "QStart";
    case TCPOPT_UTO:
        return "UTO";
    case TCPOPT_AO:
        return "AO";
    default:
        return "Unknown";
    }
}

Json::Value TCPHeader::Serialize() const
{
    Json::Value root;

    root[TCP_SERIA_NAME_SRC_PORT] = (int)this->GetSourcePort();
    root[TCP_SERIA_NAME_DST_PORT] = (int)this->GetDestinationPort();
    root[TCP_SERIA_NAME_SEQ] = (int)this->GetSeq();
    root[TCP_SERIA_NAME_ACK] = (int)this->GetAck();
    root[TCP_SERIA_NAME_OFFSET] = (int)this->GetHeaderLength();
    root[TCP_SERIA_NAME_RESERVE] = (int)this->GetReserved();
    root[TCP_SERIA_NAME_CWR_FLAG] = this->GetCWR();
    root[TCP_SERIA_NAME_ECE_FLAG] = this->GetECE();
    root[TCP_SERIA_NAME_URG_FLAG] = this->GetURG();
    root[TCP_SERIA_NAME_ACK_FLAG] = this->GetACK();
    root[TCP_SERIA_NAME_PUSH_FLAG] = this->GetPSH();
    root[TCP_SERIA_NAME_RST_FLAG] = this->GetRST();
    root[TCP_SERIA_NAME_SYN_FLAG] = this->GetSYN();
    root[TCP_SERIA_NAME_FIN_FLAG] = this->GetFIN();
    root[TCP_SERIA_NAME_WINDOW] = (int)this->GetWindow();
    root[TCP_SERIA_NAME_URG_POINT] = (int)this->GetUrgPointer();
    unsigned short sum = this->GetSum();
    root[TCP_SERIA_NAME_CHECK_SUM] = "0x" + StringHelper::byte2basestr((const unsigned char *)&sum, sizeof(sum), "", StringHelper::hex, 2);
    root[TCP_SERIA_NAME_OPT] = Json::Value(Json::arrayValue);
    auto opts = this->GetOption();
    for (auto opt : opts) {
        if (optparse.find(opt.type) == optparse.end()) {
            root[TCP_SERIA_NAME_OPT].append(CommonOptParse(opt));
        }
        else {
            root[TCP_SERIA_NAME_OPT].append(optparse[opt.type](opt));
        }
    }
    return root;
}

bool TCPHeader::UnSerialize(const Json::Value &in)
{
    if (in.isMember(TCP_SERIA_NAME_SRC_PORT) && in[TCP_SERIA_NAME_SRC_PORT].isInt()) {
        this->SetSourcePort(in[TCP_SERIA_NAME_SRC_PORT].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_DST_PORT) && in[TCP_SERIA_NAME_DST_PORT].isInt()) {
        this->SetDestinationPort(in[TCP_SERIA_NAME_DST_PORT].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_SEQ) && in[TCP_SERIA_NAME_SEQ].isInt()) {
        this->SetSeq(in[TCP_SERIA_NAME_SEQ].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_ACK) && in[TCP_SERIA_NAME_ACK].isInt()) {
        this->SetAck(in[TCP_SERIA_NAME_ACK].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_OFFSET) && in[TCP_SERIA_NAME_OFFSET].isInt()) {
        this->SetHeaderLength(in[TCP_SERIA_NAME_OFFSET].asInt());
    }
    
    if (in.isMember(TCP_SERIA_NAME_RESERVE) && in[TCP_SERIA_NAME_RESERVE].isInt()) {
        this->SetReserved(in[TCP_SERIA_NAME_RESERVE].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_CWR_FLAG) && in[TCP_SERIA_NAME_CWR_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_CWR_FLAG].asBool()) {
            this->SetCWR();
        }
        else
        {
            this->UnsetCWR();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_ECE_FLAG) && in[TCP_SERIA_NAME_ECE_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_ECE_FLAG].asBool()) {
            this->SetECE();
        }
        else
        {
            this->UnsetECE();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_URG_FLAG) && in[TCP_SERIA_NAME_URG_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_URG_FLAG].asBool()) {
            this->SetURG();
        }
        else
        {
            this->UnsetURG();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_ACK_FLAG) && in[TCP_SERIA_NAME_ACK_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_ACK_FLAG].asBool()) {
            this->SetACK();
        }
        else
        {
            this->UnsetACK();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_PUSH_FLAG) && in[TCP_SERIA_NAME_PUSH_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_PUSH_FLAG].asBool()) {
            this->SetPSH();
        }
        else
        {
            this->UnsetPSH();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_RST_FLAG) && in[TCP_SERIA_NAME_RST_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_RST_FLAG].asBool()) {
            this->SetRST();
        }
        else
        {
            this->UnsetRST();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_SYN_FLAG) && in[TCP_SERIA_NAME_SYN_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_SYN_FLAG].asBool()) {
            this->SetSYN();
        }
        else
        {
            this->UnsetSYN();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_FIN_FLAG) && in[TCP_SERIA_NAME_FIN_FLAG].isBool()) {
        if (in[TCP_SERIA_NAME_FIN_FLAG].asBool()) {
            this->SetFIN();
        }
        else
        {
            this->UnsetFIN();
        }
    }

    if (in.isMember(TCP_SERIA_NAME_WINDOW) && in[TCP_SERIA_NAME_WINDOW].isInt()) {
        this->SetWindow(in[TCP_SERIA_NAME_WINDOW].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_URG_POINT) && in[TCP_SERIA_NAME_URG_POINT].isInt()) {
        this->SetUrgPointer(in[TCP_SERIA_NAME_URG_POINT].asInt());
    }

    if (in.isMember(TCP_SERIA_NAME_CHECK_SUM) && in[TCP_SERIA_NAME_CHECK_SUM].isString()) {
        unsigned short sum = 0;
        std::string data = in[TCP_SERIA_NAME_CHECK_SUM].asString();
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

    this->length = TCP_HEADER_LEN;
    this->tcpoptlen = 0;
    
    if (in.isMember(TCP_SERIA_NAME_OPT) && in[TCP_SERIA_NAME_OPT].isArray()) {
        for (Json::ArrayIndex i = 0; i < in[TCP_SERIA_NAME_OPT].size(); i++) {
            if (!in[TCP_SERIA_NAME_OPT][i].isMember(TCP_SERIA_NAME_OPT_TYPE) || !in[TCP_SERIA_NAME_OPT][i][TCP_SERIA_NAME_OPT_TYPE].isInt()) {
                continue;
            }
            if (this->tcpoptlen == MAX_TCP_OPTIONS_LEN) {
                break;
            }
            int type = in[TCP_SERIA_NAME_OPT][i][TCP_SERIA_NAME_OPT_TYPE].asInt();
            if (optunparse.find(type) == optunparse.end()) {
                this->tcpoptlen += CommonOptUnParse(in[TCP_SERIA_NAME_OPT][i], this->h.options + this->tcpoptlen, MAX_TCP_OPTIONS_LEN - this->tcpoptlen);
            }
            else {
                this->tcpoptlen += optunparse[type](in[TCP_SERIA_NAME_OPT][i], this->h.options + this->tcpoptlen, MAX_TCP_OPTIONS_LEN - this->tcpoptlen);
            }
        }
        int i = 0, s = (this->tcpoptlen) % 4;
        s = s == 0 ? 0 : 4 - s;
        for (i = 0; i < s; i++) {
            this->h.options[this->tcpoptlen++] = TCPOPT_NOOP;
        }
    }
    this->length += this->tcpoptlen;
    return true;
}

int TCPHeader::GenerateNopOpt(unsigned char *buf, int len)
{
    int used = 0;
    unsigned char *pt = buf;
    if (buf == NULL || len < 1) {
        return used;
    }
    pt[0] = TCPOPT_NOOP;
    return 1;
}

int TCPHeader::GenerateMssOpt(unsigned char *buf, int len, unsigned short mss)
{
    int used = 0;
    unsigned char *pt = buf;
    if (buf == NULL || len < 4) {
        return used;
    }
    pt[0] = TCPOPT_MSS;
    pt[1] = 4;
    *(unsigned short*)(pt + 2) = htons(mss);
    return 4;
}

int TCPHeader::GenerateWinScaleOpt(unsigned char *buf, int len, unsigned char wscale)
{
    int used = 0;
    unsigned char *pt = buf;
    if (buf == NULL || len < 3) {
        return used;
    }
    pt[0] = TCPOPT_WSCALE;
    pt[1] = 3;
    pt[2] = wscale;
    return 3;
}

int TCPHeader::GenerateSackPermOpt(unsigned char *buf, int len)
{
    int used = 0;
    unsigned char *pt = buf;
    if (buf == NULL || len < 2) {
        return used;
    }
    pt[0] = TCPOPT_SACKOK;
    pt[1] = 2;
    return 2;
}

int TCPHeader::GenerateSackOpt(unsigned char *buf, int len, const std::vector<std::pair<unsigned int, unsigned int>> &sack)
{
    int used = 0;
    unsigned char *pt = buf;
    unsigned char *oplen = NULL;
    if (buf == NULL || len < 2) {
        return used;
    }
    pt[0] = TCPOPT_SACK;
    oplen = &pt[1];
    used += 2;
    for (auto s : sack) {
        if (used + 8 > len) {
            break;
        }
        *(unsigned int *)&pt[used] = ntohl(s.first);
        used += 4;
        *(unsigned int *)&pt[used] = ntohl(s.second);
        used += 4;
    }
    *oplen = (unsigned char)used;
    return used;
}

int TCPHeader::GenerateTimestampOpt(unsigned char *buf, int len, unsigned int req_time, unsigned int ack_time)
{
    int used = 0;
    unsigned char *pt = buf;
    if (buf == NULL || len < 10) {
        return used;
    }
    pt[0] = TCPOPT_TSTAMP;
    pt[1] = 10;
    *(unsigned int*)(pt + 2) = htonl(req_time);
    *(unsigned int*)(pt + 6) = htonl(ack_time);
    return 10;
}

Json::Value TCPHeader::CommonOptParse(const tcp_opt_t &optp)
{
    Json::Value root;

    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    if (optp.value && (optp.len - 2) > 0) {
        root[TCP_SERIA_NAME_OPT_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)optp.value, optp.len - 2, "", StringHelper::hex, 2);
    }
    return root;
}

int TCPHeader::CommonOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 0 ) {
        return used;
    }
    unsigned char buf[MAX_TCP_OPTIONS_LEN];

    pt[used++] = in[TCP_SERIA_NAME_OPT_TYPE].asInt();
    if (in[TCP_SERIA_NAME_OPT_TYPE].asInt() == TCPOPT_EOL) {
        return used;
    }
    if (used + 1 > len) {
        return used;
    }
    unsigned char *op_len = &pt[used++];
    if (in.isMember(TCP_SERIA_NAME_OPT_DATA) && in[TCP_SERIA_NAME_OPT_DATA].isString()) {
        std::string data = in[TCP_SERIA_NAME_OPT_DATA].asString();
        const std::string *hexdata = &data;
        std::string tmpdata;
        if ((data.find("0x") != std::string::npos) || (data.find("0X") != std::string::npos)) {
            tmpdata = std::string(data, 2);
            hexdata = &tmpdata;
        }
        if ((used + (int)hexdata->size() / 2) > len) {
            *op_len = used;
            return used;
        }
        if (StringHelper::hex2byte(hexdata->c_str(), (char *)buf, sizeof(buf))) {
            memcpy(&pt[used], buf, hexdata->size() / 2);
            used += hexdata->size() / 2;
        }
    }
    *op_len = used;
    return used;
}

Json::Value TCPHeader::NopOptParse(const tcp_opt_t &optp)
{
    Json::Value root;

    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    return root;
}

int TCPHeader::NopOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 0) {
        return used;
    }

    pt[used++] = TCPOPT_NOOP;
    return used;
}

Json::Value TCPHeader::MssOptParse(const tcp_opt_t &optp)
{
    Json::Value root;
    if (!optp.value || optp.len < 4) {
        return root;
    }
    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    root[TCP_SERIA_NAME_OPT_MSS] = (int)ntohs(*(unsigned short *)optp.value);
    return root;
}

int TCPHeader::MssOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 1) {
        return used;
    }

    pt[used++] = TCPOPT_MSS;
    unsigned char *op_len = &pt[used++];
    if (in.isMember(TCP_SERIA_NAME_OPT_MSS) && in[TCP_SERIA_NAME_OPT_MSS].isInt()) {
        if (used + 2 <= len) {
            *(unsigned short*)&pt[used] = ntohs(in[TCP_SERIA_NAME_OPT_MSS].asInt());
            used += 2;
        }
    }
    *op_len = used;
    return used;
}

Json::Value TCPHeader::WinScaleOptParse(const tcp_opt_t &optp)
{
    Json::Value root;
    if (!optp.value || optp.len < 3) {
        return root;
    }
    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    root[TCP_SERIA_NAME_OPT_WSCALE] = (int)*optp.value;
    return root;
}

int TCPHeader::WinScaleOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 1) {
        return used;
    }

    pt[used++] = TCPOPT_WSCALE;
    unsigned char *op_len = &pt[used++];
    if (in.isMember(TCP_SERIA_NAME_OPT_WSCALE) && in[TCP_SERIA_NAME_OPT_WSCALE].isInt()) {
        if (used + 1 <= len) {
            pt[used] = (unsigned char)in[TCP_SERIA_NAME_OPT_WSCALE].asInt();
            used += 1;
        }
    }
    *op_len = used;
    return used;
}

Json::Value TCPHeader::SackPermOptParse(const tcp_opt_t &optp)
{
    Json::Value root;

    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    return root;
}

int TCPHeader::SackPermOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 1) {
        return used;
    }

    pt[used++] = TCPOPT_SACKOK;
    unsigned char *op_len = &pt[used++];
    *op_len = used;
    return used;
}

Json::Value TCPHeader::SackOptParse(const tcp_opt_t &optp)
{
    Json::Value root;

    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    if (!optp.value || optp.len < 2) {
        return root;
    }
    if ((optp.len - 2) == 0 || ((optp.len - 2) % 8 != 0)) {
        return root;
    }
    root[TCP_SERIA_NAME_OPT_SACK] = Json::Value(Json::arrayValue);
    for (unsigned char i = 0; i < optp.len - 2; i += 8) {
        Json::Value tmp(Json::arrayValue);
        tmp.append((int)ntohl(*(int*)(optp.value + i)));
        tmp.append((int)ntohl(*(int*)(optp.value + i + 4)));
        root[TCP_SERIA_NAME_OPT_SACK].append(tmp);
    }
    return root;
}

int TCPHeader::SackOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 1) {
        return used;
    }

    pt[used++] = TCPOPT_SACK;
    unsigned char *op_len = &pt[used++];
    if (in.isMember(TCP_SERIA_NAME_OPT_SACK) && in[TCP_SERIA_NAME_OPT_SACK].isArray()) {
        for (Json::ArrayIndex i = 0; i < in[TCP_SERIA_NAME_OPT_SACK].size(); i++) {
            if (!in[TCP_SERIA_NAME_OPT_SACK][i].isArray() || in[TCP_SERIA_NAME_OPT_SACK][i].size() != 2) {
                continue;
            }
            if (used + 8 <= len) {
                *(int*)&pt[used] = ntohl(in[TCP_SERIA_NAME_OPT_SACK][i][0].asInt());
                *(int*)&pt[used+4] = ntohl(in[TCP_SERIA_NAME_OPT_SACK][i][1].asInt());
                used += 8;
            }
        }
    }
    *op_len = used;
    return used;
}

Json::Value TCPHeader::TimestampOptParse(const tcp_opt_t &optp)
{
    Json::Value root;

    root[TCP_SERIA_NAME_OPT_TYPE] = (int)optp.type;
    root[TCP_SERIA_NAME_OPT_NAME] = TCPHeader::Optcode2Str(optp.type);
    if (!optp.value || optp.len < 10) {
        return root;
    }
    root[TCP_SERIA_NAME_OPT_TIMESTAMP].append((int)ntohl(*(int*)(optp.value)));
    root[TCP_SERIA_NAME_OPT_TIMESTAMP].append((int)ntohl(*(int*)(optp.value + 4)));
    return root;
}

int TCPHeader::TimestampOptUnParse(const Json::Value &in, unsigned char *pt, int len)
{
    int used = 0;
    if (pt == NULL || len <= 1) {
        return used;
    }

    pt[used++] = TCPOPT_TSTAMP;
    unsigned char *op_len = &pt[used++];
    if (in.isMember(TCP_SERIA_NAME_OPT_TIMESTAMP) && in[TCP_SERIA_NAME_OPT_TIMESTAMP].isArray() && in[TCP_SERIA_NAME_OPT_TIMESTAMP].size()==2) {
        if (used + 8 <= len) {
            *(int*)&pt[used] = ntohl(in[TCP_SERIA_NAME_OPT_TIMESTAMP][0].asInt());
            *(int*)&pt[used + 4] = ntohl(in[TCP_SERIA_NAME_OPT_TIMESTAMP][1].asInt());
            used += 8;
        }
    }
    *op_len = used;
    return used;
}