#ifndef NBNS_HELPER_H_INCLUDED
#define NBNS_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <socket\SocketHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <socket/SocketHelper.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <vector>
#include <set>
#include <map>
#include <functional>
#include <mutex>

struct NBNSHeader;
namespace NBNSQueryBody
{
    struct tc;
}
namespace NBNSResponceBody
{
    struct tctd;
};

#define NBNS_RECV_TIMEOUT 2000
#define NBNS_SEND_TIMEOUT 1000
#define NBNS_TYPE_IS_PTR(byte_a) ((0XC0&(char)(byte_a))==(0XC0))
#define NBNS_QUERY_BUFSIZE 2048
#define NBNS_RESPONCE_BUFSIZE 2048
#define NBNS_QUERY_PACK_MINI_SIZE (sizeof(struct NBNSHeader)+sizeof(struct NBNSQueryBody::tc))
#define NBNS_RESPONCE_PACK_MINI_SIZE (sizeof(struct NBNSHeader)+sizeof(struct NBNSResponceBody::tctd))
#define NBNS_NAME_MAX_LENGTH 16

/*
00	Workstation, Domain Name
01	Messenger(Workstation)
03	Messenger(User)
06	Remote Access Server
1F	NetDDE
20	File Server
21	Remote Access Server Client
22	Microsoft Exchange Interchange
23	Microsoft Exchange Store
24	Microsoft Exchange Directory
87	Microsoft Exchange MTA
6A	Microsoft Exchange IMC
1B	Domain Master Browser
1C	Domain Controllers
1D	Master Browser
*/

#define NBNS_RECODE_NAME_WORKSTATION                    0X00
#define NBNS_RECODE_NAME_MESSENGER_WORKSTATION          0X01
#define NBNS_RECODE_NAME_MESSENGER_USER                 0X03
#define NBNS_RECODE_NAME_REMOTE_ACCESS_SERVER           0X06
#define NBNS_RECODE_NAME_NETDDE                         0X1F
#define NBNS_RECODE_NAME_FILE_SERVER                    0X20
#define NBNS_RECODE_NAME_REMOTE_ACCESS_SERVER_CLIENT    0X21
#define NBNS_RECODE_NAME_MEI                            0X22
#define NBNS_RECODE_NAME_MES                            0X23
#define NBNS_RECODE_NAME_MED                            0X24
#define NBNS_RECODE_NAME_MEMTA                          0X87
#define NBNS_RECODE_NAME_MEIMC                          0X6A
#define NBNS_RECODE_NAME_DOMAIN_MASTER_BROWSER          0X1B
#define NBNS_RECODE_NAME_DOMAIN_CONTROLLERS             0X1C
#define NBNS_RECODE_NAME_MASTERBROWSER                  0X1D
#define NBNS_RECODE_NAME_GROUP                          0XFF

#pragma pack(push,1)
#define NBNS_BCAST_PORT 137

#define NBNS_RECODE_TYPE_NB          0x0020   
#define NBNS_RECODE_TYPE_NBSTAT      0x0021    
#define NBNS_RECODE_TYPE_A           0x0001 
#define NBNS_RECODE_TYPE_NS          0x0002  
#define NBNS_RECODE_TYPE_NULL        0x000A

struct NBNSHeader
{
    unsigned short id;
#ifdef _BIG_ENDIAN
    union
    {
        unsigned short flags;
        struct {
            unsigned short flag_qr : 1;
            unsigned short flag_opcode : 4;
            unsigned short flag_aa : 1;
            unsigned short flag_tc : 1;
            unsigned short flag_rd : 1;
            unsigned short flag_ra : 1;
            unsigned short flag_z : 3;
            unsigned short flag_rcode : 4;
        }flag_in;
    }flag;
#else
    union
    {
        unsigned short flags;
        struct {
            unsigned short flag_rcode : 4;
            unsigned short flag_z : 3;
            unsigned short flag_ra : 1;
            unsigned short flag_rd : 1;
            unsigned short flag_tc : 1;
            unsigned short flag_aa : 1;
            unsigned short flag_opcode : 4;
            unsigned short flag_qr : 1;
        }flag_in;
    }flag;
#endif
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

namespace NBNSQueryBody
{
    struct name
    {
        unsigned char  *qname; //variable len, end with 0
    };
    struct tc
    {
        unsigned short qtype;
        unsigned short qclass;
    };
};

struct RecuName
{
#ifdef _BIG_ENDIAN
    union
    {
        unsigned short name;
        struct {
            unsigned short flag : 2;
            unsigned short off : 14;
        }name_in;
    }name;
#else
    union
    {
        unsigned short name;
        struct {
            unsigned short off : 14;
            unsigned short flag : 2;
        }name_in;
    }name;
#endif
};

namespace NBNSResponceBody
{
    struct name
    {
        unsigned char  *rname; //variable len, end with 0
    };
    struct tctd
    {
        unsigned short rtype;
        unsigned short rclass;
        unsigned int   rttl;
        unsigned short rdlen;
    };
    struct data
    {
        unsigned char  *rdata; //rdlen len
    };
};

namespace NBStatResponceData
{
    struct num_names
    {
        unsigned char  num_of_names;
    };
    struct name_entry
    {
        char name[16];
#ifdef _BIG_ENDIAN
        union
        {
            unsigned short flags;
            struct {
                unsigned short g : 1;
                unsigned short ont : 2;
                unsigned short org : 1;
                unsigned short cnf : 1;
                unsigned short act : 1;
                unsigned short prm : 1;
                unsigned short reserv : 9;
            }flag_in;
        }falg;
#else
        union
        {
            unsigned short flags;
            struct {
                unsigned short reserv : 9;
                unsigned short prm : 1;
                unsigned short act : 1;
                unsigned short cnf : 1;
                unsigned short org : 1;
                unsigned short ont : 2;
                unsigned short g : 1;
            }flag_in;
        }falg;
#endif
    };
    struct statistics
    {
        unsigned char unit_id[6];
        unsigned char jumper;
        unsigned char test_result;
        unsigned short version_number;
        unsigned short period_of_stat;
        unsigned short num_crc;
        unsigned short num_align_err;
        unsigned short num_collision;
        unsigned short num_send_abort;
        unsigned int num_good_send;
        unsigned int num_good_recv;
        unsigned short num_retransmit;
        unsigned short num_none_res;
        unsigned short num_cmd_block;
        unsigned short num_pend_sess;
        unsigned short max_num_pend_sess;
        unsigned short max_total_sess;
        unsigned short sess_data_pack_size;
    };
};

#pragma pack(pop)

class NBNSHelper : public BroadcastSocket
{
public:
    class NBStatTypeNameMap
    {
    public:
        std::map<int, std::set<std::string>> map;
    };
    typedef std::map<int, std::function<bool(const char *, int, int, int, NBStatTypeNameMap &)>> TypeDataOpType;

public:
    explicit NBNSHelper(u_int src_ip = INADDR_ANY) : BroadcastSocket(src_ip, 0) {}
    ~NBNSHelper(){}
    bool SendNBSTATRequest(u_int dst, const std::string &name = "*", const std::string &scope = "");
    bool RecvNextNBSTATResponce(std::string &from_ip, NBStatTypeNameMap &info);

public:
    static NBNSHeader GetNBNSQueryHeader(bool is_broad);
    static sockaddr_in GetNBNSSockaddr();
    static TypeDataOpType RegistTypeDataOp();

private:
    static bool GeneraterNBNSQueryPacket(const std::string &server, const std::string &scope, char *buf, size_t &size, bool is_broad);
    static bool CheckNBNSResponcevalidity(char *data, int size);
    static bool DealNBNSResponce(NBStatTypeNameMap &info, char *data, int size);
    static bool LevelOneEncode(const std::string &name, char *out);
    static bool LevelOneDecode(std::string &name, char *in);
    static bool EncodeDotStr(const std::string &type, char *byte, size_t &size);
    static bool DecodeDotStr(std::string &type, const char *packet, int size, int &deal_off);
    static bool ParseNBSTATData(const char *data, int size, int pos, int len, NBStatTypeNameMap &info);


private:
    static sockaddr_in m_nbns_addr;
    static TypeDataOpType m_nbns_type_data_op;
};

#endif