#ifndef TCP_HEADER_H_INCLUDED
#define TCP_HEADER_H_INCLUDED

#include "TransportLayerHeader.h"
#include <vector>
#include <map>

/* TCP FLAGS */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PSH   0x08
#define TH_ACK   0x10
#define TH_URG   0x20
#define TH_ECN   0x40
#define TH_ECE   0x40
#define TH_CWR   0x80

/* TCP OPTIONS */
#define TCPOPT_EOL         0   /* End of Option List (RFC793)                 */
#define TCPOPT_NOOP        1   /* No-Operation (RFC793)                       */
#define TCPOPT_MSS         2   /* Maximum Segment Size (RFC793)               */
#define TCPOPT_WSCALE      3   /* WSOPT - Window Scale (RFC1323)              */
#define TCPOPT_SACKOK      4   /* SACK Permitted (RFC2018)                    */
#define TCPOPT_SACK        5   /* SACK (RFC2018)                              */
#define TCPOPT_ECHOREQ     6   /* Echo (obsolete) (RFC1072)(RFC6247)          */
#define TCPOPT_ECHOREP     7   /* Echo Reply (obsolete) (RFC1072)(RFC6247)    */
#define TCPOPT_TSTAMP      8   /* TSOPT - Time Stamp Option (RFC1323)         */
#define TCPOPT_POCP        9   /* Partial Order Connection Permitted (obsol.) */
#define TCPOPT_POSP        10  /* Partial Order Service Profile (obsolete)    */
#define TCPOPT_CC          11  /* CC (obsolete) (RFC1644)(RFC6247)            */
#define TCPOPT_CCNEW       12  /* CC.NEW (obsolete) (RFC1644)(RFC6247)        */
#define TCPOPT_CCECHO      13  /* CC.ECHO (obsolete) (RFC1644)(RFC6247)       */
#define TCPOPT_ALTCSUMREQ  14  /* TCP Alternate Checksum Request (obsolete)   */
#define TCPOPT_ALTCSUMDATA 15  /* TCP Alternate Checksum Data (obsolete)      */
#define TCPOPT_MD5         19  /* MD5 Signature Option (obsolete) (RFC2385)   */
#define TCPOPT_SCPS        20  /* SCPS Capabilities                           */
#define TCPOPT_SNACK       21  /* Selective Negative Acknowledgements         */
#define TCPOPT_QSRES       27  /* Quick-Start Response (RFC4782)              */
#define TCPOPT_UTO         28  /* User Timeout Option (RFC5482)               */
#define TCPOPT_AO          29  /* TCP Authentication Option (RFC5925)         */

/* Internal constants */
#define TCP_HEADER_LEN 20
#define MAX_TCP_OPTIONS_LEN 40
#define MAX_TCP_PAYLOAD_LEN 65495 /**< Max len of a TCP packet               */

/* Default header values */
#define TCP_DEFAULT_SPORT 12345
#define TCP_DEFAULT_DPORT 80
#define TCP_DEFAULT_SEQ   0
#define TCP_DEFAULT_ACK   0
#define TCP_DEFAULT_FLAGS 0x02
#define TCP_DEFAULT_WIN   8192
#define TCP_DEFAULT_URP   0

#define TCP_SERIA_NAME_SRC_PORT "src_port"
#define TCP_SERIA_NAME_DST_PORT "dst_port"
#define TCP_SERIA_NAME_SEQ "seq"
#define TCP_SERIA_NAME_ACK "ack"
#define TCP_SERIA_NAME_OFFSET "head_len"
#define TCP_SERIA_NAME_RESERVE "reserve"
#define TCP_SERIA_NAME_CWR_FLAG "cwr_flag"
#define TCP_SERIA_NAME_ECE_FLAG "ece_flag"
#define TCP_SERIA_NAME_URG_FLAG "urg_flag"
#define TCP_SERIA_NAME_ACK_FLAG "ack_flag"
#define TCP_SERIA_NAME_PUSH_FLAG "push_flag"
#define TCP_SERIA_NAME_RST_FLAG "rst_flag"
#define TCP_SERIA_NAME_SYN_FLAG "syn_flag"
#define TCP_SERIA_NAME_FIN_FLAG "fin_flag"
#define TCP_SERIA_NAME_WINDOW "window"
#define TCP_SERIA_NAME_URG_POINT "urg_point"
#define TCP_SERIA_NAME_CHECK_SUM "check_sum"
#define TCP_SERIA_NAME_OPT "options"
#define TCP_SERIA_NAME_OPT_TYPE "type"
#define TCP_SERIA_NAME_OPT_NAME "name"
#define TCP_SERIA_NAME_OPT_DATA "data"
#define TCP_SERIA_NAME_OPT_MSS "mss"
#define TCP_SERIA_NAME_OPT_WSCALE "wscale"
#define TCP_SERIA_NAME_OPT_SACK "sack"
#define TCP_SERIA_NAME_OPT_TIMESTAMP "timestamp"
#pragma pack(push,1)
/*
+--------+--------+---------+--------...
|  Type  |  Len   |       Value
+--------+--------+---------+--------...
*/
typedef struct tcp_opt {
    unsigned char type;                           /* Option type code.           */
    unsigned char len;                            /* Option length.              */
    unsigned char *value;                         /* Option value                */
}tcp_opt_t;

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset| Res.  |C|E|U|A|P|R|S|F|            Window             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct tcp_hdr {
    unsigned short th_sport;                      /* Source port                 */
    unsigned short th_dport;                      /* Destination port            */
    unsigned int th_seq;                        /* Sequence number             */
    unsigned int th_ack;                        /* Acknowledgement number      */
#if WORDS_BIGENDIAN
    unsigned char th_off : 4;                   /* Data offset                 */
    unsigned char th_x2 : 4;                    /* Reserved                    */
#else
    unsigned char th_x2 : 4;                    /* Reserved                    */
    unsigned char th_off : 4;                   /* Data offset                 */
#endif
    unsigned char th_flags;                       /* Flags                       */
    unsigned short th_win;                        /* Window size                 */
    unsigned short th_sum;                        /* Checksum                    */
    unsigned short th_urp;                        /* Urgent pointer              */

    unsigned char options[MAX_TCP_OPTIONS_LEN];  /* Space for TCP Options       */
}tcp_hdr_t;
#pragma pack(pop)

class TCPHeader : public TransportLayerHeader
{
public:
    typedef Json::Value(*OptParse)(const tcp_opt_t &optp);
    typedef int(*OptUnParse)(const Json::Value &in, unsigned char *pt, int len);
    static std::map<int, OptParse> InitOptParse();
    static std::map<int, OptUnParse> InitOptUnParse();

public:
    TCPHeader();
    ~TCPHeader();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    bool Validate() const;
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    void SetSourcePort(unsigned short p);
    unsigned short GetSourcePort() const;

    void SetDestinationPort(unsigned short p);
    unsigned short GetDestinationPort() const;

    void SetSeq(unsigned int p);
    unsigned int GetSeq() const;

    void SetAck(unsigned int p);
    unsigned int GetAck() const;

    void SetHeaderLength();
    void SetHeaderLength(unsigned char l);
    unsigned char GetHeaderLength() const;

    void SetReserved(unsigned char r);
    unsigned char GetReserved() const;

    void SetFlags(unsigned char f);
    unsigned char GetFlags() const;
    unsigned short GetFlags16() const;
    void SetCWR();
    void UnsetCWR();
    bool GetCWR() const;
    void SetECE();
    void UnsetECE();
    bool GetECE() const;
    void SetECN();
    void UnsetECN();
    bool GetECN() const;
    void SetURG();
    void UnsetURG();
    bool GetURG() const;
    void SetACK();
    void UnsetACK();
    bool GetACK() const;
    void SetPSH();
    void UnsetPSH();
    bool GetPSH() const;
    void SetRST();
    void UnsetRST();
    bool GetRST() const;
    void SetSYN();
    void UnsetSYN();
    bool GetSYN() const;
    void SetFIN();
    void UnsetFIN();
    bool GetFIN() const;

    void SetWindow(unsigned short p);
    unsigned short GetWindow() const;

    void SetUrgPointer(unsigned short l);
    unsigned short GetUrgPointer() const;

    void SetSum();
    void SetSum(unsigned short s);
    unsigned short GetSum() const;

    void SetOptions(const unsigned char *optsbuff, size_t optslen);
    std::vector<tcp_opt_t> GetOption() const;
    static std::string Optcode2Str(unsigned char optcode);

public:
    static int GenerateNopOpt(unsigned char *buf, int len);
    static int GenerateMssOpt(unsigned char *buf, int len, unsigned short mss);
    static int GenerateWinScaleOpt(unsigned char *buf, int len, unsigned char wscale);
    static int GenerateSackPermOpt(unsigned char *buf, int len);
    static int GenerateSackOpt(unsigned char *buf, int len, const std::vector<std::pair<unsigned int, unsigned int>> &sack);
    static int GenerateTimestampOpt(unsigned char *buf, int len, unsigned int req_time, unsigned int ack_time);

private:
    static Json::Value CommonOptParse(const tcp_opt_t &optp);
    static int CommonOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value NopOptParse(const tcp_opt_t &optp);
    static int NopOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value MssOptParse(const tcp_opt_t &optp);
    static int MssOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value WinScaleOptParse(const tcp_opt_t &optp);
    static int WinScaleOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value SackPermOptParse(const tcp_opt_t &optp);
    static int SackPermOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value SackOptParse(const tcp_opt_t &optp);
    static int SackOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static Json::Value TimestampOptParse(const tcp_opt_t &optp);
    static int TimestampOptUnParse(const Json::Value &in, unsigned char *pt, int len);
    static std::map<int, OptParse> optparse;
    static std::map<int, OptUnParse> optunparse;

private:
    tcp_hdr_t h;
    int tcpoptlen; /**< Length of TCP options */

}; /* End of class TCPHeader */

#endif