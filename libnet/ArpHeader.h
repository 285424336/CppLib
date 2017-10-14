#ifndef ARP_HEADER_H_INCLUDED
#define ARP_HEADER_H_INCLUDED

#include "NetBase.h"

/* Lengths */
#define ARP_HEADER_LEN 28
#define IPv4_ADDRESS_LEN 4
#define ETH_ADDRESS_LEN  6

/* Hardware Types */
#define HDR_RESERVED      0    /* [RFC5494]                                   */
#define HDR_ETH10MB       1    /* Ethernet (10Mb)                             */
#define HDR_ETH3MB        2    /* Experimental Ethernet (3Mb)                 */
#define HDR_AX25          3    /* Amateur Radio AX.25                         */
#define HDR_PRONET_TR     4    /* Proteon ProNET Token Ring                   */
#define HDR_CHAOS         5    /* Chaos                                       */
#define HDR_IEEE802       6    /* IEEE 802 Networks                           */
#define HDR_ARCNET        7    /* ARCNET [RFC1201]                            */
#define HDR_HYPERCHANNEL  8    /* Hyperchannel                                */
#define HDR_LANSTAR       9    /* Lanstar                                     */
#define HDR_AUTONET       10   /* Autonet Short Address                       */
#define HDR_LOCALTALK     11   /* LocalTalk                                   */
#define HDR_LOCALNET      12   /* LocalNet (IBM PCNet or SYTEK LocalNET)      */
#define HDR_ULTRALINK     13   /* Ultra link                                  */
#define HDR_SMDS          14   /* SMDS                                        */
#define HDR_FRAMERELAY    15   /* Frame Relay                                 */
#define HDR_ATM           16   /* Asynchronous Transmission Mode (ATM)        */
#define HDR_HDLC          17   /* HDLC                                        */
#define HDR_FIBRE         18   /* Fibre Channel [RFC4338]                     */
#define HDR_ATMb          19   /* Asynchronous Transmission Mode (ATM)        */
#define HDR_SERIAL        20   /* Serial Line                                 */
#define HDR_ATMc          21   /* Asynchronous Transmission Mode [RFC2225]    */
#define HDR_MILSTD        22   /* MIL-STD-188-220                             */
#define HDR_METRICOM      23   /* Metricom                                    */
#define HDR_IEEE1394      24   /* IEEE 1394.199                               */
#define HDR_MAPOS         25   /* MAPOS [RFC2176]                             */
#define HDR_TWINAXIAL     26   /* Twinaxial                                   */
#define HDR_EUI64         27   /* EUI-64                                      */
#define HDR_HIPARP        28   /* HIPARP                                      */
#define HDR_ISO7816       29   /* IP and ARP over ISO 7816-3                  */
#define HDR_ARPSEC        30   /* ARPSec                                      */
#define HDR_IPSEC         31   /* IPsec tunnel                                */
#define HDR_INFINIBAND    32   /* InfiniBand (TM)                             */
#define HDR_TIA102        33   /* TIA-102 Project 25 Common Air Interface     */
#define HDR_WIEGAND       34   /* Wiegand Interface                           */
#define HDR_PUREIP        35   /* Pure IP                                     */
#define HDR_HW_EXP1       36   /* HW_EXP1 [RFC5494]                           */
#define HDR_HW_EXP2       37   /* HW_EXP2 [RFC5494]                           */

/* Operation Codes */
#define OP_ARP_REQUEST    1     /* ARP Request                                */
#define OP_ARP_REPLY      2     /* ARP Reply                                  */
#define OP_RARP_REQUEST   3     /* Reverse ARP Request                        */
#define OP_RARP_REPLY     4     /* Reverse ARP Reply                          */
#define OP_DRARP_REQUEST  5     /* DRARP-Request                              */
#define OP_DRARP_REPLY    6     /* DRARP-Reply                                */
#define OP_DRARP_ERROR    7     /* DRARP-Error                                */
#define OP_INARP_REQUEST  8     /* InARP-Request                              */
#define OP_INARP_REPLY    9     /* InARP-Reply                                */
#define OP_ARPNAK         10    /* ARP-NAK                                    */
#define OP_MARS_REQUEST   11    /* MARS-Request                               */
#define OP_MARS_MULTI     12    /* MARS-Multi                                 */
#define OP_MARS_MSERV     13    /* MARS-MServ                                 */
#define OP_MARS_JOIN      14    /* MARS-Join                                  */
#define OP_MARS_LEAVE     15    /* MARS-Leave                                 */
#define OP_MARS_NAK       16    /* MARS-NAK                                   */
#define OP_MARS_UNSERV    17    /* MARS-Unserv                                */
#define OP_MARS_SJOIN     18    /* MARS-SJoin                                 */
#define OP_MARS_SLEAVE    19    /* MARS-SLeave                                */
#define OP_MARS_GL_REQ    20    /* MARS-Grouplist-Request                     */
#define OP_MARS_GL_REP    21    /* MARS-Grouplist-Reply                       */
#define OP_MARS_REDIR_MAP 22    /* MARS-Redirect-Map                          */
#define OP_MAPOS_UNARP    23    /* MAPOS-UNARP [RFC2176]                      */
#define OP_EXP1           24    /* OP_EXP1 [RFC5494]                          */
#define OP_EXP2           25    /* OP_EXP2 [RFC5494]                          */
#define OP_RESERVED       65535 /* Reserved [RFC5494]                         */

#define ARP_SERIA_NAME_HARDWARE_TYPE          "hardware_type"
#define ARP_SERIA_NAME_PROTOCAL_TYPE          "protocal_type"
#define ARP_SERIA_NAME_HARDWARE_ADDR_LEN      "hardware_addr_len"
#define ARP_SERIA_NAME_PROTOCAL_ADDR_LEN      "protocal_addr_len"
#define ARP_SERIA_NAME_OP_CODE                "op_code"
#define ARP_SERIA_NAME_SENDER_MAC             "sender_mac"
#define ARP_SERIA_NAME_SENDER_IP              "sender_ip"
#define ARP_SERIA_NAME_TARGET_MAC             "target_mac"
#define ARP_SERIA_NAME_TARGET_IP              "target_ip"

#pragma pack(push,1)
typedef struct arp_hdr {
    unsigned short ar_hrd;   /* Hardware Type.                               */
    unsigned short ar_pro;   /* Protocol Type.                               */
    unsigned char  ar_hln;   /* Hardware Address Length.                     */
    unsigned char  ar_pln;   /* Protocol Address Length.                     */
    unsigned short ar_op;    /* Operation Code.                              */
    unsigned char  ar_sha[6];/* Sender Hardware Address.                     */
    unsigned int   ar_sip;   /* Sender Protocol Address (IPv4 address).      */
    unsigned char  ar_tha[6];/* Target Hardware Address.                     */
    unsigned int   ar_tip;   /* Target Protocol Address (IPv4 address).      */
}arp_hdr_t;
#pragma pack(pop)

class ArpHeader : public NetBase
{
public:
    ArpHeader();
    ~ArpHeader();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    /* Hardware Type */
    void SetHardwareType(unsigned short t = HDR_ETH10MB);
    unsigned short GetHardwareType() const;
    /* Protocol Type */
    void SetProtocolType(unsigned short t = 0x0800);
    unsigned short GetProtocolType() const;
    /* Hardware Address Length */
    void SetHwAddrLen(unsigned char v = ETH_ADDRESS_LEN);
    unsigned char GetHwAddrLen() const;
    /* Hardware Address Length */
    void SetProtoAddrLen(unsigned char v = IPv4_ADDRESS_LEN);
    unsigned char GetProtoAddrLen() const;
    /* Operation Code */
    void SetOpCode(unsigned short c);
    unsigned short GetOpCode() const;
    /* Sender Hardware Address */
    bool SetSenderMAC(const unsigned char *m, size_t len);
    bool GetSenderMAC(unsigned char *m, size_t len) const;
    /* Sender Protocol address */
    void SetSenderIP(struct in_addr i);
    void SetSenderIP(u_int i);
    struct in_addr GetSenderIP() const;
    /* Target Hardware Address */
    bool SetTargetMAC(const unsigned char *m, size_t len);
    bool GetTargetMAC(unsigned char *m, size_t len) const;
    /* Target Protocol Address */
    void SetTargetIP(struct in_addr i);
    void SetTargetIP(u_int i);
    struct in_addr GetTargetIP() const;

private:
    arp_hdr_t h;
};

#endif