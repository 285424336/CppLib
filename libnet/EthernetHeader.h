#ifndef ETHERNET_HEADER_H_INCLUDED
#define ETHERNET_HEADER_H_INCLUDED

#include "NetBase.h"

#define ETHTYPE_IPV4       0x0800 /* Internet Protocol Version 4              */
#define ETHTYPE_ARP        0x0806 /* Address Resolution Protocol              */
#define ETHTYPE_FRAMERELAY 0x0808 /* Frame Relay ARP                          */
#define ETHTYPE_PPTP       0x880B /* Point-to-Point Tunneling Protocol        */
#define ETHTYPE_GSMP       0x880C /* General Switch Management Protocol       */
#define ETHTYPE_RARP       0x8035 /* Reverse Address Resolution Protocol      */
#define ETHTYPE_IPV6       0x86DD /* Internet Protocol Version 6              */
#define ETHTYPE_MPLS       0x8847 /* MPLS                                     */
#define ETHTYPE_MPS_UAL    0x8848 /* MPLS with upstream-assigned label        */
#define ETHTYPE_MCAP       0x8861 /* Multicast Channel Allocation Protocol    */
#define ETHTYPE_PPPOE_D    0x8863 /* PPP over Ethernet Discovery Stage        */
#define ETHTYPE_PPOE_S     0x8864 /* PPP over Ethernet Session Stage          */
#define ETHTYPE_CTAG       0x8100 /* Customer VLAN Tag Type                   */
#define ETHTYPE_EPON       0x8808 /* Ethernet Passive Optical Network         */
#define ETHTYPE_PBNAC      0x888E /* Port-based network access control        */
#define ETHTYPE_STAG       0x88A8 /* Service VLAN tag identifier              */
#define ETHTYPE_ETHEXP1    0x88B5 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHEXP2    0x88B6 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHOUI     0x88B7 /* OUI Extended Ethertype                   */
#define ETHTYPE_PREAUTH    0x88C7 /* Pre-Authentication                       */
#define ETHTYPE_LLDP       0x88CC /* Link Layer Discovery Protocol (LLDP)     */
#define ETHTYPE_MACSEC     0x88E5 /* Media Access Control Security            */
#define ETHTYPE_MVRP       0x88F5 /* Multiple VLAN Registration Protocol      */
#define ETHTYPE_MMRP       0x88F6 /* Multiple Multicast Registration Protocol */
#define ETHTYPE_FRRR       0x890D /* Fast Roaming Remote Request              */

#define ETH_HEADER_LEN 14

#define ETH_SERIA_NAME_SRC_MAC          "src_mac"
#define ETH_SERIA_NAME_DST_MAC          "dst_mac"
#define ETH_SERIA_NAME_ETH_TYPE         "eth_type"


#pragma pack(push,1)
typedef struct eth_hdr 
{
    unsigned char  eth_dmac[6];
    unsigned char  eth_smac[6];
    unsigned short eth_type;
}eth_hdr_t;
#pragma pack(pop)

class EthernetHeader : public NetBase
{
public:
    EthernetHeader();
    ~EthernetHeader();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

    bool SetSrcMAC(const unsigned char *m, size_t len);
    bool GetSrcMAC(unsigned char *m, size_t len) const;
    bool SetDstMAC(const unsigned char *m, size_t len);
    bool GetDstMAC(unsigned char *m, size_t len) const;
    void SetEtherType(unsigned short val = ETHTYPE_IPV4);
    unsigned short GetEtherType() const;

private:
    eth_hdr_t h;
};

#endif
