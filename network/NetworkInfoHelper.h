#ifndef NETWORKINFO_HELPER_H_INCLUDED
#define NETWORKINFO_HELPER_H_INCLUDED

#include <string>
#include <mutex>
#include <map>
#include "NetworkHelper.h"
#if defined(_MSC_VER)
#include <ImageHlp.h>
#include <wlanapi.h>
#include <netlistmgr.h>
#include <iphlpapi.h>
#include <oleauto.h>
#elif defined(__GNUC__)
#include <stdlib.h>
#include <string.h>
#else
#error unsupported compiler
#endif

#define NETWORKINFO_ETH_ARP         0x0806  
#define NETWORKINFO_ARP_HARDWARE    1      
#define NETWORKINFO_ETH_IP          0x0800 
#define NETWORKINFO_ARP_REQUEST     1      
#define NETWORKINFO_ARP_REPLY       2     
#define NETWORKINFO_HOSTNUM         255  
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#define NETWORK_INFO_MAC_SPLITE ":"

class NetworkInfoHelper
{
public:
#pragma pack(push,1)
    struct EthernetHeader
    {
        unsigned char DestMAC[6];
        unsigned char SourMAC[6];
        unsigned short EthType;
    };

    struct Arpheader {
        unsigned short HardwareType;
        unsigned short ProtocolType;
        unsigned char HardwareAddLen;
        unsigned char ProtocolAddLen;
        unsigned short OperationField;
        unsigned char SourceMacAdd[6];
        unsigned int SourceIpAdd;
        unsigned char DestMacAdd[6];
        unsigned int DestIpAdd;
    };

    struct ArpPacket {
        struct EthernetHeader eh;
        struct Arpheader ah;
    };
#pragma pack(pop)

#if defined(_MSC_VER)
#elif defined(__GNUC__)
    typedef struct {
        unsigned long  Data1;
        unsigned short Data2;
        unsigned short Data3;
        unsigned char  Data4[8];
    } GUID;
#else
#error unsupported compiler
#endif

    class RouteInfo
    {
    public:
        RouteInfo():dstAddr(0), dstmask(0), srcAddr(0), gateWay(0), metric(0), index(-1)
        {
        }
        u_int dstAddr;
        u_int dstmask;
        u_int srcAddr;
        u_int gateWay;
        u_int metric;
        u_int index;
    };

    class Route
    {
    public:
        Route() :dstAddr(0), srcAddr(0), srcMac{ 0 }, index(-1)
        {
        }
        u_int  dstAddr;
        u_int  srcAddr;
        u_char srcMac[6];
        u_int  index;
    };

    class WifiInfo
    {
    public:
        WifiInfo() { clear(); }

        WifiInfo(const WifiInfo &info)
        {
            copy(info);
        }

        WifiInfo& operator=(const WifiInfo &info)
        {
            return copy(info);
        }

        WifiInfo& copy(const WifiInfo &info)
        {
            this->adapter_name = info.adapter_name;
            this->adapter_dec = info.adapter_dec;
            this->bssid = info.bssid;
            this->pwsd = info.pwsd;
            this->ssid = info.ssid;
#if defined(_MSC_VER)
            this->dot11DefaultAuthAlgorithm = info.dot11DefaultAuthAlgorithm;
            this->dot11DefaultCipherAlgorithm = info.dot11DefaultCipherAlgorithm;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
            return *this;
        }

        WifiInfo& clear()
        {

            this->adapter_name = "";
            this->adapter_dec = "";
            this->bssid = "";
            this->pwsd = "";
            this->ssid = "";
#if defined(_MSC_VER)
            this->dot11DefaultAuthAlgorithm = -1;
            this->dot11DefaultCipherAlgorithm = -1;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
            return *this;
        }

        std::string adapter_name;
        std::string adapter_dec;
        std::string ssid;
#if defined(_MSC_VER)
        int dot11DefaultAuthAlgorithm;
        int dot11DefaultCipherAlgorithm;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
        std::string bssid;
        std::string pwsd;
    };

    class AdaptInfo
    {
    public:
        AdaptInfo() { clear(); }

        AdaptInfo(const AdaptInfo &info)
        {
            copy(info);
        }

        AdaptInfo& operator=(const AdaptInfo &info)
        {
            return copy(info);
        }

        AdaptInfo& copy(const AdaptInfo &info)
        {
            this->adapter_name = info.adapter_name;
            this->adapter_dec = info.adapter_dec;
            this->dhcp_ip_address = info.dhcp_ip_address;
            this->dhcp_ip_address_int = info.dhcp_ip_address_int;
            this->gateway_ip_address = info.gateway_ip_address;
            this->gateway_ip_address_int = info.gateway_ip_address_int;
            this->gateway_mac_address = info.gateway_mac_address;
            memcpy(this->gateway_mac_address_int, info.gateway_mac_address_int, sizeof(this->gateway_mac_address_int));
            this->local_ip_address = info.local_ip_address;
            this->local_ip_address_int = info.local_ip_address_int;
            this->local_ipv6_address = info.local_ipv6_address;
            this->local_ipv6_address_int = info.local_ipv6_address_int;
            this->local_mac_address = info.local_mac_address;
            memcpy(this->local_mac_address_int, info.local_mac_address_int, sizeof(this->local_mac_address_int));
            this->subnet_ip_mask = info.subnet_ip_mask;
            this->subnet_ip_mask_int = info.subnet_ip_mask_int;
            this->index = info.index;
            this->guid = info.guid;
            return *this;
        }

        AdaptInfo& clear()
        {
            this->adapter_name = "";
            this->adapter_dec = "";
            this->dhcp_ip_address = "";
            this->dhcp_ip_address_int.s_addr = 0;
            this->gateway_ip_address = "";
            this->gateway_ip_address_int.s_addr = 0;
            this->gateway_mac_address = "";
            memset(this->gateway_mac_address_int, 0, sizeof(this->gateway_mac_address_int));
            this->local_ip_address = "";
            this->local_ip_address_int.s_addr = 0;
            this->local_ipv6_address = "";
            memset(&this->local_ipv6_address_int, 0, sizeof(this->local_ipv6_address_int));
            this->local_mac_address = "";
            memset(this->local_mac_address_int, 0, sizeof(this->local_mac_address_int));
            this->subnet_ip_mask = "";
            this->subnet_ip_mask_int.s_addr = 0;
            this->index = -1;
            memset(&this->guid, 0, sizeof(this->guid));
            return *this;
        }

        std::string adapter_name;
        std::string adapter_dec;
        std::string local_ip_address;
        in_addr local_ip_address_int;
        std::string local_ipv6_address;
        in6_addr local_ipv6_address_int;
        std::string local_mac_address;
        unsigned char local_mac_address_int[6];
        std::string gateway_ip_address;
        in_addr gateway_ip_address_int;
        std::string gateway_mac_address;
        unsigned char gateway_mac_address_int[6];
        std::string subnet_ip_mask;
        in_addr subnet_ip_mask_int;
        std::string dhcp_ip_address;
        in_addr dhcp_ip_address_int;
        u_int       index;
        GUID    guid;
    };

    class CategoryInfo
    {
    public:
        CategoryInfo() { clear(); }

        CategoryInfo(const CategoryInfo &info)
        {
            copy(info);
        }

        CategoryInfo& operator=(const CategoryInfo &info)
        {
            return copy(info);
        }

        CategoryInfo& copy(const CategoryInfo &info)
        {
#if defined(_MSC_VER)
            this->category_name = info.category_name;
            this->category_dec = info.category_dec;
            this->network_category = info.network_category;
            this->domain_type = info.domain_type;
            this->connective = info.connective;
            this->is_connected = info.is_connected;
            this->is_connect_to_internet = info.is_connect_to_internet;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
            return *this;
        }

        CategoryInfo& clear()
        {
#if defined(_MSC_VER)
            this->category_name = "";
            this->category_dec = "";
            this->network_category = NLM_NETWORK_CATEGORY_PUBLIC;
            this->domain_type = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
            this->connective = NLM_CONNECTIVITY_DISCONNECTED;
            this->is_connected = false;
            this->is_connect_to_internet = false;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
            return *this;
        }
#if defined(_MSC_VER)
        std::string category_name;
        std::string category_dec;
        NLM_NETWORK_CATEGORY network_category;
        NLM_DOMAIN_TYPE      domain_type;
        NLM_CONNECTIVITY     connective;
        VARIANT_BOOL         is_connected;
        VARIANT_BOOL         is_connect_to_internet;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
    };

    class NetworkInfo
    {
    public:
        NetworkInfo() { clear(); }
        NetworkInfo(const NetworkInfo &info)
        {
            copy(info);
        }

        NetworkInfo& operator=(const NetworkInfo &info)
        {
            return copy(info);
        }

        NetworkInfo& copy(const NetworkInfo &info)
        {
            this->is_wifi = info.is_wifi;
            this->wifi_info = info.wifi_info;
            this->adapt_info = info.adapt_info;
            this->category_info = info.category_info;
            return *this;
        }

        NetworkInfo& clear()
        {
            this->is_wifi = false;
            this->wifi_info.clear();
            this->adapt_info.clear();
            this->category_info.clear();
            return *this;
        }
        bool is_wifi;
        WifiInfo wifi_info;
        AdaptInfo adapt_info;
        CategoryInfo category_info;
    };

public:
    static NetworkInfoHelper& GetInstance();
    /**
    *get all the network info that connect to the internet
    *infos[in] the network info buf, you can input null to get need size
    *count[in] the network info buf count
    *need_gateway_mac(in): is need resolve gateway mac addr
    *return valide size
    */
    static u_int GetAllNetworkInfo(NetworkInfo *infos, u_int count, bool need_gateway_mac = true);
    /**
    *use arp protocol to fine the mac of ip
    *ip[in] the ip that you want to find the mac
    *timeout[in] the timeout, windows not support this para
    *eth_index[in] the eth that used to get eht mac, arptable use
    *src_ip[in] the eth that used to get eht mac, sendarp use
    *return the mac of the ip
    */
    static std::string GetMacFromAddress(const std::string& ip, u_int timeout = 3000, int eth_index = -1, const std::string& src_ip = "");
    /**
    *use arp protocol to fine the mac of ip
    *ip[in] the ip that you want to find the mac
    *timeout[in] the timeout, windows not support this para
    *eth_index[in] the eth that used to get eht mac, arptable use
    *src_ip[in] the eth that used to get eht mac, sendarp use
    *return the mac of the ip
    */
    static std::string GetMacFromAddress(const in_addr& _ip, u_int timeout = 3000, int eth_index = -1, const in_addr& src_ip = { 0 });
    /**
    *get the eth index of the ip
    *ip[in] the ip that you want to find the eth index
    *return -1 for error
    */
    static int GetEthIndexFromAddress(const std::string& ip);
    /**
    *get the eth index of the ip
    *ip[in] the ip that you want to find the eth index
    *return -1 for error
    */
    static int GetEthIndexFromAddress(const in_addr& _ip);
    /**
    *get all the route info
    *info[in] the routeinfo buf, you can input null to get need size
    *count[in] the routeinfo buf count
    *return valide size
    */
    static u_int GetAllRouteInfo(RouteInfo *infos, u_int count);
    /**
    *get the route info of dst
    *route(out): the route that choose
    *dst(in): dst ip
    *return true for success
    */
    static bool GetDstRoute(Route &route, const in_addr &dst);
    /**
    *get the route info of dst
    *route(out): the route that choose
    *dst(in): dst ip
    *return true for success
    */
    static bool GetDstRoute(Route &route, int dst);
    /**
    *get the specify ip network info
    *ip(in): the ip
    *use_mask(in): is use netmask to choose the interface
    *need_gateway_mac(in): is need resolve gateway mac addr
    */
    static NetworkInfo GetNetworkInfoByIp(u_int ip, bool use_mask, bool need_gateway_mac = true);
    /**
    *get the specify ip adapt info
    *ip(in): the ip
    *use_mask(in): is use netmask to choose the interface
    *need_gateway_mac(in): is need resolve gateway mac addr
    */
    static AdaptInfo GetAdaptInfoByIp(u_int ip, bool use_mask, bool need_gateway_mac = true);
    /**
    *get all device under specify network
    *network_info(in): network need to discover devices
    *return a map of ip:mac
    */
    static std::map<std::string, std::string> GetAllNeighborDevices(const NetworkInfo &network_info);
    /**
    *callback of async fun GetAllNeighborDevices
    *ip(in): the device ip
    *mac(in): the device mac
    *last(in): is the last device, will not callback any other device, when true, ip mac may be empty
    *if callback return false, the get devices action will be stop and you will not recv callback any more
    */
    typedef bool(*GetDevicesCallBack)(const std::string &ip, const std::string &mac, bool last);
    /**
    *get all device under specify network
    *network_info(in): network need to discover devices
    *callback(in): callback of recv result
    */
    static bool GetAllNeighborDevices(const NetworkInfo &network_info, GetDevicesCallBack callback);
    /**
    *get the ipv6 addr from the specify ipv4 addr eth
    *ipv6(out): ipv6
    *index(in): eth index
    */
    static bool GetIpv6ByIndex(in6_addr &ipv6, u_int index);
#if defined(_MSC_VER)
    /**
    *get the process id of specify process name
    *pszProcessName[in] the process name of wchar
    *return the process id of the process name
    */
    static DWORD GetProcessIdByProcessName(LPCWSTR pszProcessName);
    /**
    *enable or disable current specify privilege
    *pszPrivilege[in] the specify privilege that to operate
    *bEnablePrivilege[in] enable the privilege or disable the privilege
    *return true or false
    */
    static BOOL SetCurrentPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege);
    /**
    *decrypt the hex string key
    *pKeyMaterial[in] the hex string key that encrypt by system
    *pPassBuf[out] the decrypted text
    *pPassBufLen[in] size of pPassBuf
    *return 0-success, other-fail
    */
    static int DecryptKeyMaterial(char *pKeyMaterial, char *pPassBuf, int pPassBufLen);
#elif defined(__GNUC__)
    /**
    *send arp pack and get rsp
    *DestIP(in): dst ip of network byte order
    *SrcIP(in): src ip of network byte order
    */
    static u_int SendARP(u_int DestIP, u_int SrcIP, u_char *mac, u_long *len, u_int timeout = 3000);
    /**
    *get default gateway
    */
    static bool GetDefaultGateway(u_int &ip, u_int &eth_index);
#else
#error unsupported compiler
#endif

public:
    ~NetworkInfoHelper();
    /**
    *get the current using network name
    */
    std::string GetNetWorkName();
    /**
    *get the current gateway mac
    */
    std::string GetGatewayMac();
    /**
    *get the previous gateway mac
    */
    std::string GetPreNetworkGatewayMac();
    /**
    *is current network connect to the internet
    */
    bool IsConnectToInternet();
    /**
    *when the network has changed, you should invoke this to update the network cache before you invoke GetNetworkInfo
    *is_network_change[out] if the network has changed since you invoke UpadteNetworkInfo last time
    *note: if you have use NLMHelper register the network change listener, it will update network info auto
    */
    void UpadteNetworkInfo(bool &is_network_change);
    /**
    *show if current using network is wifi
    */
    bool IsWifi();
    /**
    *get the network info of current network, wifi first, only one connect network will return, see UpadteNetworkInfo for more information
    */
    NetworkInfo GetNetworkInfo();
    /**
    *get the previous network info, see UpadteNetworkInfo for more information
    */
    NetworkInfo GetPreNetworkInfo();

private:
#if defined(_MSC_VER)
    static bool GetWStrWifiSSID(std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid);
    static void GetWifiSSIDAndPwd(std::string &ssid, std::string &pwd, std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid);
    static void GetWifiDot11AuthAndCipherAlgorthim(int &dot11DefaultAuthAlgorithm, int &dot11DefaultCipherAlgorithm, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid);
    static void GetWifiBSSID(std::string &bssid, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid);
#elif defined(__GNUC__)
    static ArpPacket m_request_arp_pack;
    static ArpPacket PreBuildARPRequestPack();
    static u_int SendARPPrivate(u_int DestIP, const AdaptInfo &info, u_char *mac, u_long *len, u_int timeout);
    static void GenerateArpRequestPacket(ArpPacket &pack, u_int dest_iP, u_int src_iP, std::string src_mac);
    static int ReadNlSock(int sockFd, char *bufPtr, int buf_size, int seqNum, int pId);
    static bool ParseOneRoute(struct nlmsghdr *nlHdr, RouteInfo *rtInfo);
    static u_int IfNameToIndex(const std::string &name);
#else
#error unsupported compiler
#endif
    static u_int GetAllWifiInfo(WifiInfo *infos, u_int count);
    static u_int GetAllAdaptInfo(AdaptInfo *infos, u_int count, bool need_gateway_mac = true);
    static CategoryInfo GetCategoryInfo(const GUID &guid, u_int max_wait_time = 3 * 1000);

private:
    NetworkInfoHelper();
    void GetAdaptInfo();
    bool GetWifiInfo();
    void AdaptGatewayMacAddress();

private:
    static std::mutex m_netowrk_info_lock;

private:
    NetworkInfo m_pre_network_info;
    NetworkInfo m_last_update_network_info;
    NetworkInfo m_cur_network_info;
};

#endif