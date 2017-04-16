#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atlbase.h>
#include <ImageHlp.h>
#include <wlanapi.h>
#include <netlistmgr.h>
#include <pugixml\pugixml.hpp>
#include <string\StringHelper.h>
#include <uid\UidHelper.h>
#pragma comment(lib, "ImageHlp.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "oleaut32.lib")
#elif defined(__GNUC__)
#include <unistd.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <string/StringHelper.h>
#include <kernel32/Kernel32Helper.h>
#include <sys/time.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include "NetworkInfoHelper.h"

std::mutex NetworkInfoHelper::m_netowrk_info_lock;

#if defined(_MSC_VER)
#elif defined(__GNUC__)
NetworkInfoHelper::ArpPacket NetworkInfoHelper::m_request_arp_pack = PreBuildARPRequestPack();
NetworkInfoHelper::ArpPacket NetworkInfoHelper::PreBuildARPRequestPack()
{
    ArpPacket pack = { 0 };
    memset(pack.eh.DestMAC, 0xff, 6);
    memset(pack.ah.DestMacAdd, 0x00, 6);
    pack.eh.EthType = htons(NETWORKINFO_ETH_ARP);
    pack.ah.HardwareType = htons(NETWORKINFO_ARP_HARDWARE);
    pack.ah.ProtocolType = htons(NETWORKINFO_ETH_IP);
    pack.ah.HardwareAddLen = 6;
    pack.ah.ProtocolAddLen = 4;
    pack.ah.DestIpAdd = 0;
    pack.ah.OperationField = htons(NETWORKINFO_ARP_REQUEST);
    return pack;
}
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)

#define NUM_NETWORK		20
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef LONG KPRIORITY; // Thread priority
typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT   PVOID SystemInformation,
    IN       ULONG SystemInformationLength,
    OUT OPTIONAL  PULONG ReturnLength
    );

DWORD NetworkInfoHelper::GetProcessIdByProcessName(LPCWSTR pszProcessName)
{
    ULONG bufferSize = 1024 * sizeof(SYSTEM_PROCESS_INFORMATION_DETAILD);
    PSYSTEM_PROCESS_INFORMATION_DETAILD pspid = NULL;
    HANDLE hHeap = GetProcessHeap();
    PBYTE pBuffer = NULL;
    ULONG ReturnLength;
    PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
        GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
    NTSTATUS status;
    int uLen = lstrlenW(pszProcessName) * sizeof(WCHAR);

    __try {
        pBuffer = (PBYTE)HeapAlloc(hHeap, 0, bufferSize);
#pragma warning(disable: 4127)
        while (TRUE) {
#pragma warning(default: 4127)
            status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pBuffer,
                bufferSize, &ReturnLength);
            if (status == STATUS_SUCCESS)
                break;
            else if (status != STATUS_INFO_LENGTH_MISMATCH) { // 0xC0000004L
                return 1;   // error
            }

            bufferSize *= 2;
            pBuffer = (PBYTE)HeapReAlloc(hHeap, 0, (PVOID)pBuffer, bufferSize);
        }

        for (pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)pBuffer; ;
            pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

            if (pspid->ImageName.Length == uLen && lstrcmpiW(pspid->ImageName.Buffer, pszProcessName) == 0)
                return (DWORD)pspid->UniqueProcessId;

            if (pspid->NextEntryOffset == 0) break;
        }
    }
    __finally {
        HeapFree(hHeap, 0, pBuffer);
        pBuffer = NULL;
    }
    return 0;
}

BOOL NetworkInfoHelper::SetCurrentPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
    BOOL bSuccess = FALSE;

    if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid))
        return FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    //
    // first pass.  get current privilege setting
    //
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);

    if (GetLastError() == ERROR_SUCCESS)
    {
        //
        // second pass.  set privilege based on previous setting
        //
        tpPrevious.PrivilegeCount = 1;
        tpPrevious.Privileges[0].Luid = luid;

        if (bEnablePrivilege)
            tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
        else
            tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

        AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);

        if (GetLastError() == ERROR_SUCCESS)
            bSuccess = TRUE;

        CloseHandle(hToken);
    }
    else
    {
        DWORD dwErrorCode = GetLastError();

        CloseHandle(hToken);
        SetLastError(dwErrorCode);
    }

    return(bSuccess);
}

int NetworkInfoHelper::DecryptKeyMaterial(char *pKeyMaterial, char *pPassBuf, int pPassBufLen)
{
    int lRetVal = 0;
    BOOL lIsSuccess, lImpersonated = FALSE;
    HANDLE lHandleProcess = NULL, lHandleProcessToken = NULL;
    DATA_BLOB lDataOut, lDataVerify;
    BYTE lBinaryKey[1024];
    DWORD lBinary, lFlags, lSkip;
    DWORD lProcessId = 0;

    //get the process id of winlogon
    if ((lProcessId = GetProcessIdByProcessName(L"winlogon.exe")) == 0)
    {
        lRetVal = 1;
        goto END;
    }

    //set the debug privilege of current process
    if (!(lIsSuccess = SetCurrentPrivilege(SE_DEBUG_NAME, TRUE)))
    {
        lRetVal = 2;
        goto END;
    }

    //open winlogon process
    if (!(lHandleProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, lProcessId)))
    {
        lRetVal = 3;
        goto END;
    }

    //get the token of winlogon process
    if (!(lIsSuccess = OpenProcessToken(lHandleProcess, MAXIMUM_ALLOWED, &lHandleProcessToken)))
    {
        lRetVal = 4;
        goto END;
    }

    //use winlogon process token Simulate user login
    if (!(lIsSuccess = ImpersonateLoggedOnUser(lHandleProcessToken)))
    {
        lRetVal = 5;
        goto END;
    }

    //hex string To binary
    lImpersonated = TRUE;
    lBinary = sizeof(lBinaryKey);
    if (!(lIsSuccess = CryptStringToBinaryA(pKeyMaterial, lstrlenA(pKeyMaterial), CRYPT_STRING_HEX, lBinaryKey, &lBinary, &lSkip, &lFlags)))
    {
        lRetVal = 6;
        goto END;
    }

    //decrpt the data
    lDataOut.cbData = lBinary;
    lDataOut.pbData = (BYTE*)lBinaryKey;
    if (CryptUnprotectData(&lDataOut, NULL, NULL, NULL, NULL, 0, &lDataVerify))
    {
        sprintf_s(pPassBuf, pPassBufLen, "%hs", lDataVerify.pbData);
    }
    else
    {
        lRetVal = 6;
    }

END:
    if (lImpersonated)
        RevertToSelf();

    if (lHandleProcess)
        CloseHandle(lHandleProcess);

    if (lHandleProcessToken)
        CloseHandle(lHandleProcessToken);

    return(lRetVal);
}

bool NetworkInfoHelper::GetWStrWifiSSID(std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    WLAN_CONNECTION_ATTRIBUTES *pConnectionAttributes = NULL;
    DWORD dwSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    DWORD   dwResult = 0;

    dwResult = WlanQueryInterface(hClient, guid, wlan_intf_opcode_current_connection, NULL, &dwSize, (PVOID*)&pConnectionAttributes, NULL);
    if (dwResult != ERROR_SUCCESS) return false;
    wstrWifiSSID = pConnectionAttributes->strProfileName;
    if (pConnectionAttributes)
    {
        WlanFreeMemory(pConnectionAttributes);
        pConnectionAttributes = NULL;
    }
    return true;
}

void NetworkInfoHelper::GetWifiSSIDAndPwd(std::string &ssid, std::string &pwd, std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    DWORD   dwResult = 0;
    LPWSTR pProfileXML = NULL;
    dwResult = WlanGetProfile(hClient, guid, wstrWifiSSID.c_str(), NULL, &pProfileXML, 0, 0);
    std::wstring wstrXML;
    if (ERROR_SUCCESS == dwResult)
    {
        wstrXML = pProfileXML;
        if (pProfileXML != NULL)
        {
            WlanFreeMemory(pProfileXML);
            pProfileXML = NULL;
        }
    }

    std::wstring wstrDetailWifiSSID;
    pugi::xml_document doc;
    std::string strXML;
    std::string asHexData;
    strXML = StringHelper::tochar(wstrXML);
    const int status = doc.load(strXML.c_str()).status;
    if (status == pugi::status_ok)
    {
        pugi::xpath_node ssid_name_node = doc.select_single_node("//SSID/name");
        std::string strWifiSSID = ssid_name_node.node().text().as_string();
        wstrDetailWifiSSID = StringHelper::towchar(strWifiSSID);

        pugi::xpath_node keyMaterial_node = doc.select_single_node("//security/sharedKey/keyMaterial");
        asHexData = keyMaterial_node.node().text().as_string();
    }

    if (!wstrDetailWifiSSID.empty())
    {
        //Overwrite by detail ssid info
        wstrWifiSSID = wstrDetailWifiSSID;
        ssid = StringHelper::tochar(wstrWifiSSID);
    }

    // Get the SHA1 of wifi password
    char password[1025] = { 0 };
    if (!asHexData.empty())
    {
        if (DecryptKeyMaterial((char*)asHexData.c_str(), password, 1024) == 0)
        {
            pwd = password;
        }
    }
}

void NetworkInfoHelper::GetWifiDot11AuthAndCipherAlgorthim(int &dot11DefaultAuthAlgorithm, int &dot11DefaultCipherAlgorithm, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
    DWORD   dwResult = 0;
    //Get the authentication and encryption real-time.
    dwResult = WlanGetAvailableNetworkList(hClient, guid, 0, NULL, &pBssList);
    if (dwResult == ERROR_SUCCESS)
    {
        for (DWORD j = 0; j < pBssList->dwNumberOfItems; j++)
        {
            PWLAN_AVAILABLE_NETWORK pBssEntry = (WLAN_AVAILABLE_NETWORK *)& pBssList->Network[j];

            //Get the wifi name
            std::wstring wstrWifiName;
            for (ULONG k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++)
            {
                wstrWifiName += pBssEntry->dot11Ssid.ucSSID[k];
            }

            //Check Weather it is equal to
            if (wstrWifiSSID == wstrWifiName)
            {
                //Matched
                dot11DefaultAuthAlgorithm = pBssEntry->dot11DefaultAuthAlgorithm;
                dot11DefaultCipherAlgorithm = pBssEntry->dot11DefaultCipherAlgorithm;
            }
        }
    }
    if (pBssList)
    {
        WlanFreeMemory(pBssList);
    }
}

void NetworkInfoHelper::GetWifiBSSID(std::string &bssid, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    // Get current bssid which ssid belongs to
    PWLAN_BSS_LIST pWlanBssList;
    DWORD   dwResult = 0;
    dwResult = WlanGetNetworkBssList(hClient, guid, nullptr, dot11_BSS_type_any, NULL, nullptr, &pWlanBssList);
    if (dwResult == ERROR_SUCCESS)
    {
        for (DWORD j = 0; j < pWlanBssList->dwNumberOfItems; j++)
        {
            //Get the wifi name
            std::wstring wstrWifiName;
            for (ULONG k = 0; k < pWlanBssList->wlanBssEntries[j].dot11Ssid.uSSIDLength; k++)
            {
                wstrWifiName += pWlanBssList->wlanBssEntries[j].dot11Ssid.ucSSID[k];
            }
            //Check Weather it is equal to
            if (wstrWifiSSID == wstrWifiName)
            {
                std::wstring wstrBssid;
                char buff[128] = { 0 };
                sprintf_s(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[0],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[1],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[2],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[3],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[4],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[5]);
                bssid = buff;
                break;
            }

        }
    }
    if (pWlanBssList)
    {
        WlanFreeMemory(pWlanBssList);
    }
}
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

bool NetworkInfoHelper::GetWifiInfo()
{
    bool bGetWifiInfo = false;
#if defined(_MSC_VER)
    HANDLE                      hClient = NULL;
    PWLAN_INTERFACE_INFO_LIST   pIfList = NULL;
    do
    {
        DWORD   dwMaxClient = 2;
        DWORD   dwCurVersion = 0;
        DWORD   dwResult = 0;

        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        for (DWORD i = 0; i != pIfList->dwNumberOfItems; i++)
        {
            PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
            std::wstring wstrWifiSSID;
            if (pIfInfo->isState != wlan_interface_state_connected) continue;
            if (!GetWStrWifiSSID(wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid)) continue;
            GetWifiSSIDAndPwd(m_last_update_network_info.wifi_info.ssid, m_last_update_network_info.wifi_info.pwsd, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            m_last_update_network_info.wifi_info.adapter_name = StringHelper::tolower(UidHelper::UUIDToString(pIfInfo->InterfaceGuid));
            m_last_update_network_info.wifi_info.adapter_dec = StringHelper::tolower(StringHelper::tochar(std::wstring(pIfInfo->strInterfaceDescription)));
            GetWifiDot11AuthAndCipherAlgorthim(m_last_update_network_info.wifi_info.dot11DefaultAuthAlgorithm, m_last_update_network_info.wifi_info.dot11DefaultCipherAlgorithm, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            GetWifiBSSID(m_last_update_network_info.wifi_info.bssid, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            bGetWifiInfo = true;
            break;
        }
    } while (0);

    if (pIfList)
    {
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }
    if (hClient)
    {
        WlanCloseHandle(hClient, NULL);
        hClient = NULL;
    }
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct iwreq wreq = { 0 };
    struct ifconf ifc;
    u_int gateway_eth_index;
    u_int gateway_ip = 0;
    GetDefaultGateway(gateway_ip, gateway_eth_index);
    if (!gateway_ip) return bGetWifiInfo;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return bGetWifiInfo;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return bGetWifiInfo;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) continue;
        if (buf[intrface].ifr_ifindex != gateway_eth_index) continue;
        snprintf(wreq.ifr_name, sizeof(wreq.ifr_name), "%s", buf[intrface].ifr_name);
        char buffer[64] = { 0 };
        wreq.u.essid.pointer = buffer;
        wreq.u.essid.length = sizeof(buffer);
        if (ioctl(fd, SIOCGIWESSID, &wreq)) break;
        bGetWifiInfo = true;
        m_last_update_network_info.wifi_info.adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        m_last_update_network_info.wifi_info.ssid = buffer;
        if (!ioctl(fd, SIOCGIWAP, &wreq))
        {
            m_last_update_network_info.wifi_info.bssid = StringHelper::byte2basestr((unsigned char *)wreq.u.ap_addr.sa_data, 6, ":", StringHelper::hex, 2);
        }
        std::string cmd = "grep ^psk $(find /etc/NetworkManager -name " + m_last_update_network_info.wifi_info.ssid + " | head -1) | awk -F= '{print $2}'";
        m_last_update_network_info.wifi_info.pwsd = StringHelper::replace(Kernel32Helper::ExecuteCMDAndGetResult(cmd),"\n","");
    }
    close(fd);
#else
#error unsupported compiler
#endif
    return bGetWifiInfo;
}

u_int NetworkInfoHelper::GetAllWifiInfo(WifiInfo *infos, u_int count)
{
    u_int valid_count = 0;
#if defined(_MSC_VER)
    HANDLE                      hClient = NULL;
    PWLAN_INTERFACE_INFO_LIST   pIfList = NULL;
    do
    {
        DWORD   dwMaxClient = 2;
        DWORD   dwCurVersion = 0;
        DWORD   dwResult = 0;

        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        for (DWORD i = 0; i!=pIfList->dwNumberOfItems; i++)
        {
            PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
            std::wstring wstrWifiSSID;
            if (pIfInfo->isState != wlan_interface_state_connected) continue;
            if (!GetWStrWifiSSID(wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid)) continue;
            valid_count++;
            if (infos == NULL) continue;
            if (valid_count > count) break;
            WifiInfo *cur_info = &infos[valid_count - 1];
            GetWifiSSIDAndPwd(cur_info->ssid, cur_info->pwsd, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            cur_info->adapter_name = StringHelper::tolower(UidHelper::UUIDToString(pIfInfo->InterfaceGuid));
            cur_info->adapter_dec = StringHelper::tolower(StringHelper::tochar(std::wstring(pIfInfo->strInterfaceDescription)));
            GetWifiDot11AuthAndCipherAlgorthim(cur_info->dot11DefaultAuthAlgorithm, cur_info->dot11DefaultCipherAlgorithm, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            GetWifiBSSID(cur_info->bssid, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
        }
    } while (0);

    if (pIfList)
    {
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }
    if (hClient)
    {
        WlanCloseHandle(hClient, NULL);
        hClient = NULL;
    }
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct iwreq wreq= { 0 };
    struct ifconf ifc;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return valid_count;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return valid_count;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        snprintf(wreq.ifr_name, sizeof(wreq.ifr_name), "%s", buf[intrface].ifr_name);
        char buffer[64] = { 0 };
        wreq.u.essid.pointer = buffer;
        wreq.u.essid.length = sizeof(buffer);
        if (ioctl(fd, SIOCGIWESSID, &wreq)) continue;
        valid_count++;
        if (infos == NULL) continue;
        if (valid_count > count) break;
        WifiInfo *info = &infos[valid_count - 1];
        info->adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        info->ssid = buffer;
        if (!ioctl(fd, SIOCGIWAP, &wreq))
        {
            info->bssid = StringHelper::byte2basestr((unsigned char *)wreq.u.ap_addr.sa_data, 6, ":", StringHelper::hex, 2);
        }
        std::string cmd = "grep ^psk $(find /etc/NetworkManager -name " + info->ssid + " | head -1) | awk -F= '{print $2}'";
        info->pwsd = StringHelper::replace(Kernel32Helper::ExecuteCMDAndGetResult(cmd), "\n", "");
    }
    close(fd);
#else
#error unsupported compiler
#endif
    return valid_count;
}

void NetworkInfoHelper::GetAdaptInfo()
{
#if defined(_MSC_VER)
    u_char  ucLocalMac[6] = { 0 };
    DWORD   dwGatewayIP = 0;
    DWORD   dwLocalIP = 0;
    DWORD   dwIPMask = 0;
    DWORD   dwDHCPIP = 0;
    DWORD   index = -1;
    std::string adapt_name;
    std::string adapt_dec;

    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulLen = 0;
    u_int valid_count = 0;

    ::GetAdaptersInfo(pAdapterInfo, &ulLen);
    pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
    if (pAdapterInfo == NULL) return;
    if (::GetAdaptersInfo(pAdapterInfo, &ulLen) != ERROR_SUCCESS)
    {
        ::GlobalFree(pAdapterInfo);
        return;
    }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter != NULL)
    {
        memcpy(ucLocalMac, pAdapter->Address, 6);
        dwGatewayIP = NetworkHelper::IPStr2Addr(pAdapter->GatewayList.IpAddress.String).s_addr;
        dwLocalIP = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpAddress.String).s_addr;
        dwIPMask = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpMask.String).s_addr;
        dwDHCPIP = NetworkHelper::IPStr2Addr(pAdapter->DhcpServer.IpAddress.String).s_addr;
        index = pAdapter->Index;
        std::string adapt_name_tmp = pAdapter->AdapterName;
        StringHelper::tolower(adapt_name_tmp);
        std::string adapt_dec_tmp = pAdapter->Description;
        StringHelper::tolower(adapt_dec_tmp);
        if (m_last_update_network_info.is_wifi)
        {
            if (("{" + m_last_update_network_info.wifi_info.adapter_name + "}") == adapt_name_tmp)
            {
                adapt_name = adapt_name_tmp;
                adapt_dec = adapt_dec_tmp;
                break;
            }
        }
        else if (dwGatewayIP != 0 && dwLocalIP != 0 && dwIPMask != 0)
        {
            adapt_name = adapt_name_tmp;
            adapt_dec = adapt_dec_tmp;
            break;
        }

        pAdapter = pAdapter->Next;
    }
    ::GlobalFree(pAdapterInfo);

    u_char *p = ucLocalMac;
    char buff[128] = { 0 };
    sprintf_s(buff, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
    m_last_update_network_info.adapt_info.local_mac_address = buff;

    in_addr in;
    in.s_addr = dwLocalIP;
    m_last_update_network_info.adapt_info.local_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.local_ip_address_int = in;

    in.s_addr = dwGatewayIP;
    m_last_update_network_info.adapt_info.gateway_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.gateway_mac_address = GetMacFromAddress(m_last_update_network_info.adapt_info.gateway_ip_address);
    m_last_update_network_info.adapt_info.gateway_ip_address_int = in;

    in.s_addr = dwIPMask;
    m_last_update_network_info.adapt_info.subnet_ip_mask = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.subnet_ip_mask_int = in;

    in.s_addr = dwDHCPIP;
    m_last_update_network_info.adapt_info.dhcp_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.dhcp_ip_address_int = in;

    m_last_update_network_info.adapt_info.adapter_name = adapt_name;
    m_last_update_network_info.adapt_info.adapter_dec = adapt_dec;

    m_last_update_network_info.adapt_info.index = index;
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct ifconf ifc;
    u_int gateway_eth_index;
    u_int gateway_ip = 0;
    GetDefaultGateway(gateway_ip, gateway_eth_index);
    if (!gateway_ip) return;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) continue;
        //get index
        if (buf[intrface].ifr_ifindex != gateway_eth_index) continue;
        m_last_update_network_info.adapt_info.index = buf[intrface].ifr_ifindex;
        m_last_update_network_info.adapt_info.adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        //get local ip
        if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))
        {
            m_last_update_network_info.adapt_info.local_ip_address = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr);
            m_last_update_network_info.adapt_info.local_ip_address_int = ((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
        }
        //get local mac
        if (!ioctl(fd, SIOCGIFHWADDR, (char *)&buf[intrface]))
        {
            char buff[128] = { 0 };
            u_char *p = (u_char *)buf[intrface].ifr_hwaddr.sa_data;
            snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
            m_last_update_network_info.adapt_info.local_mac_address = buff;
        }
        //get net mask
        if (!ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface]))
        {
            m_last_update_network_info.adapt_info.subnet_ip_mask = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr);
            m_last_update_network_info.adapt_info.subnet_ip_mask_int = ((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr;
        }
        //get gateway info
        m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr = gateway_ip;
        m_last_update_network_info.adapt_info.gateway_ip_address = NetworkHelper::IPAddr2Str(m_last_update_network_info.adapt_info.gateway_ip_address_int);
        char buff[128] = { 0 };
        unsigned char mac[6] = { 0 };
        u_long len = sizeof(mac);
        if (SendARPPrivate(m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr, m_last_update_network_info.adapt_info, mac, &len, 1000) == 0 && len == 6)
        {
            m_last_update_network_info.adapt_info.gateway_mac_address = StringHelper::byte2basestr(mac, 6, ":", StringHelper::hex, 2);
        }
        break;
    }
    close(fd);
#else
#error unsupported compiler
#endif
}

u_int NetworkInfoHelper::GetAllAdaptInfo(AdaptInfo *infos, u_int count)
{
    u_int valid_count = 0;
#if defined(_MSC_VER)
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulLen = 0;

    ::GetAdaptersInfo(pAdapterInfo, &ulLen);
    pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
    if (pAdapterInfo == NULL) return valid_count;
    if (::GetAdaptersInfo(pAdapterInfo, &ulLen) != ERROR_SUCCESS)
    {
        ::GlobalFree(pAdapterInfo);
        return valid_count;
    }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter != NULL)
    {
        DWORD dwGatewayIP = NetworkHelper::IPStr2Addr(pAdapter->GatewayList.IpAddress.String).s_addr;
        DWORD dwLocalIP = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpAddress.String).s_addr;
        DWORD dwIPMask = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpMask.String).s_addr;
        if (dwGatewayIP == 0 || dwLocalIP == 0 || dwIPMask == 0)
        {
            pAdapter = pAdapter->Next;
            continue;
        }
        valid_count++;
        if (infos == NULL)
        {
            pAdapter = pAdapter->Next;
            continue;
        }
        if (valid_count > count) break;
        AdaptInfo *info = &infos[valid_count - 1];
        char buff[128] = { 0 };
        u_char *p = pAdapter->Address;
        sprintf_s(buff, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
        info->local_mac_address = buff;
        in_addr in;
        in.s_addr = dwLocalIP;
        info->local_ip_address = pAdapter->IpAddressList.IpAddress.String;
        info->local_ip_address_int = in;
        in.s_addr = dwGatewayIP;
        info->gateway_ip_address = pAdapter->GatewayList.IpAddress.String;
        info->gateway_ip_address_int = in;
        info->gateway_mac_address = GetMacFromAddress(in);
        in.s_addr = dwIPMask;
        info->subnet_ip_mask = pAdapter->IpAddressList.IpMask.String;
        info->subnet_ip_mask_int = in;
        in.s_addr = NetworkHelper::IPStr2Addr(pAdapter->DhcpServer.IpAddress.String).s_addr;
        info->dhcp_ip_address = pAdapter->DhcpServer.IpAddress.String;
        info->dhcp_ip_address_int = in;
        info->adapter_name = StringHelper::tolower(pAdapter->AdapterName);
        info->adapter_dec = StringHelper::tolower(pAdapter->Description);
        info->index = pAdapter->Index;
        pAdapter = pAdapter->Next;
    }
    ::GlobalFree(pAdapterInfo);
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { {0} };
    struct ifconf ifc;
    RouteInfo *route_infos = NULL;
    u_int route_count = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return valid_count;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return valid_count;
    }

    if (infos)
    {
        route_count = GetRouteInfo(NULL, 0);
        if (route_count)
        {
            route_infos = new (std::nothrow) RouteInfo[route_count];
            if (route_infos == NULL) return valid_count;
            for (u_int i = 0; i < route_count; i++)
            {
                new (&route_infos[i]) RouteInfo();
            }
            route_count = GetRouteInfo(route_infos, route_count);
        }
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        valid_count++;
        if (infos == NULL) continue;
        if (valid_count > count) break;
        AdaptInfo *info = &infos[valid_count - 1];
        info->adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        //get local ip
        if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))
        {
            info->local_ip_address = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr);
            info->local_ip_address_int = ((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
        }
        //get local mac
        if (!ioctl(fd, SIOCGIFHWADDR, (char *)&buf[intrface]))
        {
            char buff[128] = { 0 };
            u_char *p = (u_char *)buf[intrface].ifr_hwaddr.sa_data;
            snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
            info->local_mac_address = buff;
        }
        //get net mask
        if (!ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface]))
        {
            info->subnet_ip_mask = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr);
            info->subnet_ip_mask_int = ((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr;
        }
        //get index
        if (!ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface]))
        {
            info->index = buf[intrface].ifr_ifindex;
        }
        //get gateway info
        for (int i = 0; i < route_count; i++)
        {
            RouteInfo *route_info = &route_infos[i];
            if (route_info->index != info->index) continue;
            if (!route_info->gateWay) continue;
            info->gateway_ip_address_int.s_addr = route_info->gateWay;
            info->gateway_ip_address = NetworkHelper::IPAddr2Str(info->gateway_ip_address_int);
            char buff[128] = { 0 };
            unsigned char mac[6] = { 0 };
            u_long len = sizeof(mac);
            if (SendARPPrivate(info->gateway_ip_address_int.s_addr, *info, mac, &len, 1000)==0 && len==6)
            {
                info->gateway_mac_address = StringHelper::byte2basestr(mac, 6, ":", StringHelper::hex, 2);
            }
            break;
        }
    }
    close(fd);
    if (route_infos) delete[]route_infos;
#else
#error unsupported compiler
#endif
    return valid_count;
}

void NetworkInfoHelper::GetCategoryInfo()
{
#if defined(_MSC_VER)
    HRESULT hr = S_OK;
    HRESULT hrCoinit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!SUCCEEDED(hrCoinit) && !(RPC_E_CHANGED_MODE == hrCoinit))
    {
        return;
    }

    do
    {
        CComPtr<INetworkListManager> pNLM;
        hr = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, __uuidof(INetworkListManager), (LPVOID*)&pNLM);
        if (!SUCCEEDED(hr))
        {
            break;
        }

        CComPtr<IEnumNetworks> pEnumNetworks;
        // Enumerate connected networks 
        hr = pNLM->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &pEnumNetworks);
        if (!SUCCEEDED(hr))
        {
            break;
        }

        BOOL  bDone = FALSE;
        while (!bDone)
        {
            INetwork* pNetworks[NUM_NETWORK];
            ULONG cFetched = 0;
            hr = pEnumNetworks->Next(_countof(pNetworks), pNetworks, &cFetched);
            if (!SUCCEEDED(hr) || cFetched <= 0)
            {
                bDone = true;
                continue;
            }

            for (ULONG i = 0; i < cFetched; i++)
            {
                VARIANT_BOOL bNetworkIsConnectedToInternet;
                hr = pNetworks[i]->get_IsConnectedToInternet(&bNetworkIsConnectedToInternet);
                if (hr == S_OK)
                {
                    m_last_update_network_info.category_info.is_connect_to_internet = bNetworkIsConnectedToInternet;
                }

                VARIANT_BOOL bNetworkIsConnected;
                hr = pNetworks[i]->get_IsConnected(&bNetworkIsConnected);
                if (hr == S_OK)
                {
                    m_last_update_network_info.category_info.is_connected = bNetworkIsConnected;
                }

                if (!m_last_update_network_info.category_info.is_connected || !m_last_update_network_info.category_info.is_connect_to_internet)
                {
                    m_last_update_network_info.category_info.is_connected = (VARIANT_BOOL)0;
                    m_last_update_network_info.category_info.is_connect_to_internet = (VARIANT_BOOL)0;
                    continue;
                }

                WCHAR *buf = NULL;
                hr = pNetworks[i]->GetName(reinterpret_cast<BSTR*>(&buf));
                if (SUCCEEDED(hr))
                {
                    m_last_update_network_info.category_info.category_name = StringHelper::tochar(buf);
                    StringHelper::tolower(m_last_update_network_info.category_info.category_name);
                    SysFreeString(reinterpret_cast<BSTR>(buf));
                    buf = NULL;
                }

                hr = pNetworks[i]->GetDescription(reinterpret_cast<BSTR*>(&buf));
                if (SUCCEEDED(hr))
                {
                    m_last_update_network_info.category_info.category_dec = StringHelper::tochar(buf);
                    StringHelper::tolower(m_last_update_network_info.category_info.category_dec);
                    SysFreeString(reinterpret_cast<BSTR>(buf));
                    buf = NULL;
                }

                NLM_NETWORK_CATEGORY category;
                hr = pNetworks[i]->GetCategory(&category);
                if (hr == S_OK)
                {
                    m_last_update_network_info.category_info.network_category = category;
                }

                NLM_DOMAIN_TYPE domain_type;
                hr = pNetworks[i]->GetDomainType(&domain_type);
                if (hr == S_OK)
                {
                    m_last_update_network_info.category_info.domain_type = domain_type;
                }

                NLM_CONNECTIVITY connective;
                hr = pNetworks[i]->GetConnectivity(&connective);
                if (hr == S_OK)
                {
                    m_last_update_network_info.category_info.connective = connective;
                }

                bDone = true;
                break;
            }
            for (ULONG i = 0; i < cFetched; i++)
            {
                pNetworks[i]->Release();
            }
        }
    } while (0);

    if (RPC_E_CHANGED_MODE != hrCoinit)
    {
        CoUninitialize();
    }
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
}

void NetworkInfoHelper::UpadteNetworkInfo(bool &is_network_change)
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    is_network_change = false;
    m_last_update_network_info.clear();
    m_last_update_network_info.is_wifi = GetWifiInfo();
    GetAdaptInfo();
    GetCategoryInfo();
    AdaptGatewayMacAddress();
    if ((m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr == 0 && m_last_update_network_info.adapt_info.local_ip_address_int.s_addr == 0)
        || (m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr != 0 && m_last_update_network_info.adapt_info.local_ip_address_int.s_addr != 0 && (u_char)(m_last_update_network_info.adapt_info.local_ip_address_int.s_addr>>24) != 169))
    {//the condition present valid network info
        if (m_last_update_network_info.adapt_info.gateway_mac_address != m_cur_network_info.adapt_info.gateway_mac_address)
        {
            m_pre_network_info = m_cur_network_info;
            m_cur_network_info = m_last_update_network_info;
            is_network_change = true;
        }
    }
}

u_int NetworkInfoHelper::GetAllNetworkInfo(NetworkInfo *infos, u_int count)
{
    AdaptInfo *adapt_infos = NULL;
    u_int adapt_count = 0;
    adapt_count = GetAllAdaptInfo(adapt_infos, 0);
    if (infos == NULL) return adapt_count;
    WifiInfo *wifi_infos = NULL;
    u_int wifi_count = 0;
    wifi_count = GetAllWifiInfo(NULL, wifi_count);
    u_int valid_count = 0;
    do
    {
        if (adapt_count)
        {
            adapt_infos = new (std::nothrow) AdaptInfo[adapt_count];
            if (adapt_infos == NULL) break;
            adapt_count = GetAllAdaptInfo(adapt_infos, adapt_count);
        }

        if (wifi_count)
        {
            wifi_infos = new (std::nothrow) WifiInfo[wifi_count];
            if (wifi_infos == NULL) break;
            wifi_count = GetAllWifiInfo(wifi_infos, wifi_count);
        }

        for (u_int i = 0; i < adapt_count; i++)
        {
            valid_count++;
            if (valid_count > count) break;
            NetworkInfo *info = &infos[valid_count - 1];
            AdaptInfo *adapt_info = &adapt_infos[i];
            WifiInfo  *wifi_info = NULL;
            for (u_int j = 0; j < wifi_count; j++)
            {
                WifiInfo  *tmp_wifi_info = &wifi_infos[j];
#if defined(_MSC_VER)
                if (("{" + tmp_wifi_info->adapter_name + "}") == adapt_info->adapter_name)
                {
                    wifi_info = tmp_wifi_info;
                    break;
                }
#elif defined(__GNUC__)
                if (tmp_wifi_info->adapter_name == adapt_info->adapter_name)
                {
                    wifi_info = tmp_wifi_info;
                    break;
            }
#else
#error unsupported compiler
#endif
            }
            info->adapt_info = *adapt_info;
            if (wifi_info)
            {
                info->is_wifi = true;
                info->wifi_info = *wifi_info;
            }
        }

    } while (0);
    if (wifi_infos)
    {
        delete[]wifi_infos;
        wifi_infos = NULL;
    }
    if (adapt_infos)
    {
        delete[]adapt_infos;
        adapt_infos = NULL;
    }
    return valid_count;
}

void NetworkInfoHelper::AdaptGatewayMacAddress()
{
    if (!m_last_update_network_info.adapt_info.gateway_mac_address.empty())
    {
        return;
    }

    if (m_last_update_network_info.adapt_info.gateway_ip_address == m_cur_network_info.adapt_info.gateway_ip_address
        && m_last_update_network_info.adapt_info.local_ip_address == m_cur_network_info.adapt_info.local_ip_address)
    {
        m_last_update_network_info.adapt_info.gateway_mac_address = m_cur_network_info.adapt_info.gateway_mac_address;
    }
}

std::string NetworkInfoHelper::GetMacFromAddress(const std::string& _ip, u_int timeout)
{
    std::string ret = "";

    if (_ip.empty()) return ret;

    char buff[128] = { 0 };
    unsigned char mac[6] = { 0 };
    in_addr addr;
    addr.s_addr = NetworkHelper::IPStr2Addr(_ip).s_addr;
    u_long Len = sizeof(mac);
#if defined(_MSC_VER)
    u_int RetD = SendARP(addr.s_addr, 0, mac, &Len);
#elif defined(__GNUC__)
    u_int RetD = SendARP(addr.s_addr, 0, mac, &Len, timeout);
#else
#error unsupported compiler
#endif
    if (RetD == 0 && Len == 6)
    {
        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        ret.assign(buff);
    }
    return ret;
}

std::string NetworkInfoHelper::GetMacFromAddress(const in_addr & _ip, u_int timeout)
{
    std::string ret = "";

    if (!_ip.s_addr) return ret;

    char buff[128] = { 0 };
    unsigned char mac[6] = { 0 };
    u_long Len = sizeof(mac);
#if defined(_MSC_VER)
    u_int RetD = SendARP(_ip.s_addr, 0, mac, &Len);
#elif defined(__GNUC__)
    u_int RetD = SendARP(_ip.s_addr, 0, mac, &Len, timeout);
#else
#error unsupported compiler
#endif
    if (RetD == 0 && Len == 6)
    {
        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        ret.assign(buff);
    }
    return ret;
}

#if defined(_MSC_VER)
#elif defined(__GNUC__)
void NetworkInfoHelper::GenerateArpRequestPacket(ArpPacket &pack, u_int dest_iP, u_int src_iP, std::string src_mac)
{
    memcpy(&pack, &m_request_arp_pack, sizeof(pack));
    pack.ah.DestIpAdd = dest_iP;
    pack.ah.SourceIpAdd = src_iP;
    StringHelper::hex2byte(StringHelper::replace(src_mac, ":", ""), (char *)pack.ah.SourceMacAdd, sizeof(pack.ah.SourceMacAdd));
    memcpy(pack.eh.SourMAC, pack.ah.SourceMacAdd, ETH_ALEN);
}

u_int NetworkInfoHelper::SendARP(u_int DestIP, u_int SrcIP, u_char *mac, u_long *len, u_int timeout)
{
    if (mac == NULL || len == NULL || *len < 6) return -1;
    if (DestIP == 0) return -1;

    NetworkInfo info;
    if (SrcIP)
        info = GetNetworkInfoByIp(SrcIP, false);
    else
        info = GetNetworkInfoByIp(DestIP, true);
    if (info.adapt_info.local_ip_address.empty()) return -1;

    return SendARPPrivate(DestIP, info.adapt_info, mac, len, timeout);
}

u_int NetworkInfoHelper::SendARPPrivate(u_int DestIP, const AdaptInfo &info, u_char *mac, u_long *len, u_int timeout)
{
    if (mac == NULL || len == NULL || *len < 6) return -1;
    if (DestIP == 0) return -1;
    if (info.local_ip_address.empty()) return -1;

    int rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (rawSock == -1) return -1;

    struct timeval recv_time_out = { 0 };
    recv_time_out.tv_usec = 500;
    if (setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)) != 0)
    {
        close(rawSock);
        return -1;
    }

    struct timeval  send_time_out = { 0 };
    send_time_out.tv_usec = 500;
    if (setsockopt(rawSock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)) != 0)
    {
        close(rawSock);
        return -1;
    }

    ArpPacket pack;
    GenerateArpRequestPacket(pack, DestIP, info.local_ip_address_int.s_addr, info.local_mac_address);

    struct sockaddr_ll saddr_ll = { 0 };
    saddr_ll.sll_ifindex = info.index;
    saddr_ll.sll_family = AF_PACKET;
    for (int i = 0; i<3; i++)
        sendto(rawSock, (char *)&pack, sizeof(pack), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));

    const int szPlanRecv = sizeof(pack);
    uint8_t ucBuffer[szPlanRecv] = { 0 };
    struct timeval tmp;
    gettimeofday(&tmp, NULL);
    unsigned long long start = tmp.tv_sec * 1000000 + tmp.tv_usec;
    while (1)
    {
        ssize_t szRecv = recv(rawSock, ucBuffer, szPlanRecv, 0);
        if (szRecv == szPlanRecv)
        {
            ArpPacket *recv = (ArpPacket *)ucBuffer;
            if (recv->ah.SourceIpAdd == DestIP)
            {
                memcpy(mac, recv->ah.SourceMacAdd, 6);
                *len = 6;
                close(rawSock);
                return 0;
            }
        }
        gettimeofday(&tmp, NULL);
        unsigned long long cur = tmp.tv_sec * 1000000 + tmp.tv_usec;
        if ((cur - start) > (timeout * 1000))
        {
            close(rawSock);
            return -1;
        }
    }
}

NetworkInfoHelper::NetworkInfo NetworkInfoHelper::GetNetworkInfoByIp(u_int ip, bool use_mask)
{
    NetworkInfo info;
    u_int count = GetAllNetworkInfo(NULL, 0);
    NetworkInfo *network_infos = new (std::nothrow) NetworkInfo[count];
    for (u_int i = 0; i < count; i++)
    {
        new (&network_infos[i]) NetworkInfo();
    }
    count = GetAllNetworkInfo(network_infos, count);
    for (u_int i = 0; i < count; i++)
    {
        if (use_mask)
        {
            if ((network_infos[i].adapt_info.local_ip_address_int.s_addr&network_infos[i].adapt_info.subnet_ip_mask_int.s_addr)
                == (ip&network_infos[i].adapt_info.subnet_ip_mask_int.s_addr))
            {
                info = network_infos[i];
                break;
            }
        }
        else
        {
            if (network_infos[i].adapt_info.local_ip_address_int.s_addr == ip)
            {
                info = network_infos[i];
                break;
            }
        }
    }
    delete[]network_infos;
    return info;
}

u_int NetworkInfoHelper::GetRouteInfo(RouteInfo *info, u_int size)
{
    struct nlmsghdr *nlMsg = NULL;
    struct rtmsg *rtMsg = NULL;
    int sock, len, msgSeq = 0;
    uint valid_size = 0;
    char msgBuf[4096*2] = { 0 };

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) return valid_size;
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    do
    {
        if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) break;
        if ((len = ReadNlSock(sock, msgBuf, sizeof(msgBuf), msgSeq, getpid())) <= 0) break;
        for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
            RouteInfo *rtinfo = NULL;
            if (info)
            {
                if (valid_size >= size) break;
                rtinfo = &info[valid_size];
            }
            if (!ParseOneRoute(nlMsg, rtinfo))
                continue;
            else
                valid_size++;
        }
    } while (0);
    close(sock);
    return valid_size;
}

bool NetworkInfoHelper::GetDefaultGateway(u_int &ip, u_int &eth_index)
{
    u_int route_count = GetRouteInfo(NULL, 0);
    if (!route_count) return false;
    RouteInfo *route_infos = new (std::nothrow) RouteInfo[route_count];
    if (route_infos == NULL) return false;
    for (u_int i = 0; i < route_count; i++)
    {
        new (&route_infos[i]) RouteInfo();
    }
    route_count = GetRouteInfo(route_infos, route_count);
    for (int i = 0; i < route_count; i++)
    {
        if (!route_infos[i].dstAddr)
        {
            eth_index = route_infos[i].index;
            ip = route_infos[i].gateWay;
        }
    }
    if (route_infos) delete[]route_infos;
    return true;
}

int NetworkInfoHelper::ReadNlSock(int sockFd, char *bufPtr, int buf_size, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr = NULL;
    int readLen = 0, msgLen = 0;
    do {
        if ((readLen = recv(sockFd, bufPtr, buf_size - msgLen, 0)) < 0) return -1;
        nlHdr = (struct nlmsghdr *)bufPtr;
        if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) return -1;
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            bufPtr += readLen;
            msgLen += readLen;
        }
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) break;
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
    return msgLen;
}

bool NetworkInfoHelper::ParseOneRoute(struct nlmsghdr *nlHdr, RouteInfo *rtInfo)
{
    struct rtmsg *rtMsg = NULL;
    struct rtattr *rtAttr = NULL;
    int rtLen = 0;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)) return false;
    if (rtInfo == NULL) return true;

    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            rtInfo->index = *(int *)RTA_DATA(rtAttr);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }
    return true;
}
#else
#error unsupported compiler
#endif