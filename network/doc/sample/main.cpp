
#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string\StringHelper.h>
#include <network\NetworkInfoHelper.h>
#include <network\NLMHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <network/NetworkInfoHelper.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <iostream>
#include <vector>
#include <set>
#include <sstream>
#include <thread>
#include <chrono>

void NetworkChangeCallback(bool ev_connect);

void PrintNetworkInfo(const NetworkInfoHelper::NetworkInfo &network_info)
{
    if (network_info.is_wifi)
        std::cout << "network name: " << network_info.wifi_info.ssid << std::endl;
    else
        std::cout << "network name: " << network_info.adapt_info.adapter_name << std::endl;
    std::cout << "  " << "local ip: " << network_info.adapt_info.local_ip_address << std::endl;
    std::cout << "  " << "local mac: " << network_info.adapt_info.local_mac_address << std::endl;
    std::cout << "  " << "network ip mask: " << network_info.adapt_info.subnet_ip_mask << std::endl;
    std::cout << "  " << "gateway ip: " << network_info.adapt_info.gateway_ip_address << std::endl;
    std::cout << "  " << "gateway mac: " << network_info.adapt_info.gateway_mac_address << std::endl;
    std::cout << "  " << "dhcp server ip:" << network_info.adapt_info.dhcp_ip_address << std::endl;
    std::cout << "  " << "eth index:" << network_info.adapt_info.index << std::endl;
#if defined(_MSC_VER)
    std::cout << "  " << "network category:" << network_info.category_info.network_category << std::endl;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
    if (network_info.is_wifi)
    {
        std::cout << "  " << "wifi bssid: " << network_info.wifi_info.bssid << std::endl;
        std::cout << "  " << "wifi password md5: " << network_info.wifi_info.pwsd << std::endl;
    }
}

int main()
{
    //int ms_count = 10;
    //while (1)
    //{
    //    struct timeval tmp;
    //    gettimeofday(&tmp, NULL);
    //    unsigned long long start = tmp.tv_sec * 1000 + tmp.tv_usec/1000;
    //    std::string mac = NetworkInfoHelper::GetMacFromAddress("192.168.1.110", ms_count);
    //    gettimeofday(&tmp, NULL);
    //    unsigned long long end = tmp.tv_sec * 1000 + tmp.tv_usec/1000;
    //    std::cout << "wait ms: " << ms_count <<" use ms: "<<end-start<< " ip: 192.168.1.110 mac: " << mac << std::endl;
    //    ms_count += 10;
    //}

#if defined(_MSC_VER)
    WORD wVersion;
    WSADATA WSAData;
    wVersion = MAKEWORD(2, 2);
    WSAStartup(wVersion, &WSAData);
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

    u_int route_count = NetworkInfoHelper::GetAllRouteInfo(NULL, 0);
    if (route_count)
    {
        NetworkInfoHelper::RouteInfo *route_infos = new (std::nothrow) NetworkInfoHelper::RouteInfo[route_count];
        if (route_infos != NULL)
        {
            route_count = NetworkInfoHelper::GetAllRouteInfo(route_infos, route_count);
            std::cout << "route info*****************************" << std::endl;
            for (int i = 0; i < route_count; i++) {
                std::cout << "[" << i << "]" << std::endl;
                std::cout << "dst ip: " << NetworkHelper::IPAddr2Str(route_infos[i].dstAddr) << std::endl;
                std::cout << "dst mask: " << NetworkHelper::IPAddr2Str(route_infos[i].dstmask) << std::endl;
                std::cout << "gateway ip: " << NetworkHelper::IPAddr2Str(route_infos[i].gateWay) << std::endl;
                std::cout << "src ip: " << NetworkHelper::IPAddr2Str(route_infos[i].srcAddr) << std::endl;
                std::cout << "metric: " << route_infos[i].metric << std::endl;
                std::cout << "index: " << route_infos[i].index << std::endl;
            }
            delete[]route_infos;
        }
    }

    NetworkInfoHelper::Route route = { 0 };
    std::string dst = "10.168.1.111";
    if (NetworkInfoHelper::GetDstRoute(route, NetworkHelper::IPStr2Addr(dst)))
    {
        std::cout << "route info*****************************" << std::endl;
        std::cout << "dst ip: " << NetworkHelper::IPAddr2Str(route.dstAddr) << std::endl;
        std::cout << "src ip: " << NetworkHelper::IPAddr2Str(route.srcAddr) << std::endl;
        std::cout << "src mac: " << StringHelper::byte2basestr(route.srcMac, 6, ":", StringHelper::hex, 2) << std::endl;
        std::cout << "index: " << route.index << std::endl;
    }
    else
    {
        std::cout << "route " << dst << " info get failed!" << std::endl;
    }

    std::vector<int> ips = NetworkHelper::ResolveName("localhost");
    for (auto ip : ips)
    {
        std::cout << NetworkHelper::IPAddr2Str(ip) << std::endl;
    }
    std::cout << NetworkHelper::ResolveAddr(NetworkHelper::IPStr2Addr("127.0.0.1").s_addr) << std::endl;

    u_int count = NetworkInfoHelper::GetAllNetworkInfo(NULL, 0);
    NetworkInfoHelper::NetworkInfo *network_infos = new (std::nothrow) NetworkInfoHelper::NetworkInfo[count];
    count = NetworkInfoHelper::GetAllNetworkInfo(network_infos, count);
    std::cout << "all using network*******************" << std::endl;
    for (u_int i = 0; i < count; i++)
    {
        PrintNetworkInfo(network_infos[i]);
    }
    delete[]network_infos;

    NetworkInfoHelper::NetworkInfo network_info = NetworkInfoHelper::GetInstance().GetNetworkInfo();
    std::cout << "current using network*******************" << std::endl;
    PrintNetworkInfo(network_info);
    //CNLMHelper::GetInstance().RegistNetworkChangeCallback(NetworkChangeCallback);

    std::thread t([] {
        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            bool is_network_changed;
            NetworkInfoHelper::GetInstance().UpadteNetworkInfo(is_network_changed);
            if (!is_network_changed)
                continue;
            std::cout << "pre using network*******************" << std::endl;
            PrintNetworkInfo(NetworkInfoHelper::GetInstance().GetPreNetworkInfo());
            std::cout << "current using network*******************" << std::endl;
            PrintNetworkInfo(NetworkInfoHelper::GetInstance().GetNetworkInfo());
        }
    });

    while (1)
    {
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
    //while (true)
    //{
    //    ::WaitMessage();
    //    MSG msg;
    //    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
    //    {
    //        TranslateMessage(&msg);
    //        DispatchMessage(&msg);
    //    }
    //}
    return 0;
}

void NetworkChangeCallback(bool ev_connect)
{
    std::cout << "Network Change! is connect " << ev_connect << "*******************" << std::endl;
    NetworkInfoHelper::NetworkInfo network_info;
    if (ev_connect)
        network_info = NetworkInfoHelper::GetInstance().GetNetworkInfo();
    else
        network_info = NetworkInfoHelper::GetInstance().GetPreNetworkInfo();
    PrintNetworkInfo(network_info);
}
