
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
    //std::cout << "  " << "network category:" << network_info.category_info.network_category << std::endl;
    if (network_info.is_wifi)
    {
        std::cout << "  " << "wifi bssid: " << network_info.wifi_info.bssid << std::endl;
        std::cout << "  " << "wifi password md5: " << network_info.wifi_info.pwsd << std::endl;
    }
}

int main()
{
    u_int count = NetworkInfoHelper::GetAllNetworkInfo(NULL, 0);
    NetworkInfoHelper::NetworkInfo *network_infos = new (std::nothrow) NetworkInfoHelper::NetworkInfo[count];
    for (u_int i = 0; i < count; i++)
    {
        new (&network_infos[i]) NetworkInfoHelper::NetworkInfo();
    }
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
