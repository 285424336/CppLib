// DllInMemory.cpp : 定义控制台应用程序的入口点。
//

#include <dll\DllInMemoryHelper.h>
#include <string\StringHelper.h>
#include <file\FileHelper.h>
#include <iostream>

#pragma comment(lib, "DllTest.lib")

/*
* DRS Event Definition
*/
enum DRS_EVENT
{
    EVENT_ENVIRONMENT_CLEANUP, // The runtime environment has been cleaned up 
    EVENT_FAMILY_NETWORK_FOUND, // Current network is rated as family network
    EVENT_FAMILY_DEVICE_FOUND, // A specific device is rated as family device
    EVENT_NETWORK_CONNECTED, // PC connects to a network
    EVENT_NETWORK_DISCONNECTED, // PC disconnects from a network
    EVENT_DEVICE_CONNECTED, // A specific device connects to the current network
    EVENT_DEVICE_DISCONNECTED, // A specific device disconnects from the current network
    EVENT_SCAN_PROGRESS, // Scan Progress,
    EVENT_SCAN_COMPLETE // Scan completed with the result
};
typedef bool(*FpDrsCallback)(DRS_EVENT event, const WCHAR* pwszRes);
typedef bool(*FpDrsInitialize)(FpDrsCallback callback);
typedef bool(*FpDrsGetNetworkName)(WCHAR** pwszRes);
FpDrsInitialize init;
FpDrsGetNetworkName get_network_name;
bool DrsCallback(DRS_EVENT event, const WCHAR* pwszRes)
{
    std::cout << "time:" << time(0) << std::endl;
    std::string content;
    if (pwszRes)
    {
        content = StringHelper::tochar(pwszRes);
    }
    std::cout << "event:" << event << "\r\ncontent: " << content << std::endl;
    return true;
}
FpDrsCallback cb = DrsCallback;

typedef int(*FpBitCount)(unsigned int n);
typedef unsigned int(*FpBitReverse)(unsigned int n);
FpBitCount fnBitCount;
FpBitReverse fnBitReverse;

int main()
{
#ifndef _WIN64
    //std::string content = FileHelper::GetFileContent("DrsSdk.dll");
    //std::string content = FileHelper::GetFileContent("reverser_tcpx86.dll");
    std::string content = FileHelper::GetFileContent("..\\..\\OUTPUT\\bin\\Win32\\Debug\\DllTest\\DllTest.dll");
#else
    //std::string content = FileHelper::GetFileContent("reverser_tcpx64.dll");
    std::string content = FileHelper::GetFileContent("..\\..\\OUTPUT\\bin\\x64\\Debug\\DllTest\\DllTest.dll");
#endif // !_WIN64
    //std::cout << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), " ", StringHelper::hex, 2) << std::endl;
    std::cout << "1" << std::endl;
    try
    {
        DllInMemoryHelper dim;
        if (dim.LoadPbDllFromMemory((LPVOID)content.c_str()))
        {
            std::cout << "Load Dll Failed!" << std::endl;
            Sleep(10000);
            return 1;
        }
        DllInMemoryHelper newdim;
        swap(newdim, dim);
        {
            std::cout << "2" << std::endl;
            fnBitCount = (FpBitCount)newdim.GetProcAddressDirectly("BitCount");
            if (!fnBitCount)
            {
                std::cout << "get fun Failed!" << std::endl;
                Sleep(10000);
                return 1;
            }
            fnBitReverse = (FpBitReverse)newdim.GetProcAddressDirectly("BitReverse");
            if (!fnBitReverse)
            {
                std::cout << "get fun Failed!" << std::endl;
                Sleep(10000);
                return 1;
            }
            std::cout << "3" << std::endl;
            std::cout << fnBitCount(0XFFFFFFFF) << std::endl;
            std::cout << fnBitCount(0XFFFFFFF0) << std::endl;
            std::cout << fnBitReverse(0XF0000000) << std::endl;
            std::cout << fnBitReverse(0X80000000) << std::endl;
        }
        {
            /* std::cout << "2" << std::endl;
            init = (decltype(init))dim.GetProcAddressDirectly("DrsInitialize");
            if (!init)
            {
            std::cout << "get fun Failed!" << std::endl;
            Sleep(10000);
            return 1;
            }
            get_network_name = (decltype(get_network_name))dim.GetProcAddressDirectly("DrsGetNetworkName");
            if (!get_network_name)
            {
            std::cout << "get fun Failed!" << std::endl;
            Sleep(10000);
            return 1;
            }
            init(cb);
            wchar_t *out = NULL;
            get_network_name(&out);
            if (out) std::wcout << out << std::endl;
            else std::wcout << "error" << std::endl;*/
        }
        Sleep(5000);
    }
    catch (...)
    {
        std::cout << "Error occus!" << std::endl;
    }
    return 0;
}