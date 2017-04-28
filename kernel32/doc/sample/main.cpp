// Kernel32.cpp : Defines the entry point for the console application.
//

#if defined(_MSC_VER)
#include <kernel32\Kernel32Helper.h>
#elif defined(__GNUC__)
#include <kernel32/Kernel32Helper.h>
#else
#error unsupported compiler
#endif
#include <iostream>
#include <string>

void IsWow64ProgramTest()
{ 
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "is 32 program under 64 bit system: " << Kernel32Helper::IsWow64Program() << std::endl;
}

void Is64SystemTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "is 64 bit system: " << Kernel32Helper::Is64System() << std::endl;
}

void Is64ProgramTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "is 64 program: " << Kernel32Helper::Is64Program() << std::endl;
}

void GetProcessIdTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
#if defined(_MSC_VER)
    std::wstring process = L"winlogon.exe";
    std::cout << "winlogon.exe process id: " << Kernel32Helper::GetProcessId(process.c_str()) << std::endl;
#elif defined(__GNUC__)
    std::wstring process = L"ssh-agent";
    std::cout << "ssh-agent process id: " << Kernel32Helper::GetProcessId(process.c_str()) << std::endl;
#else
#error unsupported compiler
#endif
}

void GetProcessIdsTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::set<u_int> ids;
#if defined(_MSC_VER)
    std::wstring process = L"chrome.exe";
    ids = Kernel32Helper::GetProcessIds(process.c_str());
    std::cout << "chrome.exe process id: " << std::endl;
#elif defined(__GNUC__)
    std::wstring process = L"getty";
    ids = Kernel32Helper::GetProcessIds(process.c_str());
    std::cout << "getty process id: " << std::endl;
#else
#error unsupported compiler
#endif
    for (auto id : ids)
    {
        std::cout << "    " << id << std::endl;
    }
}

void ExecuteCMDAndGetResultTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
#if defined(_MSC_VER) 
    std::cout << "exec ipconfig /all result: " << Kernel32Helper::ExecuteCMDAndGetResult("ipconfig /all", 1000) << std::endl;
#elif defined(__GNUC__)  
    std::cout << "exec ifconfig result: " << Kernel32Helper::ExecuteCMDAndGetResult("netstat -n", 5000) << std::endl;
#else  
#error unsupported compiler
#endif 
}

void GetCPUNumTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "current usable core num: " << Kernel32Helper::GetCPUNum() << std::endl;
}

int main()
{
    IsWow64ProgramTest();
    Is64SystemTest();
    Is64ProgramTest();
    GetProcessIdTest();
    GetProcessIdsTest();
    ExecuteCMDAndGetResultTest();
    GetCPUNumTest();
    return 0;
}

