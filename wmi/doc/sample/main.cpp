// WMIHelper.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <wmi\WMIHelper.h>
#include <iostream>

WMIHelper wmi(CIMV2_WMI_NAMESPACE);

void WMIQueryStrTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    {
        std::wstring result;
        auto ret = wmi.QueryStr(result, L"SELECT * FROM Win32_ComputerSystemProduct", L"Name");
        std::wcout << L"ret: " << ret << L" SELECT * FROM Win32_ComputerSystemProduct Name: " << result << std::endl;
    }
    {
        std::wstring result;
        auto ret = wmi.QueryStr(result, L"SELECT * FROM Win32_ComputerSystemProduct", L"Vendor");
        std::wcout << L"ret: " << ret << L" SELECT * FROM Win32_ComputerSystemProduct Vendor: " << result << std::endl;
    }
}

void WMIQueryEnumTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::vector<WMIExecValue> result;
    auto ret = wmi.QueryEnum(result, L"SELECT * FROM Win32_ComputerSystemProduct");
    for (auto tmp : result)
    {
        std::wcout << tmp << std::endl;
    }
}

void WMINotificationQueryStrTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;

    std::wstring result;
    auto ret = wmi.NotificationQueryStr(result, L"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'", L"TIME_CREATED");
    std::wcout << L"ret: " << ret << L" SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' TIME_CREATED: " << result << std::endl;
}

void WMINotificationQueryEnumTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::vector<WMIExecValue> result;
    auto ret = wmi.NotificationQueryEnum(result, L"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
    for (auto tmp : result)
    {
        std::wcout << tmp << std::endl;
    }
}

void WMIExecMethodTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;

    WMIExecValue execRet;
    std::map<std::wstring, CComVariant> paras;
    CComVariant vt;
    vt.vt = VT_BSTR;
    vt.bstrVal = CComBSTR("ipconfig /all");
    paras[L"CommandLine"] = vt;
    auto ret = wmi.ExecMethod(execRet, L"Win32_Process", L"Create", L"ReturnValue", paras);
    std::wcout << "exec cmd ret " << ret << " exec return " << execRet << std::endl;
}

int main()
{
    wmi.Connect();
    WMIQueryStrTest();
    WMIQueryEnumTest();
    WMINotificationQueryStrTest();
    WMINotificationQueryEnumTest();
    WMIExecMethodTest();
    while(1)
    {
        Sleep(1000);
    }
    return 0;
}

