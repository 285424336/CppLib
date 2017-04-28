// NTServiceHelper.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <service\NTServiceHelper.h>
#include <iostream>

void QueryNTserviceStatTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    DWORD ret = NTServiceHelper::QueryNTserviceStat(server.c_str());
    std::cout << "service " << server.c_str() << " stat " << ret << std::endl;
}

void CanAccessServiceTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    bool ret = NTServiceHelper::CanAccessService(server.c_str(), GENERIC_EXECUTE | GENERIC_READ);
    std::cout << "service " << server.c_str() << " can access " << ret << std::endl;
    if (ret) QueryNTserviceStatTest();
}

void StartNTServiceTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    bool ret = NTServiceHelper::StartNTService(server.c_str());
    std::cout << "service " << server.c_str() << " start " << ret << std::endl;
}

void StopNTServiceTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    bool ret = NTServiceHelper::StopNTService(server.c_str());
    std::cout << "service " << server.c_str() << " stop " << ret << std::endl;
}

void InstallNTServiceTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    bool ret = NTServiceHelper::InstallNTService(server.c_str(), "C:\\Windows\\System32\\drivers\\npf.sys");
    std::cout << "service " << server.c_str() << " install " << ret << std::endl;
}

void UninstallNTServiceTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "npf";
    bool ret = NTServiceHelper::UninstallNTService(server.c_str());
    std::cout << "service " << server.c_str() << " uninstall " << ret << std::endl;
}

void ChangeNTServiceConfigTest()
{
    std::cout << __FUNCTION__ << "********************TEST*******************" << std::endl;
    std::string server = "QPCore";
    bool ret = NTServiceHelper::ChangeNTServiceConfig(server.c_str(), SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE
        , NULL, NULL, NULL, NULL, NULL, NULL, "QPCore test");
    std::cout << "service " << server.c_str() << " change " << ret << std::endl;
}

int main()
{
    CanAccessServiceTest();
    StopNTServiceTest();
    CanAccessServiceTest();
    StartNTServiceTest();
    CanAccessServiceTest();
    UninstallNTServiceTest();
    CanAccessServiceTest();
    InstallNTServiceTest();
    CanAccessServiceTest();
    ChangeNTServiceConfigTest();
    return 0;
}

