#pragma once

#include <windows.h>

class NTServiceHelper
{
public:
    /**
    *start the NT service
    *lpServiceName(in): NT service name, like npf
    */
    static bool StartNTService(const char *lpServiceName);
    /**
    *stop the NT service
    *lpServiceName(in): NT service name, like npf
    */
    static bool StopNTService(const char * lpServiceName);
    /**
    *Install a NT service
    *lpServiceName(in): service name
    *lpBinaryPath(in): binary path
    *dwServiceType(in): service type
    *dwStartType(in): service start type
    *dwErrorControl(in): error control
    *note: if install sucess, the initial stat is stop
    */
    static bool InstallNTService(const char * lpServiceName, const char *lpBinaryPath, DWORD dwServiceType = SERVICE_KERNEL_DRIVER, DWORD dwStartType = SERVICE_DEMAND_START, DWORD dwErrorControl = SERVICE_ERROR_NORMAL);
    /**
    *Uninstall a NT service
    *lpServiceName(in): service name
    */
    static bool UninstallNTService(const char * lpServiceName);
    /**
    *change the service config
    */
    static bool ChangeNTServiceConfig(const char *lpServiceName, DWORD dwServiceType = SERVICE_NO_CHANGE,
        _In_      DWORD     dwStartType = SERVICE_NO_CHANGE,
        _In_      DWORD     dwErrorControl = SERVICE_NO_CHANGE,
        _In_opt_  const char *   lpBinaryPathName = NULL,
        _In_opt_  const char *   lpLoadOrderGroup = NULL,
        _Out_opt_ LPDWORD   lpdwTagId = NULL,
        _In_opt_  const char *   lpDependencies = NULL,
        _In_opt_  const char *   lpServiceStartName = NULL,
        _In_opt_  const char *   lpPassword = NULL,
        _In_opt_  const char *   lpDisplayName = NULL);
    /**
    *check if service can access
    */
    static bool CanAccessService(const char * lpServiceName, DWORD dwDesiredAccess = GENERIC_READ);
    /**
    *get the service stat, 0 for error, other for stat, like SERVICE_RUNNING
    */
    static DWORD QueryNTserviceStat(const char * lpServiceName);
};