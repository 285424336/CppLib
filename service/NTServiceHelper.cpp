#include "NTServiceHelper.h"

#pragma comment(lib, "Advapi32.lib")

bool NTServiceHelper::StartNTService(const char *lpServiceName)
{
    SC_HANDLE hSCManager, hService;
    SERVICE_STATUS SrvStatus;

    // Open the SCM
    hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL) return false;

    // Get the service handle
    hService = OpenServiceA(hSCManager, lpServiceName, GENERIC_EXECUTE | GENERIC_READ);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return false;
    }

    bool ret = false;
    do
    {
        if (0 == ::QueryServiceStatus(hService, &SrvStatus)) break;

        if (SERVICE_RUNNING == SrvStatus.dwCurrentState || SERVICE_START_PENDING == SrvStatus.dwCurrentState)
        {
            ret = true;
            break;
        }

        if (::StartServiceA(hService, 0, NULL) == TRUE) ret = true;
    } while (0);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return ret;
}

bool NTServiceHelper::StopNTService(const char * lpServiceName)
{
    SC_HANDLE hSCManager, hService;
    SERVICE_STATUS SrvStatus;

    // Open the SCM
    hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL) return false;

    // Get the service handle
    hService = OpenServiceA(hSCManager, lpServiceName, GENERIC_EXECUTE | GENERIC_READ);
    if (hService == NULL)
    {
        DWORD dwErr = GetLastError();
        CloseServiceHandle(hSCManager);
        return dwErr == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    // Stop the service
    if (ControlService(hService, SERVICE_CONTROL_STOP, &SrvStatus) == FALSE)
   {
        DWORD dwErr = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return dwErr == ERROR_SERVICE_NOT_ACTIVE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool NTServiceHelper::InstallNTService(const char * lpServiceName, const char *lpBinaryPath, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl)
{
    SC_HANDLE hSCManager, hService;

    // Open SCM
    hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ | GENERIC_WRITE);
    if (hSCManager == NULL) return false;

    hService = OpenServiceA(hSCManager, lpServiceName, GENERIC_EXECUTE | GENERIC_READ);
    if (hService != NULL)
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    hService = CreateServiceA(hSCManager, lpServiceName, lpServiceName, SERVICE_ALL_ACCESS, dwServiceType, dwStartType, dwErrorControl, lpBinaryPath, NULL, NULL, NULL, NULL, NULL);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool NTServiceHelper::UninstallNTService(const char * lpServiceName)
{
    SC_HANDLE hSCManager, hService;
    SERVICE_STATUS SrvStatus;

    // Open SCM
    hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_ALL);
    if (hSCManager == NULL) return false;

    // Get service handle
    hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_ALL_ACCESS);
    if (hService == NULL)
    {
        DWORD dwErr = GetLastError();
        CloseServiceHandle(hSCManager);
        return dwErr == ERROR_SERVICE_DOES_NOT_EXIST;
    }
    // Stop service before delete.
    ControlService(hService, SERVICE_CONTROL_STOP, &SrvStatus);

    // Delete service
    if (!DeleteService(hService))
    {
        DWORD dwErr = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return dwErr == ERROR_SERVICE_MARKED_FOR_DELETE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool NTServiceHelper::ChangeNTServiceConfig(const char *lpServiceName, DWORD dwServiceType,
    _In_      DWORD     dwStartType,
    _In_      DWORD     dwErrorControl,
    _In_opt_  const char *   lpBinaryPathName,
    _In_opt_  const char *   lpLoadOrderGroup,
    _Out_opt_ LPDWORD   lpdwTagId,
    _In_opt_  const char *   lpDependencies,
    _In_opt_  const char *   lpServiceStartName,
    _In_opt_  const char *   lpPassword,
    _In_opt_  const char *   lpDisplayName)
{
    SC_HANDLE hSCManager, hService;

    // Open SCM
    hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_ALL);
    if (hSCManager == NULL) return false;

    // Get service handle
    hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_ALL_ACCESS);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SC_LOCK sclLock = ::LockServiceDatabase(hSCManager);

    if (!ChangeServiceConfigA(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName,
        lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName))
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        ::UnlockServiceDatabase(sclLock);
        return false;
    }

    if (!::UnlockServiceDatabase(sclLock))
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool NTServiceHelper::CanAccessService(const char * lpServiceName, DWORD dwDesiredAccess)
{
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL) return false;

    SC_HANDLE hService = OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

DWORD NTServiceHelper::QueryNTserviceStat(const char * lpServiceName)
{
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL) return 0;

    SC_HANDLE hService = OpenServiceA(hSCManager, lpServiceName, GENERIC_READ);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return 0;
    }
    SERVICE_STATUS SrvStatus = { 0 };
    if (0 == ::QueryServiceStatus(hService, &SrvStatus))
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return 0;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return SrvStatus.dwCurrentState;
}