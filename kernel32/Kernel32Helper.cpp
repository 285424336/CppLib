#include "Kernel32Helper.h"
#include <string>
#include <set>
#include <map>
#include <fstream>
#if defined(_MSC_VER)
#include <windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <string\StringHelper.h>
#include <file\FileHelper.h>
#include <uid\UidHelper.h>
#include <mutex>
#pragma comment(lib, "advapi32.lib")
#elif defined(__GNUC__)
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/ptrace.h>
#include <linux/unistd.h> 
#include <linux/kernel.h> 
#include <string/StringHelper.h>
#include <file/FileHelper.h>
#include <future>
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
Kernel32Helper::RTLNTSTATUSTODOSERROR Kernel32Helper::RtlNtStatusToDosError = NULL;
Kernel32Helper::ZWCREATETOKEN         Kernel32Helper::ZwCreateToken = NULL;
BOOL Kernel32Helper::init = LocateNtdllEntry();
#define popen _popen
#define pclose _pclose
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif


/**
*check if is 32 program under 64 bit system
*/
bool Kernel32Helper::IsWow64Program()
{
#if defined(_MSC_VER)
    BOOL bIsWow64 = FALSE;
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
    if (NULL == fnIsWow64Process) return false;
    if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64)) return false;
    return bIsWow64 == TRUE ? true : false;
#elif defined(__GNUC__)
    return Is64System() && !Is64Program();
#else
#error unsupported compiler
#endif
}

/**
*check if is 64 bit system
*/
bool Kernel32Helper::Is64System()
{
#if defined(_MSC_VER)
    SYSTEM_INFO si = { 0 };
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
        || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    {
        return true;
    }
    return false;
#elif defined(__GNUC__)
    return ExecuteCMDAndGetResult("uname -m").find("86_64");
#else
#error unsupported compiler
#endif
}

/**
*get the cpu num of device
*/
u_int Kernel32Helper::GetCPUNum()
{
#if defined(_MSC_VER)  
    SYSTEM_INFO info = { 0 };
    GetNativeSystemInfo(&info);
    return info.dwNumberOfProcessors;
#elif defined(__GNUC__)  
    return get_nprocs();
#else  
#error unsupported compiler
#endif  
}

/**
*get the memory size of device
*/
unsigned long long Kernel32Helper::GetMemorySize()
{
#if defined(_MSC_VER)  
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (FALSE == GlobalMemoryStatusEx(&status)) {
        return 0;
    }
    return status.ullTotalPhys;
#elif defined(__GNUC__)  
    struct sysinfo s_info;
    if (sysinfo(&s_info)) {
        return 0;
    }
    return s_info.totalram;
#else  
#error unsupported compiler
#endif  
}

#if defined(_MSC_VER)
/**
*error code to readable string
*dwMessageId(in): win error code
*return readable string
*/
std::string Kernel32Helper::ErrorCode2Str(DWORD dwMessageId)
{
    std::string r;
    char *errMsg = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
        dwMessageId,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errMsg, 0, NULL);

    if (errMsg) {
        r = errMsg;
        LocalFree(errMsg);
    }
    return r;
}

/**
*error code to readable string
*dwMessageId(in): win error code
*return readable string
*/
std::string Kernel32Helper::ErrorCode2Str(NTSTATUS dwMessageId)
{
    if (RtlNtStatusToDosError) {
        return ErrorCode2Str((DWORD)RtlNtStatusToDosError(dwMessageId));
    }
    return "";
}

/**
*get system hardware information
*lpSystemInfo(in/out): a pointer point to SYSTEM_INFO
*/
void Kernel32Helper::GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    if (NULL == lpSystemInfo)    return;
    LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(_T("kernel32")), "GetNativeSystemInfo");;
    if (NULL != fnGetNativeSystemInfo)
    {
        fnGetNativeSystemInfo(lpSystemInfo);
    }
    else
    {
        GetSystemInfo(lpSystemInfo);
    }
}

/**
*set the specify privilege of current process
*pszPrivilege(in): privilege str, you can use like SE_DEBUG_NAME
*bEnablePrivilege(in): enable or disable
*/
BOOL Kernel32Helper::SetCurProcPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
    BOOL bSuccess = FALSE;

    //get the privilege uid
    if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid)) {
        return FALSE;
    }

    //open process token and ready to change the token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    // first pass.  get current privilege setting
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
    if (GetLastError() == ERROR_SUCCESS)
    {
        // second pass.  set privilege based on previous setting
        tpPrevious.PrivilegeCount = 1;
        tpPrevious.Privileges[0].Luid = luid;
        if (bEnablePrivilege) {
            tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
        }
        else {
            tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
        }
        AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
        if (GetLastError() == ERROR_SUCCESS) {
            bSuccess = TRUE;
        }

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

/**
*display the Privilege that the specify pid can operation, default for current process
*process_id(in): pid of process, 0 for self
*/
std::string Kernel32Helper::GetProcPrivileges(u_int process_id)
{
    std::string r;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    if (!process_id) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)process_id);
        if (hProcess == NULL)
        {
            return r;
        }
    }
    // Get target process token  
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return r;
    }
    r = GetTokenPrivileges(hToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return r;
}

BOOL Kernel32Helper::AddCurUserPrivilege(LPTSTR PrivilegeName)
{
    NTSTATUS              status;
    BOOL                  ret = FALSE;
    LSA_HANDLE            PolicyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE                CurrentProcessToken = NULL;
    PTOKEN_USER           token_user = NULL;

    do
    {
        ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
        status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &PolicyHandle);
        if (status != STATUS_SUCCESS)
        {
            SetLastError(LsaNtStatusToWinError(status));
            break;
        }
        if (FALSE == OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY,
            &CurrentProcessToken))
        {
            break;
        }
        if (NULL == (token_user = (PTOKEN_USER)GetTokenInfo(CurrentProcessToken, TokenUser)))
        {
            break;
        }
        if (FALSE == AddProcPrivilege(PolicyHandle, token_user->User.Sid, PrivilegeName))
        {
            break;
        }
        ret = TRUE;
    } while (0);

    if (NULL != token_user)
    {
        FreeTokenInfo(token_user);
        token_user = NULL;
    }
    if (NULL != CurrentProcessToken)
    {
        CloseHandle(CurrentProcessToken);
        CurrentProcessToken = NULL;
    }
    if (NULL != PolicyHandle)
    {
        LsaClose(PolicyHandle);
        PolicyHandle = NULL;
    }
    return(ret);
}

BOOL Kernel32Helper::RemoveCurUserPrivilege(LPTSTR PrivilegeName)
{
    NTSTATUS              status;
    BOOL                  ret = FALSE;
    LSA_HANDLE            PolicyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE                CurrentProcessToken = NULL;
    PTOKEN_USER           token_user = NULL;

    do
    {
        ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
        status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &PolicyHandle);
        if (status != STATUS_SUCCESS)
        {
            SetLastError(LsaNtStatusToWinError(status));
            break;
        }
        if (FALSE == OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY,
            &CurrentProcessToken))
        {
            break;
        }
        if (NULL == (token_user = (PTOKEN_USER)GetTokenInfo(CurrentProcessToken, TokenUser)))
        {
            break;
        }
        if (FALSE == RemoveProcPrivilege(PolicyHandle,
            token_user->User.Sid,
            PrivilegeName))
        {
            break;
        }
        ret = TRUE;
    } while (0);

    if (NULL != token_user)
    {
        FreeTokenInfo(token_user);
        token_user = NULL;
    }
    if (NULL != CurrentProcessToken)
    {
        CloseHandle(CurrentProcessToken);
        CurrentProcessToken = NULL;
    }
    if (NULL != PolicyHandle)
    {
        LsaClose(PolicyHandle);
        PolicyHandle = NULL;
    }
    return(ret);
}

/**
*Adjust the token of the specify process what can be get current user
*process_id(in): process to adjust
*dwAccess(in): new DACL
*/
BOOL Kernel32Helper::AdjustDACLOfProcForCurUser(u_int process_id, DWORD dwAccess)
{
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    BOOL bRet = FALSE;
    PSECURITY_DESCRIPTOR pOldSd = NULL, pNewSd = NULL;
    DWORD dwLen = 0;
    DWORD dwReturn = 0;
    DWORD dwRet = 0;
    BOOL bAcl = FALSE, bDefAcl = FALSE;
    PACL pOldAcl = NULL;
    PACL pNewAcl = NULL;
    PACL pSacl = NULL;
    TCHAR szUserName[1024] = { 0 };
    EXPLICIT_ACCESS ea = { 0 };
    DWORD dwDaclSize = 0;
    DWORD dwSaclSize = 0;
    DWORD dwOwnerSize = 0;
    DWORD dwPrimaryGroupSize = 0;
    PSID pSidOwner = NULL;
    PSID pPrimaryGroup = NULL;

    if (!process_id) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)process_id);
        if (hProcess == NULL)
        {
            return false;
        }
    }

    do
    {
        //get token
        bRet = OpenProcessToken(hProcess, READ_CONTROL | WRITE_DAC, &hToken);
        if (!bRet) {
            break;
        }

        GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pOldSd, NULL, &dwLen);
        pOldSd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
        if (!pOldSd) {
            break;
        }
        bRet = GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pOldSd, dwLen, &dwReturn);
        if (!bRet) {
            break;
        }
        bRet = GetSecurityDescriptorDacl(pOldSd, &bAcl, &pOldAcl, &bDefAcl);
        if (!bRet) {
            break;
        }

        dwReturn = sizeof(szUserName) / sizeof(szUserName[0]);
        GetUserName(szUserName, &dwReturn);
        BuildExplicitAccessWithName(&ea, szUserName, dwAccess, GRANT_ACCESS, NULL);
        dwRet = SetEntriesInAcl(1, &ea, pOldAcl, &pNewAcl);
        if (!bRet) {
            break;
        }

        MakeAbsoluteSD(pOldSd,
            pNewSd,
            &dwLen,
            pOldAcl,
            &dwDaclSize,
            pSacl,
            &dwSaclSize,
            pSidOwner,
            &dwOwnerSize,
            pPrimaryGroup,
            &dwPrimaryGroupSize);
        pOldAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDaclSize);
        if (!pOldAcl) {
            break;
        }
        pSacl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSaclSize);
        if (!pSacl) {
            break;
        }
        pSidOwner = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOwnerSize);
        if (!pSidOwner) {
            break;
        }
        pPrimaryGroup = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPrimaryGroupSize);
        if (!pPrimaryGroup) {
            break;
        }
        pNewSd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
        if (!pNewSd) {
            break;
        }
        bRet = MakeAbsoluteSD(pOldSd,
            pNewSd,
            &dwLen,
            pOldAcl,
            &dwDaclSize,
            pSacl,
            &dwSaclSize,
            pSidOwner,
            &dwOwnerSize,
            pPrimaryGroup,
            &dwPrimaryGroupSize);
        if (!bRet) {
            break;
        }

        bRet = SetSecurityDescriptorDacl(pNewSd, bAcl, pNewAcl, bDefAcl);
        if (!bRet) {
            break;
        }
        bRet = SetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pNewSd);
        if (!bRet) {
            break;
        }
        bRet = TRUE;
    } while (0);

    if (hToken != NULL) CloseHandle(hToken);
    if (hProcess != NULL) CloseHandle(hProcess);
    if (pOldSd != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pOldSd);
    if (pOldAcl != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pOldAcl);
    if (pSacl != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSacl);
    if (pSidOwner != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pSidOwner);
    if (pPrimaryGroup != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pPrimaryGroup);
    if (pNewSd != NULL) HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pNewSd);
    return bRet;
}

HANDLE Kernel32Helper::CreateSystemToken(void)
{
    NTSTATUS                    status;
    HANDLE                      CurrentProcessToken = NULL;
    HANDLE                      SystemToken = NULL;
    SID_IDENTIFIER_AUTHORITY    sid_identifier_authority = SECURITY_NT_AUTHORITY;
    TOKEN_USER                  token_user = {
        { NULL, 0 }
    };
    TOKEN_SOURCE                token_source = {
        { '*', '*', 'A', 'N', 'O', 'N', '*', '*' },
        { 0, 0 }
    };
    TOKEN_OWNER                 token_owner = { NULL };
    LUID                        AuthenticationId = SYSTEM_LUID;
    SECURITY_QUALITY_OF_SERVICE security_quality_of_service = {
        sizeof(security_quality_of_service),
        SecurityAnonymous,
        SECURITY_STATIC_TRACKING,
        FALSE
    };
    OBJECT_ATTRIBUTES           object_attributes = {
        sizeof(object_attributes),
        NULL,
        NULL,
        0,
        NULL,
        &security_quality_of_service
    };
    PTOKEN_PRIVILEGES           token_privileges = NULL;
    PTOKEN_STATISTICS           token_statistics = NULL;
    PTOKEN_GROUPS               token_groups = NULL;
    PTOKEN_PRIMARY_GROUP        token_primary_groups = NULL;
    PTOKEN_DEFAULT_DACL         token_default_dacl = NULL;

    do {
        if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &CurrentProcessToken)) {
            break;
        }
        if (FALSE == AllocateAndInitializeSid(&sid_identifier_authority,
            1,
            SECURITY_LOCAL_SYSTEM_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &token_user.User.Sid)) {
            break;
        }
        token_owner.Owner = token_user.User.Sid;
        if (FALSE == AllocateLocallyUniqueId(&token_source.SourceIdentifier)) {
            break;
        }
        token_statistics = (PTOKEN_STATISTICS)GetTokenInfo(CurrentProcessToken, TokenStatistics);
        if (NULL == token_statistics) {
            break;
        }
        token_privileges = (PTOKEN_PRIVILEGES)GetTokenInfo(CurrentProcessToken, TokenPrivileges);
        if (NULL == token_privileges) {
            break;
        }
        token_groups = (PTOKEN_GROUPS)GetTokenInfo(CurrentProcessToken, TokenGroups);
        if (NULL == token_groups) {
            break;
        }
        token_primary_groups = (PTOKEN_PRIMARY_GROUP)GetTokenInfo(CurrentProcessToken, TokenPrimaryGroup);
        if (NULL == token_primary_groups) {
            break;
        }
        token_default_dacl = (PTOKEN_DEFAULT_DACL)GetTokenInfo(CurrentProcessToken, TokenDefaultDacl);
        if (NULL == token_default_dacl) {
            break;
        }
        status = ZwCreateToken(
            &SystemToken,
            TOKEN_ALL_ACCESS,
            &object_attributes,
            TokenPrimary,
            &AuthenticationId,
            &token_statistics->ExpirationTime,
            &token_user,
            token_groups,
            token_privileges,
            &token_owner,
            token_primary_groups,
            token_default_dacl,
            &token_source
        );
        if (!NT_SUCCESS(status)) {
            break;
        }
    } while (0);
    if (token_user.User.Sid != NULL)
    {
        FreeSid(token_user.User.Sid);
        token_user.User.Sid = NULL;
    }
    if (CurrentProcessToken != NULL)
    {
        CloseHandle(CurrentProcessToken);
        CurrentProcessToken = NULL;
    }
    if (token_statistics != NULL)
    {
        FreeTokenInfo(token_statistics);
        token_statistics = NULL;
    }
    if (token_privileges != NULL)
    {
        FreeTokenInfo(token_privileges);
        token_privileges = NULL;
    }
    if (token_groups != NULL)
    {
        FreeTokenInfo(token_groups);
        token_groups = NULL;
    }
    if (token_primary_groups != NULL)
    {
        FreeTokenInfo(token_primary_groups);
        token_primary_groups = NULL;
    }
    if (token_default_dacl != NULL)
    {
        FreeTokenInfo(token_default_dacl);
        token_default_dacl = NULL;
    }
    return(SystemToken);
}

int Kernel32Helper::ExecAsSystem(const std::wstring &lpszCmdLine)
{
    int ret = 0;
    if ((SetCurProcPrivilege(SE_CREATE_TOKEN_NAME, TRUE) == FALSE)
        || (SetCurProcPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME, TRUE) == FALSE)
        || (SetCurProcPrivilege(SE_INCREASE_QUOTA_NAME, TRUE) == FALSE)) {
        if ((Kernel32Helper::AddCurUserPrivilege(SE_CREATE_TOKEN_NAME) == TRUE)
            && (Kernel32Helper::AddCurUserPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) == TRUE)
            && (Kernel32Helper::AddCurUserPrivilege(SE_INCREASE_QUOTA_NAME) == TRUE)) {
            return 2;
        }
        return 0;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (FALSE == CreateProcessAsUserW (
        CreateSystemToken(),
        NULL,
        (LPWSTR)lpszCmdLine.c_str(),
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB, //note: CREATE_BREAKAWAY_FROM_JOB is must for WIN10, look https://social.technet.microsoft.com/Forums/windows/en-US/89df4e34-4a70-4503-a4db-d8cee86e0c3b/createprocessasuser-failing-with-error-code-5-erroraccessdenied?forum=w8itproappcompat for detail
        NULL,
        NULL,
        &si,
        &pi
    )) {
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        return 0;
    }
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    return 1;
}

#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
/**
*check if the process run as admin
*run_as_admin(out): if specify process run as admin
*process_id(in): process id, default is current process
*return true if check success
*/
bool Kernel32Helper::IsRunAsAdmin(bool &run_as_admin, u_int process_id)
{
    bool bElevated = false;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    if (!process_id) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)process_id);
        if (hProcess == NULL)
        {
            return false;
        }
    }
    // Get target process token  
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return false;
    }
    TOKEN_ELEVATION tokenEle;
    DWORD dwRetLen = 0;
    // Retrieve token elevation information  
    if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
    {
        if (dwRetLen == sizeof(tokenEle))
        {
            bElevated = tokenEle.TokenIsElevated != 0;
        }
    }
    else
    {
        CloseHandle(hProcess);
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hProcess);
    CloseHandle(hToken);
    run_as_admin = bElevated;
    return true;
}
#elif defined(__GNUC__)
/**
*check if the process run as admin
*run_as_admin(out): if process run as admin
*return true if check success
*/
bool Kernel32Helper::IsRunAsAdmin(bool &run_as_admin)
{
    if (geteuid() != 0)
    {
        run_as_admin = false;
    }
    else
    {
        run_as_admin = true;
    }
    return true;
}
#else
#error unsupported compiler
#endif

/**
*get the first process id of the specify process name.
*ProcessName(in): process name like winlogon.exe, should be the exec file name
*/
u_int Kernel32Helper::GetProcessId(const std::wstring &ProcessName)
{
#if defined(_MSC_VER)
    PROCESSENTRY32W pt;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hsnap) return 0;
    pt.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hsnap, &pt)) { // must call this first
        do {
            if (!lstrcmpiW(pt.szExeFile, ProcessName.c_str())) {
                CloseHandle(hsnap);
                return pt.th32ProcessID;
            }
        } while (Process32NextW(hsnap, &pt));
    }
    CloseHandle(hsnap);
    return 0;
#elif defined(__GNUC__)
    std::string pn = StringHelper::tochar(ProcessName);
    if (pn.empty()) return 0;
    std::string cmd = "ps -ef | awk '{print $2\" \"$8\" \"}' | grep '[/\\ ]" + std::move(pn) + " ' | grep -v grep | awk '{print $1}' | head -1";
    std::string result = ExecuteCMDAndGetResult(cmd);
    if (result.empty()) return 0;
    auto ids = StringHelper::split(result, "\n");
    for (auto id : ids)
    {
        if (id.empty()) continue;
        return StringHelper::convert<u_int>(id);
    }
    return 0;
#else
#error unsupported compiler
#endif
}

/**
*get all the process id of the specify process name.
*ProcessName(in): process name like winlogon.exe, should be the exec file name
*/
std::set<u_int> Kernel32Helper::GetProcessIds(const std::wstring &ProcessName)
{
    std::set<u_int> result;
#if defined(_MSC_VER)
    PROCESSENTRY32W pt;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hsnap) return result;
    pt.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hsnap, &pt)) { // must call this first
        do {
            if (!lstrcmpiW(pt.szExeFile, ProcessName.c_str())) {
                result.insert(pt.th32ProcessID);
            }
        } while (Process32NextW(hsnap, &pt));
    }
    CloseHandle(hsnap);
    return std::move(result);
#elif defined(__GNUC__)
    std::string pn = StringHelper::tochar(ProcessName);
    if (pn.empty()) return result;
    std::string cmd = "ps -ef | awk '{print $2\" \"$8\" \"}' | grep '[/\\ ]" + std::move(pn) + " ' | grep -v grep | awk '{print $1}'";
    std::string res = ExecuteCMDAndGetResult(cmd);
    if (res.empty()) return result;
    std::vector<std::string> vc = StringHelper::split(res, "\n");
    for (auto line : vc)
    {
        if (line.empty()) continue;
        result.insert(StringHelper::convert<u_int>(line));
    }
    return std::move(result);
#else
#error unsupported compiler
#endif
}

/**
*exec the cmd and get the output of the result
*cmd(in): the command want to exec
*note: it will blocking until the cmd exec complete
*/
std::string Kernel32Helper::ExecuteCMDAndGetResult(const std::string &cmd)
{
    std::string result;
    if (cmd.empty()) return result;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;
    char buffer[1024];
    while (!feof(pipe)) {
        if (fgets(buffer, 1024, pipe) != NULL) {
            result += buffer;
        }
    }
    pclose(pipe);
    return result;
}

/**
*exec the cmd and get the output of the result
*cmd(in): the command want to exec
*timeout(in): time out in millseconds
*note: it will blocking until process exit or timeout.
*/
std::string Kernel32Helper::ExecuteCMDAndGetResult(const std::string &cmd, u_int timeout)
{
#if defined(_MSC_VER)
    static std::string temp_dir = FileHelper::CoordinateFileSeparator(FileHelper::GetWinTempPath()) + "exectmp\\";
    static bool mkdir = FileHelper::MkDir(temp_dir);
    static u_int run_count = 0;
    static std::mutex run_count_mutex;

    if (temp_dir.empty())
    {
        return "";
    }

    {
        std::unique_lock<std::mutex> lock(run_count_mutex);
        run_count++;
    }

    std::string result;
    do
    {
        //Create temp file to store child process's output
        HANDLE hTmpFile = INVALID_HANDLE_VALUE;
        std::string szTempFileName = temp_dir + UidHelper::GenerateUUID() + ".tmp";

        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        hTmpFile = CreateFileA(szTempFileName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTmpFile == INVALID_HANDLE_VALUE)
        {
            break;
        }

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = hTmpFile;
        si.hStdError = hTmpFile;
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.dwFlags |= STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        if (::CreateProcessA(NULL,     // No module name (use command line)
            (LPSTR)cmd.c_str(),     // Command line
            NULL,                       // Process handle not inheritable
            NULL,                       // Thread handle not inheritable
            TRUE,                   // Set handle inheritance to TRUE
            0,                          // No creation flags
            NULL,                       // Use parent's environment block
            NULL,                       // Use parent's starting directory 
            &si,                        // Pointer to STARTUPINFO structure
            &pi))                       // Pointer to PROCESS_INFORMATION structure
        {
            DWORD ret = WaitForSingleObject(pi.hProcess, timeout);
            if (ret == WAIT_TIMEOUT)
            {
                TerminateProcess(pi.hProcess, 0);
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        CloseHandle(hTmpFile);
        result = FileHelper::GetFileContent(szTempFileName);
    } while (0);

    {
        std::unique_lock<std::mutex> lock(run_count_mutex);
        run_count--;
        if (!run_count)
        {
            FileHelper::Rm(temp_dir);
            FileHelper::MkDir(temp_dir);
        }
    }
    return result;

#elif defined(__GNUC__)
    std::string file_name = "/tmp/" + StringHelper::convert<std::string>(rand()) + StringHelper::convert<std::string>(rand()) + ".tmp";
    pid_t pid;
    int status;
    pid = fork();
    switch (pid)
    {
    case -1:
    {
        return "";
        break;
    }
    case 0:
    {
        int fd;
        std::vector<std::string> args;
        char * argv[50] = { 0 };
        int i = 0;

        fd = open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (fd < 0) exit(0);
        if (dup2(fd, 1) < 0) exit(0);
        if (dup2(fd, 2) < 0) exit(0);
        args = ParseCMDLineToArgs(cmd);
        for (auto arg : args)
        {
            if (arg.empty()) continue;
            argv[i++] = (char *)arg.c_str();
        }
        execvp(argv[0], &argv[0]);
        exit(0);
        break;
    }
    default:
    {
        auto f = std::async(std::launch::async, [pid]
        {
            int status = 0;
            waitpid(pid, &status, 0);
            return status;
        });
        auto stat = f.wait_for(std::chrono::milliseconds(timeout));
        if (stat != std::future_status::ready)
        {
            kill(pid, SIGABRT);
        }
        std::string result = FileHelper::GetFileContent(file_name);
        FileHelper::Rm(file_name);
        return result;
        break;
    }
    }
#else
#error unsupported compiler
#endif
}

#if defined(_MSC_VER) 
/**
*dump the memory of the bin specify
*deal(in): callback when data found
*bin_name(in): bin name
*mem_type(in): which memory type need to dump
*/
void Kernel32Helper::DumpBinMemory(Kernel32Helper::DumpBinMemoryDeal deal, const std::wstring &bin_name, u_int mem_type)
{
    u_int pid = GetProcessId(bin_name);
    if (!pid) {
        return;
    }
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        return;
    }
    SYSTEM_INFO sys_info = { 0 };
    GetNativeSystemInfo(&sys_info);
    char *p = 0;
    while (p < sys_info.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION info = { 0 };
        if (VirtualQueryEx(process, p, &info, sizeof(info)) != sizeof(info)) {
            break;
        }
        if (!(info.Type | mem_type) || info.State != MEM_COMMIT) {
            p += info.RegionSize;
            continue;
        }
        p = (char *)info.BaseAddress;
        SIZE_T bytes_read = 0;
        std::unique_ptr<char[]> data = std::make_unique<char[]>(info.RegionSize);
        if (!data) {
            break;
        }
        if (!ReadProcessMemory(process, p, data.get(), info.RegionSize, &bytes_read)) {
            p += info.RegionSize;
            continue;
        }
        if (!deal((const char *)data.get(), bytes_read, p)) {
            break;
        }
        p += info.RegionSize;
    }
    CloseHandle(process);
}
#elif defined(__GNUC__)  
/**
*dump the memory of the bin specify
*deal(in): callback when data found
*bin_name(in): bin name
*/
void Kernel32Helper::DumpBinMemory(DumpBinMemoryDeal deal, const std::wstring &bin_name)
{
    u_int pid = GetProcessId(bin_name);
    if (!pid) {
        return;
    }
    std::map<char *, char *> addrs = GetMapAddrs(pid);
    if (addrs.empty()) {
        return;
    }
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
        return;
    }
    do
    {
        char mem_file[30] = { 0 };
        snprintf(mem_file, sizeof(mem_file), "/proc/%d/mem", pid);
        std::ifstream fs(mem_file, std::ios::binary);
        if (!fs) {
            break;
        }
        for (std::map<char *, char *>::iterator it = addrs.begin(); it != addrs.end(); it++) {
            if ((it->second - it->first) <= 0) {
                continue;
            }
            size_t len = it->second - it->first;
            char * data = new (std::nothrow) char[len];
            if (data == NULL) {
                break;
            }
            fs.seekg((size_t)it->first, std::ios::beg);
            if (!fs) {
                delete[]data;
                break;
            }
            fs.read(data, len);
            if (!fs) {
                delete[]data;
                break;
            }
            if (!deal((const char *)data, len, it->first)) {
                delete[]data;
                break;
            }
            delete[]data;
        }
    } while (0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
#else
#error unsupported compiler
#endif

std::vector<std::string> Kernel32Helper::ParseCMDLineToArgs(const std::string &cmd)
{
    std::vector<std::string> result;
    const char blank = ' ';
    const char dquot = '"';
    const char squot = '\'';
    CMD_PARSE_STAT stat = CMD_PARSE_NORMAL;
    std::string arg;
    std::string cmd_tmp = cmd + " ";
    for (auto s : cmd_tmp)
    {
        switch (stat)
        {
        case CMD_PARSE_NORMAL:
        {
            switch (s)
            {
            case blank:
            {
                if (!arg.empty())
                {
                    result.emplace_back(arg);
                    arg.clear();
                }
            }
            break;
            case dquot:
            {
                stat = CMD_PARSE_IN_DQUOT;
            }
            break;
            case squot:
            {
                stat = CMD_PARSE_IN_SQUOT;
            }
            break;
            default:
            {
                arg.append(&s, 1);
            }
            break;
            }
        }
        break;
        case CMD_PARSE_IN_DQUOT:
        {
            switch (s)
            {
            case dquot:
            {
                stat = CMD_PARSE_NORMAL;
            }
            break;
            case blank:
            case squot:
            default:
            {
                arg.append(&s, 1);
            }
            break;
            }
        }
        break;
        case CMD_PARSE_IN_SQUOT:
        {
            switch (s)
            {
            case squot:
            {
                stat = CMD_PARSE_NORMAL;
            }
            break;
            case blank:
            case dquot:
            default:
            {
                arg.append(&s, 1);
            }
            break;
            }
        }
        break;
        default:
            return std::vector<std::string>();
            break;
        }
    }
    if (stat != CMD_PARSE_NORMAL)
    {
        return std::vector<std::string>();
    }
    return result;
}

#if defined(_MSC_VER)
/**
*load func form ntdll.dll
*/
BOOL Kernel32Helper::LocateNtdllEntry(void)
{
    BOOLEAN bool_ret = FALSE;
#ifdef _UNICODE
    wchar_t    NTDLL_DLL[] = L"ntdll.dll";
#else
    char    NTDLL_DLL[] = "ntdll.dll";
#endif // _UNICODE
    HMODULE ntdll_dll = NULL;

    /*
    * returns a handle to a mapped module without incrementing its
    * reference count
    */
    if ((ntdll_dll = GetModuleHandle(NTDLL_DLL)) == NULL)
    {
        return(FALSE);
    }
    if (!(RtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)GetProcAddress(ntdll_dll, "RtlNtStatusToDosError")))
    {
        goto LocateNtdllEntry_return;
    }
    if (!(ZwCreateToken = (ZWCREATETOKEN)GetProcAddress(ntdll_dll, "ZwCreateToken")))
    {
        goto LocateNtdllEntry_return;
    }
    bool_ret = TRUE;
LocateNtdllEntry_return:
    ntdll_dll = NULL;
    return(bool_ret);
}

/**
*get the token information
*TokenHandle(in): token handle
*TokenInformationClass(in): token information class
*return buf of token info
*/
PVOID Kernel32Helper::GetTokenInfo(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass)
{
    DWORD needed = 0;
    PVOID buf = NULL;
    DWORD error;
    BOOL  errflag = FALSE;

    if (FALSE == GetTokenInformation(TokenHandle, TokenInformationClass, NULL, 0, &needed))
    {
        error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER)
        {
            errflag = TRUE;
            goto GetFromToken_exit;
        }
    }
    if (NULL == (buf = calloc(needed, 1)))
    {
        goto GetFromToken_exit;
    }
    if (FALSE == GetTokenInformation(TokenHandle, TokenInformationClass, buf, needed, &needed))
    {
        errflag = TRUE;
        goto GetFromToken_exit;
    }
GetFromToken_exit:
    if (errflag == TRUE)
    {
        if (buf != NULL)
        {
            free(buf);
            buf = NULL;
        }
    }
    return(buf);
}

/**
*free the buf get from GetTokenInfo
*/
void Kernel32Helper::FreeTokenInfo(PVOID buf)
{
    if (buf != NULL)
    {
        free(buf);
        buf = NULL;
    }
}

/**
*get the privilege string
*hToken(in): token
*return friendly string
*/
std::string Kernel32Helper::GetTokenPrivileges(HANDLE hToken)
{
    std::string r;
    PTOKEN_PRIVILEGES token_privileges = NULL;
    DWORD PrivilegeCount;
    char PrivilegeName[256];
    char PrivilegeDisplayName[256];
    DWORD NameSize;
    DWORD LanguageId;

    if (NULL == (token_privileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges)))
    {
        return r;
    }
    for (PrivilegeCount = 0; PrivilegeCount < token_privileges->PrivilegeCount; PrivilegeCount++)
    {
        NameSize = sizeof(PrivilegeName);
        if (FALSE == LookupPrivilegeNameA(NULL, &token_privileges->Privileges[PrivilegeCount].Luid, PrivilegeName, &NameSize))
        {
            continue;
        }
        NameSize = sizeof(PrivilegeDisplayName);
        if (FALSE == LookupPrivilegeDisplayNameA(NULL, PrivilegeName, PrivilegeDisplayName, &NameSize, &LanguageId))
        {
            continue;
        }
        r += PrivilegeDisplayName + std::string(" (") + PrivilegeName + ")\n";
    }
    FreeTokenInfo(token_privileges);
    return r;
}

BOOL Kernel32Helper::AddProcPrivilege(LSA_HANDLE PolicyHandle, PSID AccountSid, LPTSTR PrivilegeName)
{
    BOOL               ret = FALSE;
    LSA_UNICODE_STRING UserRights;
    USHORT             StringLength;
    NTSTATUS           status;

    if (PrivilegeName == NULL)
    {
        return FALSE;
    }
#ifdef _UNICODE
    StringLength = (USHORT)wcslen(PrivilegeName);
    UserRights.Buffer = PrivilegeName;
    UserRights.Length = StringLength * sizeof(WCHAR);
    UserRights.MaximumLength = (StringLength + 1) * sizeof(WCHAR);
#else
    std::wstring wPrivilegeName = StringHelper::towchar(PrivilegeName);
    StringLength = (USHORT)wPrivilegeName.size();
    UserRights.Buffer = (PWSTR)wPrivilegeName.c_str();
    UserRights.Length = StringLength * sizeof(WCHAR);
    UserRights.MaximumLength = (StringLength + 1) * sizeof(WCHAR);
#endif // _UNICODE

    status = LsaAddAccountRights(PolicyHandle, AccountSid, &UserRights, 1);
    if (status != STATUS_SUCCESS)
    {
        SetLastError(LsaNtStatusToWinError(status));
        return false;
    }
    return TRUE;
}

BOOL Kernel32Helper::RemoveProcPrivilege(LSA_HANDLE PolicyHandle, PSID AccountSid, LPTSTR PrivilegeName)
{
    BOOL               ret = FALSE;
    LSA_UNICODE_STRING UserRights;
    USHORT             StringLength;
    NTSTATUS           status;

    if (PrivilegeName == NULL)
    {
        return FALSE;
    }
#ifdef _UNICODE
    StringLength = (USHORT)wcslen(PrivilegeName);
    UserRights.Buffer = PrivilegeName;
    UserRights.Length = StringLength * sizeof(WCHAR);
    UserRights.MaximumLength = (StringLength + 1) * sizeof(WCHAR);
#else
    std::wstring wPrivilegeName = StringHelper::towchar(PrivilegeName);
    StringLength = (USHORT)wPrivilegeName.size();
    UserRights.Buffer = (PWSTR)wPrivilegeName.c_str();
    UserRights.Length = StringLength * sizeof(WCHAR);
    UserRights.MaximumLength = (StringLength + 1) * sizeof(WCHAR);
#endif // _UNICODE
    status = LsaRemoveAccountRights(PolicyHandle, AccountSid, FALSE, &UserRights, 1);
    if (status != STATUS_SUCCESS)
    {
        SetLastError(LsaNtStatusToWinError(status));
        return FALSE;
    }
    return TRUE;
}

#elif defined(__GNUC__)
std::map<char *, char *> Kernel32Helper::GetMapAddrs(u_int pid)
{
    std::map<char *, char *> r;
    FILE *fp = NULL;
    char filename[30];
    char line[1024];
    size_t addr_start;
    size_t addr_end;
    char str[20];
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return r;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%zx-%zx %*s %*s %*s", &addr_start, &addr_end);
        r[(char *)addr_start] = (char *)addr_end;
    }
    fclose(fp);
    return r;
}
#else
#error unsupported compiler
#endif