#ifndef KERNEL32_HELPER_H_INCLUDED
#define KERNEL32_HELPER_H_INCLUDED

#include <string>
#include <set>
#include <map>
#include <fstream>
#if defined(_MSC_VER)
#include <windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <ntsecapi.h>
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
#define popen _popen
#define pclose _pclose
/*
* you'll find a list of NTSTATUS status codes in the DDK header
* ntstatus.h (\WINDDK\2600.1106\inc\ddk\wxp\)
*/
#define NT_SUCCESS(status)          ((NTSTATUS)(status)>=0)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

class Kernel32Helper
{
private:
#if defined(_MSC_VER)
    typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

public:

    /**
    *check if is 32 program under 64 bit system
    */
    static bool IsWow64Program();

    /**
    *check if is 64 bit system
    */
    static bool Is64System();

    /**
    *check if is 64 program
    */
    static constexpr bool Is64Program(){ return sizeof(void*) == 4 ? false : true; }

    /**
    *get the cpu num of device
    */
    static u_int GetCPUNum();

    /**
    *get the memory size of device
    */
    static unsigned long long GetMemorySize();

#if defined(_MSC_VER)
    typedef LONG NTSTATUS;
    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG           Length;
        HANDLE          RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
    } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
    typedef ULONG(__stdcall *RTLNTSTATUSTODOSERROR) (IN NTSTATUS Status);
    typedef NTSTATUS(__stdcall *ZWCREATETOKEN) (OUT PHANDLE TokenHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN TOKEN_TYPE Type, IN PLUID AuthenticationId, IN PLARGE_INTEGER ExpirationTime, IN PTOKEN_USER User, IN PTOKEN_GROUPS Groups, IN PTOKEN_PRIVILEGES Privileges, IN PTOKEN_OWNER Owner, IN PTOKEN_PRIMARY_GROUP PrimaryGroup, IN PTOKEN_DEFAULT_DACL DefaultDacl, IN PTOKEN_SOURCE Source);

    /**
    *error code to readable string
    *dwMessageId(in): win error code
    *return readable string
    */
    static std::string ErrorCode2Str(DWORD dwMessageId);

    /**
    *error code to readable string
    *dwMessageId(in): win error code
    *return readable string
    */
    static std::string ErrorCode2Str(NTSTATUS dwMessageId);

    /**
    *get system hardware information
    *lpSystemInfo(in/out): a pointer point to SYSTEM_INFO
    */
    static void GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);

    /**
    *set the specify privilege of current process
    *pszPrivilege(in): privilege str, you can use like SE_DEBUG_NAME
    *bEnablePrivilege(in): enable or disable
    */
    static BOOL SetCurProcPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege);

    /**
    *display the Privilege that the specify pid can operation, default for current process
    *process_id(in): pid of process, 0 for self
    */
    static std::string GetProcPrivileges(u_int process_id = 0);

    /**
    *add the privilege of process user, the Privilege will not accessable until user relogin
    *PrivilegeName(in): privilege str, you can use like SE_DEBUG_NAME
    */
    static BOOL AddCurUserPrivilege(LPTSTR PrivilegeName);

    /**
    *remove the privilege of process user, , the Privilege will not unaccessable until user relogin
    *PrivilegeName(in): privilege str, you can use like SE_DEBUG_NAME
    */
    static BOOL RemoveCurUserPrivilege(LPTSTR PrivilegeName);

    /**
    *Adjust the token of the specify process what can be get current user
    *process_id(in): process to adjust
    *dwAccess(in): new DACL
    */
    static BOOL AdjustDACLOfProcForCurUser(u_int process_id, DWORD dwAccess);

    /**
    *create a system token, which can exec cmd as SYSTEM user, process must have and enable SE_CREATE_TOKEN_NAME and SE_ASSIGNPRIMARYTOKEN_NAME privilege
    *return the token handle
    */
    static HANDLE CreateSystemToken(void);

    /**
    *exec the cmdline in a system context, process must have the admin previlege
    *return 0-failed, 1-success, 2-need user relogin
    */
    static int ExecAsSystem(const std::wstring &lpszCmdLine);
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
    static bool IsRunAsAdmin(bool &run_as_admin, u_int process_id = 0);
#elif defined(__GNUC__)
    /**
    *check if the process run as admin
    *run_as_admin(out): if process run as admin
    *return true if check success
    */
    static bool IsRunAsAdmin(bool &run_as_admin);
#else
#error unsupported compiler
#endif

    /**
    *get the first process id of the specify process name.
    *ProcessName(in): process name like winlogon.exe, should be the exec file name
    */
    static u_int GetProcessId(const std::wstring &ProcessName);

    /**
    *get all the process id of the specify process name.
    *ProcessName(in): process name like winlogon.exe, should be the exec file name
    */
    static std::set<u_int> GetProcessIds(const std::wstring &ProcessName);

    /**
    *exec the cmd and get the output of the result
    *cmd(in): the command want to exec
    *note: it will blocking until the cmd exec complete 
    */
    static std::string ExecuteCMDAndGetResult(const std::string &cmd);

    /**
    *exec the cmd and get the output of the result
    *cmd(in): the command want to exec
    *timeout(in): time out in millseconds
    *note: it will blocking until process exit or timeout.
    */
    static std::string ExecuteCMDAndGetResult(const std::string &cmd, u_int timeout);

    /**
    *call back of DumpBinMemory call func
    *p: a copy of process data
    *len: len of p
    *vstart: the address of the process that to dump
    *return true for continue, return false for stop now
    */
    typedef bool(*DumpBinMemoryDeal)(const char *p, u_int len, const char *vstart);
#if defined(_MSC_VER) 
    /**
    *dump the memory of the bin specify
    *deal(in): callback when data found
    *bin_name(in): bin name
    *mem_type(in): which memory type need to dump
    */
    static void DumpBinMemory(DumpBinMemoryDeal deal, const std::wstring &bin_name, u_int mem_type = MEM_PRIVATE | MEM_MAPPED);
#elif defined(__GNUC__)  
    /**
    *dump the memory of the bin specify
    *deal(in): callback when data found
    *bin_name(in): bin name
    */
    static void DumpBinMemory(DumpBinMemoryDeal deal, const std::wstring &bin_name);
#else  
#error unsupported compiler
#endif 

private:
    typedef enum
    {
        CMD_PARSE_NORMAL,
        CMD_PARSE_IN_DQUOT,
        CMD_PARSE_IN_SQUOT,
    }CMD_PARSE_STAT;
    static std::vector<std::string> ParseCMDLineToArgs(const std::string &cmd);

#if defined(_MSC_VER)
    static RTLNTSTATUSTODOSERROR RtlNtStatusToDosError;
    static ZWCREATETOKEN         ZwCreateToken;
    static BOOL                  init;
    /**
    *load func form ntdll.dll
    */
    static BOOL LocateNtdllEntry(void);

    /**
    *get the token information
    *TokenHandle(in): token handle
    *TokenInformationClass(in): token information class
    *return buf of token info
    */
    static PVOID GetTokenInfo(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass);

    /**
    *free the buf get from GetTokenInfo
    */
    static void FreeTokenInfo(PVOID buf);

    /**
    *get the privilege string
    *hToken(in): token
    *return friendly string
    */
    static std::string GetTokenPrivileges(HANDLE hToken);

    /**
    *add user privilege
    */
    static BOOL AddProcPrivilege(LSA_HANDLE PolicyHandle, PSID AccountSid, LPTSTR PrivilegeName);

    /**
    *remove user privilege
    */
    static BOOL RemoveProcPrivilege(LSA_HANDLE PolicyHandle, PSID AccountSid, LPTSTR PrivilegeName);
    
#elif defined(__GNUC__)
    static std::map<char *, char *> GetMapAddrs(u_int pid);
#else
#error unsupported compiler
#endif

};
#endif