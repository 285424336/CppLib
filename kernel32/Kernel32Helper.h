#ifndef KERNEL32_HELPER_H_INCLUDED
#define KERNEL32_HELPER_H_INCLUDED

#include <string>
#include <set>
#if defined(_MSC_VER)
#include <windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <string\StringHelper.h>
#include <file\FileHelper.h>
#elif defined(__GNUC__)
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <string/StringHelper.h>
#include <file/FileHelper.h>
#include <future>
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
#define popen _popen
#define pclose _pclose
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
    static bool IsWow64Program()
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
    static bool Is64System()
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
    *check if is 64 program
    */
    static constexpr bool Is64Program()
    {
        return sizeof(void*) == 4 ? false : true;
    }

    static u_int GetCPUNum()
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

#if defined(_MSC_VER)
    /**
    *get system hardware information
    *lpSystemInfo(in/out): a pointer point to SYSTEM_INFO
    */
    static void GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
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
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

    /**
    *get the first process id of the specify process name.
    *ProcessName(in): process name like winlogon.exe, should be the exec file name
    */
    static u_int GetProcessId(const std::wstring &ProcessName)
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
    static std::set<u_int> GetProcessIds(const std::wstring &ProcessName)
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
    static std::string ExecuteCMDAndGetResult(const std::string &cmd)
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
    static std::string ExecuteCMDAndGetResult(const std::string &cmd, u_int timeout)
    {
#if defined(_MSC_VER)
        //Create temp file to store child process's output
        HANDLE hTmpFile = INVALID_HANDLE_VALUE;
        std::string szTempFileName = FileHelper::GetWinTempFile();
        if (szTempFileName.empty()) return "";

        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        hTmpFile = CreateFileA(szTempFileName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTmpFile == INVALID_HANDLE_VALUE)
        {
            return "";
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
        std::string result = FileHelper::GetFileContent(szTempFileName);
        FileHelper::Rm(szTempFileName);
        return result;

#elif defined(__GNUC__)
        std::string file_name = StringHelper::convert<std::string>(rand()) + StringHelper::convert<std::string>(rand()) + ".tmp";
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
            args = StringHelper::split(cmd, " ");
            for (auto arg : args)
            {
                if (arg.empty()) continue;
                argv[i++] = (char *)arg.c_str();
            }
            execvp(argv[0], &argv[1]);
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
};

#endif