#pragma once
#include <windows.h>
#include <Dbghelp.h>
#include <shlwapi.h>
#include <Shlobj.h>
#include <string>
#include <Psapi.h>
#include <mutex>
using namespace std; 

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")
	
class CDumpCatch
{
	/**
	*Note you should invoke Instance or SetDumpFilePath at least once
	*/

public:
	/**
	*Get or init the instance of DumpCatch
	*/
	static CDumpCatch& Instance()
	{
		static CDumpCatch instance;
		return instance;
	}

	/**
	*Set the dump file path, defalut path is work dir.
	*p(in): the dump file path you want to set, empty path will not effect
	*return the dump file path in using
	*/
	static std::wstring SetDumpFilePath(const std::wstring &p = std::wstring())
	{
		static std::wstring dump_file_path;
		static std::mutex lock;

		Instance();
		std::unique_lock<std::mutex> lck(lock);
		if (!p.empty()) {
			dump_file_path = p;
		}
		return dump_file_path;
	}

private:
	static LONG WINAPI UnhandledExceptionFilterEx(struct _EXCEPTION_POINTERS *pException)
	{
		wchar_t szFileName[MAX_PATH] = { 0 };
		wchar_t szProcName[MAX_PATH] = { 0 };
		SYSTEMTIME stLocalTime = { 0 };
		GetLocalTime(&stLocalTime);
		HANDLE cur = GetCurrentProcess();
		if (GetModuleBaseNameW(cur, NULL, szProcName, MAX_PATH)) {
			wsprintfW(szFileName, L"%s_%04d%02d%02d%02d%02d%02d_%d.dmp",
				szProcName,
				(int)stLocalTime.wYear, (int)stLocalTime.wMonth, (int)stLocalTime.wDay,
				(int)stLocalTime.wHour, (int)stLocalTime.wMinute, (int)stLocalTime.wSecond,
				(int)GetCurrentProcessId());
		}
		else {
			wsprintfW(szFileName, L"%04d%02d%02d%02d%02d%02d_%d.dmp",
				(int)stLocalTime.wYear, (int)stLocalTime.wMonth, (int)stLocalTime.wDay,
				(int)stLocalTime.wHour, (int)stLocalTime.wMinute, (int)stLocalTime.wSecond,
				(int)GetCurrentProcessId());
		}
		CloseHandle(cur);
		std::wstring path = SetDumpFilePath();
		if (path.empty()) {
			path = szFileName;
		}
		else {
			::SHCreateDirectoryExW(NULL, path.c_str(), NULL);
			path += std::wstring(L"\\") + szFileName;
		}
		BOOL bRelease = GeneratorDumpFile(path.c_str(), pException);
		if (bRelease) {
			return EXCEPTION_EXECUTE_HANDLER;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	static BOOL GeneratorDumpFile(const std::wstring& strPath, EXCEPTION_POINTERS *pException)
	{
		HANDLE hDumpFile = ::CreateFileW(strPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDumpFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
		dumpInfo.ExceptionPointers = pException;
		dumpInfo.ThreadId = ::GetCurrentThreadId();
		dumpInfo.ClientPointers = FALSE;
		BOOL bRet = ::MiniDumpWriteDump(::GetCurrentProcess(), ::GetCurrentProcessId(), hDumpFile, MiniDumpWithFullMemory, &dumpInfo, NULL, NULL);
		::CloseHandle(hDumpFile);
		return bRet;
	}

	static void PureCallHandler(void)
	{
		throw std::invalid_argument("PureCallHandler");
	}

	static void InvalidParameterHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
	{
		throw std::invalid_argument("InvalidParameterHandler");
	}


private:
	CDumpCatch()
	{
		SetInvalidHandle();
		AddExceptionHandle();
	}

	CDumpCatch(const CDumpCatch&) = delete;
	CDumpCatch& operator=(const CDumpCatch&) = delete;

	~CDumpCatch()
	{
		UnSetInvalidHandle();
		RemoveExceptionHandle();
	}

	BOOL AddExceptionHandle()
	{
		m_preFilter = ::SetUnhandledExceptionFilter(UnhandledExceptionFilterEx);
		return TRUE;
	}

	BOOL RemoveExceptionHandle()
	{
		if (m_preFilter != NULL) {
			::SetUnhandledExceptionFilter(m_preFilter);
			m_preFilter = NULL;
		}
		return TRUE;
	}

	void SetInvalidHandle()
	{
#if _MSC_VER >= 1400  // MSVC 2005/8
		m_preIph = _set_invalid_parameter_handler(CDumpCatch::InvalidParameterHandler);
		_CrtSetReportMode(_CRT_ASSERT, 0);
#endif  // _MSC_VER >= 1400
		m_prePch = _set_purecall_handler(CDumpCatch::PureCallHandler);
	}
	void UnSetInvalidHandle()
	{
#if _MSC_VER >= 1400  // MSVC 2005/8
		if (m_preIph) {
			_set_invalid_parameter_handler(m_preIph);
			m_preIph = NULL;
		}
#endif  // _MSC_VER >= 1400
		if (m_prePch) {
			_set_purecall_handler(m_prePch);
			m_prePch = NULL;
		}
	}

private:
	LPTOP_LEVEL_EXCEPTION_FILTER m_preFilter;
	_purecall_handler m_prePch;
#if _MSC_VER >= 1400  // MSVC 2005/8
	_invalid_parameter_handler m_preIph;
#endif
};
