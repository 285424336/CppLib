#ifndef DLL_IN_MEMORY_HELPER_H
#define DLL_IN_MEMORY_HELPER_H

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <utility>

typedef enum 
{
    DLL_IN_MEMORY_NO_ERROR = 0,
    DLL_IN_MEMORY_DOS_SIG_CHECK_ERROR = 1,
    DLL_IN_MEMORY_NT_SIG_CHECK_ERROR = 2,
    DLL_IN_MEMORY_OPTION_HDR_SIG_CHECK_ERROR = 3,
    DLL_IN_MEMORY_NO_SECTION_ERROR = 4,
    DLL_IN_MEMORY_MACHINE_ERROR = 5,
    DLL_IN_MEMORY_NOT_SUPPORT_SECTION_ALIGN_ERROR = 6,
    DLL_IN_MEMORY_PARAMETER_ERROR = 7,
    DLL_IN_MEMORY_ALEARDY_LOAD_ERROR = 8,
    DLL_IN_MEMORY_GET_MEM_SIZE_ERROR = 9,
    DLL_IN_MEMORY_INTERNEL_ERROR = 10,
    DLL_IN_MEMORY_RELOCATION_ERROR = 11,
    DLL_IN_MEMORY_BUILD_IMPORT_TABLE_ERROR = 12,
}DLL_IN_MEMORY_ERROR_CODE;

class DllInMemoryHelper
{
private:
    typedef BOOL(CALLBACK * LPENTRYPOINT) (HANDLE hInstance, DWORD Reason, LPVOID Reserved);

public:
    DllInMemoryHelper() : pImageBase(NULL){}
    DllInMemoryHelper(const DllInMemoryHelper&) = delete;
    DllInMemoryHelper(DllInMemoryHelper &&mv)
    {
        this->pImageBase = mv.pImageBase;
        mv.pImageBase = NULL;
    }
    DllInMemoryHelper& operator= (const DllInMemoryHelper&) = delete;
    DllInMemoryHelper& operator= (DllInMemoryHelper &&mv)
    {
        this->pImageBase = mv.pImageBase;
        mv.pImageBase = NULL;
        return *this;
    }
    ~DllInMemoryHelper() { UnloadPbDllFromMemory(); }
    void swap(DllInMemoryHelper &mv)
    {
        DllInMemoryHelper temp(std::move(mv));
        mv = std::move(*this);
        *this = std::move(temp);
    }
    /**
    *load dll memory, note, one object just can load once befor it unload
    *lpRawDll(in): the dll memory point 
    */
    DLL_IN_MEMORY_ERROR_CODE LoadPbDllFromMemory(LPVOID lpRawDll);
    /**
    *get the process addr in the dll load
    *FuncName(in): func name, or index
    */
    FARPROC GetProcAddressDirectly(const char *FuncName);
    /**
    *unload the dll explicit
    */
    void UnloadPbDllFromMemory();

private:
    bool AllocDllMemory(LPVOID lpRawDll, size_t pageSize);
    bool ExecuteTLS();
    bool ExecuteEntryPoint();

private:
    static LPVOID GetPtrFromRVA(DWORD rva, PBYTE imageBase);
    static PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader);
    static size_t GetRealSectionSize(LPVOID lpNewDll, PIMAGE_SECTION_HEADER section);
    static DLL_IN_MEMORY_ERROR_CODE CheckIsValidPEFormat(LPVOID lpRawDll);
    static size_t GetVirtualMemoryMaxSize(LPVOID lpRawDll);
    static bool CopyHeader(LPVOID lpRawDll, LPVOID lpNewDll);
    static bool CopySections(LPVOID lpRawDll, LPVOID lpNewDll);
    static bool PerformBaseRelocation(LPVOID lpRawDll, LPVOID lpNewDll);
    static bool BuildImportTable(LPVOID lpNewDll);
    static bool FinalizeSection(LPVOID address, size_t size, DWORD characteristics);
    static bool FinalizeSections(LPVOID lpNewDll);
    static inline uintptr_t AlignValueDown(uintptr_t value, uintptr_t alignment)
    {
        return value & ~(alignment - 1);
    }
    static inline size_t AlignValueUp(size_t value, size_t alignment)
    {
        return (value + alignment - 1) & ~(alignment - 1);
    }

private:
    PBYTE pImageBase;
};

inline void swap(DllInMemoryHelper &left, DllInMemoryHelper &right)
{
    left.swap(right);
}

#endif