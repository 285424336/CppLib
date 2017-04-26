#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <lmerr.h>
#include <stdio.h>
#include <string\StringHelper.h>
#ifndef NODEBUG
#include <iostream>
#endif
#include "DllInMemoryHelper.h"

#define MakePtr( cast, ptr, addValue ) (cast)((char*)(ptr)+(size_t)(addValue))
#define GetImgDirEntry( pNTHdr, IDE ) (&(pNTHdr->OptionalHeader.DataDirectory[IDE]))
#define GetImgDirEntryRVA( pNTHdr, IDE ) (pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)
#define GetImgDirEntrySize( pNTHdr, IDE ) (pNTHdr->OptionalHeader.DataDirectory[IDE].Size)

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
    {
        // not executable
        { PAGE_NOACCESS, PAGE_WRITECOPY },
        { PAGE_READONLY, PAGE_READWRITE },
    },{
        // executable
        { PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
        { PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
    },
};

PIMAGE_SECTION_HEADER DllInMemoryHelper::GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);

    for (decltype(pNTHeader->FileHeader.NumberOfSections) i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        auto size = section->Misc.VirtualSize;
        if (0 == size) size = section->SizeOfRawData;
        if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size))) return section;
    }
    return 0;
}

LPVOID DllInMemoryHelper::GetPtrFromRVA(DWORD rva, PBYTE imageBase)
{
    PIMAGE_SECTION_HEADER pSectionHdr = NULL;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
    if (!pSectionHdr) return 0;
    return (PVOID)(imageBase + rva - (pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData));
}

size_t DllInMemoryHelper::GetRealSectionSize(LPVOID lpNewDll, PIMAGE_SECTION_HEADER section)
{
    PIMAGE_DOS_HEADER pRawDosHeader = (PIMAGE_DOS_HEADER)lpNewDll;
    PIMAGE_NT_HEADERS pRawNTHeader = MakePtr(PIMAGE_NT_HEADERS, pRawDosHeader, pRawDosHeader->e_lfanew);
    DWORD size = section->SizeOfRawData;
    if (size == 0)
    {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        {
            size = pRawNTHeader->OptionalHeader.SizeOfInitializedData;
        }
        else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            size = pRawNTHeader->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (size_t)size;
}

DLL_IN_MEMORY_ERROR_CODE DllInMemoryHelper::CheckIsValidPEFormat(LPVOID lpRawDll)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pNTHeader = NULL;

    if ((TRUE == IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER))) || (IMAGE_DOS_SIGNATURE != dosHeader->e_magic)) return DLL_IN_MEMORY_DOS_SIG_CHECK_ERROR;
    pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    if ((TRUE == IsBadReadPtr(pNTHeader, sizeof(IMAGE_NT_HEADERS))) || (IMAGE_NT_SIGNATURE != pNTHeader->Signature)) return DLL_IN_MEMORY_NT_SIG_CHECK_ERROR;
    if ((pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(pNTHeader->OptionalHeader)) || (pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)) return DLL_IN_MEMORY_OPTION_HDR_SIG_CHECK_ERROR;
    if (!pNTHeader->FileHeader.NumberOfSections) return DLL_IN_MEMORY_NO_SECTION_ERROR;
    if (pNTHeader->FileHeader.Machine != HOST_MACHINE) return DLL_IN_MEMORY_MACHINE_ERROR;
    if (pNTHeader->OptionalHeader.SectionAlignment & 1) return DLL_IN_MEMORY_NOT_SUPPORT_SECTION_ALIGN_ERROR;
    return DLL_IN_MEMORY_NO_ERROR;
}

size_t DllInMemoryHelper::GetVirtualMemoryMaxSize(LPVOID lpRawDll)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    size_t optionalSectionSize = pNTHeader->OptionalHeader.SectionAlignment;
    size_t headerSize = sizeof(IMAGE_SECTION_HEADER);
    size_t maxLen = ((char *)section - (char *)dosHeader) + headerSize * pNTHeader->FileHeader.NumberOfSections;
    SYSTEM_INFO sSysInfo = { 0 };
    size_t maxMemory = 0;

    for (decltype(pNTHeader->FileHeader.NumberOfSections) i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
    {
        size_t len = 0;
        if (pNTHeader->FileHeader.NumberOfSections)
        {
            len = section[i].VirtualAddress + section[i].SizeOfRawData;
        }
        else
        {
            len = section[i].VirtualAddress + optionalSectionSize;
        }
        if (maxLen < len)
        {
            maxLen = len;
        }
    }
    GetNativeSystemInfo(&sSysInfo);
    maxMemory = AlignValueUp(pNTHeader->OptionalHeader.SizeOfImage, sSysInfo.dwPageSize);
    if (maxMemory != AlignValueUp(maxLen, sSysInfo.dwPageSize)) return -1;
    return maxMemory;
}

bool DllInMemoryHelper::AllocDllMemory(LPVOID lpRawDll, size_t pageSize)
{
    PIMAGE_DOS_HEADER pRawDosHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pRawNTHeader = MakePtr(PIMAGE_NT_HEADERS, pRawDosHeader, pRawDosHeader->e_lfanew);

    pImageBase = (unsigned char *)VirtualAlloc((LPVOID)pRawNTHeader->OptionalHeader.ImageBase,
        pageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (pImageBase == NULL)
    {
        pImageBase = (unsigned char *)VirtualAlloc(NULL,
            pageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
    }

    return pImageBase != NULL;
}

bool DllInMemoryHelper::CopyHeader(LPVOID lpRawDll, LPVOID lpNewDll)
{
    PIMAGE_DOS_HEADER pRawDosHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pRawNTHeader = MakePtr(PIMAGE_NT_HEADERS, pRawDosHeader, pRawDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pRawSection = IMAGE_FIRST_SECTION(pRawNTHeader);
    PIMAGE_NT_HEADERS pNewNTHeader = NULL;

    unsigned char *headers = (unsigned char *)VirtualAlloc(lpNewDll,
        pRawNTHeader->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT,
        PAGE_READWRITE);
    if (headers == NULL) return false;

    // copy PE header to code
    memcpy(headers, pRawDosHeader, pRawNTHeader->OptionalHeader.SizeOfHeaders);
    // update position
    pNewNTHeader = MakePtr(PIMAGE_NT_HEADERS, headers, pRawDosHeader->e_lfanew);
    pNewNTHeader->OptionalHeader.ImageBase = (uintptr_t)headers;
    return true;
}

bool DllInMemoryHelper::CopySections(LPVOID lpRawDll, LPVOID lpNewDll)
{
    PIMAGE_DOS_HEADER pRawDosHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pRawNTHeader = MakePtr(PIMAGE_NT_HEADERS, pRawDosHeader, pRawDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pRawSection = IMAGE_FIRST_SECTION(pRawNTHeader);
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)lpNewDll;
    PIMAGE_NT_HEADERS pNewNTHeader = MakePtr(PIMAGE_NT_HEADERS, pNewDosHeader, pNewDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pNewSection = IMAGE_FIRST_SECTION(pNewNTHeader);
    DWORD section_size = 0;
    unsigned char *dest = NULL;

    for (decltype(pRawNTHeader->FileHeader.NumberOfSections) i = 0; i < pRawNTHeader->FileHeader.NumberOfSections; i++)
    {
        if (!pRawSection[i].VirtualAddress) continue;

        if (pRawSection[i].SizeOfRawData == 0)
        {
            // section doesn't contain data in the dll itself, but may define
            // uninitialized data
            section_size = pRawNTHeader->OptionalHeader.SectionAlignment;
            if (section_size > 0)
            {
                dest = (unsigned char *)VirtualAlloc(MakePtr(unsigned char *, lpNewDll, pNewSection[i].VirtualAddress),
                    section_size,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                if (dest == NULL) return false;

                dest = MakePtr(unsigned char *, lpNewDll, pNewSection[i].VirtualAddress);
                // NOTE: On 64bit systems we truncate to 32bit here but expand
                // again later when "PhysicalAddress" is used.
                pNewSection[i].Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
                memset(dest, 0, section_size);
            }
            continue;
        }

        dest = (unsigned char *)VirtualAlloc(MakePtr(unsigned char *, lpNewDll, pNewSection[i].VirtualAddress),
            pNewSection[i].SizeOfRawData,
            MEM_COMMIT,
            PAGE_READWRITE);
        if (dest == NULL) return false;

        dest = MakePtr(unsigned char *, lpNewDll, pNewSection[i].VirtualAddress);
        memcpy(dest, MakePtr(unsigned char *, lpRawDll, pRawSection[i].PointerToRawData), pRawSection[i].SizeOfRawData);
        // NOTE: On 64bit systems we truncate to 32bit here but expand
        // again later when "PhysicalAddress" is used.
        pNewSection[i].Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
    }
    return true;
}

bool DllInMemoryHelper::PerformBaseRelocation(LPVOID lpRawDll, LPVOID lpNewDll)
{
    PIMAGE_DOS_HEADER dosRawHeader = (PIMAGE_DOS_HEADER)lpRawDll;
    PIMAGE_NT_HEADERS pNTRawHeader = MakePtr(PIMAGE_NT_HEADERS, dosRawHeader, dosRawHeader->e_lfanew);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpNewDll;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    PIMAGE_DATA_DIRECTORY directory = GetImgDirEntry(pNTHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    auto delta = (ptrdiff_t)(pNTHeader->OptionalHeader.ImageBase - pNTRawHeader->OptionalHeader.ImageBase);
    if (delta == 0) return true;
    if (directory->Size == 0) return true;

    PIMAGE_BASE_RELOCATION relocation = MakePtr(PIMAGE_BASE_RELOCATION, lpNewDll, directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) 
    {
        DWORD i;
        unsigned char *dest = MakePtr(unsigned char *, lpNewDll, relocation->VirtualAddress);
        unsigned short *relInfo = MakePtr(unsigned short*, relocation, sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i<((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
        {
            // the upper 4 bits define the type of relocation
            int type = *relInfo >> 12;
            // the lower 12 bits define the offset
            int offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
            {
                DWORD *patchAddrHL = MakePtr(DWORD *, dest, offset);
                *patchAddrHL += (DWORD)delta;
            }
            break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
            {
                ULONGLONG *patchAddr64 = MakePtr(ULONGLONG *, dest, offset);
                *patchAddr64 += (ULONGLONG)delta;
            }
            break;
#endif

            default:
                //printf("Unknown relocation: %d\n", type);
                break;
            }
        }

        // advance to next relocation block
        relocation = MakePtr(PIMAGE_BASE_RELOCATION, relocation, relocation->SizeOfBlock);
    }
    return true;
}

bool DllInMemoryHelper::BuildImportTable(LPVOID lpNewDll)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpNewDll;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    PIMAGE_DATA_DIRECTORY directory = GetImgDirEntry(pNTHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = NULL;

    if (directory->Size == 0) return true;

    importDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, lpNewDll, directory->VirtualAddress);
    for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++)
    {
        uintptr_t *thunkRef;
        FARPROC *funcRef;
        const char *sDllName = MakePtr(const char *, dosHeader, importDesc->Name);
        HINSTANCE hDll = GetModuleHandleA(sDllName);
        if (hDll == 0) hDll = LoadLibraryA(sDllName);
        if (hDll == 0) return false;

        if (importDesc->OriginalFirstThunk)
        {
            thunkRef = MakePtr(uintptr_t *, lpNewDll, importDesc->OriginalFirstThunk);
            funcRef = MakePtr(FARPROC *, lpNewDll, importDesc->FirstThunk);
        }
        else 
        {
            // no hint table
            thunkRef = MakePtr(uintptr_t *, lpNewDll, importDesc->FirstThunk);
            funcRef = MakePtr(FARPROC *, lpNewDll, importDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) 
        {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) 
            {
                *funcRef = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME thunkData = MakePtr(PIMAGE_IMPORT_BY_NAME, lpNewDll , (*thunkRef));
                *funcRef = GetProcAddress(hDll, (LPCSTR)&thunkData->Name);
            }
            if (*funcRef == 0) return false;
        }
    }

    return true;
}

bool DllInMemoryHelper::FinalizeSection(LPVOID address, size_t size, DWORD characteristics)
{
    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (size == 0) return TRUE;

    // determine protection flags based on characteristics
    executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    protect = ProtectionFlags[executable][readable][writeable];
    if (characteristics & IMAGE_SCN_MEM_NOT_CACHED) protect |= PAGE_NOCACHE;

    // change memory access flags
    if (VirtualProtect(address, size, protect, &oldProtect) == 0) return false;
    return true;
}

bool DllInMemoryHelper::FinalizeSections(LPVOID lpNewDll)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpNewDll;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    SYSTEM_INFO sSysInfo = { 0 };
#ifdef _WIN64
    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    uintptr_t imageOffset = ((uintptr_t)pNTHeader->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
    static const uintptr_t imageOffset = 0;
#endif
    auto address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    GetNativeSystemInfo(&sSysInfo);
    auto alignedAddress = (LPVOID)AlignValueDown((uintptr_t)address, sSysInfo.dwPageSize);
    auto size = GetRealSectionSize(lpNewDll, section);
    auto characteristics = section->Characteristics;
    section++;
    // loop through all sections and change access flags
    for (decltype(pNTHeader->FileHeader.NumberOfSections) i = 1; i<pNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        LPVOID tmp_sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID tmp_alignedAddress = (LPVOID)AlignValueDown((uintptr_t)tmp_sectionAddress, sSysInfo.dwPageSize);
        SIZE_T tmp_sectionSize = GetRealSectionSize(lpNewDll, section);
        // Combine access flags of all sections that share a page
        // TODO(fancycode): We currently share flags of a trailing large section
        //   with the page of a first small section. This should be optimized.
        if (alignedAddress == tmp_alignedAddress || (uintptr_t)address + size >(uintptr_t) tmp_alignedAddress)
        {
            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) 
            {
                characteristics = (characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            }
            else 
            {
                characteristics |= section->Characteristics;
            }
            size = (((uintptr_t)tmp_sectionAddress) + ((uintptr_t)tmp_sectionSize)) - (uintptr_t)address;
            continue;
        }

        if (!FinalizeSection(address, size, characteristics))  return false;
        address = tmp_sectionAddress;
        alignedAddress = tmp_alignedAddress;
        size = tmp_sectionSize;
        characteristics = section->Characteristics;
    }
    if (!FinalizeSection(address, size, characteristics))  return false;
    return true;
}

bool DllInMemoryHelper::ExecuteTLS()
{
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    PIMAGE_DATA_DIRECTORY directory = GetImgDirEntry(pNTHeader, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) return true;

    tls = (PIMAGE_TLS_DIRECTORY)(pImageBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
    if (callback) 
    {
        while (*callback) 
        {
            (*callback)((LPVOID)pImageBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return true;
}

bool DllInMemoryHelper::ExecuteEntryPoint()
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    if (!pNTHeader->OptionalHeader.AddressOfEntryPoint) return false;

    LPENTRYPOINT EntryPoint = MakePtr(LPENTRYPOINT, dosHeader, pNTHeader->OptionalHeader.AddressOfEntryPoint);
    LPVOID lpReserved = 0;
    EntryPoint((HINSTANCE)dosHeader, DLL_PROCESS_ATTACH, lpReserved);
    return true;
}

DLL_IN_MEMORY_ERROR_CODE DllInMemoryHelper::LoadPbDllFromMemory(LPVOID lpRawDll)
{
    if (NULL == lpRawDll) return DLL_IN_MEMORY_PARAMETER_ERROR;
    if (NULL != pImageBase) return DLL_IN_MEMORY_ALEARDY_LOAD_ERROR;

    DLL_IN_MEMORY_ERROR_CODE ret = CheckIsValidPEFormat(lpRawDll);
    if (ret != DLL_IN_MEMORY_NO_ERROR) return ret;

    size_t pageSize = GetVirtualMemoryMaxSize(lpRawDll);
    if (pageSize == -1 || pageSize == 0) return  DLL_IN_MEMORY_GET_MEM_SIZE_ERROR;

    bool res = AllocDllMemory(lpRawDll, pageSize);
    if (!res) return  DLL_IN_MEMORY_INTERNEL_ERROR;

    res = CopyHeader(lpRawDll, pImageBase);
    if (!res) return  DLL_IN_MEMORY_INTERNEL_ERROR;

    res = CopySections(lpRawDll, pImageBase);
    if (!res) return  DLL_IN_MEMORY_INTERNEL_ERROR;

    res = PerformBaseRelocation(lpRawDll, pImageBase);
    if (!res) return  DLL_IN_MEMORY_RELOCATION_ERROR;

    res = BuildImportTable(pImageBase);
    if (!res) return  DLL_IN_MEMORY_BUILD_IMPORT_TABLE_ERROR;

    res = FinalizeSections(pImageBase);
    if (!res) return  DLL_IN_MEMORY_INTERNEL_ERROR;

    ExecuteTLS();

    ExecuteEntryPoint();

    return DLL_IN_MEMORY_NO_ERROR;
}

FARPROC DllInMemoryHelper::GetProcAddressDirectly(const char *FuncName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
    PIMAGE_DATA_DIRECTORY directory = NULL;
    LPDWORD lpFunctions = NULL;
    DWORD idx = 0;

    if (dosHeader == NULL) return NULL;

    pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    directory = GetImgDirEntry(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (directory->Size == 0) return NULL;
    pExportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, dosHeader, directory->VirtualAddress);
    if (pExportDir->NumberOfNames == 0 || pExportDir->NumberOfFunctions == 0) return NULL;

    lpFunctions = MakePtr(LPDWORD, dosHeader, pExportDir->AddressOfFunctions);

    if (HIWORD(FuncName) != 0)
    {
        PWORD lpNameOrdinals = MakePtr(PWORD, dosHeader, pExportDir->AddressOfNameOrdinals);
        LPDWORD lpName = MakePtr(LPDWORD, dosHeader, pExportDir->AddressOfNames);
        bool found = false;

        for (decltype(pExportDir->NumberOfNames) i = 0; i<pExportDir->NumberOfNames; i++, lpName++, lpNameOrdinals++) {
            if (_stricmp(FuncName, MakePtr(const char *, dosHeader, (*lpName))) == 0) {
                idx = *lpNameOrdinals;
                found = true;
                break;
            }
        }

        if (!found) return NULL;
    }
    else
    {
        if (LOWORD(FuncName) < pExportDir->Base) return NULL;
        idx = LOWORD(FuncName) - pExportDir->Base;
    }

    if (idx > pExportDir->NumberOfFunctions) return NULL;
    if (lpFunctions[idx]) return MakePtr(FARPROC, dosHeader, lpFunctions[idx]);
    return NULL;
}

void DllInMemoryHelper::UnloadPbDllFromMemory()
{
    if (!pImageBase) return;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
    LPENTRYPOINT EntryPoint = MakePtr(LPENTRYPOINT, dosHeader, pNTHeader->OptionalHeader.AddressOfEntryPoint);
    EntryPoint((HINSTANCE)dosHeader, DLL_PROCESS_DETACH, 0);
    VirtualFree(dosHeader, 0, MEM_RELEASE);
    pImageBase = NULL;
}