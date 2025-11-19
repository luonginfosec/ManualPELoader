#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include "Helper.h"

ULONG_PTR PELoader(ULONG_PTR pImageBase)
{
    NTSTATUS ntstatus;
    ULONG_PTR pSectionHeadersBase;
    ULONG_PTR pDllBase;
    ULONG_PTR pAddressOfFunctions;
    ULONG_PTR pAddressOfNames;
    ULONG_PTR pAddressOfOrdinals;
    ULONG_PTR pModuleBuffer;
    ULONG_PTR pSource;
    ULONG_PTR pDestination;
    ULONG_PTR pRelocationBlock;
    ULONG_PTR pEntryPoint;
    ULONG_PTR pTlsCallbackAddress;
    ULONG_PTR pExportDirectory;
    LPCSTR procName;
    ULONG protect;
    SIZE_T nImageSize;
    SIZE_T nDataSize;
    USHORT machine;
    USHORT subsystem;
    BOOL isDll;
    DWORD e_lfanew;
    DWORD nExportDirectoryOffset;
    DWORD nNumberOfNames;
    DWORD nOrdinal;
    DWORD nStrLen;
    DWORD nSections;
    DWORD nRelocations;
    PPEB_LDR_DATA pLdrData;
    PLDR_DATA_TABLE_ENTRY pLdrDataTable;
    PUNICODE_STRING pBaseDllName;
    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_DATA_DIRECTORY pImageDataDirectory;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoadDescriptor;
    PIMAGE_TLS_DIRECTORY pImageTlsDirectory;
    PIMAGE_THUNK_DATA pIntTable;
    PIMAGE_THUNK_DATA pIatTable;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    PIMAGE_BASE_RELOCATION pImageBaseRelocation;
    PIMAGE_RELOC pImageReloc;
    PIMAGE_TLS_CALLBACK pImageTlsCallback;
    ULONG_PTR pKernel32 = 0;
    ULONG_PTR pNtdll = 0;
    ULONG_PTR pLoadLibraryA = 0;
    ULONG_PTR pGetProcAddress = 0;
    ULONG_PTR pNtAllocateVirtualMemory = 0;
    ULONG_PTR pNtProtectVirtualMemory = 0;
    ULONG_PTR pNtFlushInstructionCache = 0;
#ifdef _WIN64
    ULONG_PTR pRtlAddFunctionTable = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pImageRuntimeFunctionEntry;
#endif

    /*
    * Bước 1 Tìm địa chỉ cơ sở của kernel32.dll và ntdll.dll
    */
#ifdef _WIN64
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readgsqword(0x60) + 0x18));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
#elif _WIN32
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readfsdword(0x30) + 0xC));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x8);
#else
    return 0;
#endif

    while (pLdrDataTable->DllBase)
    {
#ifdef _WIN64
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x58);
#elif _WIN32
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x2C);
#else
        break;
#endif

        if (CalcHash((ULONG_PTR)pBaseDllName->Buffer, pBaseDllName->Length) == KERNEL32_HASH)
            pKernel32 = (ULONG_PTR)pLdrDataTable->DllBase;
        else if (CalcHash((ULONG_PTR)pBaseDllName->Buffer, pBaseDllName->Length) == NTDLL_HASH)
            pNtdll = (ULONG_PTR)pLdrDataTable->DllBase;

        if (pKernel32 && pNtdll)
            break;

#ifdef _WIN64
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x10);
#elif _WIN32
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x8);
#else
        break;
#endif
    }

    if (!pKernel32 || !pNtdll)
        return 0;

    /*
    * Bước 2: Giải quyết các hàm cần thiết từ kernel32.dll
    */
    e_lfanew = *(DWORD*)((ULONG_PTR)pKernel32 + 0x3C); // Offset to PE Header
    machine = *(SHORT*)((ULONG_PTR)pKernel32 + e_lfanew + 0x18); // Machine type
	// Check 32 hay 64 bit dùng trường Magic 
    if (machine == 0x020B) 
        nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)pKernel32 + e_lfanew + 0x88);
    else if (machine == 0x010B) 
        nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)pKernel32 + e_lfanew + 0x78);
    else
        return 0;

    pExportDirectory = (ULONG_PTR)pKernel32 + nExportDirectoryOffset; // Address of Export Directory
    nNumberOfNames = *(DWORD*)((ULONG_PTR)pExportDirectory + 0x18); // Number of Names
    pAddressOfFunctions = (ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x1C)); // Address of Functions
    pAddressOfNames = (ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x20)); // Address of Names
    pAddressOfOrdinals = (ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x24)); // Address of Ordinals

    for (DWORD index = 0; index < nNumberOfNames; index++)
    {
        nStrLen = 0;
        procName = (LPCSTR)((ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfNames + ((ULONG_PTR)index * 4)))); // Get function name
        nOrdinal = (DWORD)(*(SHORT*)((ULONG_PTR)pAddressOfOrdinals + ((ULONG_PTR)index * 2))); // Get function ordinal

        while (procName[nStrLen]) // Calculate length of function name
            nStrLen++;

        if (CalcHash((ULONG_PTR)procName, nStrLen) == GETPROCADDRESS_HASH)
            pGetProcAddress = (ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4))); // Get function address
        else if (CalcHash((ULONG_PTR)procName, nStrLen) == LOADLIBRARYA_HASH)
            pLoadLibraryA = (ULONG_PTR)pKernel32 + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4))); // Get function address

        if (pGetProcAddress && pLoadLibraryA)
            break;
    }

    if (!pGetProcAddress || !pLoadLibraryA)
        return 0;

    /*
    * Bước 3: Tìm các hàm cần thiết từ ntdll.dll
    */
    e_lfanew = *(DWORD*)((ULONG_PTR)pNtdll + 0x3C);
    machine = *(SHORT*)((ULONG_PTR)pNtdll + e_lfanew + 0x18);

    if (machine == 0x020B)
        nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)pNtdll + e_lfanew + 0x88);
    else if (machine == 0x010B)
        nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)pNtdll + e_lfanew + 0x78);
    else
        return 0;

    pExportDirectory = (ULONG_PTR)pNtdll + nExportDirectoryOffset;
    nNumberOfNames = *(DWORD*)((ULONG_PTR)pExportDirectory + 0x18);
    pAddressOfFunctions = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x1C));
    pAddressOfNames = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x20));
    pAddressOfOrdinals = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x24));

    for (DWORD index = 0; index < nNumberOfNames; index++)
    {
        nStrLen = 0;
        procName = (LPCSTR)((ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfNames + ((ULONG_PTR)index * 4))));
        nOrdinal = (DWORD)(*(SHORT*)((ULONG_PTR)pAddressOfOrdinals + ((ULONG_PTR)index * 2)));

        while (procName[nStrLen])
            nStrLen++;

        if (CalcHash((ULONG_PTR)procName, nStrLen) == NTALLOCATEVIRTUALMEMORY_HASH)
            pNtAllocateVirtualMemory = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
        else if (CalcHash((ULONG_PTR)procName, nStrLen) == NTPROTECTVIRTUALMEMORY_HASH)
            pNtProtectVirtualMemory = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
        else if (CalcHash((ULONG_PTR)procName, nStrLen) == NTFLUSHINSTRUCTIONCACHE_HASH)
            pNtFlushInstructionCache = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
#ifdef _WIN64
        else if (CalcHash((ULONG_PTR)procName, nStrLen) == RTLADDFUNCTIONTABLE_HASH)
            pRtlAddFunctionTable = (ULONG_PTR)pNtdll + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));

        if (pNtAllocateVirtualMemory && pNtProtectVirtualMemory && pNtFlushInstructionCache && pRtlAddFunctionTable)
            break;
#else
        if (pNtAllocateVirtualMemory && pNtProtectVirtualMemory && pNtFlushInstructionCache)
            break;
#endif
    }

#ifdef _WIN64
    if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache || !pRtlAddFunctionTable)
        return 0;
#else
    if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache)
        return 0;
#endif

    /*
	* Bước 4 : Check Dll hoặc Exe và lấy các thông tin cần thiết
    */
    pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase; // DOS header
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew); // NT header
    nImageSize = (SIZE_T)pImageNtHeaders->OptionalHeader.SizeOfImage; // Size of image
    nSections = pImageNtHeaders->FileHeader.NumberOfSections; // Number of sections
    subsystem = pImageNtHeaders->OptionalHeader.Subsystem; // Subsystem type
    isDll = (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE; // Check if DLL
    pSectionHeadersBase = (ULONG_PTR)pImageNtHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pImageNtHeaders->FileHeader.SizeOfOptionalHeader; // Offset to section headers
    pSectionHeader = (PIMAGE_SECTION_HEADER)pSectionHeadersBase; // First section header

    /*
    * Step 5 : Parse this PE file's data to new memory
    * Bước 5 : Phân tích dữ liệu PE này sang bộ nhớ mới
    */
    pModuleBuffer = 0;
	// Cấp phát bộ nhớ 
    ntstatus = ((NtAllocateVirtualMemory_t)pNtAllocateVirtualMemory)(
        (HANDLE)-1,
        &pModuleBuffer,
        0,
        &nImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pModuleBuffer == 0)
        return 0;

	// Copy DOS header and NT headers
    pDestination = pModuleBuffer;
    pSource = pImageBase;
    nDataSize = pImageNtHeaders->OptionalHeader.SizeOfHeaders;
    CopyData(pDestination, pSource, nDataSize);

    // Set section data
    for (DWORD index = 0; index < nSections; index++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pSectionHeadersBase + (sizeof(IMAGE_SECTION_HEADER) * index));
        pDestination = pModuleBuffer + pSectionHeader->VirtualAddress;
        pSource = pImageBase + pSectionHeader->PointerToRawData;
        nDataSize = pSectionHeader->SizeOfRawData;
        CopyData(pDestination, pSource, nDataSize);
    }

    /*
	* Step 6 : Giải quyết import table
    */
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (pImageDataDirectory->Size && pImageDataDirectory->VirtualAddress)
    {
        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pModuleBuffer + pImageDataDirectory->VirtualAddress);

        while (pImportDescriptor->Name && pImportDescriptor->FirstThunk)
        {
            LPCSTR dllName = (LPCSTR)(pModuleBuffer + pImportDescriptor->Name);
            pDllBase = ((LoadLibraryA_t)pLoadLibraryA)(dllName);

            if (!pDllBase) {
                pImportDescriptor++;
                continue;
            }

            pIntTable = pImportDescriptor->OriginalFirstThunk ?
                (PIMAGE_THUNK_DATA)(pModuleBuffer + pImportDescriptor->OriginalFirstThunk) :
                (PIMAGE_THUNK_DATA)(pModuleBuffer + pImportDescriptor->FirstThunk);

            pIatTable = (PIMAGE_THUNK_DATA)(pModuleBuffer + pImportDescriptor->FirstThunk);

            while (pIatTable->u1.AddressOfData)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pIntTable->u1.Ordinal))
                {
                    ULONG_PTR ordinal = IMAGE_ORDINAL(pIntTable->u1.Ordinal);
                    pIatTable->u1.Function = (ULONG_PTR)((GetProcAddress_t)pGetProcAddress)((HMODULE)pDllBase, (LPCSTR)ordinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pModuleBuffer + pIntTable->u1.AddressOfData);
                    pIatTable->u1.Function = (ULONG_PTR)((GetProcAddress_t)pGetProcAddress)((HMODULE)pDllBase, (LPCSTR)pImportByName->Name);
                }

                pIatTable++;
                if (pImportDescriptor->OriginalFirstThunk) {
                    pIntTable++;
                }
            }

            pImportDescriptor++;
        }
    }

    /*
	* Step 7 : Giaỉ quuyết delay import table
    */
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
    if (pImageDataDirectory->Size && pImageDataDirectory->VirtualAddress)
    {
        pDelayLoadDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)(pModuleBuffer + pImageDataDirectory->VirtualAddress);

        while (pDelayLoadDescriptor->DllNameRVA) 
        {
            LPCSTR dllName = (LPCSTR)(pModuleBuffer + pDelayLoadDescriptor->DllNameRVA);
            pDllBase = ((LoadLibraryA_t)pLoadLibraryA)(dllName);

            if (pDllBase)
            {
                pIntTable = (PIMAGE_THUNK_DATA)(pModuleBuffer + pDelayLoadDescriptor->ImportNameTableRVA);
                pIatTable = (PIMAGE_THUNK_DATA)(pModuleBuffer + pDelayLoadDescriptor->ImportAddressTableRVA);

                while (pIatTable->u1.Function)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(pIntTable->u1.Ordinal))
                    {
                        ULONG_PTR ordinal = IMAGE_ORDINAL(pIntTable->u1.Ordinal);
                        pIatTable->u1.Function = (ULONG_PTR)((GetProcAddress_t)pGetProcAddress)((HMODULE)pDllBase, (LPCSTR)ordinal);
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pModuleBuffer + pIntTable->u1.AddressOfData);
                        pIatTable->u1.Function = (ULONG_PTR)((GetProcAddress_t)pGetProcAddress)((HMODULE)pDllBase, (LPCSTR)pImportByName->Name);
                    }

                    pIatTable++;
                    pIntTable++;
                }
            }

            pDelayLoadDescriptor++;
        }
    }
    /*
    * // Bước 8 : Tái định vị
    */
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBuffer + ((PIMAGE_DOS_HEADER)pModuleBuffer)->e_lfanew);
    pDllBase = pModuleBuffer - pImageNtHeaders->OptionalHeader.ImageBase;
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

    if (pImageDataDirectory->Size)
    {
        pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(pModuleBuffer + pImageDataDirectory->VirtualAddress);

        while (pImageBaseRelocation->SizeOfBlock)
        {
            pRelocationBlock = pModuleBuffer + pImageBaseRelocation->VirtualAddress;
            nRelocations = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
            pImageReloc = (PIMAGE_RELOC)((ULONG_PTR)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

            while (nRelocations--)
            {
                if (pImageReloc->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(pRelocationBlock + pImageReloc->offset) += pDllBase;
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(pRelocationBlock + pImageReloc->offset) += (DWORD)pDllBase;
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(pRelocationBlock + pImageReloc->offset) += HIWORD(pDllBase);
                else if (pImageReloc->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(pRelocationBlock + pImageReloc->offset) += LOWORD(pDllBase);

                pImageReloc = (PIMAGE_RELOC)((ULONG_PTR)pImageReloc + sizeof(IMAGE_RELOC));
            }

            pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
        }
    }

    /*
    * // Bước 9 : Đặt bảo vệ cho trang
    */
    for (DWORD index = 0; index < nSections; index++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pSectionHeadersBase + (sizeof(IMAGE_SECTION_HEADER) * index));
        pDestination = pModuleBuffer + pSectionHeader->VirtualAddress;
        nDataSize = pSectionHeader->SizeOfRawData;

        if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            protect = PAGE_EXECUTE_READWRITE;
        }
        else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ))
        {
            protect = PAGE_EXECUTE_READ;
        }
        else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            protect = PAGE_EXECUTE_WRITECOPY;
        }
        else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            protect = PAGE_READWRITE;
        }
        else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            protect = PAGE_EXECUTE;
        }
        else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
        {
            protect = PAGE_READONLY;
        }
        else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            protect = PAGE_WRITECOPY;
        }
        else
        {
            continue;
        }

        ((NtProtectVirtualMemory_t)pNtProtectVirtualMemory)(
            (HANDLE)-1,
            &pDestination,
            &nDataSize,
            protect,
            &protect);
    }

    /*
    * // Bước 10 : Gọi các callback tls
    */
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);

    if (pImageDataDirectory->Size)
    {
        pImageTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pModuleBuffer + pImageDataDirectory->VirtualAddress);
        pTlsCallbackAddress = pImageTlsDirectory->AddressOfCallBacks;

        while (*(PIMAGE_TLS_CALLBACK*)pTlsCallbackAddress)
        {
            pImageTlsCallback = *(PIMAGE_TLS_CALLBACK*)pTlsCallbackAddress;

            pImageTlsCallback((PVOID)pModuleBuffer, DLL_PROCESS_ATTACH, NULL);

            pTlsCallbackAddress += sizeof(PIMAGE_TLS_CALLBACK);
        }
    }

    /*
    * // Bước 11 : Giải quyết trình xử lý ngoại lệ (chỉ x64)
    */
#ifdef _WIN64
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);

    if (pImageDataDirectory->Size)
    {
        pImageRuntimeFunctionEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pModuleBuffer + pImageDataDirectory->VirtualAddress);

        ((RtlAddFunctionTable_t)pRtlAddFunctionTable)(pImageRuntimeFunctionEntry, (pImageDataDirectory->Size / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, pModuleBuffer);
    }
#endif

    /*
    * // Bước 12 : Gọi entry (DLL hoặc EXE)
    */
    pEntryPoint = pModuleBuffer + pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
    ((NtFlushInstructionCache_t)pNtFlushInstructionCache)((HANDLE)-1, NULL, 0);

    if (isDll)
    {
        // Gọi DllMain cho file DLL
        ((DllMain_t)pEntryPoint)((HINSTANCE)pModuleBuffer, DLL_PROCESS_ATTACH, NULL);
    }
    else
    {
        // Call appropriate entry point for EXE files based on subsystem
        // Gọi điểm vào thích hợp cho file EXE dựa trên subsystem
        switch (subsystem)
        {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            // WinMain entry point
            ((WinMainCRTStartup_t)pEntryPoint)();
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            // main entry point (console)
            ((MainCRTStartup_t)pEntryPoint)();
            break;
        default:
            // Try to call as console application by default
            ((MainCRTStartup_t)pEntryPoint)();
            break;
        }
    }

    return pModuleBuffer;
} 