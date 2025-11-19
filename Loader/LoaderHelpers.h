#pragma once

// Helper functions for working with loaded PE files

// Get exported function from loaded DLL
// Usage: FARPROC func = GetExportedFunction(loadedBase, "FunctionName");
__forceinline FARPROC GetExportedFunction(ULONG_PTR moduleBase, const char* functionName)
{
    if (!moduleBase || !functionName)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_DATA_DIRECTORY exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->Size == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDir->VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);
    WORD* addressOfOrdinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        const char* currentName = (const char*)(moduleBase + addressOfNames[i]);
        
        // Compare function names
        BOOL match = TRUE;
        for (int j = 0; functionName[j] != '\0' || currentName[j] != '\0'; j++)
        {
            if (functionName[j] != currentName[j])
            {
                match = FALSE;
                break;
            }
        }

        if (match)
        {
            WORD ordinal = addressOfOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (FARPROC)(moduleBase + functionRva);
        }
    }

    return NULL;
}

// Get exported function by ordinal
__forceinline FARPROC GetExportedFunctionByOrdinal(ULONG_PTR moduleBase, WORD ordinal)
{
    if (!moduleBase)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_DATA_DIRECTORY exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->Size == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDir->VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);

    DWORD index = ordinal - exportDirectory->Base;
    if (index >= exportDirectory->NumberOfFunctions)
        return NULL;

    DWORD functionRva = addressOfFunctions[index];
    return (FARPROC)(moduleBase + functionRva);
}

// Unload PE from memory (cleanup)
// Note: This only frees the allocated memory, doesn't call DllMain(DLL_PROCESS_DETACH)
__forceinline BOOL UnloadPE(ULONG_PTR moduleBase)
{
    if (!moduleBase)
        return FALSE;

    // You would need to resolve NtFreeVirtualMemory here
    // For simplicity, we'll use VirtualFree which requires the exact base address
    // In production, you should call DllMain with DLL_PROCESS_DETACH first
    
    return VirtualFree((LPVOID)moduleBase, 0, MEM_RELEASE);
}

// Call DllMain with DLL_PROCESS_DETACH before unloading
__forceinline BOOL CallDllMainDetach(ULONG_PTR moduleBase)
{
    if (!moduleBase)
        return FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Check if it's a DLL
    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
        return FALSE;

    ULONG_PTR entryPoint = moduleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    
    typedef BOOL(*DllMain_t)(HINSTANCE, DWORD, LPVOID);
    DllMain_t dllMain = (DllMain_t)entryPoint;

    return dllMain((HINSTANCE)moduleBase, DLL_PROCESS_DETACH, NULL);
}

// Example usage for calling exported functions from loaded DLL:
/*
    // Load DLL
    ULONG_PTR dllBase = ReflectiveLoader(peData);
    
    // Get exported function
    typedef int (*MyFunction_t)(int, int);
    MyFunction_t myFunc = (MyFunction_t)GetExportedFunction(dllBase, "MyFunction");
    
    if (myFunc)
    {
        int result = myFunc(10, 20);
        printf("Result: %d\n", result);
    }
    
    // Cleanup before exit
    CallDllMainDetach(dllBase);
    UnloadPE(dllBase);
*/
