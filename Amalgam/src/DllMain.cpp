#include <Windows.h>
#include <winternl.h>
#include <process.h>
#include "Core/Core.h"
#include "Utils/ExceptionHandler/ExceptionHandler.h"

// Global state for non-standard injection methods
static HMODULE g_hModule = nullptr;
static volatile LONG g_bInitialized = FALSE;

// Forward declare UNICODE_STRING from Windows SDK (defined in winternl.h)
// Custom LDR structure - rename to avoid conflicts
typedef struct _CUSTOM_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} CUSTOM_LDR_DATA_TABLE_ENTRY, *PCUSTOM_LDR_DATA_TABLE_ENTRY;

typedef struct _CUSTOM_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} CUSTOM_PEB_LDR_DATA, *PCUSTOM_PEB_LDR_DATA;

typedef struct _CUSTOM_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PCUSTOM_PEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} CUSTOM_PEB, *PCUSTOM_PEB;

// Check if module is in the PEB (indicates legitimate vs manual map)
static bool IsModuleInPEB(HMODULE hModule)
{
    if (!hModule) return false;
    
    __try
    {
        PCUSTOM_PEB pPeb = reinterpret_cast<PCUSTOM_PEB>(__readgsqword(0x60));
        if (!pPeb || !pPeb->Ldr) return false;
        
        PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY pListEntry = pListHead->Flink;
        
        while (pListEntry && pListEntry != pListHead)
        {
            PCUSTOM_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, CUSTOM_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (pEntry->DllBase == hModule)
                return true;
            pListEntry = pListEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // If we fault reading PEB, assume not in PEB (manual map)
        return false;
    }
    
    return false;
}

// Get our module handle safely
static HMODULE GetCurrentModule()
{
    if (g_hModule)
        return g_hModule;
    
    HMODULE hModule = nullptr;
    
    // Try to get module handle from an address in this DLL
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&GetCurrentModule),
        &hModule
    );
    
    if (hModule)
        g_hModule = hModule;
    
    return hModule;
}

unsigned int __stdcall MainThread(void* pParam)
{
    HMODULE hModule = static_cast<HMODULE>(pParam);
    if (!hModule)
        hModule = GetCurrentModule();
    
    __try
    {
        U::ExceptionHandler.Initialize(hModule);
        U::Core.Load();
        U::Core.Loop();
        U::ExceptionHandler.Unload();
        U::Core.Unload();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Emergency cleanup on exception
        __try { U::Core.Unload(); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    
    // Reset initialization flag
    InterlockedExchange(&g_bInitialized, FALSE);
    
    // FreeLibraryAndExitThread will silently fail if the module isn't in the loader list
    // but that's fine - it's safe to call regardless
    FreeLibraryAndExitThread(hModule, EXIT_SUCCESS);
    
    return EXIT_SUCCESS;
}

// Initialize the DLL (thread-safe)
static bool InitializeDLL(HMODULE hModule)
{
    // Prevent multiple initializations
    if (InterlockedCompareExchange(&g_bInitialized, TRUE, FALSE) != FALSE)
        return false; // Already initialized
    
    if (!hModule)
    {
        hModule = GetCurrentModule();
        if (!hModule)
        {
            InterlockedExchange(&g_bInitialized, FALSE);
            return false;
        }
    }
    
    // Store module handle
    g_hModule = hModule;
    
    // Create worker thread using _beginthreadex (CRT-safe)
    const uintptr_t hThread = _beginthreadex(
        nullptr,              // security
        0,                    // stack size (0 = default)
        MainThread,           // start address
        hModule,              // arg (the module handle)
        0,                    // init flag
        nullptr               // thread id
    );
    
    if (hThread)
    {
        CloseHandle(reinterpret_cast<HANDLE>(hThread));
        return true;
    }
    
    // Failed to create thread, reset flag
    InterlockedExchange(&g_bInitialized, FALSE);
    return false;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Optimization: disable thread attach/detach notifications
            DisableThreadLibraryCalls(hinstDLL);
            
            // Store module handle
            g_hModule = hinstDLL;
            
            // Initialize the DLL
            InitializeDLL(hinstDLL);
            
            break;
        }
        
        case DLL_PROCESS_DETACH:
        {
            // Only do cleanup if we're being unloaded dynamically (lpvReserved == nullptr)
            // If lpvReserved != nullptr, the process is terminating and cleanup is unnecessary/unsafe
            if (lpvReserved == nullptr)
            {
                // Optional: signal shutdown to main thread
                // Most injectors will handle this themselves
            }
            break;
        }
    }
    
    return TRUE;
}

// QueueUserAPC entry point
extern "C" __declspec(dllexport) void CALLBACK APCEntry(ULONG_PTR dwParam)
{
    HMODULE hModule = dwParam ? reinterpret_cast<HMODULE>(dwParam) : GetCurrentModule();
    InitializeDLL(hModule);
}

// SetWindowsHookEx entry point
extern "C" __declspec(dllexport) LRESULT CALLBACK HookEntry(int nCode, WPARAM wParam, LPARAM lParam)
{
    InitializeDLL(GetCurrentModule());
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// CreateRemoteThread / Thread Hijacking entry point
extern "C" __declspec(dllexport) DWORD WINAPI RemoteThreadEntry(LPVOID lpParam)
{
    HMODULE hModule = lpParam ? static_cast<HMODULE>(lpParam) : GetCurrentModule();
    
    // We're already in a remote thread, so just run MainThread directly
    // Don't create another thread
    return MainThread(hModule);
}

// NtCreateThreadEx entry point (used by some injectors)
extern "C" __declspec(dllexport) DWORD WINAPI ThreadEntry(LPVOID lpParam)
{
    return RemoteThreadEntry(lpParam);
}