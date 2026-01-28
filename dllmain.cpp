#include "pch.h"
#include <windows.h>
#include "MinHook.h"
#include "log.h"
#include "FUN_145cc6360.h"
#include <UnkLoadUIDefaultDataFunc.h>

// -----------------------------------------------
//  DLL Entry Point
// -----------------------------------------------
DWORD WINAPI InitThread(LPVOID)
{
    Sleep(1500);
    Log("[DllMain] Installing hooks after delay...\n");

    HMODULE hGame = GetModuleHandleA("mgsvtpp.exe");
    if (!hGame)
        hGame = GetModuleHandle(NULL);

    Log("[DllMain] DLL base: %p\n", GetModuleHandle(NULL));
    Log("[DllMain] Game base: %p\n", hGame);

    // Initialize MinHook
    if (MH_Initialize() != MH_OK)
    {
        Log("[DllMain] MH_Initialize failed.\n");
        return 1;
    }

    // Install both hooks
    if (!InstallLanguageHook(hGame))
        Log("[DllMain] Failed to install language hook.\n");
    else
        Log("[DllMain] installed InstallLanguageHook.\n");

    if (!Install_UnkLoadUIDefaultDataFunc_Hook())
        Log("[DllMain] Failed to install language hook.\n");
    else
        Log("[DllMain] installed InstallLanguageHook.\n");

    Log("[DllMain] Hooks installed.\n");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        #ifdef _DEBUG
            InitLog();
            Log("[LOG] Console Initialized\n");
            Log("[DllMain] DLL_PROCESS_ATTACH\n");
        #endif // _DEBUG

        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        RemoveLanguageHook();
        MH_Uninitialize();
        CloseLog();
        break;
    }

    return TRUE;
}
