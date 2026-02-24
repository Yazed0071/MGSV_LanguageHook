#include "pch.h"
#include <windows.h>
#include "MinHook.h"
#include "log.h"
#include "FUN_145cc6360.h"
#include "UnkLoadUIDefaultDataFunc.h"
#include "SetAnnounceText.h"
#include "SetTextMissionTelopName.h"
#include "GetFtexPathId.h"
#include "ShowTextureLogo.h"
#include "ReloadForLangChange.h"

HMODULE realDInput8 = nullptr;

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

    if (!InstallLanguageHook(hGame))
        Log("[DllMain] Failed to install language hook.\n");

    if (!Install_UnkLoadUIDefaultDataFunc_Hook())
        Log("[DllMain] Failed to install UnkLoadUIDefaultDataFunc hook.\n");

    if (!Install_CountAnnounceSwap_Hook(hGame))
        Log("[DllMain] Failed to install SetAnnounceText hook.\n");

    if (!InstallGetFtexPathIdHook(hGame))
        Log("[DllMain] Failed to install InstallGetFtexPathIdHook hook.\n");

    if (!InstallShowTextureLogoHook(hGame))
        Log("[DllMain] Failed to install InstallShowTextureLogoHook hook.\n");

    if (!Install_EpisodeFormatSwap(hGame))
        Log("[DllMain] Failed to install Install_EpisodeFormatSwap hook.\n");

    if (!Install_ReloadForLangChangeHook(hGame))
		Log("[DllMain] Failed to install Install_ChangeLanguageHook hook.\n");



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
