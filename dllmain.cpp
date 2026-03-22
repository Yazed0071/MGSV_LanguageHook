#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdio>

#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"


bool InstallGameLangStateKeepCJKHook(HMODULE hGame);
bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame);
bool InstallLanguageHook(HMODULE hGame);
bool InstallShowTextureLogoArabicHook(HMODULE hGame);
bool InstallChapterTelopArabicFtexHook(HMODULE hGame);
bool Install_UnkLoadUIDefaultDataFunc_Hook();
bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame);
bool InstallGetTipsLangBlockPathHook(HMODULE hGame);
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame);
bool InstallUiLangInitExtraLoadFuncsHook(HMODULE hGame);
bool Install_SetLuaFunctions_Hook();

void RemoveGameLangStateKeepCJKHook();
void RemoveLangSelectPopupPagedRewriteHooks();
void RemoveLanguageHook();
void RemoveShowTextureLogoArabicHook();
void RemoveChapterTelopArabicFtexHook();
void RemoveUnkLoadTppPartsLangFpkArabicFixHook();
void RemoveGetTipsLangBlockPathHook();
void RemoveGetPauseHelpLangBlockPathHook();
void RemoveUiLangInitExtraLoadFuncsHook();
bool Uninstall_SetLuaFunctions_Hook();


namespace
{
    static std::atomic_bool gStarted{ false };
    static std::atomic_bool gConsoleReady{ false };

    static HMODULE gRealDinput8 = nullptr;

    // Function: pointer type for the real system DirectInput8Create.
    // Params:
    // - hinst: module instance
    // - dwVersion: DirectInput version
    // - riidltf: requested interface id
    // - ppvOut: returned interface pointer
    // - punkOuter: outer unknown for aggregation
    using DirectInput8Create_t =
        HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPVOID);

    static DirectInput8Create_t gRealDirectInput8Create = nullptr;
}

// Function: loads the real system dinput8.dll and resolves DirectInput8Create.
// Params:
// - none
static void LoadRealDinput8()
{
    if (gRealDinput8)
        return;

    wchar_t sysPath[MAX_PATH]{};
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\dinput8.dll");

    gRealDinput8 = LoadLibraryW(sysPath);
    if (!gRealDinput8)
        return;

    gRealDirectInput8Create =
        reinterpret_cast<DirectInput8Create_t>(
            GetProcAddress(gRealDinput8, "DirectInput8Create"));
}

// Function: exported proxy for DirectInput8Create so the game can still call the real one.
// Params:
// - hinst: module instance
// - dwVersion: DirectInput version
// - riidltf: requested interface id
// - ppvOut: returned interface pointer
// - punkOuter: outer unknown for aggregation
extern "C" __declspec(dllexport)
HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst,
    DWORD dwVersion,
    REFIID riidltf,
    LPVOID* ppvOut,
    LPVOID punkOuter)
{
    LoadRealDinput8();

    if (!gRealDirectInput8Create)
        return E_FAIL;

    return gRealDirectInput8Create(
        hinst,
        dwVersion,
        riidltf,
        ppvOut,
        punkOuter);
}

// Function: creates or attaches a console for debug logging.
// Params:
// - none
static void SetupConsole()
{
    if (gConsoleReady.load())
        return;

    if (!AllocConsole())
        AttachConsole(ATTACH_PARENT_PROCESS);

    FILE* fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);

    SetConsoleTitleW(L"V_FrameWork");
    gConsoleReady.store(true);

    printf("[DLL] Console ready\n");
    fflush(stdout);
}

// Function: initializes MinHook and installs all runtime hooks on a worker thread.
// Params:
// - unused: unused thread parameter
// Returns:
// - thread exit code
static DWORD WINAPI InitThread(LPVOID)
{
    #ifdef _DEBUG
    SetupConsole();
    #endif

    HMODULE hGame = GetModuleHandleA("mgsvtpp.exe");
    if (!hGame)
        hGame = GetModuleHandleW(nullptr);

    if (!hGame)
    {
        Log("[DLL] Failed to get game module.\n");
        return 0;
    }

    if (!ResolveAddressSet(hGame))
    {
        Log("[DLL] ResolveAddressSet failed.\n");
        return 0;
    }

    Log("[DLL] InitThread started. build=%s\n", GetGameBuildName(gGameBuild));

    const MH_STATUS st = MH_Initialize();
    Log("[DLL] MH_Initialize -> %d\n", static_cast<int>(st));
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
        return 0;


    if (!Install_SetLuaFunctions_Hook())
        Log("[DLL] Failed to install Install_SetLuaFunctions_Hook hook.\n");

    if (!InstallGameLangStateKeepCJKHook(hGame))
        Log("[DLL] Failed to install GameLangStateKeepCJK hook.\n");

    if (!InstallLangSelectPopupPagedRewriteHooks(hGame))
        Log("[DLL] Failed to install LangSelectPopupPagedDynamic hooks.\n");

    if (!InstallLanguageHook(hGame))
        Log("[DLL] Failed to install LanguageHook.\n");

    if (!InstallShowTextureLogoArabicHook(hGame))
        Log("[DLL] Failed to install ShowTextureLogo Arabic hook.\n");

    if (!InstallChapterTelopArabicFtexHook(hGame))
        Log("[DLL] Failed to install ChapterTelopInfo::GetFtexPathId Arabic hook.\n");

    if (!Install_UnkLoadUIDefaultDataFunc_Hook())
        Log("[DLL] Failed to install UnkLoadUIDefaultDataFunc hook.\n");

    if (!InstallUnkLoadTppPartsLangFpkArabicFixHook(hGame))
        Log("[DLL] Failed to install UnkLoadTppPartsLangFpk Arabic fix hook.\n");

    if (!InstallGetTipsLangBlockPathHook(hGame))
        Log("[DLL] Failed to install GetTipsLangBlockPath hook.\n");

    if (!InstallGetPauseHelpLangBlockPathHook(hGame))
        Log("[DLL] Failed to install GetPauseHelpLangBlockPath hook.\n");

    Log("[DLL] InitThread done.\n");
    return 0;
}

// Function: removes installed hooks and frees the proxied system dinput8 when the DLL unloads normally.
// Params:
// - processTerminating: true if the process is shutting down
static void UninstallAll(bool processTerminating)
{
    if (processTerminating)
        return;

    Uninstall_SetLuaFunctions_Hook();
    RemoveGameLangStateKeepCJKHook();
    RemoveLangSelectPopupPagedRewriteHooks();
    RemoveLanguageHook();
    RemoveShowTextureLogoArabicHook();
    RemoveChapterTelopArabicFtexHook();
    RemoveUnkLoadTppPartsLangFpkArabicFixHook();
    RemoveGetTipsLangBlockPathHook();
    RemoveGetPauseHelpLangBlockPathHook();


    MH_Uninitialize();
    Log("[DLL] UninstallAll done.\n");

    if (gRealDinput8)
    {
        FreeLibrary(gRealDinput8);
        gRealDinput8 = nullptr;
        gRealDirectInput8Create = nullptr;
    }

    fflush(stdout);
    fflush(stderr);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);

        bool expected = false;
        if (!gStarted.compare_exchange_strong(expected, true))
            return TRUE;

        HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (hThread)
            CloseHandle(hThread);

        return TRUE;
    }

    case DLL_PROCESS_DETACH:
    {
        UninstallAll(lpReserved != nullptr);
        return TRUE;
    }
    }

    return TRUE;
}