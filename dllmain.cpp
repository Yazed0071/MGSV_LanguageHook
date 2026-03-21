#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdio>

#include "MinHook.h"
#include "log.h"

bool InstallGameLangStateKeepCJKHook(HMODULE hGame);
bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame);
bool InstallLanguageHook(HMODULE hGame);
bool InstallShowTextureLogoArabicHook(HMODULE hGame);
bool InstallChapterTelopArabicFtexHook(HMODULE hGame);
bool Install_UnkLoadUIDefaultDataFunc_Hook();
bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame);
bool InstallGetTipsLangBlockPathHook(HMODULE hGame);
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame);

void RemoveGameLangStateKeepCJKHook();
void RemoveLangSelectPopupPagedRewriteHooks();
void RemoveLanguageHook();
void RemoveShowTextureLogoArabicHook();
void RemoveChapterTelopArabicFtexHook();
void RemoveUnkLoadTppPartsLangFpkArabicFixHook();
void RemoveGetTipsLangBlockPathHook();
void RemoveGetPauseHelpLangBlockPathHook();

namespace
{
    static std::atomic_bool gStarted{ false };
    static std::atomic_bool gConsoleReady{ false };

    static HMODULE gRealDinput8 = nullptr;

    // What it does: function pointer type for the real system DirectInput8Create.
    // Params: same params as DirectInput8Create.
    using DirectInput8Create_t =
        HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPVOID);

    static DirectInput8Create_t gRealDirectInput8Create = nullptr;
}

// What it does: loads the real system dinput8.dll and resolves DirectInput8Create.
// Params: none.
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

// What it does: exported proxy for DirectInput8Create so the game can still use the real system dinput8.
// Params: standard DirectInput8Create params from the game.
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

// What it does: creates or attaches a console for debug logging.
// Params: none.
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

// What it does: initializes MinHook and installs all runtime hooks on a worker thread.
// Params: unused thread parameter.
static DWORD WINAPI InitThread(LPVOID)
{
    #ifdef _DEBUG
    SetupConsole();
    #endif

    HMODULE hGame = GetModuleHandleA("mgsvtpp.exe");
    if (!hGame)
        hGame = GetModuleHandle(nullptr);

    Log("[DLL] InitThread started.\n");

    const MH_STATUS st = MH_Initialize();
    Log("[DLL] MH_Initialize -> %d\n", static_cast<int>(st));
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
        return 0;

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

// What it does: removes installed hooks and frees the proxied system dinput8 when the DLL unloads normally.
// Params: processTerminating tells whether the process is shutting down.
static void UninstallAll(bool processTerminating)
{
    if (processTerminating)
        return;

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

// What it does: standard Windows DLL entry point that starts your init thread.
// Params: standard DllMain params.
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