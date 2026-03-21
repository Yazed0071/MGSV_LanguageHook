#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdio>

#include "MinHook.h"
#include "log.h"

bool Install_SetLuaFunctions_Hook();
bool InstallGameLangStateKeepCJKHook(HMODULE hGame);
bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame);
bool InstallLanguageHook(HMODULE hGame);
bool InstallShowTextureLogoArabicHook(HMODULE hGame);
bool InstallChapterTelopArabicFtexHook(HMODULE hGame);
bool Install_UnkLoadUIDefaultDataFunc_Hook();
bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame);
bool InstallGetTipsLangBlockPathHook(HMODULE hGame);
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame);


bool Uninstall_SetLuaFunctions_Hook();
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
}

// Creates or attaches a console for debug logging.
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

// Initializes MinHook and all runtime hooks on a worker thread.
static DWORD WINAPI InitThread(LPVOID)
{
    #ifdef _DEBUG
    SetupConsole();
    #endif // DEBUG

    HMODULE hGame = GetModuleHandleA("mgsvtpp.exe");
    if (!hGame)
        hGame = GetModuleHandle(NULL);


    Log("[DLL] InitThread started.\n");

    const MH_STATUS st = MH_Initialize();
    Log("[DLL] MH_Initialize -> %d\n", static_cast<int>(st));
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
        return 0;

	if (!Install_SetLuaFunctions_Hook())
		Log("[DLL] Failed to install SetLuaFunctions hook.\n");

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

// Removes all hooks when the DLL unloads normally.
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

    fflush(stdout);
    fflush(stderr);
}

// Standard Windows DLL entry point.
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