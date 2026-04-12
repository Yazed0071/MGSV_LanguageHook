#include "pch.h"
#include <Windows.h>
#include <unknwn.h>
#include <atomic>
#include <cwchar>
#include <cstdio>

#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

#define VRL_ENABLE_AUTO_INIT_THREAD 1
#define VRL_ENABLE_DINPUT8_PROXY 1
#define VRL_PROXY_ONLY_IF_NAMED_DINPUT8 1

bool InstallGameLangStateKeepCJKHook(HMODULE hGame);
bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame);
bool InstallLanguageHook(HMODULE hGame);
bool InstallShowTextureLogoArabicHook(HMODULE hGame);
bool InstallChapterTelopArabicFtexHook(HMODULE hGame);
bool Install_UnkLoadUIDefaultDataFunc_Hook();
bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame);
bool InstallGetTipsLangBlockPathHook(HMODULE hGame);
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame);
bool Install_SetLuaFunctions_Hook();
bool InstallDisplayTimerEvCallSetDisplayTextHook(HMODULE hGame);
bool InstallMbLogViewerBodyLayoutSetMainTextArabicHook(HMODULE hGame);
bool InstallCustomizeSlotSelectorSetupListElementWalkerGearHook(HMODULE hGame);
bool InstallGamePauseMenuArabicTextHooks(HMODULE hGame);
bool InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook(HMODULE hGame);
bool InstallCallMenuImplSetCommandTextArabicHook(HMODULE hGame);
bool InstallTipsLayoutControllerSetPageTextHook(HMODULE hGame);
bool InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(HMODULE hGame);
bool InstallSetTextMissionTelopNameArabicEpisodeFormatHook(HMODULE hGame);
bool InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook(HMODULE hGame);
bool InstallMbTitleEvGetTypingTextArabicHook(HMODULE hGame);
bool InstallMbTitleEvSetMenuNameTextArabicHook(HMODULE hGame);
bool InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook(HMODULE hGame);
bool InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook(HMODULE hGame);
bool InstallMissionPreparationCallbackImplSetupMissionNameArabicHook(HMODULE hGame);
bool InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(HMODULE hGame);
bool InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(HMODULE hGame);
bool InstallTppUIInfoTypingTextImplSetTypingTextArabicHook(HMODULE hGame);
bool InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook(HMODULE hGame);
bool InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook(HMODULE hGame);
bool InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook(HMODULE hGame);
bool InstallTppUICountAnnounceImplSetAnnounceTextArabicHook(HMODULE hGame);
bool InstallLoadingTipsEvGetTitleTextArabicHook(HMODULE hGame);
bool InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook(HMODULE hGame);
bool InstallSetEquipBackgroundTextureArabicHook(HMODULE hGame);
bool InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook(HMODULE hGame);

void RemoveGameLangStateKeepCJKHook();
void RemoveLangSelectPopupPagedRewriteHooks();
void RemoveLanguageHook();
void RemoveShowTextureLogoArabicHook();
void RemoveChapterTelopArabicFtexHook();
void RemoveUnkLoadTppPartsLangFpkArabicFixHook();
void RemoveGetTipsLangBlockPathHook();
void RemoveGetPauseHelpLangBlockPathHook();
bool Uninstall_SetLuaFunctions_Hook();
void RemoveDisplayTimerEvCallSetDisplayTextHook();
void RemoveMbLogViewerBodyLayoutSetMainTextArabicHook();
void RemoveCustomizeSlotSelectorSetupListElementWalkerGearHook();
void RemoveGamePauseMenuArabicTextHooks();
void RemoveMbDvcMissionInfoSetMissionInfoTextsArabicHook();
void RemoveCallMenuImplSetCommandTextArabicHook();
void RemoveTipsLayoutControllerSetPageTextHook();
void RemoveTelopStartTitleEvCallUpdateArabicTypingDirectionHook();
void RemoveSetTextMissionTelopNameArabicEpisodeFormatHook();
void RemoveAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook();
void RemoveHeadMarkMarkerEvCallSetMarkerTextArabicHook();
void RemoveMbTitleEvGetTypingTextArabicHook();
void RemoveMbTitleEvSetMenuNameTextArabicHook();
void RemoveMbDvcMissionListRecordCallFuncStartArabicFormatHook();
void RemoveMbDvcSideOpsRecordCallFuncViewRecordArabicHook();
void RemoveMissionPreparationCallbackImplSetupMissionNameArabicHook();
void RemoveEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook();
void RemoveEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook();
void RemoveTppUIInfoTypingTextImplSetTypingTextArabicHook();
void RemoveLoadoutPanelInfoRefreshLoadoutTextArabicHook();
void RemoveItemSelectorRecordCallFuncUpdateRecordsArabicHook();
void RemoveMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook();
void RemoveTppUICountAnnounceImplSetAnnounceTextArabicHook();
void RemoveLoadingTipsEvGetTitleTextArabicHook();
void RemoveLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook();
void RemoveEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook();
void RemoveMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook();
void RemoveGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook();
void RemovePopupEvCallSettingPopupArabicLeftToRightAlignHook();
void RemoveSetEquipBackgroundTextureArabicHook();
void RemoveMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook();

namespace
{
    static std::atomic_bool gStarted{ false };
    static std::atomic_bool gInitialized{ false };
    static std::atomic_bool gConsoleReady{ false };
}

#if VRL_ENABLE_DINPUT8_PROXY

#pragma comment(linker, "/EXPORT:DirectInput8Create=ProxyDirectInput8Create")
#pragma comment(linker, "/EXPORT:DllCanUnloadNow=ProxyDllCanUnloadNow")
#pragma comment(linker, "/EXPORT:DllGetClassObject=ProxyDllGetClassObject")
#pragma comment(linker, "/EXPORT:DllRegisterServer=ProxyDllRegisterServer")
#pragma comment(linker, "/EXPORT:DllUnregisterServer=ProxyDllUnregisterServer")
#pragma comment(linker, "/EXPORT:GetdfDIJoystick=ProxyGetdfDIJoystick")

using DirectInput8Create_t = HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
using DllCanUnloadNow_t = HRESULT(STDAPICALLTYPE*)();
using DllGetClassObject_t = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
using DllRegisterServer_t = HRESULT(STDAPICALLTYPE*)();
using DllUnregisterServer_t = HRESULT(STDAPICALLTYPE*)();
using GetdfDIJoystick_t = const void* (WINAPI*)();

static HMODULE gRealDInput8 = nullptr;
static DirectInput8Create_t  gRealDirectInput8Create = nullptr;
static DllCanUnloadNow_t     gRealDllCanUnloadNow = nullptr;
static DllGetClassObject_t   gRealDllGetClassObject = nullptr;
static DllRegisterServer_t   gRealDllRegisterServer = nullptr;
static DllUnregisterServer_t gRealDllUnregisterServer = nullptr;
static GetdfDIJoystick_t     gRealGetdfDIJoystick = nullptr;

static bool IsCurrentModuleNamedDInput8(HMODULE hModule)
{
    if (!hModule)
        return false;

    wchar_t path[MAX_PATH] = {};
    if (GetModuleFileNameW(hModule, path, MAX_PATH) == 0)
        return false;

    const wchar_t* fileName = wcsrchr(path, L'\\');
    fileName = fileName ? (fileName + 1) : path;
    return _wcsicmp(fileName, L"dinput8.dll") == 0;
}

static bool ShouldUseDInput8Proxy(HMODULE hModule)
{
    #if VRL_PROXY_ONLY_IF_NAMED_DINPUT8
    return IsCurrentModuleNamedDInput8(hModule);
    #else
    UNREFERENCED_PARAMETER(hModule);
    return true;
    #endif
}

static bool BuildSystemDInput8Path(wchar_t* outPath, size_t outCount)
{
    if (!outPath || outCount == 0)
        return false;

    wchar_t systemDir[MAX_PATH] = {};
    const UINT len = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return false;

    if (wcscpy_s(outPath, outCount, systemDir) != 0)
        return false;

    if (wcscat_s(outPath, outCount, L"\\dinput8.dll") != 0)
        return false;

    return true;
}

static bool ResolveRealDInput8Exports()
{
    if (!gRealDInput8)
        return false;

    gRealDirectInput8Create =
        reinterpret_cast<DirectInput8Create_t>(GetProcAddress(gRealDInput8, "DirectInput8Create"));
    gRealDllCanUnloadNow =
        reinterpret_cast<DllCanUnloadNow_t>(GetProcAddress(gRealDInput8, "DllCanUnloadNow"));
    gRealDllGetClassObject =
        reinterpret_cast<DllGetClassObject_t>(GetProcAddress(gRealDInput8, "DllGetClassObject"));
    gRealDllRegisterServer =
        reinterpret_cast<DllRegisterServer_t>(GetProcAddress(gRealDInput8, "DllRegisterServer"));
    gRealDllUnregisterServer =
        reinterpret_cast<DllUnregisterServer_t>(GetProcAddress(gRealDInput8, "DllUnregisterServer"));
    gRealGetdfDIJoystick =
        reinterpret_cast<GetdfDIJoystick_t>(GetProcAddress(gRealDInput8, "GetdfDIJoystick"));

    return gRealDirectInput8Create != nullptr;
}

static bool LoadRealDInput8IfNeeded(HMODULE hModule)
{
    if (!ShouldUseDInput8Proxy(hModule))
        return true;

    if (gRealDInput8)
        return true;

    wchar_t realPath[MAX_PATH] = {};
    if (!BuildSystemDInput8Path(realPath, _countof(realPath)))
    {
        Log("[DLL] Failed to build system dinput8 path.\n");
        return false;
    }

    gRealDInput8 = LoadLibraryW(realPath);
    if (!gRealDInput8)
    {
        Log("[DLL] Failed to load real dinput8.dll.\n");
        return false;
    }

    if (!ResolveRealDInput8Exports())
    {
        Log("[DLL] Failed to resolve real dinput8 exports.\n");
        FreeLibrary(gRealDInput8);
        gRealDInput8 = nullptr;
        return false;
    }

    Log("[DLL] Real dinput8.dll loaded.\n");
    return true;
}

static void FreeRealDInput8()
{
    if (gRealDInput8)
    {
        FreeLibrary(gRealDInput8);
        gRealDInput8 = nullptr;
    }

    gRealDirectInput8Create = nullptr;
    gRealDllCanUnloadNow = nullptr;
    gRealDllGetClassObject = nullptr;
    gRealDllRegisterServer = nullptr;
    gRealDllUnregisterServer = nullptr;
    gRealGetdfDIJoystick = nullptr;
}

extern "C" HRESULT WINAPI ProxyDirectInput8Create(
    HINSTANCE hinst,
    DWORD dwVersion,
    REFIID riidltf,
    LPVOID* ppvOut,
    LPUNKNOWN punkOuter)
{
    if (!gRealDirectInput8Create)
        return E_FAIL;

    return gRealDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
}

extern "C" HRESULT STDAPICALLTYPE ProxyDllCanUnloadNow(void)
{
    if (!gRealDllCanUnloadNow)
        return S_FALSE;

    return gRealDllCanUnloadNow();
}

extern "C" HRESULT STDAPICALLTYPE ProxyDllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (!gRealDllGetClassObject)
        return CLASS_E_CLASSNOTAVAILABLE;

    return gRealDllGetClassObject(rclsid, riid, ppv);
}

extern "C" HRESULT STDAPICALLTYPE ProxyDllRegisterServer(void)
{
    if (!gRealDllRegisterServer)
        return E_FAIL;

    return gRealDllRegisterServer();
}

extern "C" HRESULT STDAPICALLTYPE ProxyDllUnregisterServer(void)
{
    if (!gRealDllUnregisterServer)
        return E_FAIL;

    return gRealDllUnregisterServer();
}

extern "C" const void* WINAPI ProxyGetdfDIJoystick(void)
{
    if (!gRealGetdfDIJoystick)
        return nullptr;

    return gRealGetdfDIJoystick();
}

#endif

static void SetupConsole()
{
    #ifdef _DEBUG
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
    #endif
}

static void InstallAll(HMODULE hGame)
{
    if (!Install_SetLuaFunctions_Hook())
        Log("[DLL] Failed: Install_SetLuaFunctions_Hook\n");

    if (!InstallGameLangStateKeepCJKHook(hGame))
        Log("[DLL] Failed: InstallGameLangStateKeepCJKHook\n");

    if (!InstallLangSelectPopupPagedRewriteHooks(hGame))
        Log("[DLL] Failed: InstallLangSelectPopupPagedRewriteHooks\n");

    if (!InstallLanguageHook(hGame))
        Log("[DLL] Failed: InstallLanguageHook\n");

    if (!InstallShowTextureLogoArabicHook(hGame))
        Log("[DLL] Failed: InstallShowTextureLogoArabicHook\n");

    if (!InstallChapterTelopArabicFtexHook(hGame))
        Log("[DLL] Failed: InstallChapterTelopArabicFtexHook\n");

    if (!Install_UnkLoadUIDefaultDataFunc_Hook())
        Log("[DLL] Failed: Install_UnkLoadUIDefaultDataFunc_Hook\n");

    if (!InstallUnkLoadTppPartsLangFpkArabicFixHook(hGame))
        Log("[DLL] Failed: InstallUnkLoadTppPartsLangFpkArabicFixHook\n");

    if (!InstallGetTipsLangBlockPathHook(hGame))
        Log("[DLL] Failed: InstallGetTipsLangBlockPathHook\n");

    if (!InstallGetPauseHelpLangBlockPathHook(hGame))
        Log("[DLL] Failed: InstallGetPauseHelpLangBlockPathHook\n");

    if (!InstallDisplayTimerEvCallSetDisplayTextHook(hGame))
        Log("[DLL] Failed: InstallDisplayTimerEvCallSetDisplayTextHook\n");

    if (!InstallMbLogViewerBodyLayoutSetMainTextArabicHook(hGame))
        Log("[DLL] Failed: InstallMbLogViewerBodyLayoutSetMainTextArabicHook\n");

    if (!InstallCustomizeSlotSelectorSetupListElementWalkerGearHook(hGame))
        Log("[DLL] Failed: InstallCustomizeSlotSelectorSetupListElementWalkerGearHook\n");

    if (!InstallGamePauseMenuArabicTextHooks(hGame))
        Log("[DLL] Failed: InstallGamePauseMenuArabicTextHooks\n");

    if (!InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook(hGame))
        Log("[DLL] Failed: InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook\n");

    if (!InstallCallMenuImplSetCommandTextArabicHook(hGame))
        Log("[DLL] Failed: InstallCallMenuImplSetCommandTextArabicHook\n");

    if (!InstallTipsLayoutControllerSetPageTextHook(hGame))
        Log("[DLL] Failed: InstallTipsLayoutControllerSetPageTextHook\n");

    if (!InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(hGame))
        Log("[DLL] Failed: InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook\n");

    if (!InstallSetTextMissionTelopNameArabicEpisodeFormatHook(hGame))
        Log("[DLL] Failed: InstallSetTextMissionTelopNameArabicEpisodeFormatHook\n");

    if (!InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook\n");

    if (!InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook(hGame))
        Log("[DLL] Failed: InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook\n");

    if (!InstallMbTitleEvGetTypingTextArabicHook(hGame))
        Log("[DLL] Failed: InstallMbTitleEvGetTypingTextArabicHook\n");

    if (!InstallMbTitleEvSetMenuNameTextArabicHook(hGame))
        Log("[DLL] Failed: InstallMbTitleEvSetMenuNameTextArabicHook\n");

    if (!InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook(hGame))
        Log("[DLL] Failed: InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook\n");

    if (!InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook(hGame))
        Log("[DLL] Failed: InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook\n");

    if (!InstallMissionPreparationCallbackImplSetupMissionNameArabicHook(hGame))
        Log("[DLL] Failed: InstallMissionPreparationCallbackImplSetupMissionNameArabicHook\n");

    if (!InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(hGame))
        Log("[DLL] Failed: InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook\n");

    if (!InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(hGame))
        Log("[DLL] Failed: InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook\n");

    if (!InstallTppUIInfoTypingTextImplSetTypingTextArabicHook(hGame))
        Log("[DLL] Failed: InstallTppUIInfoTypingTextImplSetTypingTextArabicHook\n");

    if (!InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook(hGame))
        Log("[DLL] Failed: InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook\n");

    if (!InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook(hGame))
        Log("[DLL] Failed: InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook\n");

    if (!InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook(hGame))
        Log("[DLL] Failed: InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook\n");

    if (!InstallTppUICountAnnounceImplSetAnnounceTextArabicHook(hGame))
        Log("[DLL] Failed: InstallTppUICountAnnounceImplSetAnnounceTextArabicHook\n");

    if (!InstallLoadingTipsEvGetTitleTextArabicHook(hGame))
        Log("[DLL] Failed: InstallLoadingTipsEvGetTitleTextArabicHook\n");

    if (!InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook\n");

    if (!InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook\n");

    if (!InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook\n");

    if (!InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook\n");

    if (!InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed: InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook\n");

    if (!InstallSetEquipBackgroundTextureArabicHook(hGame))
        Log("[DLL] Failed: InstallSetEquipBackgroundTextureArabicHook\n");

    if (!InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook(hGame))
        Log("[DLL] Failed: InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook\n");
}

static void RemoveAll()
{
    Uninstall_SetLuaFunctions_Hook();
    RemoveGameLangStateKeepCJKHook();
    RemoveLangSelectPopupPagedRewriteHooks();
    RemoveLanguageHook();
    RemoveShowTextureLogoArabicHook();
    RemoveChapterTelopArabicFtexHook();
    RemoveUnkLoadTppPartsLangFpkArabicFixHook();
    RemoveGetTipsLangBlockPathHook();
    RemoveGetPauseHelpLangBlockPathHook();
    RemoveDisplayTimerEvCallSetDisplayTextHook();
    RemoveMbLogViewerBodyLayoutSetMainTextArabicHook();
    RemoveCustomizeSlotSelectorSetupListElementWalkerGearHook();
    RemoveGamePauseMenuArabicTextHooks();
    RemoveMbDvcMissionInfoSetMissionInfoTextsArabicHook();
    RemoveCallMenuImplSetCommandTextArabicHook();
    RemoveTipsLayoutControllerSetPageTextHook();
    RemoveTelopStartTitleEvCallUpdateArabicTypingDirectionHook();
    RemoveSetTextMissionTelopNameArabicEpisodeFormatHook();
    RemoveAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook();
    RemoveHeadMarkMarkerEvCallSetMarkerTextArabicHook();
    RemoveMbTitleEvGetTypingTextArabicHook();
    RemoveMbTitleEvSetMenuNameTextArabicHook();
    RemoveMbDvcMissionListRecordCallFuncStartArabicFormatHook();
    RemoveMbDvcSideOpsRecordCallFuncViewRecordArabicHook();
    RemoveMissionPreparationCallbackImplSetupMissionNameArabicHook();
    RemoveEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook();
    RemoveEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook();
    RemoveTppUIInfoTypingTextImplSetTypingTextArabicHook();
    RemoveLoadoutPanelInfoRefreshLoadoutTextArabicHook();
    RemoveItemSelectorRecordCallFuncUpdateRecordsArabicHook();
    RemoveMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook();
    RemoveTppUICountAnnounceImplSetAnnounceTextArabicHook();
    RemoveLoadingTipsEvGetTitleTextArabicHook();
    RemoveLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook();
    RemoveEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook();
    RemoveMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook();
    RemoveGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook();
    RemovePopupEvCallSettingPopupArabicLeftToRightAlignHook();
    RemoveSetEquipBackgroundTextureArabicHook();
    RemoveMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook();
}

static DWORD WINAPI InitThread(LPVOID)
{
    #ifdef _DEBUG
    SetupConsole();
    InitLog();
    #endif

    Log("[DLL] InitThread started.\n");

    HMODULE hGame = GetModuleHandleW(nullptr);
    if (!hGame)
    {
        Log("[DLL] GetModuleHandleW(nullptr) failed.\n");
        return 0;
    }

    if (!ResolveAddressSet(hGame))
    {
        Log("[DLL] ResolveAddressSet failed.\n");
        return 0;
    }

    const MH_STATUS st = MH_Initialize();
    Log("[DLL] MH_Initialize -> %d\n", static_cast<int>(st));
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
        return 0;

    InstallAll(hGame);

    gInitialized.store(true);
    Log("[DLL] InitThread done.\n");
    return 0;
}

static void UninstallAll(bool processTerminating)
{
    if (processTerminating)
        return;

    if (gInitialized.load())
    {
        RemoveAll();
        MH_Uninitialize();
        gInitialized.store(false);
        Log("[DLL] UninstallAll done.\n");
    }

    #if VRL_ENABLE_DINPUT8_PROXY
    FreeRealDInput8();
    #endif

    fflush(stdout);
    fflush(stderr);
    CloseLog();
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

        #if VRL_ENABLE_DINPUT8_PROXY
        InitLog();
        if (!LoadRealDInput8IfNeeded(hModule))
            return FALSE;
        #endif

        #if VRL_ENABLE_AUTO_INIT_THREAD
        HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (hThread)
            CloseHandle(hThread);
        #else
        InitThread(nullptr);
        #endif

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