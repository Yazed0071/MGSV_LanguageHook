#include "pch.h"
#include <Windows.h>
#include <unknwn.h>
#include <atomic>
#include <cwchar>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

#define VRL_ENABLE_AUTO_INIT_THREAD 1
#define VRL_ENABLE_DINPUT8_PROXY    1
#define VRL_PROXY_ONLY_IF_NAMED_DINPUT8 1
#define VRL_ENABLE_SECURITY_UPDATE_EVENT_LOG_INFO_HOOK      0
#define VRL_ENABLE_SECURITY_GET_EVENT_LOG_TYPING_TEXT_HOOK  0


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

bool InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(HMODULE hGame);
void RemoveTelopStartTitleEvCallUpdateArabicTypingDirectionHook();

bool InstallSetTextMissionTelopNameArabicEpisodeFormatHook(HMODULE hGame);
void RemoveSetTextMissionTelopNameArabicEpisodeFormatHook();

bool InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook(HMODULE hGame);
void RemoveAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook();

bool InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook(HMODULE hGame);
void RemoveHeadMarkMarkerEvCallSetMarkerTextArabicHook();

bool InstallMbTitleEvGetTypingTextArabicHook(HMODULE hGame);
void RemoveMbTitleEvGetTypingTextArabicHook();

bool InstallMbTitleEvSetMenuNameTextArabicHook(HMODULE hGame);
void RemoveMbTitleEvSetMenuNameTextArabicHook();

bool InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook(HMODULE hGame);
void RemoveMbDvcMissionListRecordCallFuncStartArabicFormatHook();

bool InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook(HMODULE hGame);
void RemoveMbDvcSideOpsRecordCallFuncViewRecordArabicHook();

bool InstallMissionPreparationCallbackImplSetupMissionNameArabicHook(HMODULE hGame);
void RemoveMissionPreparationCallbackImplSetupMissionNameArabicHook();

bool InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(HMODULE hGame);
void RemoveEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook();

bool InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(HMODULE hGame);
void RemoveEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook();

bool InstallTppUIInfoTypingTextImplSetTypingTextArabicHook(HMODULE hGame);
void RemoveTppUIInfoTypingTextImplSetTypingTextArabicHook();

bool InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook(HMODULE hGame);
void RemoveLoadoutPanelInfoRefreshLoadoutTextArabicHook();

bool InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook(HMODULE hGame);
void RemoveItemSelectorRecordCallFuncUpdateRecordsArabicHook();

bool InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook(HMODULE hGame);
void RemoveMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook();

bool InstallTppUICountAnnounceImplSetAnnounceTextArabicHook(HMODULE hGame);
void RemoveTppUICountAnnounceImplSetAnnounceTextArabicHook();

bool InstallLoadingTipsEvGetTitleTextArabicHook(HMODULE hGame);
void RemoveLoadingTipsEvGetTitleTextArabicHook();

bool InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook(HMODULE hGame);
void RemoveLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook();

bool InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(HMODULE hGame);
void RemoveEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook();

bool InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook(HMODULE hGame);
void RemoveMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook();

bool InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook(HMODULE hGame);
void RemoveGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook();

bool InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook(HMODULE hGame);
void RemovePopupEvCallSettingPopupArabicLeftToRightAlignHook();

bool InstallSetEquipBackgroundTextureArabicHook(HMODULE hGame);
void RemoveSetEquipBackgroundTextureArabicHook();

bool InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook(HMODULE hGame);
void RemoveMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook();

// ------------------------------------------------------------
// dinput8 proxy
// ------------------------------------------------------------

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

#endif

namespace
{
    static std::atomic_bool gInitialized{ false };
    static std::atomic_bool gInitStarted{ false };
}

/* Checks if this DLL file is actually named dinput8.dll. Parameters: hModule = current DLL module. */
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

#if VRL_ENABLE_DINPUT8_PROXY

/* Returns true if proxy mode should be active. Parameters: hModule = current DLL module. */
static bool ShouldUseDInput8Proxy(HMODULE hModule)
{
    #if VRL_PROXY_ONLY_IF_NAMED_DINPUT8
    return IsCurrentModuleNamedDInput8(hModule);
    #else
    UNREFERENCED_PARAMETER(hModule);
    return true;
    #endif
}

/* Builds the full path to the real system dinput8.dll. Parameters: outPath = destination buffer, outCount = number of wchar_t entries. */
static bool BuildSystemDInput8Path(wchar_t* outPath, size_t outCount)
{
    if (!outPath || outCount == 0)
        return false;

    wchar_t systemDir[MAX_PATH] = {};
    UINT len = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return false;

    if (wcscpy_s(outPath, outCount, systemDir) != 0)
        return false;

    if (wcscat_s(outPath, outCount, L"\\dinput8.dll") != 0)
        return false;

    return true;
}

/* Resolves all needed real dinput8 exports. Parameters: none. */
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

    if (!gRealDirectInput8Create)
        return false;

    return true;
}

/* Loads the real system dinput8.dll. Parameters: hModule = current DLL module. */
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

/* Frees the real system dinput8.dll. Parameters: none. */
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

extern "C" HRESULT WINAPI ProxyDirectInput8Create(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter)
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

/* Installs all enabled hooks. Parameters: hGame = main game module. */
static void InstallAll(HMODULE hGame)
{
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

    if (!InstallDisplayTimerEvCallSetDisplayTextHook(hGame))
        Log("[DLL] Failed to install InstallDisplayTimerEvCallSetDisplayTextHook hook.\n");

    if (!InstallMbLogViewerBodyLayoutSetMainTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbLogViewerBodyLayoutSetMainTextArabicHook hook.\n");

    if (!InstallCustomizeSlotSelectorSetupListElementWalkerGearHook(hGame))
        Log("[DLL] Failed to install InstallCustomizeSlotSelectorSetupListElementWalkerGearHook hook.\n");

    if (!InstallGamePauseMenuArabicTextHooks(hGame))
        Log("[DLL] Failed to install InstallGamePauseMenuArabicTextHooks hook.\n");

    if (!InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook hook.\n");

    if (!InstallCallMenuImplSetCommandTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallCallMenuImplSetCommandTextArabicHook hook.\n");

    if (!InstallTipsLayoutControllerSetPageTextHook(hGame))
        Log("[DLL] Failed to install InstallTipsLayoutControllerSetPageTextHook hook.\n");

    if (!InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(hGame))
        Log("[DLL] Failed to install InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook hook.\n");

    if (!InstallSetTextMissionTelopNameArabicEpisodeFormatHook(hGame))
        Log("[DLL] Failed to install InstallSetTextMissionTelopNameArabicEpisodeFormatHook hook.\n");

    if (!InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallAnnounceLogViewerCallLogViewArabicLeftToRightAlignHook hook.\n");

    if (!InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallHeadMarkMarkerEvCallSetMarkerTextArabicHook hook.\n");

    if (!InstallMbTitleEvGetTypingTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbTitleEvGetTypingTextArabicHook hook.\n");

    if (!InstallMbTitleEvSetMenuNameTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbTitleEvSetMenuNameTextArabicHook hook.\n");

    if (!InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook hook.\n");

    if (!InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook hook.\n");

    if (!InstallMissionPreparationCallbackImplSetupMissionNameArabicHook(hGame))
        Log("[DLL] Failed to install InstallMissionPreparationCallbackImplSetupMissionNameArabicHook hook.\n");

    if (!InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook hook.\n");

    if (!InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook hook.\n");

    if (!InstallTppUIInfoTypingTextImplSetTypingTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallTppUIInfoTypingTextImplSetTypingTextArabicHook hook.\n");

    if (!InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallLoadoutPanelInfoRefreshLoadoutTextArabicHook hook.\n");

    if (!InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook(hGame))
        Log("[DLL] Failed to install InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook hook.\n");

    if (!InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook hook.\n");

    if (!InstallTppUICountAnnounceImplSetAnnounceTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallTppUICountAnnounceImplSetAnnounceTextArabicHook hook.\n");

    if (!InstallLoadingTipsEvGetTitleTextArabicHook(hGame))
        Log("[DLL] Failed to install InstallLoadingTipsEvGetTitleTextArabicHook hook.\n");

    if (!InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallLoadingTipsEvUpdateActPhaseArabicLeftToRightAlignHook hook.\n");

    if (!InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallEquipCrossEvCallSetCircleCursorFromSrickDirArabicLeftToRightAlignHook hook.\n");

    if (!InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcMissionListCallbackImplShowMissionInfoTextBoxArabicLeftToRightAlignHook hook.\n");

    if (!InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallGameOverEvCallUpdateSelectTextArabicLeftToRightAlignHook hook.\n");

    if (!InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook(hGame))
        Log("[DLL] Failed to install InstallPopupEvCallSettingPopupArabicLeftToRightAlignHook hook.\n");

    if (!InstallSetEquipBackgroundTextureArabicHook(hGame))
        Log("[DLL] Failed to install InstallSetEquipBackgroundTextureArabicHook hook.\n");

    if (!InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook(hGame))
        Log("[DLL] Failed to install InstallMbDvcSideOpsCallbackImplUpdateInformationTextBoxArabicHook hook.\n");
}

/* Removes all enabled hooks. Parameters: none. */
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

// Opens the debug console only in Debug builds.
static void OpenDebugConsoleIfNeeded()
{
    #ifdef _DEBUG
    if (GetConsoleWindow() == nullptr)
    {
        AllocConsole();
        FILE* dummy = nullptr;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
        freopen_s(&dummy, "CONIN$", "r", stdin);
    }
    #endif
}


/* Initializes hooks once. Parameters: hGame = main game module handle. */
extern "C" __declspec(dllexport) bool InitializeHooks(HMODULE hGame)
{
    if (gInitialized.load())
        return true;

    if (!hGame)
        return false;

    #if _DEBUG
    InitLog();
    #endif // _DEBUG

    Log("[VRL] InitializeHooks begin.\n");

    if (!ResolveAddressSet(hGame))
    {
        Log("[VRL] ResolveAddressSet failed.\n");
        CloseLog();
        return false;
    }

    const MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        Log("[VRL] MH_Initialize failed: %d\n", static_cast<int>(st));
        CloseLog();
        return false;
    }

    InstallAll(hGame);

    gInitialized.store(true);
    Log("[VRL] InitializeHooks done.\n");
    return true;
}

/* Shuts everything down once. Parameters: none. */
extern "C" __declspec(dllexport) void ShutdownHooks()
{
    if (!gInitialized.load())
        return;

    Log("[VRL] ShutdownHooks begin.\n");

    RemoveAll();
    MH_Uninitialize();

    gInitialized.store(false);
    gInitStarted.store(false);

    Log("[VRL] ShutdownHooks done.\n");
    CloseLog();
}

/* Worker thread for startup. Parameters: unused. */
static DWORD WINAPI InitThread(LPVOID)
{
    HMODULE hGame = GetModuleHandleW(nullptr);
    InitializeHooks(hGame);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        InitLog();

        #if VRL_ENABLE_DINPUT8_PROXY
        if (!LoadRealDInput8IfNeeded(hModule))
            return FALSE;
        #endif

        #if VRL_ENABLE_AUTO_INIT_THREAD
        bool expected = false;
        if (!gInitStarted.compare_exchange_strong(expected, true))
            return TRUE;

        HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (hThread)
            CloseHandle(hThread);
        #else
        InitializeHooks(GetModuleHandleW(nullptr));
        #endif

        return TRUE;
    }

    case DLL_PROCESS_DETACH:
    {
        if (lpReserved == nullptr)
            ShutdownHooks();

        #if VRL_ENABLE_DINPUT8_PROXY
        FreeRealDInput8();
        #endif

        return TRUE;
    }
    }

    return TRUE;
}