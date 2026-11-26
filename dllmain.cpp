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

bool InstallLanguageProfile(HMODULE hGame);
bool InstallGameLangStateKeepCJKHook(HMODULE hGame);
bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame);
bool InstallLanguageHook(HMODULE hGame);
bool InstallShowTextureLogoArabicHook(HMODULE hGame);
bool InstallChapterTelopArabicFtexHook(HMODULE hGame);
bool Install_UnkLoadUIDefaultDataFunc_Hook();
bool InitFoxAssetExists(HMODULE hGame);
bool InstallArabicPackRedirectHook(HMODULE hGame);
void RemoveArabicPackRedirectHook();
bool InitAvatarEditCameraMirror(HMODULE hGame);
void ShutdownAvatarEditCameraMirror();
bool InstallUnkLoadTppPartsLangFpkArabicFixHook(HMODULE hGame);
bool InstallGetTipsLangBlockPathHook(HMODULE hGame);
bool InstallSubtitleStreamLineLimit(HMODULE hGame);
void RemoveSubtitleStreamLineLimit();
bool InstallSubtitleAreaPackKeeper(HMODULE hGame);
void RemoveSubtitleAreaPackKeeper();
bool InstallGetPauseHelpLangBlockPathHook(HMODULE hGame);
bool Install_SetLuaFunctions_Hook();
bool InstallLuaCrashReport();
void RemoveLuaCrashReport();
bool InstallDisplayTimerEvCallSetDisplayTextHook(HMODULE hGame);
bool InstallBinoMicMirrorGaugeHook(HMODULE hGame);
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
bool InstallTppUIInfoTypingTextUpdateTextRtlHook(HMODULE hGame);
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
bool InstallArabicScrollReversalHook(HMODULE hGame);
bool InstallCreateTextUnitsArabicWrapHook(HMODULE hGame);
bool InstallGetUTF8TextFromBackArabicRevealHook(HMODULE hGame);
bool InstallArabicGlyphRenderingHooks(HMODULE hGame);
bool InstallFntHarakatHook(HMODULE hGame);
bool InstallArabicRubyLayoutHook(HMODULE hGame);
bool InstallEpilogueControllerSetupAssetArabicHook(HMODULE hGame);
bool InstallRadioButtonGuideArabicMirrorHook(HMODULE hGame);
bool InstallTppUIMusicTelopArabicRightAlignHook(HMODULE hGame);
bool InstallMbTitleEvUpdateArabicHook(HMODULE hGame);
bool InstallMbCommonPopupActUpdateArabicHook(HMODULE hGame);
bool InstallTppUIResultImplRadioFileLabelsHook(HMODULE hGame);
bool InstallMenuTitleArabicBreadcrumbHook(HMODULE hGame);
bool InstallDataBaseCallbackImplArabicInfoTextHook(HMODULE hGame);
bool InstallUixUtilityArabicRecordRowsHook(HMODULE hGame);
bool InstallCombatDeployCallbackImplRefreshMissionTextBoxArabicHook(HMODULE hGame);
bool InstallWorldMarkerLengthTextArabicHook(HMODULE hGame);
bool InstallActiveSonarDistanceArabicHook(HMODULE hGame);
bool InstallStrncpySArabicGuardHook(HMODULE hGame);
bool InstallMissionSkillViewArabicHook(HMODULE hGame);
bool InstallMbDvcResourceRecordAmountColumnArabicHook(HMODULE hGame);
bool InstallPauseHelpTutorialPopupArabicHook(HMODULE hGame);
bool InstallPauseHelpRefreshHelpPageArabicHook(HMODULE hGame);
bool InstallPauseHelpRefreshHeaderTextArabicHook(HMODULE hGame);
bool InstallUiUtilitySetPadButtonPromptArabicHook(HMODULE hGame);
bool InstallGradeMarkRtlHook(HMODULE hGame);
bool InstallLongArabicAnnounceTextHook(HMODULE hGame);
bool InstallUiInspectorHook(HMODULE hGame);
bool InstallActSetTextUpdateArabicAlignHook(HMODULE hGame);
bool InstallModelNodeTextDrawArabicAlignHook(HMODULE hGame);
bool InstallStaffFullNameArabicHooks(HMODULE hGame);
bool InstallServerLanguageFallbackHooks(HMODULE hGame);
bool InstallCassetteSeekButtonSwapHook(HMODULE hGame);
bool InstallMapMaskMirrorHook(HMODULE hGame);
bool InstallSecurityDetailValueXMirrorHook(HMODULE hGame);

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
void RemoveBinoMicMirrorGaugeHook();
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
void RemoveTppUIInfoTypingTextUpdateTextRtlHook();
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
void RemoveArabicScrollReversalHook();
void RemoveCreateTextUnitsArabicWrapHook();
void RemoveGetUTF8TextFromBackArabicRevealHook();
void RemoveArabicGlyphRenderingHooks();
void RemoveFntHarakatHook();
void RemoveArabicRubyLayoutHook();
void RemoveEpilogueControllerSetupAssetArabicHook();
void RemoveRadioButtonGuideArabicMirrorHook();
void RemoveTppUIMusicTelopArabicRightAlignHook();
void RemoveMbTitleEvUpdateArabicHook();
void RemoveMbCommonPopupActUpdateArabicHook();
void RemoveTppUIResultImplRadioFileLabelsHook();
void RemoveMenuTitleArabicBreadcrumbHook();
void RemoveDataBaseCallbackImplArabicInfoTextHook();
void RemoveUixUtilityArabicRecordRowsHook();
void RemoveCombatDeployCallbackImplRefreshMissionTextBoxArabicHook();
void RemoveWorldMarkerLengthTextArabicHook();
void RemoveActiveSonarDistanceArabicHook();
void RemoveStrncpySArabicGuardHook();
void RemoveMissionSkillViewArabicHook();
void RemoveMbDvcResourceRecordAmountColumnArabicHook();
void RemovePauseHelpTutorialPopupArabicHook();
void RemovePauseHelpRefreshHelpPageArabicHook();
void RemovePauseHelpRefreshHeaderTextArabicHook();
void RemoveUiUtilitySetPadButtonPromptArabicHook();
void RemoveGradeMarkRtlHook();
void RemoveLongArabicAnnounceTextHook();
void RemoveUiInspectorHook();
void RemoveActSetTextUpdateArabicAlignHook();
void RemoveModelNodeTextDrawArabicAlignHook();
void RemoveStaffFullNameArabicHooks();
void RemoveServerLanguageFallbackHooks();
void RemoveCassetteSeekButtonSwapHook();
void RemoveMapMaskMirrorHook();
void RemoveSecurityDetailValueXMirrorHook();

namespace
{
    static std::atomic_bool gStarted{ false };
    static std::atomic_bool gInitialized{ false };
    static std::atomic_bool gConsoleReady{ false };
    static HANDLE gInstanceRecord = nullptr;
    static bool gIdleCopy = false;
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

static void InstallStartupHooks(HMODULE hGame)
{
    InstallLanguageProfile(hGame);

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

    InitFoxAssetExists(hGame);
    InitAvatarEditCameraMirror(hGame);

    if (!InstallArabicPackRedirectHook(hGame) && !Install_UnkLoadUIDefaultDataFunc_Hook())
        Log("[DLL] Failed: Install_UnkLoadUIDefaultDataFunc_Hook\n");

    if (!InstallUnkLoadTppPartsLangFpkArabicFixHook(hGame))
        Log("[DLL] Failed: InstallUnkLoadTppPartsLangFpkArabicFixHook\n");

    if (!InstallGetTipsLangBlockPathHook(hGame))
        Log("[DLL] Failed: InstallGetTipsLangBlockPathHook\n");

    if (!InstallSubtitleStreamLineLimit(hGame))
        Log("[DLL] Failed: InstallSubtitleStreamLineLimit\n");

    if (!InstallSubtitleAreaPackKeeper(hGame))
        Log("[DLL] Failed: InstallSubtitleAreaPackKeeper\n");

    if (!InstallArabicGlyphRenderingHooks(hGame))
        Log("[DLL] Failed: InstallArabicGlyphRenderingHooks\n");
}

static void InstallAll(HMODULE hGame)
{
    if (!InstallLuaCrashReport())
        Log("[DLL] Failed: InstallLuaCrashReport\n");

    if (!InstallDisplayTimerEvCallSetDisplayTextHook(hGame))
        Log("[DLL] Failed: InstallDisplayTimerEvCallSetDisplayTextHook\n");

    if (!InstallBinoMicMirrorGaugeHook(hGame))
        Log("[DLL] Failed: InstallBinoMicMirrorGaugeHook\n");

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

    if (!InstallTppUIInfoTypingTextUpdateTextRtlHook(hGame))
        Log("[DLL] Failed: InstallTppUIInfoTypingTextUpdateTextRtlHook\n");

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

    if (!InstallArabicScrollReversalHook(hGame))
        Log("[DLL] Failed: InstallArabicScrollReversalHook\n");

    if (!InstallCreateTextUnitsArabicWrapHook(hGame))
        Log("[DLL] Failed: InstallCreateTextUnitsArabicWrapHook\n");

    if (!InstallGetUTF8TextFromBackArabicRevealHook(hGame))
        Log("[DLL] Failed: InstallGetUTF8TextFromBackArabicRevealHook\n");

    if (!InstallArabicRubyLayoutHook(hGame))
        Log("[DLL] Failed: InstallArabicRubyLayoutHook\n");

    if (!InstallEpilogueControllerSetupAssetArabicHook(hGame))
        Log("[DLL] Failed: InstallEpilogueControllerSetupAssetArabicHook\n");

    if (!InstallRadioButtonGuideArabicMirrorHook(hGame))
        Log("[DLL] Failed: InstallRadioButtonGuideArabicMirrorHook\n");

    if (!InstallTppUIMusicTelopArabicRightAlignHook(hGame))
        Log("[DLL] Failed: InstallTppUIMusicTelopArabicRightAlignHook\n");

    if (!InstallMbTitleEvUpdateArabicHook(hGame))
        Log("[DLL] Failed: InstallMbTitleEvUpdateArabicHook\n");

    if (!InstallMbCommonPopupActUpdateArabicHook(hGame))
        Log("[DLL] Failed: InstallMbCommonPopupActUpdateArabicHook\n");

    if (!InstallTppUIResultImplRadioFileLabelsHook(hGame))
        Log("[DLL] Failed: InstallTppUIResultImplRadioFileLabelsHook\n");

    if (!InstallMenuTitleArabicBreadcrumbHook(hGame))
        Log("[DLL] Failed: InstallMenuTitleArabicBreadcrumbHook\n");

    if (!InstallDataBaseCallbackImplArabicInfoTextHook(hGame))
        Log("[DLL] Failed: InstallDataBaseCallbackImplArabicInfoTextHook\n");

    if (!InstallUixUtilityArabicRecordRowsHook(hGame))
        Log("[DLL] Failed: InstallUixUtilityArabicRecordRowsHook\n");

    if (!InstallCombatDeployCallbackImplRefreshMissionTextBoxArabicHook(hGame))
        Log("[DLL] Failed: InstallCombatDeployCallbackImplRefreshMissionTextBoxArabicHook\n");

    if (!InstallWorldMarkerLengthTextArabicHook(hGame))
        Log("[DLL] Failed: InstallWorldMarkerLengthTextArabicHook\n");

    if (!InstallActiveSonarDistanceArabicHook(hGame))
        Log("[DLL] Failed: InstallActiveSonarDistanceArabicHook\n");

    if (!InstallStrncpySArabicGuardHook(hGame))
        Log("[DLL] Failed: InstallStrncpySArabicGuardHook\n");

    if (!InstallMissionSkillViewArabicHook(hGame))
        Log("[DLL] Failed: InstallMissionSkillViewArabicHook\n");

    if (!InstallMbDvcResourceRecordAmountColumnArabicHook(hGame))
        Log("[DLL] Failed: InstallMbDvcResourceRecordAmountColumnArabicHook\n");

    if (!InstallPauseHelpTutorialPopupArabicHook(hGame))
        Log("[DLL] Failed: InstallPauseHelpTutorialPopupArabicHook\n");

    if (!InstallPauseHelpRefreshHelpPageArabicHook(hGame))
        Log("[DLL] Failed: InstallPauseHelpRefreshHelpPageArabicHook\n");
    if (!InstallPauseHelpRefreshHeaderTextArabicHook(hGame))
        Log("[DLL] Failed: InstallPauseHelpRefreshHeaderTextArabicHook\n");

    if (!InstallUiUtilitySetPadButtonPromptArabicHook(hGame))
        Log("[DLL] Failed: InstallUiUtilitySetPadButtonPromptArabicHook\n");

    if (!InstallGradeMarkRtlHook(hGame))
        Log("[DLL] Failed: InstallGradeMarkRtlHook\n");

    if (!InstallLongArabicAnnounceTextHook(hGame))
        Log("[DLL] Failed: InstallLongArabicAnnounceTextHook\n");

    if (!InstallUiInspectorHook(hGame))
        Log("[DLL] Failed: InstallUiInspectorHook\n");

    if (!InstallActSetTextUpdateArabicAlignHook(hGame))
        Log("[DLL] Failed: InstallActSetTextUpdateArabicAlignHook\n");

    if (!InstallModelNodeTextDrawArabicAlignHook(hGame))
        Log("[DLL] Failed: InstallModelNodeTextDrawArabicAlignHook\n");

    if (!InstallStaffFullNameArabicHooks(hGame))
        Log("[DLL] Failed: InstallStaffFullNameArabicHooks\n");

    if (!InstallServerLanguageFallbackHooks(hGame))
        Log("[DLL] Failed: InstallServerLanguageFallbackHooks\n");

    if (!InstallCassetteSeekButtonSwapHook(hGame))
        Log("[DLL] Failed: InstallCassetteSeekButtonSwapHook\n");

    if (!InstallMapMaskMirrorHook(hGame))
        Log("[DLL] Failed: InstallMapMaskMirrorHook\n");

    if (!InstallSecurityDetailValueXMirrorHook(hGame))
        Log("[DLL] Failed: InstallSecurityDetailValueXMirrorHook\n");

    if (!InstallFntHarakatHook(hGame))
        Log("[DLL] Failed: InstallFntHarakatHook\n");

}

static void RemoveAll()
{
    RemoveLuaCrashReport();
    Uninstall_SetLuaFunctions_Hook();
    RemoveGameLangStateKeepCJKHook();
    RemoveLangSelectPopupPagedRewriteHooks();
    RemoveLanguageHook();
    RemoveShowTextureLogoArabicHook();
    RemoveChapterTelopArabicFtexHook();
    RemoveUnkLoadTppPartsLangFpkArabicFixHook();
    RemoveArabicPackRedirectHook();
    ShutdownAvatarEditCameraMirror();
    RemoveGetTipsLangBlockPathHook();
    RemoveSubtitleStreamLineLimit();
    RemoveSubtitleAreaPackKeeper();
    RemoveDisplayTimerEvCallSetDisplayTextHook();
    RemoveBinoMicMirrorGaugeHook();
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
    RemoveTppUIInfoTypingTextUpdateTextRtlHook();
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
    RemoveArabicScrollReversalHook();
    RemoveCreateTextUnitsArabicWrapHook();
    RemoveGetUTF8TextFromBackArabicRevealHook();
    RemoveArabicGlyphRenderingHooks();
    RemoveFntHarakatHook();
    RemoveArabicRubyLayoutHook();
    RemoveEpilogueControllerSetupAssetArabicHook();
    RemoveRadioButtonGuideArabicMirrorHook();
    RemoveTppUIMusicTelopArabicRightAlignHook();
    RemoveMbTitleEvUpdateArabicHook();
    RemoveMbCommonPopupActUpdateArabicHook();
    RemoveTppUIResultImplRadioFileLabelsHook();
    RemoveMenuTitleArabicBreadcrumbHook();
    RemoveDataBaseCallbackImplArabicInfoTextHook();
    RemoveUixUtilityArabicRecordRowsHook();
    RemoveCombatDeployCallbackImplRefreshMissionTextBoxArabicHook();
    RemoveWorldMarkerLengthTextArabicHook();
    RemoveActiveSonarDistanceArabicHook();
    RemoveStrncpySArabicGuardHook();
    RemoveMissionSkillViewArabicHook();
    RemoveMbDvcResourceRecordAmountColumnArabicHook();
    RemovePauseHelpTutorialPopupArabicHook();
    RemovePauseHelpRefreshHelpPageArabicHook();
    RemovePauseHelpRefreshHeaderTextArabicHook();
    RemoveUiUtilitySetPadButtonPromptArabicHook();
    RemoveGradeMarkRtlHook();
    RemoveLongArabicAnnounceTextHook();
    RemoveUiInspectorHook();
    RemoveActSetTextUpdateArabicAlignHook();
    RemoveModelNodeTextDrawArabicAlignHook();
    RemoveStaffFullNameArabicHooks();
    RemoveServerLanguageFallbackHooks();
    RemoveCassetteSeekButtonSwapHook();
    RemoveMapMaskMirrorHook();
    RemoveSecurityDetailValueXMirrorHook();
}

void RL_ShowUnsupportedBuildNotice();

static DWORD WINAPI InitThread(LPVOID)
{
    #ifdef _DEBUG
    SetupConsole();
    #endif
    InitLog();

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
        RL_ShowUnsupportedBuildNotice();
        return 0;
    }

    const MH_STATUS st = MH_Initialize();
    Log("[DLL] MH_Initialize -> %d\n", static_cast<int>(st));
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
        return 0;

    BeginHookBatch();
    InstallStartupHooks(hGame);
    const int startupApplied = EndHookBatch();
    Log("[DLL] start-up loader hooks switched on first (MinHook %d)\n", startupApplied);

    BeginHookBatch();
    InstallAll(hGame);
    const int applied = EndHookBatch();
    Log("[DLL] all other hooks switched on in one pass (MinHook %d)\n", applied);

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

    if (gInstanceRecord)
    {
        CloseHandle(gInstanceRecord);
        gInstanceRecord = nullptr;
    }

    fflush(stdout);
    fflush(stderr);
    CloseLog();
}

static bool ClaimProcessInstance(HMODULE hModule, wchar_t* otherPath, size_t otherCount)
{
    wchar_t name[64] = {};
    swprintf_s(name, L"Local\\V_Restored_Languages.%lu", GetCurrentProcessId());
    const DWORD bytes = MAX_PATH * sizeof(wchar_t);
    HANDLE record = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, bytes, name);
    if (!record)
        return true;
    const bool existed = GetLastError() == ERROR_ALREADY_EXISTS;
    if (void* view = MapViewOfFile(record, FILE_MAP_ALL_ACCESS, 0, 0, bytes))
    {
        wchar_t* path = static_cast<wchar_t*>(view);
        if (existed)
            wcsncpy_s(otherPath, otherCount, path, _TRUNCATE);
        else
            GetModuleFileNameW(hModule, path, MAX_PATH);
        UnmapViewOfFile(view);
    }
    if (existed)
    {
        CloseHandle(record);
        return false;
    }
    gInstanceRecord = record;
    return true;
}

static void NoteIdleCopy(HMODULE hModule, const wchar_t* otherPath)
{
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(hModule, self, MAX_PATH);
    char selfUtf8[MAX_PATH * 3] = {};
    char otherUtf8[MAX_PATH * 3] = {};
    WideCharToMultiByte(CP_UTF8, 0, self, -1, selfUtf8, sizeof(selfUtf8), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, (otherPath && *otherPath) ? otherPath : L"another module", -1, otherUtf8,
                        sizeof(otherUtf8), nullptr, nullptr);

    char notePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, notePath, MAX_PATH);
    char* lastSlash = strrchr(notePath, '\\');
    if (lastSlash)
        *(lastSlash + 1) = '\0';
    strcat_s(notePath, "MGSV_ArabicHook.2.log");

    FILE* note = nullptr;
    if (fopen_s(&note, notePath, "w") != 0 || !note)
        return;
    fprintf(note, "[DLL] V_Restored_Languages is already running in this game from %s.\n", otherUtf8);
    fprintf(note, "[DLL] This copy (%s) stays idle, so no hook is installed twice. The DLL was loaded twice - keep only one plugin loader.\n",
            selfUtf8);
    fclose(note);
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

        wchar_t otherCopy[MAX_PATH] = {};
        gIdleCopy = !ClaimProcessInstance(hModule, otherCopy, _countof(otherCopy));

        #if VRL_ENABLE_DINPUT8_PROXY
        if (!gIdleCopy)
            InitLog(2, false);
        if (!LoadRealDInput8IfNeeded(hModule))
            return FALSE;
        #endif

        if (gIdleCopy)
        {
            NoteIdleCopy(hModule, otherCopy);
            return TRUE;
        }

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
        if (gIdleCopy)
        {
            #if VRL_ENABLE_DINPUT8_PROXY
            if (!lpReserved)
                FreeRealDInput8();
            #endif
            return TRUE;
        }
        UninstallAll(lpReserved != nullptr);
        return TRUE;
    }
    }

    return TRUE;
}