#include "pch.h"
#include <Windows.h>
#include <atomic>
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

bool InstallSecurityUpdateEventLogInfoArabicHook(HMODULE hGame);
void RemoveSecurityUpdateEventLogInfoArabicHook();

bool InstallSecurityGetEventLogTypingTextArabicHook(HMODULE hGame);
void RemoveSecurityGetEventLogTypingTextArabicHook();

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

bool InstallTipsLayoutControllerSetPageTextHook(HMODULE hGame);
void RemoveTipsLayoutControllerSetPageTextHook();

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
namespace
{
    static std::atomic_bool gInitialized{ false };
    static std::atomic_bool gInitStarted{ false };
}

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

    if (!InstallTipsLayoutControllerSetPageTextHook(hGame))
        Log("[DLL] Failed to install InstallTipsLayoutControllerSetPageTextHook hook.\n");

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
    RemoveTipsLayoutControllerSetPageTextHook();
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

extern "C" __declspec(dllexport) void ShutdownHooks()
{
    if (!gInitialized.load())
        return;

    Log("[VRL] ShutdownHooks begin.\n");

    RemoveAll();
    MH_Uninitialize();

    gInitialized.store(false);
    Log("[VRL] ShutdownHooks done.\n");
    CloseLog();
}

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

        bool expected = false;
        if (!gInitStarted.compare_exchange_strong(expected, true))
            return TRUE;

        HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (hThread)
            CloseHandle(hThread);

        return TRUE;
    }

    case DLL_PROCESS_DETACH:
    {
        if (lpReserved == nullptr)
            ShutdownHooks();

        return TRUE;
    }
    }

    return TRUE;
}