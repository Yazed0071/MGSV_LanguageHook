#pragma once
#include <Windows.h>
#include <cstdint>

enum class GameBuild
{
    Unknown,
    English,
    Japanese
};

struct AddressSet
{
    uintptr_t IsArabLanguage = 0;
    uintptr_t GetFtexPathId = 0;
    uintptr_t GetGameLanguageState = 0;
    uintptr_t SetGameLanguageState = 0;
    uintptr_t GameConfigGetInstance = 0;
    uintptr_t FixKorCh_Fun145cc6360 = 0;
    uintptr_t SetSelectLangList = 0;
    uintptr_t UpdateLangList = 0;
    uintptr_t DecideLangList = 0;
    uintptr_t UpdateLangPopup = 0;
    uintptr_t ChangeLanguage = 0;
    uintptr_t ApplyFormVariation = 0;
    uintptr_t FoxStringCtor = 0;
    uintptr_t StdFree = 0;
    uintptr_t PathCInitWithString = 0;
    uintptr_t PathAssign = 0;
    uintptr_t PathDtor = 0;
    uintptr_t LoadPageBlock = 0;
    uintptr_t UnkLoadTppPartsLangFpk = 0;
    uintptr_t UnkLoadUIDefaultDataFunc = 0;
    uintptr_t GetUiUtility = 0;
    uintptr_t GetTipsLangBlockPath = 0;
    uintptr_t GetPauseHelpLangBlockPath = 0;
    uintptr_t ShowTextureLogo = 0;
    uintptr_t CommonDataManager_GetInstance = 0;
    uintptr_t CommonDataManager_SetDispLogo = 0;
    uintptr_t UiLangInit = 0;
    uintptr_t FileRegisterLoadFunc = 0;
    uintptr_t LangLoadFuncHandler = 0;
    uintptr_t SetLuaFunctions = 0;
    uintptr_t FoxLuaRegisterLibrary = 0;
    uintptr_t lua_tolstring = 0;
    uintptr_t lua_tointeger = 0;
    uintptr_t lua_pushnumber = 0;
    uintptr_t GetStringId = 0;
    uintptr_t LuaCheckGlueString = 0;
    uintptr_t LuaToGlueString = 0;
    uintptr_t lua_isstring = 0;
    uintptr_t lua_isnumber = 0;
    uintptr_t lua_tonumber = 0;




    uintptr_t SetDisplayText = 0;
    uintptr_t SetMainText = 0;
    uintptr_t CreateTextUnits = 0; 
    uintptr_t SetupListElementWalkerGear = 0;
    uintptr_t SetupMenuText = 0;
    uintptr_t SetMenuInfoText = 0;
    uintptr_t SetMissionInfoTexts = 0;
    uintptr_t SetCommandText = 0;
    uintptr_t SetPageText = 0;
    uintptr_t SetTextForModelNodeText = 0;
    uintptr_t TelopStartTitleEvCallUpdate = 0;
    uintptr_t SetTextMissionTelopNameEpisodeSnprintfCall = 0;
    uintptr_t CallLogView = 0;
    uintptr_t SetMarkerText = 0;
    uintptr_t GetTypingText = 0;
    uintptr_t SetMenuNameText = 0;
    uintptr_t GetLangText = 0;
    uintptr_t MbDvcMissionListRecordCallFuncStart = 0;
    uintptr_t MbDvcSideOpsRecordCallFuncViewRecord = 0;
    uintptr_t MissionPreparationCallbackImpl_SetupMissionName = 0;
    uintptr_t EquipDetailsCallbackImpl_CreateCarryingDifferenceText = 0;
    uintptr_t EquipDetailsCallbackImpl_CreateBulletDifferenceText = 0;
    uintptr_t TppUIInfoTypingTextImpl_SetTypingText = 0;
    uintptr_t LoadoutPanelInfo_RefreshLoadoutText = 0;
    uintptr_t ItemSelectorRecordCallFunc_UpdateRecords = 0;
    uintptr_t MbDvcSideOpsCallbackImpl_ShowCompleteRatio = 0;
    uintptr_t TppUICountAnnounceImpl_SetAnnounceText = 0;
    uintptr_t LoadingTipsEv_GetTitleText = 0;
    uintptr_t LoadingTipsEv_UpdateActPhase = 0;
    uintptr_t EquipCrossEvCall_SetCircleCursorFromSrickDir = 0;
    uintptr_t MbDvcMissionListCallbackImpl_ShowMissionInfoTextBox = 0;
    uintptr_t GameOverEvCall_UpdateSelectText = 0;
    uintptr_t PopupEvCall_SettingPopup = 0;
    uintptr_t SetEquipBackgroundTexture = 0;
    uintptr_t ModelNodeMesh_SetTextureName = 0;
    uintptr_t MbDvcSideOpsCallbackImpl_UpdateInformationTextBox = 0;

    uintptr_t ModelNodeText_ScrollDriver = 0;
    uintptr_t ModelNodeText_GetDisplayWidth = 0;
    uintptr_t SetAutoScrollTextForModelNodeText = 0;
    uintptr_t SetTextForModelNodeTextUseAutoScroll = 0;
    uintptr_t SettingTextUnitForScroll = 0;
    uintptr_t SetTrack = 0;
    uintptr_t CassetteListCtor = 0;
    uintptr_t CassetteListDtor = 0;
    uintptr_t MbDvcTapeListRecordText = 0;
    uintptr_t MbDvcTrackListRecordText = 0;
    uintptr_t CassetteUpdatePlayerPanel = 0;
    uintptr_t MissionTaskRowUpdate = 0;
    uintptr_t MissionTaskRowUpdate2 = 0;
    uintptr_t UpdateIconInfo = 0;
    uintptr_t TppUIInfoTypingText_UpdateText = 0;
    uintptr_t EquipDetailsSetupDetails = 0;
    uintptr_t GetUixUtilityToFeedQuarkEnvironment = 0;
};

extern GameBuild gGameBuild;
extern AddressSet gAddr;

bool ResolveAddressSet(HMODULE hGame);
const char* GetGameBuildName(GameBuild build);