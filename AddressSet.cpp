#include "AddressSet.h"
#include "log.h"

#include <string>
#include <fstream>
#include <algorithm>

GameBuild gGameBuild = GameBuild::Unknown;
AddressSet gAddr{};

static const AddressSet kEnglish = {
    0x145F134E0ull, // IsArabLanguage
    0x1408D05F0ull, // GetFtexPathId
    0x146084A80ull, // GetGameLanguageState
    0x14094E950ull, // SetGameLanguageState
    0x14052F9C0ull, // GameConfigGetInstance
    0x145CC6360ull, // FixKorCh_Fun145cc6360
    0x14A4140D0ull, // SetSelectLangList
    0x141606250ull, // UpdateLangList
    0x14A412670ull, // DecideLangList
    0x141606490ull, // UpdateLangPopup
    0x14090F130ull, // ChangeLanguage
    0x1404E1E60ull, // ApplyFormVariation
    0x1400163F0ull, // FoxStringCtor
    0x140004200ull, // StdFree
    0x140085780ull, // PathCInitWithString
    0x140085650ull, // PathAssign
    0x140085610ull, // PathDtor
    0x140928D10ull, // LoadPageBlock
    0x14095CA10ull, // UnkLoadTppPartsLangFpk
    0x145F86420ull, // UnkLoadUIDefaultDataFunc
    0x140939A20ull, // GetUiUtility
    0x146089BD0ull, // GetTipsLangBlockPath
    0x145DDE150ull, // GetPauseHelpLangBlockPath
    0x1408DFFB0ull, // ShowTextureLogo
    0x140865D00ull, // CommonDataManager_GetInstance
    0x140867330ull, // CommonDataManager_SetDispLogo
    0x14D750C70ull, // UiLangInit
    0x1400CEF90ull, // FileRegisterLoadFunc
    0x141DF67B0ull, // LangLoadFuncHandler
    0x1408D78A0ull, // SetLuaFunctions
    0x14006B6D0ull, // FoxLuaRegisterLibrary
    0x141A123C0ull, // lua_tolstring
    0x141A12390ull, // lua_tointeger
    0x141A11BC0ull, // lua_pushnumber
    0x1409137A0ull, // GetStringId
    0x1400F1D50ull, // LuaCheckGlueString
    0x1400F21D0ull, // LuaToGlueString
    0x141A116B0ull, // lua_isstring
    0x141A11680ull, // lua_isnumber
    0x141A12460ull, // lua_tonumber






    //ARABIC
    0x1408BF270ull, // SetDisplayText
    0x14087ABD0ull, // SetMainText
    0x141DC36B0ull, // CreateTextUnits
    0x14A4C14F0ull, // SetupListElementWalkerGear
    0x140884AE0ull, // SetupMenuText
    0x145CB1770ull, // SetMenuInfoText
    0x1460FD9C0ull, // SetMissionInfoTexts
    0x14A902820ull, // SetCommandText
    0x140884670ull, // SetPageText 
    0x1409171D0ull, // SetTextForModelNodeText
    0x1408A8DC0ull, // TelopStartTitleEvCallUpdate
    0x145D05D19ull, // SetTextMissionTelopNameEpisodeSnprintfCall
    0x14093E510ull, // CallLogView
    0x1408B8CE0ull, // SetMarkerText
    0x145C5DBE0ull, // GetTypingText
    0x145C5FCD0ull, // SetMenuNameText
    0x1409122D0ull, // GetLangText
    0x140F33E20ull, // MbDvcMissionListRecordCallFuncStart
    0x1419A47B0ull, // SecurityUpdateEventLogInfo
    0x1419914F0ull, // SecurityGetEventLogTypingText
    0x149476B10ull, // MbDvcSideOpsRecordCallFuncViewRecord
    0x1416C1080ull, // MissionPreparationCallbackImpl_SetupMissionName
    0x14A4D94F0ull, // EquipDetailsCallbackImpl_CreateCarryingDifferenceText
    0x14A4D8E70ull, // EquipDetailsCallbackImpl_CreateBulletDifferenceText
    0x141604540ull, // TppUIInfoTypingTextImpl_SetTypingText
    0x14A5A9D90ull, // LoadoutPanelInfo_RefreshLoadoutText
    0x1416AF270ull, // ItemSelectorRecordCallFunc_UpdateRecords
    0x149473B60ull, // MbDvcSideOpsCallbackImpl_ShowCompleteRatio
    0x14A3EAE70ull, // TppUICountAnnounceImpl_SetAnnounceText
    0x145CCDC10ull, // LoadingTipsEv_GetTitleText
    0x145CCFCC0ull, // LoadingTipsEv_UpdateActPhase
    0x1408B14C0ull, // EquipCrossEvCall_SetCircleCursorFromSrickDir
    0x140F33780ull, // MbDvcMissionListCallbackImpl_ShowMissionInfoTextBox
    0x145CB9470ull, // GameOverEvCall_UpdateSelectText
    0x1408979C0ull, // PopupEvCall_SettingPopup
    0x145F236F0ull, // SetEquipBackgroundTexture
    0x141DC78F0ull, // ModelNodeMesh_SetTextureName
    0x149475810ull, // MbDvcSideOpsCallbackImpl_UpdateInformationTextBox
    
};

static const AddressSet kJapanese = {
    0x0ull, // IsArabLanguage
    0x0ull, // GetFtexPathId
    0x0ull, // GetGameLanguageState
    0x0ull, // SetGameLanguageState
    0x0ull, // GameConfigGetInstance
    0x0ull, // FixKorCh_Fun145cc6360
    0x0ull, // SetSelectLangList
    0x0ull, // UpdateLangList
    0x0ull, // DecideLangList
    0x0ull, // UpdateLangPopup
    0x0ull, // ChangeLanguage
    0x0ull, // ApplyFormVariation
    0x0ull, // FoxStringCtor
    0x0ull, // StdFree
    0x0ull, // PathCInitWithString
    0x0ull, // PathAssign
    0x0ull, // PathDtor
    0x0ull, // LoadPageBlock
    0x0ull, // UnkLoadTppPartsLangFpk
    0x0ull, // UnkLoadUIDefaultDataFunc
    0x0ull, // GetUiUtility
    0x0ull, // GetTipsLangBlockPath
    0x0ull, // GetPauseHelpLangBlockPath
    0x0ull, // ShowTextureLogo
    0x0ull, // CommonDataManager_GetInstance
    0x0ull, // CommonDataManager_SetDispLogo
    0x0ull, // UiLangInit
    0x0ull, // FileRegisterLoadFunc
    0x0ull, // LangLoadFuncHandler
    0x0ull, // SetLuaFunctions
    0x0ull, // FoxLuaRegisterLibrary
    0x0ull, // lua_tolstring
    0x0ull, // lua_tointeger
    0x0ull, // lua_pushnumber
    0x0ull, // GetStringId
    0x0ull, // LuaCheckGlueString
    0x0ull, // LuaToGlueString
    0x0ull, // lua_isstring
    0x0ull, // lua_isnumber
    0x0ull, // lua_tonumber
    0x0ull, // CreateTextUnits
    




    //ARABIC
    0x0ull, // SetDisplayText
    0x0ull, // SetMainText
    0x0ull, // SetupListElementWalkerGear
    0x0ull, // SetupMenuText
    0x0ull, // SetMenuInfoText
    0x0ull, // SetMissionInfoTexts
    0x0ull, // SetCommandText
    0x0ull, // SetPageText 
    0x0ull, // SetTextForModelNodeText   
    0x0ull, // TelopStartTitleEvCallUpdate
    0x0ull, // SetTextMissionTelopNameEpisodeSnprintfCall
    0x0ull, // CallLogView
    0x0ull, // SetMarkerText
    0x0ull, // GetTypingText
    0x0ull, // SetMenuNameText
    0x0ull, // GetLangText
    0x0ull, // MbDvcMissionListRecordCallFuncStart
    0x0ull, // SecurityUpdateEventLogInfo
    0x0ull, // SecurityGetEventLogTypingText
    0x0ull, // MbDvcSideOpsRecordCallFuncViewRecord
    0x0ull, // MissionPreparationCallbackImpl_SetupMissionName
    0x0ull, // EquipDetailsCallbackImpl_CreateCarryingDifferenceText
    0x0ull, // EquipDetailsCallbackImpl_CreateBulletDifferenceText
    0x0ull, // TppUIInfoTypingTextImpl_SetTypingText
    0x0ull, // LoadoutPanelInfo_RefreshLoadoutText
    0x0ull, // ItemSelectorRecordCallFunc_UpdateRecords
    0x0ull, // MbDvcSideOpsCallbackImpl_ShowCompleteRatio
    0x0ull, // TppUICountAnnounceImpl_SetAnnounceText
    0x0ull, // LoadingTipsEv_GetTitleText
    0x0ull, // LoadingTipsEv_UpdateActPhase
    0x0ull, // EquipCrossEvCall_SetCircleCursorFromSrickDir
    0x0ull, // MbDvcMissionListCallbackImpl_ShowMissionInfoTextBox
    0x0ull, // GameOverEvCall_UpdateSelectText
    0x0ull, // PopupEvCall_SettingPopup
    0x0ull, // SetEquipBackgroundTexture
    0x0ull, // ModelNodeMesh_SetTextureName
    0x0ull, // MbDvcSideOpsCallbackImpl_UpdateInformationTextBox
};

static std::wstring GetModuleDirectory(HMODULE hModule)
{
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(hModule, path, MAX_PATH))
        return L"";

    std::wstring fullPath(path);
    const size_t slash = fullPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return L"";

    return fullPath.substr(0, slash);
}

static std::string ReadWholeFileUtf8OrAnsi(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    std::string content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    return content;
}

static std::string ToLowerAscii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static GameBuild DetectGameBuildFromVersionInfo(HMODULE hGame)
{
    const std::wstring dir = GetModuleDirectory(hGame ? hGame : GetModuleHandleW(nullptr));
    if (dir.empty())
        return GameBuild::Unknown;

    const std::wstring versionInfoPath = dir + L"\\version_info.txt";
    std::string text = ReadWholeFileUtf8OrAnsi(versionInfoPath);
    if (text.empty())
    {
        Log("[AddressSet] Failed to read version_info.txt\n");
        return GameBuild::Unknown;
    }

    text = ToLowerAscii(text);

    Log("[AddressSet] version_info.txt = %s\n", text.c_str());

    if (text.find("mst_en") != std::string::npos)
        return GameBuild::English;

    else if (text.find("mst_jp") != std::string::npos)
        return GameBuild::Japanese;
    else
        return GameBuild::English;

    return GameBuild::Unknown;
}

const char* GetGameBuildName(GameBuild build)
{
    switch (build)
    {
    case GameBuild::English:  return "English";
    case GameBuild::Japanese: return "Japanese";
    default:                  return "Unknown";
    }
}

bool ResolveAddressSet(HMODULE hGame)
{
    if (!hGame)
        return false;

    gGameBuild = DetectGameBuildFromVersionInfo(hGame);

    switch (gGameBuild)
    {
    case GameBuild::English:
        gAddr = kEnglish;
        Log("[AddressSet] Selected English address set.\n");
        return true;

    case GameBuild::Japanese:
        gAddr = kJapanese;
        Log("[AddressSet] Selected Japanese address set.\n");
        return true;

    default:
        gAddr = {};
        Log("[AddressSet] Failed to detect supported game build.\n");
        return false;
    }
}