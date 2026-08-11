#include "AddressSet.h"
#include "log.h"

#include <string>
#include <fstream>
#include <algorithm>

GameBuild gGameBuild = GameBuild::Unknown;
AddressSet gAddr{};

static const AddressSet kEnglish = {
    0x140915700ull, // IsArabLanguage
    0x1408D0F60ull, // GetFtexPathId
    0x14094E6F0ull, // GetGameLanguageState
    0x14094F410ull, // SetGameLanguageState
    0x140530200ull, // GameConfigGetInstance
    0x140896390ull, // FixKorCh_Fun140896390 (15.4 EN: KeySettingEvCall::StartSub)
    0x141604C50ull, // SetSelectLangList
    0x1416050D0ull, // UpdateLangList
    0x141604740ull, // DecideLangList
    0x141604BF0ull, // UpdateLangPopup
    0x1408CE490ull, // ChangeLanguage
    0x1404E1AF0ull, // ApplyFormVariation
    0x140016490ull, // FoxStringCtor
    0x1400041C0ull, // StdFree
    0x1400858D0ull, // PathCInitWithString
    0x1400857A0ull, // PathAssign
    0x140085760ull, // PathDtor
    0x140929760ull, // LoadPageBlock
    0x14095D4E0ull, // UnkLoadTppPartsLangFpk
    0x140929690ull, // UnkLoadUIDefaultDataFunc
    0x14093A480ull, // GetUiUtility
    0x14094E940ull, // GetTipsLangBlockPath
    0x1408E8A60ull, // GetPauseHelpLangBlockPath
    0x1408E0900ull, // ShowTextureLogo
    0x140866910ull, // CommonDataManager_GetInstance
    0x140867F50ull, // CommonDataManager_SetDispLogo
    0x0ull,         // UiLangInit
    0x0ull,         // FileRegisterLoadFunc
    0x0ull,         // LangLoadFuncHandler
    0x14065CC80ull, // SetLuaFunctions
    0x14006B8C0ull, // FoxLuaRegisterLibrary
    0x141A12150ull, // lua_tolstring
    0x141A12120ull, // lua_tointeger
    0x141A11950ull, // lua_pushnumber
    0x1409140E0ull, // GetStringId
    0x1400F16A0ull, // LuaCheckGlueString
    0x1400F1B20ull, // LuaToGlueString
    0x141A11440ull, // lua_isstring
    0x141A11410ull, // lua_isnumber
    0x141A121F0ull, // lua_tonumber






    //ARABIC
    0x1408BF9B0ull, // SetDisplayText
    0x14087B700ull, // SetMainText
    0x141DC3AA0ull, // CreateTextUnits
    0x1416510F0ull, // SetupListElementWalkerGear
    0x140885320ull, // SetupMenuText
    0x140884E00ull, // SetMenuInfoText
    0x140962180ull, // SetMissionInfoTexts
    0x14179B340ull, // SetCommandText
    0x140884EB0ull, // SetPageText
    0x140917B10ull, // SetTextForModelNodeText
    0x1408A9500ull, // TelopStartTitleEvCallUpdate
    0x1408A9219ull, // SetTextMissionTelopNameEpisodeSnprintfCall
    0x14093EF80ull, // CallLogView
    0x1408B9410ull, // SetMarkerText
    0x14087DAD0ull, // GetTypingText
    0x14087E2F0ull, // SetMenuNameText
    0x140912C10ull, // GetLangText
    0x140F33800ull, // MbDvcMissionListRecordCallFuncStart
    0x140F40D70ull, // MbDvcSideOpsRecordCallFuncViewRecord
    0x1416C00D0ull, // MissionPreparationCallbackImpl_SetupMissionName
    0x141660270ull, // EquipDetailsCallbackImpl_CreateCarryingDifferenceText
    0x141660130ull, // EquipDetailsCallbackImpl_CreateBulletDifferenceText
    0x1416033C0ull, // TppUIInfoTypingTextImpl_SetTypingText
    0x1416D64D0ull, // LoadoutPanelInfo_RefreshLoadoutText
    0x1416AE280ull, // ItemSelectorRecordCallFunc_UpdateRecords
    0x140F3FDC0ull, // MbDvcSideOpsCallbackImpl_ShowCompleteRatio
    0x1415EC880ull, // TppUICountAnnounceImpl_SetAnnounceText
    0x140899A30ull, // LoadingTipsEv_GetTitleText
    0x14089A700ull, // LoadingTipsEv_UpdateActPhase
    0x1408B1CF0ull, // EquipCrossEvCall_SetCircleCursorFromSrickDir
    0x140F33160ull, // MbDvcMissionListCallbackImpl_ShowMissionInfoTextBox
    0x1408886E0ull, // GameOverEvCall_UpdateSelectText
    0x140898100ull, // PopupEvCall_SettingPopup
    0x140918030ull, // SetEquipBackgroundTexture
    0x141DC7CE0ull, // ModelNodeMesh_SetTextureName
    0x140F404A0ull, // MbDvcSideOpsCallbackImpl_UpdateInformationTextBox
    0x141DB7E10ull, // ModelNodeText_ScrollDriver
    0x141DB36A0ull, // ModelNodeText_GetDisplayWidth
    0x1409175D0ull, // SetAutoScrollTextForModelNodeText
    0x140917C30ull, // SetTextForModelNodeTextUseAutoScroll
    0x14091B6D0ull, // SettingTextUnitForScroll
    0x14087E7A0ull, // SetTrack
    0x0ull,         // CassetteListCtor
    0x0ull,         // CassetteListDtor
    0x140EF67D0ull, // MbDvcTapeListRecordText
    0x140EF6960ull, // MbDvcTrackListRecordText
    0x140EFB0A0ull, // CassetteUpdatePlayerPanel
    0x140F33DB0ull, // MissionTaskRowUpdate (MbDvcMissionTaskListRecordCallFunc::Start)
    0x140964030ull, // MissionTaskRowUpdate2 (mission-prep task list, hidden-task variant)
    0x140F0B1A0ull, // UpdateIconInfo (map icon-info / LZ callout box)
    0x1416041A0ull, // TppUIInfoTypingText_UpdateText (per-line typing reveal)
    0x141667AE0ull, // EquipDetailsSetupDetails (weapon detail/develop panel)
    0x14050B580ull, // GetUixUtilityToFeedQuarkEnvironment (Quark node prop/pos setter host)
};

static const AddressSet kJapanese = {
    0x1409155E0ull, // IsArabLanguage
    0x1408D0E90ull, // GetFtexPathId
    0x14094E620ull, // GetGameLanguageState
    0x14094F340ull, // SetGameLanguageState
    0x140530610ull, // GameConfigGetInstance
    0x1408962C0ull, // FixKorCh_Fun140896390 (15.4 EN: KeySettingEvCall::StartSub)
    0x141604C50ull, // SetSelectLangList
    0x1416050D0ull, // UpdateLangList
    0x141604740ull, // DecideLangList
    0x141604BF0ull, // UpdateLangPopup
    0x1408CE3C0ull, // ChangeLanguage
    0x1404E1F50ull, // ApplyFormVariation
    0x1400164A0ull, // FoxStringCtor
    0x1400041C0ull, // StdFree
    0x140085930ull, // PathCInitWithString
    0x140085800ull, // PathAssign
    0x1400857C0ull, // PathDtor
    0x140929660ull, // LoadPageBlock
    0x14095D410ull, // UnkLoadTppPartsLangFpk
    0x140929590ull, // UnkLoadUIDefaultDataFunc
    0x14093A360ull, // GetUiUtility
    0x14094E870ull, // GetTipsLangBlockPath
    0x1408E8950ull, // GetPauseHelpLangBlockPath
    0x1408E0830ull, // ShowTextureLogo
    0x1408669B0ull, // CommonDataManager_GetInstance
    0x140868000ull, // CommonDataManager_SetDispLogo
    0x0ull,         // UiLangInit
    0x0ull,         // FileRegisterLoadFunc
    0x0ull,         // LangLoadFuncHandler
    0x14065CCB0ull, // SetLuaFunctions
    0x14006B920ull, // FoxLuaRegisterLibrary
    0x141A120A0ull, // lua_tolstring
    0x141A12070ull, // lua_tointeger
    0x141A11890ull, // lua_pushnumber
    0x140913FC0ull, // GetStringId
    0x1400F1B80ull, // LuaCheckGlueString
    0x1400F2000ull, // LuaToGlueString
    0x141A11380ull, // lua_isstring
    0x141A11350ull, // lua_isnumber
    0x141A12140ull, // lua_tonumber






    //ARABIC
    0x1408BF8F0ull, // SetDisplayText
    0x14087B650ull, // SetMainText
    0x141DC3B00ull, // CreateTextUnits
    0x1416510D0ull, // SetupListElementWalkerGear
    0x140885270ull, // SetupMenuText
    0x140884D50ull, // SetMenuInfoText
    0x1409620C0ull, // SetMissionInfoTexts
    0x14179B230ull, // SetCommandText
    0x140884E00ull, // SetPageText
    0x1409179F0ull, // SetTextForModelNodeText
    0x1408A9430ull, // TelopStartTitleEvCallUpdate
    0x1408A9149ull, // SetTextMissionTelopNameEpisodeSnprintfCall
    0x14093EE60ull, // CallLogView
    0x1408B9340ull, // SetMarkerText
    0x14087DA20ull, // GetTypingText
    0x14087E240ull, // SetMenuNameText
    0x140912AF0ull, // GetLangText
    0x140F33840ull, // MbDvcMissionListRecordCallFuncStart
    0x140F40DB0ull, // MbDvcSideOpsRecordCallFuncViewRecord
    0x1416C00B0ull, // MissionPreparationCallbackImpl_SetupMissionName
    0x141660240ull, // EquipDetailsCallbackImpl_CreateCarryingDifferenceText
    0x141660100ull, // EquipDetailsCallbackImpl_CreateBulletDifferenceText
    0x1416033C0ull, // TppUIInfoTypingTextImpl_SetTypingText
    0x1416D64B0ull, // LoadoutPanelInfo_RefreshLoadoutText
    0x1416AE250ull, // ItemSelectorRecordCallFunc_UpdateRecords
    0x140F3FE00ull, // MbDvcSideOpsCallbackImpl_ShowCompleteRatio
    0x1415EC890ull, // TppUICountAnnounceImpl_SetAnnounceText
    0x140899950ull, // LoadingTipsEv_GetTitleText
    0x14089A620ull, // LoadingTipsEv_UpdateActPhase
    0x1408B1C20ull, // EquipCrossEvCall_SetCircleCursorFromSrickDir
    0x140F331A0ull, // MbDvcMissionListCallbackImpl_ShowMissionInfoTextBox
    0x140888630ull, // GameOverEvCall_UpdateSelectText
    0x140898030ull, // PopupEvCall_SettingPopup
    0x140917F10ull, // SetEquipBackgroundTexture
    0x141DC7D40ull, // ModelNodeMesh_SetTextureName
    0x140F404E0ull, // MbDvcSideOpsCallbackImpl_UpdateInformationTextBox
    0x141DB7E80ull, // ModelNodeText_ScrollDriver
    0x141DB3710ull, // ModelNodeText_GetDisplayWidth
    0x1409174B0ull, // SetAutoScrollTextForModelNodeText
    0x140917B10ull, // SetTextForModelNodeTextUseAutoScroll
    0x14091B5B0ull, // SettingTextUnitForScroll
    0x14087E6F0ull, // SetTrack
    0x0ull,         // CassetteListCtor
    0x0ull,         // CassetteListDtor
    0x140EF6800ull, // MbDvcTapeListRecordText
    0x140EF6990ull, // MbDvcTrackListRecordText
    0x140EFB0D0ull, // CassetteUpdatePlayerPanel
    0x140F33DF0ull, // MissionTaskRowUpdate (MbDvcMissionTaskListRecordCallFunc::Start)
    0x140963F70ull, // MissionTaskRowUpdate2 (mission-prep task list, hidden-task variant)
    0x140F0B1D0ull, // UpdateIconInfo (map icon-info / LZ callout box)
    0x1416041A0ull, // TppUIInfoTypingText_UpdateText (per-line typing reveal)
    0x141667AB0ull, // EquipDetailsSetupDetails (weapon detail/develop panel)
    0x14050B9D0ull, // GetUixUtilityToFeedQuarkEnvironment (Quark node prop/pos setter host)
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

static constexpr const char* kVerifiedEnglishTokens[] = { "day3800", "day3900" };
static constexpr const char* kVerifiedJapaneseTokens[] = { "day3900" };

template <size_t N>
static bool TextMatchesAnyToken(const std::string& text, const char* const (&tokens)[N])
{
    for (size_t i = 0; i < N; ++i)
    {
        if (text.find(tokens[i]) != std::string::npos)
            return true;
    }
    return false;
}

template <size_t N>
static std::string JoinTokens(const char* const (&tokens)[N])
{
    std::string joined;
    for (size_t i = 0; i < N; ++i)
    {
        if (i != 0)
            joined += " / ";
        joined += tokens[i];
    }
    return joined;
}

static uint32_t GetModuleSizeOfImage(HMODULE hModule)
{
    if (!hModule)
        return 0;

    const auto* base = reinterpret_cast<const uint8_t*>(hModule);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return nt->OptionalHeader.SizeOfImage;
}

static GameBuild DetectGameBuildFromVersionInfo(HMODULE hGame)
{
    HMODULE module = hGame ? hGame : GetModuleHandleW(nullptr);

    const std::wstring dir = GetModuleDirectory(module);
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

    const uint32_t sizeOfImage = GetModuleSizeOfImage(module);

    Log("[AddressSet] version_info.txt = %s\n", text.c_str());
    Log("[AddressSet] SizeOfImage = 0x%X\n", sizeOfImage);

    const bool isEnglish = text.find("mst_en") != std::string::npos;
    const bool isJapanese = text.find("mst_jp") != std::string::npos;

    if (!isEnglish && !isJapanese)
    {
        Log("[AddressSet] version_info.txt carries no mst_en / mst_jp marker.\n");
        return GameBuild::Unknown;
    }

    const bool tokenMatches = isEnglish
        ? TextMatchesAnyToken(text, kVerifiedEnglishTokens)
        : TextMatchesAnyToken(text, kVerifiedJapaneseTokens);

    if (!tokenMatches)
    {
        const std::string expected = isEnglish
            ? JoinTokens(kVerifiedEnglishTokens)
            : JoinTokens(kVerifiedJapaneseTokens);

        Log("[AddressSet] UNSUPPORTED game build: the %s address table was resolved for '%s' "
            "and this executable is a different patch. Refusing to install any hooks, because "
            "the stored addresses would point at unrelated code in this build.\n",
            isEnglish ? "English" : "Japanese", expected.c_str());
        return GameBuild::Unknown;
    }

    return isEnglish ? GameBuild::English : GameBuild::Japanese;
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
