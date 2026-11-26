#include "AddressSet.h"
#include "log.h"

#include <string>
#include <fstream>
#include <algorithm>
#include <cstring>

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
    0x1416B2CD0ull, // LoadoutSelectorRecord_Refresh (arsenal row renderer; name node +0x48, text array +0x68)
    0x1416BC080ull, // MissionPreparationCallbackImpl_RefreshLoadoutText (deploy screen twin of LoadoutPanelInfo)
    0x1408B56F0ull, // EquipCrossEvCall_Update (per-frame; re-runs box text so align must be reapplied)
    0x14160B7F0ull, // TppUIPickUpPanel_UpdateAmmoBoxInfo (ammo-box prompt; text buffer this+0x62 size 0x64, node *(this+0x1D0))
    0x141619AC0ull, // TppUISideFobInfo_Update (quest-area banner; text nodes *(this+0x40,0x48,0x50,0x58))
    0x140914DA0ull, // GetUTF8TextFromBack (dst, size, src, n): copies the last n UTF-8 chars; RTL typewriter reveal
    0x1408AA253ull, // TelopStartTitleFromBackRetA (TelopStartTitleEvCall::Update passes counter-1)
    0x1408AA3A0ull, // TelopStartTitleFromBackRetB (TelopStartTitleEvCall::Update passes counter-1)
    0x140224820ull, // FontDataLoad (fox::gr::dg::FontData::LoadFontData: ffnt -> GLYP header +8, records +0x18, FTDT +0x20, atlas +0x28)
    0x142B93BB8ull, // FontSystemInstance (fox::gr::dg::FontSystem::m_instance; fonts at +8 + id*8)
    0x1402255E0ull, // GlyphCacheRasterize (cache, pitch, height, mapped, request): 1-bit atlas glyph -> 3x3-blurred A8 cache cell
    0x140223C30ull, // GlyphMetrics (fox::gr::dg::FontSystem::CalculateMetrics: out[9], glyph, halfTexelU, halfTexelV, scale)
    0x141DC5190ull, // TextUnitSetting (fox::ui::TextUnit::Setting: stores the text POINTER in the unit, no copy)
    0x141DC3D11ull, // RubyForceInline (inside CreateTextUnits: TEST BL,BL / MOV ECX,1 / CMOVNZ forces inline ruby unless jpn/kor/cht)
    0x141DB72E0ull, // StoreTextData (fox::ui::ModelNodeText::StoreTextData: per-unit layout; ruby lift = gap + base entry height)
    0x141DB7190ull, // SetupRubyFontGroupInfo (JMP stub; node+0xB0 ruby font group, else half the base size)
    0x1408C90A0ull, // EpilogueController_SetupAsset (ending epigraph text node at this+0x228; non-jpn sets +0xD8=0 left, +0xDA=1)
    0x1408CA510ull, // EpilogueController_Update (vtable +0x10 at 0x1422537F8, polled every frame with the time; text commands go through CreateBoxText into this+0x228)
    0x1412DA8F0ull, // RadioButtonGuideImpl_InitRadioButtonGuide (tutorial/control guide bar: box text into info+0x50, infos at this+0x28 stride 0x78)
    0x1412DA580ull, // RadioButtonGuideImpl_ActRadioButtonGuide (per frame; info +0x6C shown, +0x6D closing)
    0x141DB72B0ull, // ModelNodeText_StopTextScroll (+0x1B4 = 0, +0x92 = 0, flags &~4 |0x10)
    0x141DB3580ull, // ModelNodeText_DisableStencilArea (flags &~2)
    0x141DE9F60ull, // ActSetText_Update (fox::ui::ActSetText::Update: node at this+0x88; rewrites +0xD8/+0xD9/+0xDA from the act's props unless node+0x91 bit0)
    0x141DBE5C0ull, // ModelNode_SetTranslateX (thunk; node, float x; TelopStartTitleEvCall::Update state 0xC places the location lines with it)
    0x141DB7A10ull, // ModelNodeText_Draw (vtable draw; rebuilds glyph quads only while node+0x90 bit 0x10 is set, reading +0xD8/+0xDA then)
    0x14089A430ull, // LoadingTipsEv_Update (virtual, per frame; calls UpdateActPhase, which V_FrameWork.dll also hooks and bypasses ours)
    0x140F8D820ull, // StaffControllerImpl_GetStaffFullNameByIndex (vtable +0xD8; snprintf(*buf, size, "%s %s"); list/deploy callers pass size 0x36)
    0x140F8D920ull, // StaffControllerImpl_GetStaffFullNameBySeed (vtable +0xD0; same format)
    0x141DC5240ull, // TextAnalysis_SettingTextUnit (all direct text sets: measures width and counts chars from the text it is given)
    0x1416E32B0ull, // MainListRecordCallFunc_RefreshName (Staff Management list row: name via GetStaffFullName(seed), 0x36, into record+0x90, node record+0x88)
    0x1416DE290ull, // StaffListCallbackImpl_SetSectionInfoText (assign-unit description: box text of record+0x40 into node this+0x5D48, 8 units)
    0x1416DF140ull, // StaffListCallbackImpl_RefreshStaffDetails (details panel: full name 0x40 into this+0x618A, name node above the portrait this+0x68D8)
    0x141635920ull, // BaseFacilities_RefreshDescription (platform description box text; node fetched by hash 0x43EC68E337DA -> 0xE65790C5E5AD, never stored)
    0x1416D0990ull, // ResourceManagement_RefreshDescription (resources screen: description of the selected resource, box text into node this+0x8F0, 8 units)
    0x140EF1C60ull, // AnnouncePopupBodyStart (MbDvcAnnouncePopupBodyCallFunc::Start, per frame: title node this+0x40, body box text this+0x48; this+0x50 is a background, never write it)
    0x14238B9C0ull, // AnnouncePopupBodyStartVtSlot (vtable slot +0x78 holding Start; V_FrameWork.dll inline-hooks Start and drops other inline hooks, so ours swaps this pointer)
    0x140898510ull, // PopupEvCall_UpdatePopup (event/notice popup, per frame; case 2 rebuilds the body box text on this+0x168 every frame)
    0x1405102D0ull, // UixSetTextForModelNodeTextImpl (uix +0x708 body: node, unit, text; used to catch the event popup title node during UpdatePopup)
    0x140512A20ull, // UixPrefabTextCallFunc (uix prefab single-text callfunc: node this+0x38, mode this+0x44 [1 = plain, >=2 = box text with that many units], text this+0x48; OK/Cancel confirmation popup body)
    0x140EF9360ull, // MbDvcTrackListRecordStart (MbDvcTrackListRecordCallFunc::Start, calls the row text FUN_140EF6960 directly; V_FrameWork inline-hooks that row text)
    0x14238C0D8ull, // MbDvcTrackListRecordStartVtSlot (vtable slot holding Start)
    0x1404B4430ull, // SubtitlesBlockControllerDataBody_Setup (create controller, load packageFileNames only if it was created)
    0x1404B3D00ull, // SubtitlesBlockControllerDataBody_Activate (load request to whatever controller exists)
    0x1404B3EB0ull, // SubtitlesBlockControllerDataBody_Deactivate (unload + delete controller)
    0x1404B4470ull, // SubtitlesBlockControllerDataBody_Update (same as Setup)
    0x1404B3C50ull, // SubtitlesBlockControllerDataBody_Destructor (scalar deleting; unload + delete controller)
    0x1404D1910ull, // SubtitlesManager_CreateSubtitlesBlockController (-1 when manager+0x128 already holds one)
    0x1404D0B20ull, // SubtitlesManager_ControlSubtitlesBlockLoading (per frame; deletes the controller on load failure or after unload)
    0x1404B4200ull, // SubtitlesBlockControllerDataBody_SendRequestToLoad (reads packageFileNames, asks the manager to load them)
    0x1404DAFF0ull, // SubtitlesBinaryCollector_Constructor (CreateMemArray 1 x10 0x400, 2 x2 0x20CC, tag 0x120008)
    0x1404DB800ull, // SubtitlesBinaryCollector_CreateMemArray (thunk: collector, type, size, count, tag)
    0x142BACD78ull, // SubtitlesBinaryCollector_Instance (set at the start of the constructor)
    0x1404DB18Eull, // SubtitlesStreamLineAllocSize (imm32 of mov r8d,0x20CC in the constructor)
    0x1404DC3F6ull, // SubtitlesStreamLineReadSize (imm32 of mov r12d,0x20CC in ReadSubbData: bytes read per streamed line)
    0x1421798D8ull, // SubtitlesStreamLineLimit (double 8396.8, read only by ReadSubbData: larger lines are refused)
    0x140015F60ull, // FoxAllocAnnotated (size, tag)
    0x140015F90ull, // FoxFreeAnnotated (ptr, tag)
    0x141607D00ull, // TppUIMusicTelopImpl_Update (music credit card; impl = this-0x20, state impl+0x60, box text into impl+0x160 and twin impl+0x168 via UpdateMusicTelop 0x141607EE0 or the formatted variant 0x141607DA0)
    0x14087F2D0ull, // MbTitleEv_Update (iDroid title bar per frame; menu help box text node this+0x13E8 (debug MbTitleEv::Update 0x140805B10, help node +0x1220))
    0x1419713D0ull, // DataBaseCallbackImpl_Update (database screen per frame (this = impl+0x20); description node impl+0x6C8 = this+0x6A8; V_FrameWork hooks RefreshInfoLayout 0x14196EF60 itself)
    0x1405107C0ull, // UixUtility_RefreshRecordTextScroll (uix vt+0x720 (vtable 0x142184F90): record-scroll select(uix, record, selected, index); overflow -> stencil, D8=0, start scroll if selected else stop; fits -> stencil off, origin align, stop)
    0x142435FD0ull, // CombatDeployMissionListRecord_Vtable (combat deploy mission row record vtable; slot 1 0x14164B7B0 tail-jumps to the row refresh 0x141643740 (V_FrameWork hooks that refresh); title node record+0x60 via uix vt+0x718)
    0x14238C8F0ull, // ChallengeTaskListRecord_Vtable (challenge task row record vtable (retail-only); refresh 0x140F01470, title node record+0x1F8 via uix vt+0x748)
    0x141646D60ull, // CombatDeployCallbackImpl_RefreshMissionTextBox (combat deploy mission description "%s\n( %s )", 12-unit box text into this+0x2F0 (debug 0x14150C5B0, node +0x260))
    0x142390FD8ull, // MbDvcMissionListRecord_Vtable (iDroid mission list row record; slot 1 = MbDvcMissionListRecordCallFuncStart 0x140F33800; title node record+0xF8 via uix vt+0x718, index 0)
    0x1408A6980ull, // WorldMarkerLayout_LengthTextOn (world marker distance "%d%s" with const_metre into layout+0xF0, node layout+0xD8, distance cached at +0x14; debug 0x14082A9F0)
    0x1408A6A80ull, // WorldMarkerLayout_LengthTextOnWithID (same distance text plus the marker id letter in layout+0xFF / node +0xE8; debug 0x14082AAF0)
    0x140F33310ull, // MbDvcMissionListCallbackImpl_ShowSkillView (mission list "obtainable skills/blueprints": 4 slots of 0x20 at this+0x1268 {group, -, name +0x10 via uix vt+0x710, icon +0x18}; debug 0x140E58B60 slots +0xE68)
    0x140963A30ull, // MbDvcMissionInfoCallback_ShowSkillLayout (same panel in the in-mission mission info, slots this+0xA30; debug 0x1408D8D30)
    0x140F3D610ull, // MbDvcPauseHelpCallbackImpl_SetupTutorialPopup (iDroid tutorial popup mbtutorial_*: title this+0x3E8 via uix vt+0x710, body box text this+0x3F0 (vt+0x738, 12 units), close guide this+0x410; debug 0x140E62380)
    0x140F3B370ull, // MbDvcPauseHelpCallbackImpl_RefreshHelpPage (iDroid help callouts, 10 entries: title box text this+0x190+i*8 at (X-640)*0.1, body this+0x1E0+i*8 at (X-620)*0.1, frame this+0x2D0+i*8 sized to max(titleW, bodyW+20)+padding, pointer lines +0x3C0; unnamed FUN in retail; debug 0x140E60150)
    0x14093CCD0ull, // UiUtilityImpl_SetPadButtonPrompt (UiUtility vt+0x988 thunk -> FUN_140883de0(prompt, button, units, text, maxUnits): prompt +0x8 pad icon mesh, +0x10 box text node, +0x18 show anim, +0x20 hide anim; only callers = the title-screen legal/privacy prompt 0x1A202A0E0AB2 in TitleMenuImpl/CyprusTitle/FUN_1412d6a10; added after the debug build)
    0x140BF3520ull, // StringSystemImpl_snprintf (fox::impl::StringSystemImpl::snprintf(this, buf, size, fmt, ...), QuarkSystemTable+0x20 vt+0x18; ~80 announce/UI sites format into 0x80 stack buffers with size 0x7F)
    0x140023440ull, // FoxVsnprintf (fox::vsnprintf(buf, size, fmt, va); negative when the text did not fit)
    0x140863C60ull, // CommonDataManager_AnnounceLogView (tpp::ui::hud::CommonDataManager::AnnounceLogView(this, text, ...); copies text into a fox::String for AnnounceLog::RegistLog)
    0x141DC1AE0ull, // Model_Draw (fox::ui::Model draw: model+0x74 bit0 enabled, root +0x80, nodes +0x98 count +0x90, drawables +0xB8 count +0xB0; node +0x10 parent, +0x20 translation, +0x40 scale, +0x6C name hash, +0x72 type, +0x8 bit0 visible)
    0x141DB6A50ull, // ModelNodeText_SetTextUnits (fox::ui::ModelNodeText::SetTextUnits(node, units, count, ...); keeps the CALLER's unit array at node+0x138, count +0x140)
    0x14006E040ull, // BlockLoad (fox::Block::Load(Block*, ErrorCode*, const PathId* paths, uint count) - every pack load ends here; PathId = PathCode64, fpkd/pftxs derived from the same code)
    0x14003C770ull, // FsLocatePath (fox::fs::FileLocationManager::LocatePath(const fs::Path*, uint) - true when the loader can open the PathCode64 from the mounted archives; debug twin 0x14003CFA0)
    0x141DF62E0ull, // FontCreateText (fox::ui::Font::CreateText(font, text, w, h, space, xy[4*n], uv[4*n], float* penX, float* maxH): one quad per code point, x += w/emW * (cellW-padL-padR) + space; every .fnt measure/draw path)
    0x140C0E830ull, // ActiveSonarImpl_UpdateDistanceText (tpp::ui::hud::impl::ActiveSonarImpl: per contact (count byte +0x981, entries +0x88 stride 0x90) "%d%s" distance (+0x68 float) + lang unit_metre into a 6-byte buffer +0x6C, set on node +0x20 via uix vt+0x708 with text unit this+0x38)
    0x140871BE0ull, // MbCommonPopupAct_Update (tpp::ui::menu::MbCommonPopupAct::Update, iDroid common popup opened by CommonPopupUtility::OpenPopup: SET_MESSAGE_TEXT(_PTR) -> CreateBoxText(this+0x1F0 message node, units this+0x1F8, 16); same offsets in the debug build, 6 units there)
    0x141618430ull, // TppUIResultImpl_UpdateMissionRadioCommand (tpp::ui::hud::impl::TppUIResultImpl::UpdateMissionRadioCommand, radio character file card: exe-only labels "FILE NUMBER"/"CAT."/"STS." printed "%s" into card+0x79/+0xBA/+0xD8 and set via uix vt+0x708 on card+0x40/+0x50/+0x60; values on +0x48/+0x58/+0x68, status codes MPA..MPK/SPL/SPM/SPN at 0x142430448)
    0x140C0ACA0ull, // MenuTitleCallbackImpl_SetMenuNameText (tpp::ui::menu::impl::MenuTitleCallbackImpl::SetMenuNameText, called every frame from Update: path "a > b > c" in this+0xA2, segment char marks this+0x68 (u16 x5), typed text this+0x1A2 -> uix vt+0x708 on node this+0x330 with unit this+0x78; Sortie Prep / avatar / emblem title bar; debug same offsets)
    0x140C0AA80ull, // MenuTitleCallbackImpl_GetTypingText (named in retail; reveal count this+0x2B8, typing flag this+0x2BC, copies the first N chars + "_")
    0x14050F9D0ull, // UixSetTextAlign (fox::uix::impl::UixUtilityImpl::SetTextAlign(uix, node, align): node+0xD8 = align; only reached through the uix vtable)
    0x142185408ull, // UixSetTextAlignVtSlot (uix vtable slot holding SetTextAlign; V_FrameWork's Lua SetTextAlign also calls through it)
    0x140023400ull, // FoxSnprintf (fox::snprintf(buf, size, fmt, ...) = RapidVsnprintf + terminate; TipsLayoutController::SetPageText formats the title into this+0x6A with size 100)
    0x140F3D180ull, // MbDvcPauseHelpCallbackImpl_RefreshHeaderText (FUN_140F3D180: help title this+0xF8 (uix vt+0x708), body box text this+0x168 (vt+0x738, 8 units), dark panel this+0x180 placed at the cached body position this+0x188/+0x18C and sized via vt+0x5D0 vertex controls to the body text width/height)
    0x141A10BE0ull, // LuaCodeBegin (f_Ccall, first Lua 5.1 function)
    0x141A3BD20ull, // LuaCodeEnd (after lcode.c patchlistaux helpers)
    0x1416D0F70ull, // MbDvcResourceRecord_LayoutAmountColumn (FUN_1416D0F70: column visibility + owned amount this+0xF8 x = 34.2 / 44.6 via uix vt+0x350)
    0x14093CFD0ull, // GradeMark_SetGrade (FUN_14093CFD0(self, node, grade u8, style u8, alt u8): grade 1-11 cell of mark_equip_tag_alp 0x156952C3B25E9BFC, 12-15 mark_equip_tag_2_alp 0x156858BF33913C2F, UV via uix vt+0x5A0, ends with uix vt+0x518 SetTexture(node, hash, Base_Texture 0xCAFB3BBF9889))
    0x1407E5130ull, // NetUtil_GetLangString (tpp::net::util::GetLangString: GameConfig vt+0x188 -> 0x142A3D700 {en,fr,es,pt,it,de,ar,ru,ja,ct,ko}; login lang + Accept-Language)
    0x1407E4820ull, // GateServer_RequestGetInformationList (CMD_GET_INFORMATIONLIST2 builder (self, serverLang edx, region r8d); Online News UiOnlineNewsControllerImpl::RequestServer 0x14096EAF0 via NetworkSystem vt+0xB80)
    0x140807A20ull, // RequestGetCampaignDialogList (CMD_GET_CAMPAIGN_DIALOG_LIST builder (self, kind u8, serverLang r8d, region r9d); caller 0x1409338E0 via vt+0x7D0)
    0x140EF8870ull, // MbDvcCassetteTape_SetupPanel (FUN_140EF8870(this+0x20): panel button types this+0x538 = {0 rewind,1 play,2 stop,3 fast-forward,4,5,6}, slot icons this+0x500; DecidePanelButton/hold-seek/key help all read the type by slot)
    0x141E0B2F0ull, // NetworkSystem_GetServerText (NetworkSystemImpl vt+0x898 (self, keyHash32, lang) -> FUN_1407D8150 on the server text store 0x142BEFC28)
    0x14050F8F0ull, // UiUtility_SetMaskOffset (uix vt+0x5B0 (self, node, x, y): mesh shader params 0x2FC9FA66/0x1B6BF7D5 = screen mask offset; size is vt+0x5C8 0xC5A5EE70/0xA8903ABD)
    0x140F17000ull, // MbDvcMapCodeBegin (map controller code that applies the per-mode mask table [settings+0x1FB8+mode*16] on mode change)
    0x140F2B000ull, // MbDvcMapCodeEnd
    0x14050FEE0ull, // UixUtility_SetTranslateX (uix vt+0x350 (self, node, x); 5-byte jmp thunk into .xtext)
    0x1419956B6ull, // SecurityDetailIconRow_ValueXReturn (return address of the icon-row refresh's vt+0x350 call that puts value node 021A32E0 (record +0xB8) at literal x 34.2)
    0x141DFA330ull, // GraphResourceLayout_SetupFromRawFile (fox::ui::GraphResourceLayout::SetupResourceFromRawFile(this, BlockPackage*, SharedPtr<Layout>*, Array<RawFile*>*): builds a Layout from a .uilb; this+0x30 RawFile (status +0x40 == 2, data +0x60), this+0x58 Layout)
    0x141DAB6E0ull, // GraphManager_GetGraphFile (File* (BlockPackage* or null, PathCode64): the loaded file for a path; null package = global registry)
    0x140276B70ull, // Material_BindParameter (fox::gr::Material::BindParameter(material, nameHash32, const Vector4*): mesh node material +0xA8, params +0xC8, name table +0xD0)
    0x1423CFAB0ull, // AvatarEdit_CameraOffset (16-byte constant (-0.13, 0.03, 0, 0) read once by SpecialEventActionImpl::StateAvatarEdit at 0x14128747E: camera target offset in the head locator's frame; x decides the screen side of the head)
    0x1415E3620ull, // TppUIBinoSubjective_UpdateMic (per-frame directional-mic meter: bar meshes this+0x5E8/+0x5F0 fill shader param (0, f), peak mark this+0x5F8 x = this+0x9A0 + 2.7)
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
    0x1416B2CA0ull, // LoadoutSelectorRecord_Refresh (listing match 50/60, EN-0x30)
    0x1416BC060ull, // MissionPreparationCallbackImpl_RefreshLoadoutText (listing match 51/60, EN-0x20)
    0x1408B5620ull, // EquipCrossEvCall_Update (listing match 56/60, EN-0xd0)
    0x14160B7D0ull, // TppUIPickUpPanel_UpdateAmmoBoxInfo (listing match 58/60, EN-0x20)
    0x141619AB0ull, // TppUISideFobInfo_Update (listing match 56/60, EN-0x10)
    0x140914C80ull, // GetUTF8TextFromBack (listing match 56/60, EN-0x120)
    0x1408AA183ull, // TelopStartTitleFromBackRetA (listing match 50/60, EN-0xd0)
    0x1408AA2D0ull, // TelopStartTitleFromBackRetB (listing match 50/60, EN-0xd0)
    0x140224D90ull, // FontDataLoad (listing match 55/60, EN+0x570)
    0x142B93BB8ull, // FontSystemInstance (same data VA as EN; JP font code loads DAT_142B93BB8)
    0x140225B50ull, // GlyphCacheRasterize (listing match 54/60, EN+0x570)
    0x1402241B0ull, // GlyphMetrics (listing match 55/60, EN+0x580)
    0x141DC51F0ull, // TextUnitSetting (listing match 42/60, EN+0x60)
    0x141DC3D71ull, // RubyForceInline (listing match 36/60, EN+0x60)
    0x141DB7350ull, // StoreTextData (listing match 44/60, EN+0x70)
    0x141DB7200ull, // SetupRubyFontGroupInfo (listing match 46/60, EN+0x70)
    0x1408C8FD0ull, // EpilogueController_SetupAsset (listing match 56/60, EN-0xd0)
    0x1408CA440ull, // EpilogueController_Update (listing match 54/60, EN-0xd0)
    0x1412DA910ull, // RadioButtonGuideImpl_InitRadioButtonGuide (listing match 52/60, EN+0x20)
    0x1412DA5A0ull, // RadioButtonGuideImpl_ActRadioButtonGuide (listing match 55/60, EN+0x20)
    0x141DB7320ull, // ModelNodeText_StopTextScroll (listing match 44/60, EN+0x70)
    0x141DB35F0ull, // ModelNodeText_DisableStencilArea (listing match 38/60, EN+0x70)
    0x141DE9F60ull, // ActSetText_Update (listing match 48/60, EN+0x0)
    0x141DBE620ull, // ModelNode_SetTranslateX (JMP thunk into obfuscated code at EN+0x60, same as EN)
    0x141DB7A80ull, // ModelNodeText_Draw (listing match 45/60, EN+0x70)
    0x14089A350ull, // LoadingTipsEv_Update (listing match 53/60, EN-0xe0)
    0x140F8D880ull, // StaffControllerImpl_GetStaffFullNameByIndex (listing match 47/60, EN+0x60)
    0x140F8D980ull, // StaffControllerImpl_GetStaffFullNameBySeed (listing match 48/60, EN+0x60)
    0x141DC52A0ull, // TextAnalysis_SettingTextUnit (listing match 49/60, EN+0x60)
    0x1416E3290ull, // MainListRecordCallFunc_RefreshName (listing match 43/60, EN-0x20)
    0x1416DE270ull, // StaffListCallbackImpl_SetSectionInfoText (listing match 48/60, EN-0x20)
    0x1416DF120ull, // StaffListCallbackImpl_RefreshStaffDetails (listing match 54/60, EN-0x20)
    0x141635900ull, // BaseFacilities_RefreshDescription (listing match 40/60, EN-0x20)
    0x1416D0970ull, // ResourceManagement_RefreshDescription (listing match 55/60, EN-0x20)
    0x140EF1C90ull, // AnnouncePopupBodyStart (listing match 54/60, EN+0x30)
    0x14238BCD0ull, // AnnouncePopupBodyStartVtSlot (JP vtable slot pointing to JP AnnouncePopupBodyStart 0x140EF1C90 (EN+0x310))
    0x140898430ull, // PopupEvCall_UpdatePopup (listing match 57/60, EN-0xe0)
    0x140510720ull, // UixSetTextForModelNodeTextImpl (listing match 42/60, EN+0x450)
    0x140512E40ull, // UixPrefabTextCallFunc (listing match 55/60, EN+0x420)
    0x140EF9390ull, // MbDvcTrackListRecordStart (listing match 56/60, EN+0x30)
    0x14238C3E8ull, // MbDvcTrackListRecordStartVtSlot (JP vtable slot pointing to JP MbDvcTrackListRecordStart 0x140EF9390 (EN+0x310))
    0x1404B4B00ull, // SubtitlesBlockControllerDataBody_Setup (listing match 58/60, EN+0x6d0)
    0x1404B43D0ull, // SubtitlesBlockControllerDataBody_Activate (listing match 52/60, EN+0x6d0)
    0x1404B4580ull, // SubtitlesBlockControllerDataBody_Deactivate (listing match 58/60, EN+0x6d0)
    0x1404B4B40ull, // SubtitlesBlockControllerDataBody_Update (listing match 56/60, EN+0x6d0)
    0x1404B4320ull, // SubtitlesBlockControllerDataBody_Destructor (listing match 52/60, EN+0x6d0)
    0x1404D1D20ull, // SubtitlesManager_CreateSubtitlesBlockController (listing match 50/60, EN+0x410)
    0x1404D0F30ull, // SubtitlesManager_ControlSubtitlesBlockLoading (listing match 50/60, EN+0x410)
    0x1404B48D0ull, // SubtitlesBlockControllerDataBody_SendRequestToLoad (listing match 51/60, EN+0x6d0)
    0x1404DB430ull, // SubtitlesBinaryCollector_Constructor (listing match 52/60, EN+0x440)
    0x1404DBC40ull, // SubtitlesBinaryCollector_CreateMemArray (listing match 48/60, EN+0x440)
    0x142BACD78ull, // SubtitlesBinaryCollector_Instance (JP code ref qword ptr [.xpdata:DAT_142bacd78],RDI)
    0x1404DB5CEull, // SubtitlesStreamLineAllocSize (imm32 of mov r8d,0x20CC in the JP constructor 0x1404DB430 (+2))
    0x1404DC836ull, // SubtitlesStreamLineReadSize (imm32 of mov r12d,0x20CC in ReadSubbData (+2))
    0x142179888ull, // SubtitlesStreamLineLimit (JP code ref XMM0,qword ptr [.xtext:DAT_142179888])
    0x140015F70ull, // FoxAllocAnnotated (listing match 54/60, EN+0x10)
    0x140015FA0ull, // FoxFreeAnnotated (listing match 53/60, EN+0x10)
    0x141607CE0ull, // TppUIMusicTelopImpl_Update (listing match 59/60, EN-0x20)
    0x14087F220ull, // MbTitleEv_Update (listing match 55/60, EN-0xb0)
    0x141971320ull, // DataBaseCallbackImpl_Update (listing match 51/60, EN-0xb0)
    0x140510C10ull, // UixUtility_RefreshRecordTextScroll (listing match 51/60, EN+0x450)
    0x1424362D0ull, // CombatDeployMissionListRecord_Vtable (JP code ref RAX,[.xtext:PTR_FUN_1424362d0])
    0x14238CC00ull, // ChallengeTaskListRecord_Vtable (JP code ref RAX,[.xtext:PTR_FUN_14238cc00])
    0x141646D40ull, // CombatDeployCallbackImpl_RefreshMissionTextBox (listing match 54/60, EN-0x20)
    0x1423912E8ull, // MbDvcMissionListRecord_Vtable (JP code ref RAX,[.xtext:PTR_FUN_1423912e8])
    0x1408A68B0ull, // WorldMarkerLayout_LengthTextOn (listing match 49/60, EN-0xd0)
    0x1408A69B0ull, // WorldMarkerLayout_LengthTextOnWithID (listing match 54/60, EN-0xd0)
    0x140F33350ull, // MbDvcMissionListCallbackImpl_ShowSkillView (listing match 52/60, EN+0x40)
    0x140963970ull, // MbDvcMissionInfoCallback_ShowSkillLayout (listing match 49/60, EN-0xc0)
    0x140F3D650ull, // MbDvcPauseHelpCallbackImpl_SetupTutorialPopup (listing match 54/60, EN+0x40)
    0x140F3B3B0ull, // MbDvcPauseHelpCallbackImpl_RefreshHelpPage (listing match 47/60, EN+0x40)
    0x14093CBB0ull, // UiUtilityImpl_SetPadButtonPrompt (listing match 50/60, EN-0x120)
    0x140BF34D0ull, // StringSystemImpl_snprintf (listing match 58/60, EN-0x50)
    0x140023460ull, // FoxVsnprintf (listing match 55/60, EN+0x20)
    0x140863D00ull, // CommonDataManager_AnnounceLogView (listing match 57/60, EN+0xa0)
    0x141DC1B40ull, // Model_Draw (listing match 57/60, EN+0x60)
    0x141DB6AC0ull, // ModelNodeText_SetTextUnits (listing match 47/60, EN+0x70)
    0x14006E0B0ull, // BlockLoad (listing match 54/60, EN+0x70)
    0x14003C7D0ull, // FsLocatePath (listing match 40/60, EN+0x60)
    0x141DF62B0ull, // FontCreateText (listing match 38/60, EN-0x30)
    0x140C0E7B0ull, // ActiveSonarImpl_UpdateDistanceText (listing match 39/60, EN-0x80)
    0x140871B30ull, // MbCommonPopupAct_Update (prologue + CreateBoxText(this+0x1F0, this+0x1F8, 0x10) at +0x244 identical, EN-0xb0)
    0x141618420ull, // TppUIResultImpl_UpdateMissionRadioCommand (prologue identical, "FILE NUMBER" LEA at 0x141618D53, EN-0x10)
    0x140C0AC30ull, // MenuTitleCallbackImpl_SetMenuNameText (prologue identical, calls GetTypingText at 0x140C0ADE8, EN-0x70)
    0x140C0AA10ull, // MenuTitleCallbackImpl_GetTypingText (prologue + CMP [RCX+0x2BC],0 identical, EN-0x70)
    0x14050FE20ull, // UixSetTextAlign (same 12-byte body)
    0x1421853B8ull, // UixSetTextAlignVtSlot (JP uix vtable slot pointing to JP SetTextAlign)
    0x140023420ull, // FoxSnprintf (body identical to EN 0x140023400, EN+0x20; RapidVsnprintf call EN 0x1400222C0 -> JP 0x1400222E0)
    0x140F3D1C0ull, // MbDvcPauseHelpCallbackImpl_RefreshHeaderText (EN+0x40 like its RefreshHelpPage/SetupTutorialPopup neighbours; listing: same prologue, CMP [RDI+0x42E], [RAX+0x630], uix +0x750)
    0x141A10B00ull, // LuaCodeBegin (EN range widened: JP lua_* sit EN-0xB0..-0xC0)
    0x141A3BD20ull, // LuaCodeEnd
    0x1416D0F50ull, // MbDvcResourceRecord_LayoutAmountColumn (listing match 24/24, EN-0x20)
    0x14093CEB0ull, // GradeMark_SetGrade (listing match 24/24, EN-0x120)
    0x1407E5220ull, // NetUtil_GetLangString (listing match 20/20, EN+0xF0; same check bytes, language table 0x142A3D700)
    0x1407E4920ull, // GateServer_RequestGetInformationList (listing match 24/24, EN+0x100; same check bytes)
    0x140807AF0ull, // RequestGetCampaignDialogList (listing match 24/24, EN+0xD0; same check bytes)
    0x140EF88A0ull, // MbDvcCassetteTape_SetupPanel (listing match 24/24, EN+0x30)
    0x141E0B2D0ull, // NetworkSystem_GetServerText (listing match 18/18, EN-0x20; store 0x142BEFC28, calls JP 0x1407D8220)
    0x14050FD40ull, // UiUtility_SetMaskOffset (EN+0x450; the one of three look-alikes with params 0x2FC9FA66 / 0x1B6BF7D5)
    0x140F17000ull, // MbDvcMapCodeBegin (JP map mask calls sit at 0x140F17E03..0x140F2AF1A, EN+0x30..+0x40)
    0x140F2B000ull, // MbDvcMapCodeEnd (next caller outside the map code is far above)
    0x140510330ull, // UixUtility_SetTranslateX (EN+0x450; E9 thunk right after the same epilogue)
    0x141995606ull, // SecurityDetailIconRow_ValueXReturn (EN-0xB0; after call [rax+0x350] with literal 34.2 at JP 0x1424A3A50)
    0x141DFA310ull, // GraphResourceLayout_SetupFromRawFile (listing match 26/26, EN-0x20; calls JP GetGraphFile three times)
    0x141DAB5C0ull, // GraphManager_GetGraphFile (listing match 19/19, EN-0x120; registry lookup FUN_1400cd5a0)
    0x140277120ull, // Material_BindParameter (listing match 44/44, EN+0x5B0; called by the mesh parameter binder at JP 0x141DC5D70)
    0x1423CFCE0ull, // AvatarEdit_CameraOffset (EN+0x230; same 16 bytes, read by the same code at JP 0x1412874AE)
    0x1415E3630ull, // TppUIBinoSubjective_UpdateMic (EN+0x10; 24/24 mnemonics match)
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

        Log("[AddressSet] version_info.txt names a %s patch other than '%s' - the game code decides.\n",
            isEnglish ? "English" : "Japanese", expected.c_str());
        return GameBuild::Unknown;
    }

    return isEnglish ? GameBuild::English : GameBuild::Japanese;
}

static bool ReadGameBytes(HMODULE hGame, uintptr_t va, uint8_t* out, size_t size)
{
    if (!hGame || va < 0x140000000ull)
        return false;
    const uint32_t imageSize = GetModuleSizeOfImage(hGame);
    const uintptr_t rva = va - 0x140000000ull;
    if (rva + size > imageSize)
        return false;
    __try
    {
        memcpy(out, reinterpret_cast<const uint8_t*>(hGame) + rva, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool CodeFingerprintMatches(HMODULE hGame, const AddressSet& table)
{
    uint8_t lang[16] = {};
    uint8_t camera[16] = {};
    if (!ReadGameBytes(hGame, table.IsArabLanguage, lang, sizeof(lang)) ||
        !ReadGameBytes(hGame, table.AvatarEdit_CameraOffset, camera, sizeof(camera)))
        return false;
    static const uint8_t kLangHead[] = { 0x48, 0x83, 0xEC, 0x28, 0xE8 };
    static const uint8_t kLangMid[] = { 0x48, 0x8B, 0xC8, 0xE8 };
    static const uint8_t kCamera[] = { 0xB8, 0x1E, 0x05, 0x00, 0x8F, 0xC2, 0xF5, 0x3C,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (memcmp(lang, kLangHead, sizeof(kLangHead)) != 0 || memcmp(lang + 9, kLangMid, sizeof(kLangMid)) != 0)
        return false;
    for (size_t i = 0; i < sizeof(kCamera); ++i)
    {
        if (i == 3)
        {
            if (camera[i] != 0xBE && camera[i] != 0x3E)
                return false;
        }
        else if (camera[i] != kCamera[i])
        {
            return false;
        }
    }
    return true;
}

static GameBuild DetectGameBuild(HMODULE hGame)
{
    const GameBuild labelled = DetectGameBuildFromVersionInfo(hGame);
    const bool english = CodeFingerprintMatches(hGame, kEnglish);
    const bool japanese = CodeFingerprintMatches(hGame, kJapanese);
    Log("[AddressSet] code check: English 1.0.15.4 %s, Japanese day3900 %s.\n", english ? "matches" : "no",
        japanese ? "matches" : "no");
    if (english == japanese)
    {
        Log("[AddressSet] the game code is not a version this mod knows - no hooks.\n");
        return GameBuild::Unknown;
    }
    const GameBuild build = english ? GameBuild::English : GameBuild::Japanese;
    if (labelled != build)
        Log("[AddressSet] version_info.txt does not name this build, but the game code matches the %s build - "
            "using it.\n", english ? "English" : "Japanese");
    return build;
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

    gGameBuild = DetectGameBuild(hGame);

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
