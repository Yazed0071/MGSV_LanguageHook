#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

bool FoxPackExists(uint64_t fpkCode, bool withTextures);
bool AvatarEditCameraMirrorReady();
void SetAvatarEditCameraMirror(bool headLeft);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using BlockLoad_t = int32_t*(__fastcall*)(void* block, int32_t* err, const uint64_t* paths, uint32_t count);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint32_t MAX_STACK_PATHS = 64;
    constexpr uint32_t MAX_PATHS = 4096;

    const uint8_t kPrologue[] = { 0x48, 0x8B, 0xC4, 0x57, 0x41, 0x54, 0x41, 0x55,
                                  0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40 };

    struct PackRedirect
    {
        uint64_t vanilla;
        uint64_t rtl;
        const char* name;
    };

    const PackRedirect kRedirects[] = {
        { 0x522AAFAD99424718ull, 0x522A669AD20FC10Eull, "ui/ui_default_data2" },
        { 0x5229CB6C81444814ull, 0x522A47ED65DF6ACAull, "mbdvc/mb_dvc_top" },
        { 0x52280FC8C565A343ull, 0x5228AB7A5BCECCB4ull, "mbdvc/mb_child_window_staff" },
        { 0x52284163454BCEBAull, 0x522A72D246929A54ull, "mbdvc/mb_child_window_combat_deploy" },
        { 0x522AE4CC10FF95D8ull, 0x522B3D4E82E3C0D0ull, "mbdvc/mb_child_window_dev_wep" },
        { 0x522A6F57632A62B3ull, 0x5229A2ED0544AAD5ull, "mbdvc/mb_child_window_support_weapon" },
        { 0x52293D7D28A94280ull, 0x522892FB52393925ull, "mbdvc/mb_child_window_loadout" },
        { 0x522A01EDC9521141ull, 0x522A6D874E2F520Bull, "mbdvc/mb_child_window_mission_info" },
        { 0x522AF44C333F6AE3ull, 0x5229ECA3FD7727B8ull, "mbdvc/mb_child_window_log_viewer" },
        { 0x522BD6639673DB4Aull, 0x5228AA14A35C16C0ull, "mbdvc/mb_child_window_cassette" },
        { 0x5229C97691E3ACFAull, 0x52294F28D5D71530ull, "mbdvc/mb_child_window_fob_mission2" },
        { 0x522B1A08FF43291Eull, 0x5229182DED1F5DF0ull, "mbdvc/mb_child_window_resource" },
        { 0x522BD0DD6CCC70E4ull, 0x522934D404C10BF2ull, "mbdvc/mb_child_window_data_base" },
        { 0x5229E29420992BABull, 0x522970087A3D4593ull, "mbdvc/mb_child_window_base_list" },
        { 0x5229701C79D2F80Full, 0x5228DEF684EEE14Cull, "mbdvc/mb_child_window_security" },
        { 0x52280E80481D7865ull, 0x522925895B9517CFull, "mbdvc/mb_child_window_mission_list" },
        { 0x52281BD5BABB7EE0ull, 0x522A9474106F22AEull, "mbdvc/mb_child_window_mtbs_info" },
        { 0x522B56399B877F83ull, 0x522B5D790A799349ull, "mbdvc/mb_child_window_side_ops" },
        { 0x5229CF666BB3452Full, 0x5228D4583BA297BFull, "mbdvc/mb_child_window_pool_reward" },
        { 0x522A128A0EA0B34Full, 0x522A819E99E769D3ull, "mbdvc/mb_child_window_emblem" },
        { 0x522874638B2682BBull, 0x52293E9E6AB5DA10ull, "mbdvc/mb_child_window_pf_rating" },
        { 0x5229B2CC629F6BB6ull, 0x522A9F576F3CD0BAull, "mbdvc/mb_child_window_challenge" },
        { 0x522B0708B7517F09ull, 0x5229AA93AFFFDBBEull, "ui/result_data" },
        { 0x5228104FADBE4248ull, 0x52297EDD919FC80Aull, "ui/ui_bonus_popup" },
        { 0x522BB27C6E838D72ull, 0x522862FE454F4B56ull, "ui/ui_pause_playrecord" },
        { 0x5229837B89934A4Dull, 0x522949A76009A54Bull, "ui/ui_pause_ranking" },
        { 0x5229338C7F6E8A48ull, 0x5228433080355C57ull, "mission2/heli/heli_ui" },
        { 0x522ACE65206BBFE8ull, 0x522880C1C050FF28ull, "ui/gz/gz_pause_key_setting_data" },
        { 0x522BD7AFB39292B9ull, 0x522A94999BBA88D6ull, "ui/ui_respawn_menu" },
        { 0x52281DF879E89DCEull, 0x522833D4213A0B6Bull, "mission2/common/mis_com_avatar_edit" },
    };

    constexpr size_t REDIRECT_COUNT = sizeof(kRedirects) / sizeof(kRedirects[0]);
    constexpr uint64_t AVATAR_EDIT_PACK = 0x52281DF879E89DCEull;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    BlockLoad_t oBlockLoad = nullptr;
    void* gTarget = nullptr;
    std::atomic<uint8_t> gLogged[REDIRECT_COUNT] = {};
    std::atomic<bool> gLayoutPackSeen{ false };
    std::atomic<uint64_t> gLoadTick[REDIRECT_COUNT] = {};
    std::atomic<uint8_t> gLoadRightToLeft[REDIRECT_COUNT] = {};

    bool IsArabicSafe()
    {
        if (!gIsArabLanguage)
            return false;
        __try
        {
            return gIsArabLanguage();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool CodeMatches(const void* target, const uint8_t* expected, size_t size)
    {
        __try
        {
            return std::memcmp(target, expected, size) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadHead(const void* target, uint8_t* out, size_t size)
    {
        __try
        {
            std::memcpy(out, target, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    int FindRedirect(uint64_t code)
    {
        for (size_t i = 0; i < REDIRECT_COUNT; ++i)
        {
            if (kRedirects[i].vanilla == code)
                return static_cast<int>(i);
        }
        return -1;
    }

    bool ReadPath(const uint64_t* paths, uint32_t index, uint64_t& code)
    {
        __try
        {
            code = paths[index];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void NoteDecision(int index, bool redirected)
    {
        const uint8_t bit = redirected ? 1 : 2;
        if (gLogged[index].fetch_or(bit) & bit)
            return;
        if (redirected)
            Log("[fox::Block::Load] right-to-left pack: %s_rtl.fpk loaded instead of the vanilla pack.\n",
                kRedirects[index].name);
        else
            Log("[fox::Block::Load] %s_rtl.fpk/.fpkd/.pftxs not found - vanilla pack loaded.\n", kRedirects[index].name);
    }

    void NoteLoad(int index, bool rightToLeft)
    {
        gLoadRightToLeft[index].store(rightToLeft ? 1 : 0, std::memory_order_relaxed);
        gLoadTick[index].store(GetTickCount64(), std::memory_order_relaxed);
        gLayoutPackSeen.store(true, std::memory_order_release);
    }

    std::atomic<int> gTraceBudget{ 400 };
    std::atomic<bool> gLargeLoadLogged{ false };

    void TraceLoad(const uint64_t* paths, uint32_t count)
    {
        if (!paths || count == 0 || count > MAX_PATHS || gTraceBudget.load() <= 0)
            return;
        for (uint32_t i = 0; i < count && gTraceBudget.fetch_sub(1) > 0; ++i)
        {
            uint64_t code = 0;
            if (ReadPath(paths, i, code))
                LogDetail("[fox::Block::Load] load %u/%u 0x%016llX\n", i + 1, count, static_cast<unsigned long long>(code));
        }
    }

    int32_t* __fastcall hkBlockLoad(void* block, int32_t* err, const uint64_t* paths, uint32_t count)
    {
        TraceLoad(paths, count);
        if (!paths || count == 0 || count > MAX_PATHS)
            return oBlockLoad(block, err, paths, count);
        if (!IsArabicSafe())
        {
            for (uint32_t i = 0; i < count; ++i)
            {
                uint64_t code = 0;
                if (!ReadPath(paths, i, code))
                    break;
                const int index = FindRedirect(code);
                if (index < 0)
                    continue;
                NoteLoad(index, false);
                if (code == AVATAR_EDIT_PACK)
                    SetAvatarEditCameraMirror(false);
            }
            return oBlockLoad(block, err, paths, count);
        }

        uint64_t stackPaths[MAX_STACK_PATHS];
        std::vector<uint64_t> heapPaths;
        uint64_t* local = stackPaths;
        if (count > MAX_STACK_PATHS)
        {
            if (!gLargeLoadLogged.exchange(true))
                Log("[fox::Block::Load] block load with %u packs (more than %u) - redirect list copied to the heap.\n",
                    count, MAX_STACK_PATHS);
            heapPaths.resize(count);
            local = heapPaths.data();
        }
        bool changed = false;
        for (uint32_t i = 0; i < count; ++i)
        {
            if (!ReadPath(paths, i, local[i]))
                return oBlockLoad(block, err, paths, count);
            const int index = FindRedirect(local[i]);
            if (index < 0)
                continue;
            const bool avatarEdit = local[i] == AVATAR_EDIT_PACK;
            const bool ready = FoxPackExists(kRedirects[index].rtl, true) &&
                               (!avatarEdit || AvatarEditCameraMirrorReady());
            NoteDecision(index, ready);
            NoteLoad(index, ready);
            if (avatarEdit)
                SetAvatarEditCameraMirror(ready);
            if (ready)
            {
                local[i] = kRedirects[index].rtl;
                changed = true;
            }
        }
        return oBlockLoad(block, err, changed ? local : paths, count);
    }
}

bool RL_LayoutPackSeen()
{
    return gLayoutPackSeen.load(std::memory_order_acquire);
}

bool RL_LayoutPackLoad(uint64_t vanillaCode, uint64_t& tick, bool& rightToLeft)
{
    const int index = FindRedirect(vanillaCode);
    if (index < 0)
        return false;
    tick = gLoadTick[index].load(std::memory_order_relaxed);
    rightToLeft = gLoadRightToLeft[index].load(std::memory_order_relaxed) != 0;
    return tick != 0;
}

bool InstallArabicPackRedirectHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.BlockLoad)
    {
        Log("[fox::Block::Load] address missing - right-to-left packs are not redirected.\n");
        return false;
    }
    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (gAddr.BlockLoad - IDA_IMAGE_BASE));
    uint8_t head[8] = {};
    if (!ReadHead(target, head, sizeof(head)))
        return false;
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        const bool chained = head[0] == 0xE9 || (head[0] == 0xFF && head[1] == 0x25);
        Log("[fox::Block::Load] entry at %p starts %02X %02X %02X %02X %02X %02X %02X %02X - %s.\n", target, head[0],
            head[1], head[2], head[3], head[4], head[5], head[6], head[7],
            chained ? "another mod hooks it, chaining on top" : "unknown code, right-to-left packs are not redirected");
        if (!chained)
            return false;
    }
    const MH_STATUS initStatus = MH_Initialize();
    if (initStatus != MH_OK && initStatus != MH_ERROR_ALREADY_INITIALIZED)
        return false;
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkBlockLoad), reinterpret_cast<void**>(&oBlockLoad)) != MH_OK)
    {
        Log("[fox::Block::Load] MH_CreateHook failed.\n");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[fox::Block::Load] MH_EnableHook failed.\n");
        return false;
    }
    gTarget = target;
    Log("[fox::Block::Load] right-to-left pack redirect hooked at %p (%u UI packs, vanilla when the _rtl files are "
        "missing).\n",
        target, static_cast<unsigned>(REDIRECT_COUNT));
    return true;
}

void RemoveArabicPackRedirectHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oBlockLoad = nullptr;
    gIsArabLanguage = nullptr;
}
