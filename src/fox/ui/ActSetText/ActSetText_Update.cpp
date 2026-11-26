#include "pch.h"
#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using ActSetTextUpdate_t = void(__fastcall*)(uint8_t* act);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_ACT_NODE = 0x88;
    constexpr size_t OFF_ALIGN = 0xD8;
    constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
    constexpr size_t MAX_KEPT_NODES = 16;

    const uint8_t kActSetTextUpdatePrologue[] = {
        0x4C, 0x8B, 0xDC, 0x55, 0x53, 0x57, 0x49, 0x8D, 0x6B, 0xA1, 0x48, 0x81, 0xEC, 0xC0,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    ActSetTextUpdate_t oActSetTextUpdate = nullptr;
    void* gTarget = nullptr;

    std::array<std::atomic<void*>, MAX_KEPT_NODES> gKeptNodes{};
    std::atomic<size_t> gNextSlot{ 0 };
    std::atomic<bool> gAnyKept{ false };
    std::atomic<bool> gLoggedKeep{ false };

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

    bool IsKept(const void* node)
    {
        for (const auto& slot : gKeptNodes)
        {
            if (slot.load(std::memory_order_relaxed) == node)
                return true;
        }
        return false;
    }

    uint8_t* ReadActNode(const uint8_t* act)
    {
        __try
        {
            return *reinterpret_cast<uint8_t* const*>(act + OFF_ACT_NODE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void WriteRightAlign(uint8_t* node)
    {
        __try
        {
            node[OFF_ALIGN] = TEXT_ALIGN_RIGHT;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void __fastcall hkActSetTextUpdate(uint8_t* act)
    {
        oActSetTextUpdate(act);
        if (!gAnyKept.load(std::memory_order_relaxed) || !act)
            return;

        uint8_t* node = ReadActNode(act);
        if (!node || !IsKept(node) || !IsArabicSafe())
            return;

        WriteRightAlign(node);
        if (!gLoggedKeep.exchange(true))
            Log("[fox::ui::ActSetText::Update] kept Arabic right-aligned lines after a text update\n");
    }
}

void KeepArabicLinesRightAligned(void* node)
{
    if (!node || IsKept(node))
        return;

    const size_t slot = gNextSlot.fetch_add(1) % MAX_KEPT_NODES;
    gKeptNodes[slot].store(node);
    gAnyKept.store(true);
}

bool InstallActSetTextUpdateArabicAlignHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.ActSetText_Update)
    {
        Log("[fox::ui::ActSetText::Update] address missing - text updates keep the authored alignment.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(hGame) + (gAddr.ActSetText_Update - IDA_IMAGE_BASE));

    if (!CodeMatches(target, kActSetTextUpdatePrologue, sizeof(kActSetTextUpdatePrologue)))
    {
        Log("[fox::ui::ActSetText::Update] code is not what this build should have - not hooked.\n");
        return true;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkActSetTextUpdate),
                      reinterpret_cast<void**>(&oActSetTextUpdate)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[fox::ui::ActSetText::Update] hook failed.\n");
        return false;
    }

    gTarget = target;
    Log("[fox::ui::ActSetText::Update] Arabic right-aligned nodes kept after text updates.\n");
    return true;
}

void RemoveActSetTextUpdateArabicAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    for (auto& slot : gKeptNodes)
        slot.store(nullptr);
    gAnyKept.store(false);
    oActSetTextUpdate = nullptr;
    gIsArabLanguage = nullptr;
}
