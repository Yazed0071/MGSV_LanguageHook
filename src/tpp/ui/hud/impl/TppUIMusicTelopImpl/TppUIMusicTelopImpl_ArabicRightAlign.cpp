#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using Update_t = void(__fastcall*)(uint8_t* self);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_IMPL_FROM_UPDATE = 0x20;
    constexpr size_t OFF_STATE = 0x60;
    constexpr size_t OFF_TEXT_NODES[] = { 0x160, 0x168 };
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr uint32_t kTextLeaseMs = 500;

    const uint8_t kUpdatePrologue[] = {
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0x79, 0x10, 0x00, 0x48, 0x8B, 0xD9,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    Update_t oUpdate = nullptr;
    void* gTarget = nullptr;
    std::atomic<bool> gLogged{ false };

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

    uint8_t ReadState(const uint8_t* impl)
    {
        __try
        {
            return impl[OFF_STATE];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    uint8_t* ReadNode(const uint8_t* impl, size_t offset)
    {
        __try
        {
            return *reinterpret_cast<uint8_t* const*>(impl + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void LogFirstCredit(const uint8_t* node)
    {
        if (gLogged.exchange(true))
            return;
        unsigned line = 0xFF;
        unsigned block = 0xFF;
        __try
        {
            line = node[NODE_LINE_ALIGN];
            block = node[NODE_BLOCK_ALIGN];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] Arabic music credit node %p (authored line align %u, block align %u) - lines right-aligned while shown\n",
            node, line, block);
    }

    void __fastcall hkUpdate(uint8_t* self)
    {
        oUpdate(self);
        if (!self || !IsArabicSafe())
            return;

        const uint8_t* impl = self - OFF_IMPL_FROM_UPDATE;
        if (ReadState(impl) == 0)
            return;

        for (size_t offset : OFF_TEXT_NODES)
        {
            uint8_t* node = ReadNode(impl, offset);
            if (!node)
                continue;
            if (offset == OFF_TEXT_NODES[0])
                LogFirstCredit(node);
            KeepArabicLinesRightAlignedWhileShown(node, kTextLeaseMs);
        }
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallTppUIMusicTelopArabicRightAlignHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.TppUIMusicTelopImpl_Update)
    {
        Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] address missing - music credits keep the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = Resolve(hGame, gAddr.TppUIMusicTelopImpl_Update);
    if (!CodeMatches(target, kUpdatePrologue, sizeof(kUpdatePrologue)))
    {
        Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] Update prologue mismatch at %p - music credits keep the stock layout.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) != MH_OK)
    {
        Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] MH_CreateHook failed - music credits keep the stock layout.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] MH_EnableHook failed - music credits keep the stock layout.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::hud::impl::TppUIMusicTelopImpl] Arabic music credit right-align hooked at %p.\n", target);
    return true;
}

void RemoveTppUIMusicTelopArabicRightAlignHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
}
