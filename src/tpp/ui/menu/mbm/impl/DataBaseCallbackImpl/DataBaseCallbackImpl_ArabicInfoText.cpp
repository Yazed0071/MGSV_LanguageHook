#include "pch.h"
#include <Windows.h>
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
    constexpr size_t OFF_INFO_NODE_FROM_UPDATE = 0x6A8;
    constexpr uint32_t kInfoLeaseMs = 500;

    const uint8_t kUpdatePrologue[] = {
        0x40, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0xB6, 0x81, 0xF5, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xF1,
        0x83, 0xF8, 0x06,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    Update_t oUpdate = nullptr;
    void* gTarget = nullptr;

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

    void* ReadNode(const uint8_t* self, size_t offset)
    {
        __try
        {
            return *reinterpret_cast<void* const*>(self + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void __fastcall hkUpdate(uint8_t* self)
    {
        oUpdate(self);
        if (!self || !IsArabicSafe())
            return;
        if (void* node = ReadNode(self, OFF_INFO_NODE_FROM_UPDATE))
            KeepArabicLinesRightAlignedWhileShown(node, kInfoLeaseMs);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallDataBaseCallbackImplArabicInfoTextHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.DataBaseCallbackImpl_Update)
    {
        Log("[tpp::ui::menu::mbm::impl::DataBaseCallbackImpl] address missing - database descriptions keep the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = Resolve(hGame, gAddr.DataBaseCallbackImpl_Update);
    if (!CodeMatches(target, kUpdatePrologue, sizeof(kUpdatePrologue)))
    {
        Log("[tpp::ui::menu::mbm::impl::DataBaseCallbackImpl] Update prologue mismatch at %p - database descriptions keep the stock layout.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) != MH_OK)
    {
        Log("[tpp::ui::menu::mbm::impl::DataBaseCallbackImpl] MH_CreateHook failed - database descriptions keep the stock layout.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::mbm::impl::DataBaseCallbackImpl] MH_EnableHook failed - database descriptions keep the stock layout.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::mbm::impl::DataBaseCallbackImpl] Arabic database descriptions right-aligned per frame (hooked at %p).\n", target);
    return true;
}

void RemoveDataBaseCallbackImplArabicInfoTextHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    gIsArabLanguage = nullptr;
}
