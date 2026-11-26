#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using LayoutAmountColumn_t = void(__fastcall*)(uint8_t* self, void* data, uint8_t resource);
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t RECORD_OWNER = 0x30;
    constexpr size_t OWNER_UIX = 0x08;
    constexpr size_t RECORD_NAME_NODE = 0xE0;
    constexpr size_t RECORD_AMOUNT_NODE = 0xF8;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr float MIRRORED_NAME_MIN_X = 20.0f;
    constexpr float MIRROR_SUM = 59.8f;

    const uint8_t kPrologue[] = {
        0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10, 0x49, 0x89, 0x73, 0x18, 0x57,
        0x48, 0x83, 0xEC, 0x50, 0x48, 0x8B, 0x81, 0x10, 0x01, 0x00, 0x00,
    };

    LayoutAmountColumn_t gOriginal = nullptr;
    void* gTarget = nullptr;
    std::atomic<bool> gLogged{ false };

    bool CodeMatches(const void* target)
    {
        __try
        {
            return std::memcmp(target, kPrologue, sizeof(kPrologue)) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadRecord(const uint8_t* self, void*& uix, uint8_t*& amount, float& nameX, float& amountX)
    {
        __try
        {
            const uint8_t* owner = *reinterpret_cast<uint8_t* const*>(self + RECORD_OWNER);
            if (!owner)
                return false;
            uix = *reinterpret_cast<void* const*>(owner + OWNER_UIX);
            const uint8_t* name = *reinterpret_cast<uint8_t* const*>(self + RECORD_NAME_NODE);
            amount = *reinterpret_cast<uint8_t* const*>(self + RECORD_AMOUNT_NODE);
            if (!uix || !name || !amount)
                return false;
            nameX = *reinterpret_cast<const float*>(name + NODE_TRANSLATION);
            amountX = *reinterpret_cast<const float*>(amount + NODE_TRANSLATION);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void SetNodeX(void* uix, void* node, float x)
    {
        __try
        {
            void** vt = *reinterpret_cast<void***>(uix);
            reinterpret_cast<SetTranslateX_t>(vt[VT_SET_TRANSLATE_X / sizeof(void*)])(uix, node, x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void __fastcall hkLayoutAmountColumn(uint8_t* self, void* data, uint8_t resource)
    {
        gOriginal(self, data, resource);
        if (!self || !RL_IsRightToLeft())
            return;

        void* uix = nullptr;
        uint8_t* amount = nullptr;
        float nameX = 0.0f;
        float amountX = 0.0f;
        if (!ReadRecord(self, uix, amount, nameX, amountX) || nameX < MIRRORED_NAME_MIN_X)
            return;

        const float mirroredX = MIRROR_SUM - amountX;
        SetNodeX(uix, amount, mirroredX);

        if (!gLogged.exchange(true))
            Log("[MbDvcResourceRecord::LayoutAmountColumn] Arabic owned-amount column mirrored: game x %.2f -> %.2f "
                "(resource %u, name x %.2f)\n", amountX, mirroredX, static_cast<unsigned>(resource), nameX);
    }
}

bool InstallMbDvcResourceRecordAmountColumnArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.MbDvcResourceRecord_LayoutAmountColumn)
    {
        Log("[MbDvcResourceRecord::LayoutAmountColumn] address missing - the owned amount keeps the stock x.\n");
        return true;
    }

    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) +
        (gAddr.MbDvcResourceRecord_LayoutAmountColumn - IDA_IMAGE_BASE));
    if (!CodeMatches(target))
    {
        Log("[MbDvcResourceRecord::LayoutAmountColumn] prologue mismatch at %p - the owned amount keeps the stock x.\n",
            target);
        return true;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkLayoutAmountColumn), reinterpret_cast<void**>(&gOriginal)) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        gOriginal = nullptr;
        return false;
    }

    gTarget = target;
    Log("[MbDvcResourceRecord::LayoutAmountColumn] hooked at %p (Arabic: owned amount follows the mirrored columns)\n",
        target);
    return true;
}

void RemoveMbDvcResourceRecordAmountColumnArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    gOriginal = nullptr;
    gLogged = false;
}
