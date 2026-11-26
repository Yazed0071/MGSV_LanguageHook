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
    using SetupAsset_t = uint64_t(__fastcall*)(uint8_t* controller, void* layout);
    using Update_t = void(__fastcall*)(uint8_t* controller, uint32_t time);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_TEXT_NODE = 0x228;
    constexpr size_t OFF_ALIGN = 0xD8;
    constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
    constexpr uint32_t kTextLeaseMs = 1000;

    const uint8_t kSetupAssetPrologue[] = {
        0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF2,
    };
    const uint8_t kUpdatePrologue[] = {
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x41, 0x0C, 0x48, 0x8B, 0xD9, 0x3B, 0x41,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    SetupAsset_t oSetupAsset = nullptr;
    Update_t oUpdate = nullptr;
    void* gTarget = nullptr;
    void* gUpdateTarget = nullptr;
    std::atomic<bool> gLoggedLease{ false };

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

    uint8_t* EpilogueTextNode(uint8_t* controller)
    {
        __try
        {
            return *reinterpret_cast<uint8_t**>(controller + OFF_TEXT_NODE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    bool RightAlignEpilogueText(uint8_t* controller)
    {
        uint8_t* node = EpilogueTextNode(controller);
        if (!node)
            return false;
        __try
        {
            node[OFF_ALIGN] = TEXT_ALIGN_RIGHT;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint64_t __fastcall hkSetupAsset(uint8_t* controller, void* layout)
    {
        const uint64_t result = oSetupAsset(controller, layout);
        if ((result & 0xFF) && controller && IsArabicSafe() && RightAlignEpilogueText(controller))
            Log("[tpp::ui::impl::EpilogueController::SetupAsset] epigraph lines right-aligned for Arabic\n");
        return result;
    }

    void __fastcall hkUpdate(uint8_t* controller, uint32_t time)
    {
        oUpdate(controller, time);
        if (!controller || !IsArabicSafe())
            return;
        uint8_t* node = EpilogueTextNode(controller);
        if (!node)
            return;
        KeepArabicLinesRightAlignedWhileShown(node, kTextLeaseMs);
        if (!gLoggedLease.exchange(true))
            Log("[tpp::ui::impl::EpilogueController::Update] epigraph lines kept right-aligned while shown\n");
    }
}

bool InstallEpilogueControllerSetupAssetArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.EpilogueController_SetupAsset)
    {
        Log("[tpp::ui::impl::EpilogueController::SetupAsset] address missing - epigraph keeps the stock alignment.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(hGame) + (gAddr.EpilogueController_SetupAsset - IDA_IMAGE_BASE));

    if (!CodeMatches(target, kSetupAssetPrologue, sizeof(kSetupAssetPrologue)))
    {
        Log("[tpp::ui::impl::EpilogueController::SetupAsset] code is not what this build should have - not hooked.\n");
        return true;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkSetupAsset), reinterpret_cast<void**>(&oSetupAsset)) !=
            MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[tpp::ui::impl::EpilogueController::SetupAsset] hook failed.\n");
        return false;
    }
    gTarget = target;

    void* update = gAddr.EpilogueController_Update
                       ? reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) +
                                                 (gAddr.EpilogueController_Update - IDA_IMAGE_BASE))
                       : nullptr;
    if (update && CodeMatches(update, kUpdatePrologue, sizeof(kUpdatePrologue)) &&
        MH_CreateHook(update, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) == MH_OK)
    {
        if (MH_EnableHook(update) == MH_OK)
            gUpdateTarget = update;
        else
            MH_RemoveHook(update);
    }

    Log("[tpp::ui::impl::EpilogueController::SetupAsset] Arabic epigraph right-align hook enabled%s.\n",
        gUpdateTarget ? " (kept right-aligned every frame)" : " - per-frame keeper NOT hooked");
    return true;
}

void RemoveEpilogueControllerSetupAssetArabicHook()
{
    if (gUpdateTarget)
    {
        MH_DisableHook(gUpdateTarget);
        MH_RemoveHook(gUpdateTarget);
        gUpdateTarget = nullptr;
    }
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    oSetupAsset = nullptr;
    gIsArabLanguage = nullptr;
}
