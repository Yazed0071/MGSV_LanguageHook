#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using RefreshMissionTextBox_t = void(__fastcall*)(uint8_t* self);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_MISSION_TEXT_NODE = 0x2F0;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_RIGHT = 2;

    const uint8_t kPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,
    };
    const uint8_t kNodeLoad[] = { 0x48, 0x8B, 0x97, 0xF0, 0x02, 0x00, 0x00 };
    constexpr size_t kNodeLoadOffset = 0x1A9;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    RefreshMissionTextBox_t oRefresh = nullptr;
    void* gTarget = nullptr;
    bool gLogged = false;

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

    bool RightAlignLines(uint8_t* self, void*& nodeOut, unsigned& was)
    {
        __try
        {
            auto* node = *reinterpret_cast<uint8_t**>(self + OFF_MISSION_TEXT_NODE);
            nodeOut = node;
            if (!node)
                return false;
            was = node[NODE_LINE_ALIGN];
            if (node[NODE_LINE_ALIGN] == ALIGN_RIGHT)
                return false;
            node[NODE_LINE_ALIGN] = ALIGN_RIGHT;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkRefresh(uint8_t* self)
    {
        oRefresh(self);
        if (!self || !IsArabicSafe())
            return;
        void* node = nullptr;
        unsigned was = 0;
        if (RightAlignLines(self, node, was) && !gLogged)
        {
            gLogged = true;
            Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] Arabic mission description %p: line align %u -> right\n",
                node, was);
        }
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallCombatDeployCallbackImplRefreshMissionTextBoxArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.CombatDeployCallbackImpl_RefreshMissionTextBox)
    {
        Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] address missing - the description keeps the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = Resolve(hGame, gAddr.CombatDeployCallbackImpl_RefreshMissionTextBox);
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)) ||
        !CodeMatches(static_cast<uint8_t*>(target) + kNodeLoadOffset, kNodeLoad, sizeof(kNodeLoad)))
    {
        Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] code mismatch at %p - the description keeps the stock layout.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkRefresh), reinterpret_cast<void**>(&oRefresh)) != MH_OK)
    {
        Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::mbm::impl::CombatDeployCallbackImpl::RefreshMissionTextBox] Arabic mission description right-aligned (hooked at %p).\n", target);
    return true;
}

void RemoveCombatDeployCallbackImplRefreshMissionTextBoxArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oRefresh = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
}
