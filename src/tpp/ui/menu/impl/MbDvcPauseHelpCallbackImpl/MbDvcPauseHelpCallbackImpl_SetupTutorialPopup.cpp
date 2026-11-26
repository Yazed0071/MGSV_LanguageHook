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
    using IsArabLanguage_t = bool(__cdecl*)();
    using SetupTutorialPopup_t = void(__fastcall*)(uint8_t* self);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_TITLE_NODE = 0x3E8;
    constexpr size_t OFF_BODY_NODE = 0x3F0;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_RIGHT = 2;

    const uint8_t kSetupPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0x05,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    SetupTutorialPopup_t oSetup = nullptr;
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

    uint8_t* ReadNode(const uint8_t* self, size_t offset)
    {
        __try
        {
            return *reinterpret_cast<uint8_t* const*>(self + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    float TextWidth(const uint8_t* node)
    {
        __try
        {
            return *reinterpret_cast<const float*>(node + NODE_TEXT_WIDTH);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1.0f;
        }
    }

    float DisplayWidth(void* node)
    {
        if (!gGetDisplayWidth)
            return -1.0f;
        __try
        {
            return gGetDisplayWidth(node);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1.0f;
        }
    }

    bool AlignRight(uint8_t* node)
    {
        __try
        {
            node[NODE_LINE_ALIGN] = ALIGN_RIGHT;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkSetup(uint8_t* self)
    {
        oSetup(self);
        if (!self || !IsArabicSafe())
            return;

        uint8_t* body = ReadNode(self, OFF_BODY_NODE);
        const bool bodyDone = body && AlignRight(body);

        bool titleDone = false;
        uint8_t* title = ReadNode(self, OFF_TITLE_NODE);
        const float textWidth = title ? TextWidth(title) : -1.0f;
        const float boxWidth = title ? DisplayWidth(title) : -1.0f;
        if (title && textWidth >= 0.0f && boxWidth > 0.0f && textWidth <= boxWidth)
            titleDone = AlignRight(title);

        if (!gLogged.exchange(true))
            Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] Arabic tutorial popup: body %s, title %s "
                "(text %.1f of %.1f)\n",
                bodyDone ? "right-aligned" : "untouched", titleDone ? "right-aligned" : "left to the marquee", textWidth,
                boxWidth);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallPauseHelpTutorialPopupArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.MbDvcPauseHelpCallbackImpl_SetupTutorialPopup)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] address missing - tutorial popups keep the stock alignment.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    if (gAddr.ModelNodeText_GetDisplayWidth)
        gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    void* target = Resolve(hGame, gAddr.MbDvcPauseHelpCallbackImpl_SetupTutorialPopup);
    if (!CodeMatches(target, kSetupPrologue, sizeof(kSetupPrologue)))
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] prologue mismatch at %p - tutorial popups keep the stock alignment.\n",
            target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkSetup), reinterpret_cast<void**>(&oSetup)) != MH_OK)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::SetupTutorialPopup] Arabic tutorial popup right-align hooked at %p.\n",
        target);
    return true;
}

void RemovePauseHelpTutorialPopupArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oSetup = nullptr;
    gGetDisplayWidth = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
}
