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
    using RefreshHeader_t = void(__fastcall*)(uint8_t* self);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);
    using GetUix_t = void*(__cdecl*)();
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_TITLE = 0xF8;
    constexpr size_t OFF_BODY = 0x168;
    constexpr size_t OFF_BODY_ORIGIN_X = 0x188;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr float PIXEL_TO_TRANSLATE = 0.1f;
    constexpr float EPSILON = 0.01f;

    const uint8_t kRefreshPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57,
        0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00,
    };

    struct Placed
    {
        uint8_t* node;
        float authoredX;
        bool moved;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    GetUix_t gGetUix = nullptr;
    RefreshHeader_t oRefresh = nullptr;
    void* gTarget = nullptr;
    Placed gTitle = {};
    Placed gBody = {};
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

    float DisplayWidth(void* node)
    {
        if (!gGetDisplayWidth || !node)
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

    bool ReadPtr(const uint8_t* base, size_t offset, uint8_t*& out)
    {
        __try
        {
            out = *reinterpret_cast<uint8_t* const*>(base + offset);
            return out != nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadFloat(const uint8_t* base, size_t offset, float& out)
    {
        __try
        {
            out = *reinterpret_cast<const float*>(base + offset);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void SetNodeX(void* node, float x)
    {
        if (!gGetUix || !node)
            return;
        __try
        {
            void* uix = gGetUix();
            if (!uix)
                return;
            void** vt = *reinterpret_cast<void***>(uix);
            reinterpret_cast<SetTranslateX_t>(vt[VT_SET_TRANSLATE_X / sizeof(void*)])(uix, node, x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    Placed* Track(Placed& slot, uint8_t* node)
    {
        if (slot.node != node)
        {
            float x = 0.0f;
            if (!ReadFloat(node, NODE_TRANSLATION, x))
                return nullptr;
            slot = { node, x, false };
        }
        return &slot;
    }

    void MoveTo(Placed& slot, float x)
    {
        float current = 0.0f;
        if (ReadFloat(slot.node, NODE_TRANSLATION, current) && current > x - EPSILON && current < x + EPSILON)
        {
            slot.moved = true;
            return;
        }
        SetNodeX(slot.node, x);
        slot.moved = true;
    }

    void Restore(Placed& slot)
    {
        if (!slot.node || !slot.moved)
            return;
        SetNodeX(slot.node, slot.authoredX);
        slot.moved = false;
    }

    void __fastcall hkRefresh(uint8_t* self)
    {
        oRefresh(self);
        if (!self)
            return;
        uint8_t* title = nullptr;
        uint8_t* body = nullptr;
        ReadPtr(self, OFF_TITLE, title);
        ReadPtr(self, OFF_BODY, body);
        Placed* titleSlot = title ? Track(gTitle, title) : nullptr;
        Placed* bodySlot = body ? Track(gBody, body) : nullptr;
        if (!IsArabicSafe())
        {
            if (titleSlot)
                Restore(*titleSlot);
            if (bodySlot)
                Restore(*bodySlot);
            return;
        }
        if (!bodySlot)
            return;
        float origin = 0.0f;
        float textWidth = 0.0f;
        if (!ReadFloat(self, OFF_BODY_ORIGIN_X, origin) || !ReadFloat(body, NODE_TEXT_WIDTH, textWidth) ||
            !(textWidth > 0.0f))
        {
            if (titleSlot)
                Restore(*titleSlot);
            Restore(*bodySlot);
            return;
        }
        const float bodyBox = DisplayWidth(body);
        if (!(bodyBox > 0.0f))
            return;
        const float right = origin + textWidth * PIXEL_TO_TRANSLATE;
        MoveTo(*bodySlot, right - bodyBox * PIXEL_TO_TRANSLATE);
        const float titleBox = titleSlot ? DisplayWidth(title) : -1.0f;
        if (titleSlot && titleBox > 0.0f)
            MoveTo(*titleSlot, right - titleBox * PIXEL_TO_TRANSLATE);
        if (!gLogged.exchange(true))
            Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] Arabic help text ends at the panel edge "
                "(origin %.2f, text %.1f, box %.1f -> right %.2f)\n",
                origin, textWidth, bodyBox, right);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallPauseHelpRefreshHeaderTextArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.MbDvcPauseHelpCallbackImpl_RefreshHeaderText ||
        !gAddr.ModelNodeText_GetDisplayWidth || !gAddr.GetUixUtilityToFeedQuarkEnvironment)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] address missing - help text keeps the stock position.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    gGetUix = reinterpret_cast<GetUix_t>(Resolve(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));
    void* target = Resolve(hGame, gAddr.MbDvcPauseHelpCallbackImpl_RefreshHeaderText);
    if (!CodeMatches(target, kRefreshPrologue, sizeof(kRefreshPrologue)))
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] prologue mismatch at %p - help text keeps the stock position.\n",
            target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkRefresh), reinterpret_cast<void**>(&oRefresh)) != MH_OK)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHeaderText] Arabic help text fitted to its panel, hooked at %p.\n",
        target);
    return true;
}

void RemovePauseHelpRefreshHeaderTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oRefresh = nullptr;
    gGetDisplayWidth = nullptr;
    gGetUix = nullptr;
    gIsArabLanguage = nullptr;
    gTitle = {};
    gBody = {};
    gLogged = false;
}
