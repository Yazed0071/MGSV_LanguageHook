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
    using SetPadButtonPrompt_t = uint64_t(__fastcall*)(void* self, uint8_t* prompt, int button, void* units,
                                                       const char* text, uint32_t maxUnits);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);
    using GetUix_t = void*(__cdecl*)();
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t PROMPT_ICON = 0x8;
    constexpr size_t PROMPT_TEXT = 0x10;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr float PIXEL_TO_TRANSLATE = 0.1f;
    constexpr size_t MAX_AUTHORED = 8;

    const uint8_t kPrologue[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x44, 0x24, 0x68, 0x4D, 0x8B, 0xD1 };

    struct Authored
    {
        uint8_t* node;
        float x;
        uint8_t line;
        bool moved;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    GetUix_t gGetUix = nullptr;
    SetPadButtonPrompt_t oSetPrompt = nullptr;
    void* gTarget = nullptr;
    Authored gAuthored[MAX_AUTHORED] = {};
    size_t gAuthoredNext = 0;
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

    uint8_t* ReadNode(const uint8_t* prompt, size_t offset)
    {
        __try
        {
            return *reinterpret_cast<uint8_t* const*>(prompt + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
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

    Authored* AuthoredFor(uint8_t* node)
    {
        if (!node)
            return nullptr;
        for (Authored& entry : gAuthored)
        {
            if (entry.node == node)
                return &entry;
        }
        float x = 0.0f;
        uint8_t line = 0;
        __try
        {
            x = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            line = node[NODE_LINE_ALIGN];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
        Authored& slot = gAuthored[gAuthoredNext++ % MAX_AUTHORED];
        slot = { node, x, line, false };
        return &slot;
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

    void WriteLineAlign(uint8_t* node, uint8_t align, bool rebuild)
    {
        __try
        {
            node[NODE_LINE_ALIGN] = align;
            if (rebuild)
                *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void Restore(Authored* icon, Authored* text)
    {
        if (icon && icon->moved)
        {
            SetNodeX(icon->node, icon->x);
            icon->moved = false;
        }
        if (text && text->moved)
        {
            SetNodeX(text->node, text->x);
            WriteLineAlign(text->node, text->line, true);
            text->moved = false;
        }
    }

    void Mirror(Authored* icon, Authored* text)
    {
        const float box = DisplayWidth(text->node);
        if (!(box > 0.0f))
            return;
        const float right = text->x + box * PIXEL_TO_TRANSLATE;
        const float iconX = right;
        const float textX = icon->x;
        SetNodeX(icon->node, iconX);
        SetNodeX(text->node, textX);
        WriteLineAlign(text->node, ALIGN_RIGHT, true);
        icon->moved = true;
        text->moved = true;
        if (!gLogged.exchange(true))
            Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] Arabic prompt mirrored (box %.1f): "
                "icon %.2f -> %.2f, text %.2f -> %.2f, lines right-aligned\n",
                box, icon->x, iconX, text->x, textX);
    }

    uint64_t __fastcall hkSetPrompt(void* self, uint8_t* prompt, int button, void* units, const char* text,
                                    uint32_t maxUnits)
    {
        const bool arabic = IsArabicSafe();
        uint8_t* iconNode = prompt ? ReadNode(prompt, PROMPT_ICON) : nullptr;
        uint8_t* textNode = prompt ? ReadNode(prompt, PROMPT_TEXT) : nullptr;
        Authored* icon = AuthoredFor(iconNode);
        Authored* body = AuthoredFor(textNode);
        if (arabic && body)
            WriteLineAlign(textNode, ALIGN_RIGHT, false);

        const uint64_t result = oSetPrompt(self, prompt, button, units, text, maxUnits);

        if (!icon || !body)
            return result;
        if (arabic)
            Mirror(icon, body);
        else
            Restore(icon, body);
        return result;
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallUiUtilitySetPadButtonPromptArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.UiUtilityImpl_SetPadButtonPrompt ||
        !gAddr.ModelNodeText_GetDisplayWidth || !gAddr.GetUixUtilityToFeedQuarkEnvironment)
    {
        Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] address missing - the legal prompt keeps the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    gGetUix = reinterpret_cast<GetUix_t>(Resolve(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));
    void* target = Resolve(hGame, gAddr.UiUtilityImpl_SetPadButtonPrompt);
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] prologue mismatch at %p - the legal prompt keeps the stock layout.\n",
            target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkSetPrompt), reinterpret_cast<void**>(&oSetPrompt)) != MH_OK)
    {
        Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::utility::UiUtilityImpl::SetPadButtonPrompt] Arabic legal prompt mirror hooked at %p.\n", target);
    return true;
}

void RemoveUiUtilitySetPadButtonPromptArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    for (Authored& entry : gAuthored)
        entry = {};
    oSetPrompt = nullptr;
    gGetDisplayWidth = nullptr;
    gGetUix = nullptr;
    gIsArabLanguage = nullptr;
    gAuthoredNext = 0;
    gLogged = false;
}
