#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using RefreshHelpPage_t = void(__fastcall*)(uint8_t* self);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);
    using GetUix_t = void*(__cdecl*)();
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t ENTRY_COUNT = 10;
    constexpr size_t OFF_TITLES = 0x190;
    constexpr size_t OFF_BODIES = 0x1E0;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr float PIXEL_TO_TRANSLATE = 0.1f;
    constexpr float BODY_INDENT = 20.0f;
    constexpr float COLUMN_MATCH = 0.05f;
    constexpr size_t MAX_AUTHORED = 2 * ENTRY_COUNT + 4;

    const uint8_t kRefreshPrologue[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70, 0x18, 0x48,
        0x89, 0x78, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    };

    struct Authored
    {
        void* node;
        uint8_t line;
        bool changed;
    };

    struct NodeInfo
    {
        uint8_t* node;
        float x;
        float textWidth;
        float boxWidth;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    GetUix_t gGetUix = nullptr;
    RefreshHelpPage_t oRefresh = nullptr;
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

    bool ReadNode(const uint8_t* self, size_t offset, NodeInfo& out)
    {
        __try
        {
            out.node = *reinterpret_cast<uint8_t* const*>(self + offset);
            if (!out.node)
                return false;
            out.x = *reinterpret_cast<const float*>(out.node + NODE_TRANSLATION);
            out.textWidth = *reinterpret_cast<const float*>(out.node + NODE_TEXT_WIDTH);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        out.boxWidth = DisplayWidth(out.node);
        return out.boxWidth > 0.0f;
    }

    Authored* AuthoredFor(uint8_t* node)
    {
        for (Authored& entry : gAuthored)
        {
            if (entry.node == node)
                return &entry;
        }
        uint8_t line = 0;
        __try
        {
            line = node[NODE_LINE_ALIGN];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
        Authored& slot = gAuthored[gAuthoredNext++ % MAX_AUTHORED];
        slot = { node, line, false };
        return &slot;
    }

    void SetLineAlign(uint8_t* node, uint8_t align)
    {
        __try
        {
            if (node[NODE_LINE_ALIGN] == align)
                return;
            node[NODE_LINE_ALIGN] = align;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
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

    void RightAlign(uint8_t* node, float x)
    {
        if (Authored* authored = AuthoredFor(node))
            authored->changed = true;
        SetNodeX(node, x);
        SetLineAlign(node, ALIGN_RIGHT);
    }

    void Restore(uint8_t* node)
    {
        Authored* authored = AuthoredFor(node);
        if (!authored || !authored->changed)
            return;
        SetLineAlign(node, authored->line);
        authored->changed = false;
    }

    struct Entry
    {
        NodeInfo title;
        NodeInfo body;
        float content;
        bool used;
    };

    void MirrorPage(const uint8_t* self, bool arabic, int& mirrored)
    {
        Entry entries[ENTRY_COUNT] = {};
        for (size_t i = 0; i < ENTRY_COUNT; ++i)
        {
            Entry& e = entries[i];
            if (!ReadNode(self, OFF_TITLES + i * sizeof(void*), e.title) ||
                !ReadNode(self, OFF_BODIES + i * sizeof(void*), e.body))
                continue;
            if (!arabic)
            {
                Restore(e.title.node);
                Restore(e.body.node);
                continue;
            }
            if (!(e.title.textWidth > 0.0f) && !(e.body.textWidth > 0.0f))
                continue;
            e.content = e.title.textWidth > 0.0f ? e.title.textWidth : 0.0f;
            if (e.body.textWidth > 0.0f && e.body.textWidth + BODY_INDENT > e.content)
                e.content = e.body.textWidth + BODY_INDENT;
            e.used = true;
        }
        if (!arabic)
            return;

        for (size_t i = 0; i < ENTRY_COUNT; ++i)
        {
            if (!entries[i].used)
                continue;
            float column = entries[i].content;
            for (size_t j = 0; j < ENTRY_COUNT; ++j)
            {
                if (entries[j].used && std::fabs(entries[j].title.x - entries[i].title.x) < COLUMN_MATCH &&
                    entries[j].content > column)
                    column = entries[j].content;
            }
            const Entry& e = entries[i];
            const float right = e.title.x + column * PIXEL_TO_TRANSLATE;
            RightAlign(e.title.node, right - e.title.boxWidth * PIXEL_TO_TRANSLATE);
            RightAlign(e.body.node, right - (BODY_INDENT + e.body.boxWidth) * PIXEL_TO_TRANSLATE);
            ++mirrored;
        }
    }

    void __fastcall hkRefresh(uint8_t* self)
    {
        oRefresh(self);
        if (!self)
            return;
        const bool arabic = IsArabicSafe();
        int mirrored = 0;
        MirrorPage(self, arabic, mirrored);
        if (arabic && mirrored && !gLogged.exchange(true))
            Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] Arabic help boxes right-aligned (%d on this page)\n",
                mirrored);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallPauseHelpRefreshHelpPageArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.MbDvcPauseHelpCallbackImpl_RefreshHelpPage ||
        !gAddr.ModelNodeText_GetDisplayWidth || !gAddr.GetUixUtilityToFeedQuarkEnvironment)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] address missing - help boxes keep the stock alignment.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    gGetUix = reinterpret_cast<GetUix_t>(Resolve(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));
    void* target = Resolve(hGame, gAddr.MbDvcPauseHelpCallbackImpl_RefreshHelpPage);
    if (!CodeMatches(target, kRefreshPrologue, sizeof(kRefreshPrologue)))
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] prologue mismatch at %p - help boxes keep the stock alignment.\n",
            target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkRefresh), reinterpret_cast<void**>(&oRefresh)) != MH_OK)
    {
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] MH_EnableHook failed.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::impl::MbDvcPauseHelpCallbackImpl::RefreshHelpPage] Arabic help box right-align hooked at %p.\n",
        target);
    return true;
}

void RemovePauseHelpRefreshHelpPageArabicHook()
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
    gAuthoredNext = 0;
    for (Authored& entry : gAuthored)
        entry = {};
    gLogged = false;
}
