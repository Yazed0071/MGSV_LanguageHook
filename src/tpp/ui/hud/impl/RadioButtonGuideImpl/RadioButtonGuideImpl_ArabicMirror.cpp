#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using InitGuide_t = uint64_t(__fastcall*)(uint8_t* guide, uint8_t* info);
    using ActGuide_t = void(__fastcall*)(uint8_t* guide);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_INFOS = 0x28;
    constexpr size_t INFO_STRIDE = 0x78;
    constexpr size_t INFO_COUNT = 3;
    constexpr size_t INFO_TEXT_NODE = 0x50;
    constexpr size_t INFO_ACTIVE = 0x6C;
    constexpr size_t INFO_CLOSING = 0x6D;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_LEFT = 0;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr size_t MAX_NODES = 8;

    const uint8_t kInitPrologue[] = { 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x48, 0x4C, 0x8B, 0xF2, 0x4C, 0x8B, 0xF9 };
    const uint8_t kActPrologue[] = { 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x41, 0x54, 0x41 };

    struct AuthoredAlign
    {
        void* node;
        uint8_t block;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    InitGuide_t oInit = nullptr;
    ActGuide_t oAct = nullptr;
    void* gInitTarget = nullptr;
    void* gActTarget = nullptr;
    AuthoredAlign gAuthored[MAX_NODES] = {};
    size_t gAuthoredCount = 0;
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

    uint8_t AuthoredBlockAlign(void* node, uint8_t current)
    {
        for (size_t i = 0; i < gAuthoredCount; ++i)
        {
            if (gAuthored[i].node == node)
                return gAuthored[i].block;
        }
        if (gAuthoredCount < MAX_NODES)
            gAuthored[gAuthoredCount++] = { node, current };
        return current;
    }

    bool MirrorNode(uint8_t* node)
    {
        __try
        {
            const uint8_t authored = AuthoredBlockAlign(node, node[NODE_BLOCK_ALIGN]);
            const uint8_t block = authored == ALIGN_LEFT ? ALIGN_RIGHT : authored;
            if (node[NODE_LINE_ALIGN] == ALIGN_RIGHT && node[NODE_BLOCK_ALIGN] == block)
                return false;
            node[NODE_LINE_ALIGN] = ALIGN_RIGHT;
            node[NODE_BLOCK_ALIGN] = block;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint8_t* InfoNode(uint8_t* info, bool requireShown)
    {
        __try
        {
            if (requireShown && (!info[INFO_ACTIVE] || info[INFO_CLOSING]))
                return nullptr;
            return *reinterpret_cast<uint8_t**>(info + INFO_TEXT_NODE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void NoteMirrored()
    {
        if (gLogged)
            return;
        gLogged = true;
        Log("[tpp::ui::hud::impl::RadioButtonGuideImpl] Arabic button guide mirrored to the right of its bar\n");
    }

    uint64_t __fastcall hkInit(uint8_t* guide, uint8_t* info)
    {
        const uint64_t shown = oInit(guide, info);
        if ((shown & 0xFF) && info && IsArabicSafe())
        {
            if (uint8_t* node = InfoNode(info, false))
            {
                if (MirrorNode(node))
                    NoteMirrored();
            }
        }
        return shown;
    }

    void __fastcall hkAct(uint8_t* guide)
    {
        oAct(guide);
        if (!guide || !IsArabicSafe())
            return;
        for (size_t i = 0; i < INFO_COUNT; ++i)
        {
            if (uint8_t* node = InfoNode(guide + OFF_INFOS + i * INFO_STRIDE, true))
                MirrorNode(node);
        }
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    void* HookOne(HMODULE hGame, uintptr_t va, const uint8_t* prologue, size_t size, void* detour, void** original)
    {
        if (!va)
            return nullptr;
        void* target = Resolve(hGame, va);
        if (!CodeMatches(target, prologue, size) || MH_CreateHook(target, detour, original) != MH_OK)
            return nullptr;
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            return nullptr;
        }
        return target;
    }
}

bool InstallRadioButtonGuideArabicMirrorHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.RadioButtonGuideImpl_InitRadioButtonGuide ||
        !gAddr.RadioButtonGuideImpl_ActRadioButtonGuide)
    {
        Log("[tpp::ui::hud::impl::RadioButtonGuideImpl] address missing - button guides keep the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gInitTarget = HookOne(hGame, gAddr.RadioButtonGuideImpl_InitRadioButtonGuide, kInitPrologue, sizeof(kInitPrologue),
                          reinterpret_cast<void*>(&hkInit), reinterpret_cast<void**>(&oInit));
    gActTarget = HookOne(hGame, gAddr.RadioButtonGuideImpl_ActRadioButtonGuide, kActPrologue, sizeof(kActPrologue),
                         reinterpret_cast<void*>(&hkAct), reinterpret_cast<void**>(&oAct));

    Log("[tpp::ui::hud::impl::RadioButtonGuideImpl] Arabic button guide mirror: init %s, per frame %s.\n",
        gInitTarget ? "on" : "NOT hooked", gActTarget ? "on" : "NOT hooked");
    return true;
}

void RemoveRadioButtonGuideArabicMirrorHook()
{
    for (void** target : { &gInitTarget, &gActTarget })
    {
        if (*target)
        {
            MH_DisableHook(*target);
            MH_RemoveHook(*target);
            *target = nullptr;
        }
    }
    gAuthoredCount = 0;
    oInit = nullptr;
    oAct = nullptr;
    gIsArabLanguage = nullptr;
}
