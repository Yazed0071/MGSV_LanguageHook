#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs);
void ArabicScrollStampRtlNode(void* node);
void ArabicScrollReleaseFittingNode(void* node);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using Update_t = void(__fastcall*)(uint8_t* self);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_MENU_HELP_NODE = 0x13E8;
    constexpr size_t OFF_MISSION_PANEL_NODES[] = { 0x1488, 0x1490, 0x1498 };
    constexpr size_t OFF_OBJECTIVE_NODE = 0x1498;
    constexpr size_t NODE_SCROLL_STATE = 0x92;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr uint32_t kHelpLeaseMs = 500;
    constexpr size_t MAX_AUTHORED = 16;

    const uint8_t kUpdatePrologue[] = {
        0x40, 0x56, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF1, 0xE8, 0xA2, 0xFD, 0xFF, 0xFF,
        0x80, 0xBE, 0x50, 0x13, 0x00, 0x00, 0x00,
    };
    const uint8_t kDisplayWidthPrologue[] = { 0xF3, 0x0F, 0x10, 0x81, 0xF0, 0x00, 0x00, 0x00 };

    struct Authored
    {
        uint8_t line;
        uint8_t block;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    Update_t oUpdate = nullptr;
    void* gTarget = nullptr;
    std::mutex gAuthoredMutex;
    std::unordered_map<void*, Authored> gAuthored;
    bool gLoggedPanel = false;

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

    struct NodeState
    {
        float textWidth;
        uint8_t line;
        uint8_t block;
        uint8_t scrollState;
    };

    bool ReadState(const uint8_t* node, NodeState& state)
    {
        __try
        {
            state.textWidth = *reinterpret_cast<const float*>(node + NODE_TEXT_WIDTH);
            state.line = node[NODE_LINE_ALIGN];
            state.block = node[NODE_BLOCK_ALIGN];
            state.scrollState = node[NODE_SCROLL_STATE];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    float DisplayWidth(void* node)
    {
        __try
        {
            return gGetDisplayWidth(node);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0.0f;
        }
    }

    void WriteAlign(uint8_t* node, uint8_t line, uint8_t block)
    {
        __try
        {
            node[NODE_LINE_ALIGN] = line;
            node[NODE_BLOCK_ALIGN] = block;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    Authored RememberAuthored(void* node, const NodeState& state)
    {
        std::lock_guard<std::mutex> lock(gAuthoredMutex);
        auto it = gAuthored.find(node);
        if (it != gAuthored.end())
            return it->second;
        const Authored authored{ state.line, state.block };
        if (gAuthored.size() < MAX_AUTHORED)
            gAuthored.emplace(node, authored);
        return authored;
    }

    void MirrorPanelLine(uint8_t* node, bool scrolls)
    {
        NodeState state{};
        if (!ReadState(node, state))
            return;
        const Authored authored = RememberAuthored(node, state);
        const float displayWidth = DisplayWidth(node);
        if (displayWidth <= 0.0f || state.textWidth <= 0.0f)
            return;

        if (state.textWidth <= displayWidth)
        {
            if (scrolls)
                ArabicScrollReleaseFittingNode(node);
            if (state.line != ALIGN_RIGHT || state.block != ALIGN_RIGHT)
            {
                WriteAlign(node, ALIGN_RIGHT, ALIGN_RIGHT);
                if (!gLoggedPanel)
                {
                    gLoggedPanel = true;
                    Log("[tpp::ui::menu::MbTitleEv] Arabic mission panel node %p right-aligned (authored line %u block %u, text %.1f of %.1f)\n",
                        node, static_cast<unsigned>(authored.line), static_cast<unsigned>(authored.block),
                        state.textWidth, displayWidth);
                }
            }
            return;
        }

        if (state.block == ALIGN_RIGHT && authored.block != ALIGN_RIGHT)
            WriteAlign(node, state.line == ALIGN_RIGHT ? authored.line : state.line, authored.block);
        if (scrolls && state.scrollState != 0)
            ArabicScrollStampRtlNode(node);
    }

    void __fastcall hkUpdate(uint8_t* self)
    {
        oUpdate(self);
        if (!self || !IsArabicSafe())
            return;
        if (uint8_t* help = ReadNode(self, OFF_MENU_HELP_NODE))
            KeepArabicLinesRightAlignedWhileShown(help, kHelpLeaseMs);
        for (size_t offset : OFF_MISSION_PANEL_NODES)
        {
            if (uint8_t* node = ReadNode(self, offset))
                MirrorPanelLine(node, offset == OFF_OBJECTIVE_NODE);
        }
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallMbTitleEvUpdateArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.MbTitleEv_Update || !gAddr.ModelNodeText_GetDisplayWidth)
    {
        Log("[tpp::ui::menu::MbTitleEv] address missing - the iDroid title bar keeps the stock layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    void* target = Resolve(hGame, gAddr.MbTitleEv_Update);
    if (!CodeMatches(target, kUpdatePrologue, sizeof(kUpdatePrologue)) ||
        !CodeMatches(reinterpret_cast<void*>(gGetDisplayWidth), kDisplayWidthPrologue, sizeof(kDisplayWidthPrologue)))
    {
        Log("[tpp::ui::menu::MbTitleEv] Update prologue mismatch at %p - the iDroid title bar keeps the stock layout.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) != MH_OK)
    {
        Log("[tpp::ui::menu::MbTitleEv] MH_CreateHook failed - the iDroid title bar keeps the stock layout.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::MbTitleEv] MH_EnableHook failed - the iDroid title bar keeps the stock layout.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::MbTitleEv] Arabic help line and mission panel right-aligned per frame (hooked at %p).\n", target);
    return true;
}

void RemoveMbTitleEvUpdateArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    gGetDisplayWidth = nullptr;
    gIsArabLanguage = nullptr;
    gLoggedPanel = false;
    std::lock_guard<std::mutex> lock(gAuthoredMutex);
    gAuthored.clear();
}
