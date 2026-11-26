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

bool TextUnitsWereBuiltFromArabic(const void* units, bool& arabic);
void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using Update_t = void(__fastcall*)(uint8_t* self);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_MESSAGE_NODE = 0x1F0;
    constexpr size_t OFF_MESSAGE_UNITS = 0x1F8;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_LEFT = 0;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr uint32_t kMessageLeaseMs = 300;
    constexpr size_t MAX_TRACKED = 16;

    const uint8_t kUpdatePrologue[] = {
        0x4C, 0x8B, 0xDC, 0x53, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x81, 0xA0, 0x00, 0x00, 0x00,
    };

    struct MessageState
    {
        uint8_t authoredLine;
        uint8_t authoredBlock;
        bool arabic;
        bool mirrored;
        bool logged;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    Update_t oUpdate = nullptr;
    void* gTarget = nullptr;
    std::mutex gStatesMutex;
    std::unordered_map<void*, MessageState> gStates;

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

    bool ReadAlign(const uint8_t* node, uint8_t& line, uint8_t& block, float& textWidth)
    {
        __try
        {
            line = node[NODE_LINE_ALIGN];
            block = node[NODE_BLOCK_ALIGN];
            textWidth = *reinterpret_cast<const float*>(node + NODE_TEXT_WIDTH);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void WriteAlign(uint8_t* node, uint8_t line, uint8_t block)
    {
        __try
        {
            if (node[NODE_LINE_ALIGN] == line && node[NODE_BLOCK_ALIGN] == block)
                return;
            node[NODE_LINE_ALIGN] = line;
            node[NODE_BLOCK_ALIGN] = block;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    MessageState& StateFor(void* node, uint8_t line, uint8_t block)
    {
        auto it = gStates.find(node);
        if (it != gStates.end())
            return it->second;
        if (gStates.size() >= MAX_TRACKED)
            gStates.clear();
        return gStates.emplace(node, MessageState{ line, block, false, false, false }).first->second;
    }

    void __fastcall hkUpdate(uint8_t* self)
    {
        oUpdate(self);
        if (!self)
            return;
        uint8_t* node = ReadNode(self, OFF_MESSAGE_NODE);
        uint8_t line = 0, block = 0;
        float textWidth = 0.0f;
        if (!node || !ReadAlign(node, line, block, textWidth))
            return;

        const bool arabicUi = IsArabicSafe();
        std::lock_guard<std::mutex> lock(gStatesMutex);
        if (!arabicUi)
        {
            auto it = gStates.find(node);
            if (it != gStates.end() && it->second.mirrored)
            {
                WriteAlign(node, it->second.authoredLine, it->second.authoredBlock);
                it->second.mirrored = false;
            }
            return;
        }

        MessageState& state = StateFor(node, line, block);
        bool builtArabic = false;
        if (TextUnitsWereBuiltFromArabic(self + OFF_MESSAGE_UNITS, builtArabic))
            state.arabic = builtArabic;

        if (!state.arabic)
        {
            if (state.mirrored)
            {
                WriteAlign(node, state.authoredLine, state.authoredBlock);
                state.mirrored = false;
            }
            return;
        }

        const uint8_t wantBlock = state.authoredBlock == ALIGN_LEFT ? ALIGN_RIGHT : state.authoredBlock;
        WriteAlign(node, ALIGN_RIGHT, wantBlock);
        KeepArabicLinesRightAlignedWhileShown(node, kMessageLeaseMs);
        state.mirrored = true;
        if (!state.logged)
        {
            state.logged = true;
            Log("[tpp::ui::menu::MbCommonPopupAct] Arabic popup message %p right-aligned (authored line %u block %u -> line 2 block %u, text %.1f)\n",
                node, static_cast<unsigned>(state.authoredLine), static_cast<unsigned>(state.authoredBlock),
                static_cast<unsigned>(wantBlock), textWidth);
        }
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallMbCommonPopupActUpdateArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.MbCommonPopupAct_Update)
    {
        Log("[tpp::ui::menu::MbCommonPopupAct] address missing - iDroid popup messages keep their stock alignment.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = Resolve(hGame, gAddr.MbCommonPopupAct_Update);
    if (!CodeMatches(target, kUpdatePrologue, sizeof(kUpdatePrologue)))
    {
        Log("[tpp::ui::menu::MbCommonPopupAct] Update prologue mismatch at %p - iDroid popup messages keep their stock alignment.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) != MH_OK)
    {
        Log("[tpp::ui::menu::MbCommonPopupAct] MH_CreateHook failed - iDroid popup messages keep their stock alignment.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::menu::MbCommonPopupAct] MH_EnableHook failed - iDroid popup messages keep their stock alignment.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::menu::MbCommonPopupAct] Arabic iDroid popup messages right-aligned (hooked at %p).\n", target);
    return true;
}

void RemoveMbCommonPopupActUpdateArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    gIsArabLanguage = nullptr;
    std::lock_guard<std::mutex> lock(gStatesMutex);
    gStates.clear();
}
