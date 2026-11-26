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

void ArabicScrollStampRtlNode(void* node);
void ArabicScrollUnstampRtlNode(void* node);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using RefreshRecordScroll_t = void(__fastcall*)(void* uix, uint8_t* record, uint8_t selected, uint8_t index);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_RECORD_SCROLL_NODE = 0x18;
    constexpr size_t OFF_RECORD_SCROLL_WIDTH = 0x28;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr size_t NODE_SCROLL_STATE = 0x92;
    constexpr size_t NODE_SCROLL_POS = 0x1B4;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_LEFT = 0;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr size_t MAX_AUTHORED = 256;

    const uint8_t kRefreshPrologue[] = {
        0x48, 0x85, 0xD2, 0x0F, 0x84, 0xBF, 0x00, 0x00, 0x00, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48,
        0x83, 0xEC, 0x30, 0x41, 0x0F, 0xB6, 0xC1,
    };
    const uint8_t kDisplayWidthPrologue[] = { 0xF3, 0x0F, 0x10, 0x81, 0xF0, 0x00, 0x00, 0x00 };

    struct RowClass
    {
        uintptr_t vtable;
        size_t titleNode;
        const char* name;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    RefreshRecordScroll_t oRefresh = nullptr;
    void* gTarget = nullptr;
    RowClass gRows[3] = {};
    size_t gRowCount = 0;
    std::mutex gAuthoredMutex;
    std::unordered_map<void*, uint8_t> gAuthoredBlockAlign;
    bool gLogged[3] = {};

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

    struct RowState
    {
        uint8_t* node;
        float textWidth;
        uint8_t blockAlign;
    };

    int FindRowClass(const uint8_t* record, RowState& row)
    {
        __try
        {
            const uintptr_t vtable = *reinterpret_cast<const uintptr_t*>(record);
            for (size_t i = 0; i < gRowCount; ++i)
            {
                if (gRows[i].vtable != vtable)
                    continue;
                row.node = *reinterpret_cast<uint8_t* const*>(record + OFF_RECORD_SCROLL_NODE);
                if (!row.node || *reinterpret_cast<uint8_t* const*>(record + gRows[i].titleNode) != row.node)
                    return -1;
                row.textWidth = *reinterpret_cast<const float*>(record + OFF_RECORD_SCROLL_WIDTH);
                row.blockAlign = row.node[NODE_BLOCK_ALIGN];
                return static_cast<int>(i);
            }
            return -1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1;
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

    void SetAlign(uint8_t* node, int line, uint8_t block)
    {
        __try
        {
            bool changed = false;
            if (line >= 0 && node[NODE_LINE_ALIGN] != static_cast<uint8_t>(line))
            {
                node[NODE_LINE_ALIGN] = static_cast<uint8_t>(line);
                changed = true;
            }
            if (node[NODE_BLOCK_ALIGN] != block)
            {
                node[NODE_BLOCK_ALIGN] = block;
                changed = true;
            }
            if (changed)
                *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void ShowLineStart(uint8_t* node, float offset)
    {
        __try
        {
            if (node[NODE_SCROLL_STATE] != 0)
                return;
            *reinterpret_cast<float*>(node + NODE_SCROLL_POS) = offset;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    uint8_t AuthoredBlockAlign(void* node, uint8_t current)
    {
        std::lock_guard<std::mutex> lock(gAuthoredMutex);
        auto it = gAuthoredBlockAlign.find(node);
        if (it != gAuthoredBlockAlign.end())
            return it->second;
        if (gAuthoredBlockAlign.size() >= MAX_AUTHORED)
            return current == ALIGN_RIGHT ? ALIGN_LEFT : current;
        gAuthoredBlockAlign.emplace(node, current);
        return current;
    }

    void AlignRow(int rowClass, const RowState& row, bool selected)
    {
        const uint8_t authored = AuthoredBlockAlign(row.node, row.blockAlign);
        const float displayWidth = DisplayWidth(row.node);
        if (displayWidth <= 0.0f || row.textWidth <= 0.0f)
            return;

        if (!gLogged[rowClass])
        {
            gLogged[rowClass] = true;
            Log("[fox::uix::UixUtility] Arabic %s rows mirrored (first node %p: authored block align %u, text %.1f of %.1f)\n",
                gRows[rowClass].name, row.node, static_cast<unsigned>(authored), row.textWidth, displayWidth);
        }

        if (row.textWidth <= displayWidth)
        {
            ArabicScrollUnstampRtlNode(row.node);
            SetAlign(row.node, ALIGN_RIGHT, ALIGN_RIGHT);
            return;
        }

        SetAlign(row.node, -1, authored);
        if (!selected)
        {
            ArabicScrollUnstampRtlNode(row.node);
            ShowLineStart(row.node, row.textWidth - displayWidth);
            return;
        }
        ArabicScrollStampRtlNode(row.node);
    }

    void __fastcall hkRefresh(void* uix, uint8_t* record, uint8_t selected, uint8_t index)
    {
        oRefresh(uix, record, selected, index);
        if (!record || index != 0 || !IsArabicSafe())
            return;

        RowState row{};
        const int rowClass = FindRowClass(record, row);
        if (rowClass >= 0)
            AlignRow(rowClass, row, selected != 0);
    }

    uintptr_t ResolveVa(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE);
    }

    void AddRow(HMODULE hGame, uintptr_t vtable, size_t titleNode, const char* name)
    {
        if (vtable && gRowCount < sizeof(gRows) / sizeof(gRows[0]))
            gRows[gRowCount++] = { ResolveVa(hGame, vtable), titleNode, name };
    }
}

bool InstallUixUtilityArabicRecordRowsHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.UixUtility_RefreshRecordTextScroll || !gAddr.ModelNodeText_GetDisplayWidth)
    {
        Log("[fox::uix::UixUtility] address missing - list rows keep the stock layout.\n");
        return true;
    }

    gRowCount = 0;
    AddRow(hGame, gAddr.CombatDeployMissionListRecord_Vtable, 0x60, "combat deploy mission");
    AddRow(hGame, gAddr.ChallengeTaskListRecord_Vtable, 0x1F8, "challenge task");
    AddRow(hGame, gAddr.MbDvcMissionListRecord_Vtable, 0xF8, "mission list");
    if (gRowCount == 0)
        return true;

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(ResolveVa(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    void* target = reinterpret_cast<void*>(ResolveVa(hGame, gAddr.UixUtility_RefreshRecordTextScroll));
    if (!CodeMatches(target, kRefreshPrologue, sizeof(kRefreshPrologue)) ||
        !CodeMatches(reinterpret_cast<void*>(gGetDisplayWidth), kDisplayWidthPrologue, sizeof(kDisplayWidthPrologue)))
    {
        Log("[fox::uix::UixUtility] prologue mismatch at %p - list rows keep the stock layout.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkRefresh), reinterpret_cast<void**>(&oRefresh)) != MH_OK)
    {
        Log("[fox::uix::UixUtility] MH_CreateHook failed - list rows keep the stock layout.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[fox::uix::UixUtility] MH_EnableHook failed - list rows keep the stock layout.\n");
        return true;
    }
    gTarget = target;
    Log("[fox::uix::UixUtility] Arabic record rows (combat deploy missions, challenge tasks, mission list) hooked at %p.\n", target);
    return true;
}

void RemoveUixUtilityArabicRecordRowsHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oRefresh = nullptr;
    gGetDisplayWidth = nullptr;
    gIsArabLanguage = nullptr;
    gRowCount = 0;
    gLogged[0] = gLogged[1] = gLogged[2] = false;
    std::lock_guard<std::mutex> lock(gAuthoredMutex);
    gAuthoredBlockAlign.clear();
}
