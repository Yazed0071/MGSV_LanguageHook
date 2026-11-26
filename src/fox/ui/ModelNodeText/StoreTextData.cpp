#include <windows.h>
#include <cstdint>
#include <atomic>
#include <cfloat>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

using IsArabLanguage_t = bool(__cdecl*)();
using StoreTextData_t = uint64_t(__fastcall*)(
    uint8_t* node,
    uint8_t* unit,
    float fontWidth,
    float fontHeight,
    float spacing,
    float lineGap,
    char measureOnly,
    float* pen,
    float* lineHeight,
    uint8_t* entry);
using SetupRubyFontGroupInfo_t = void(__fastcall*)(uint8_t* node, uint8_t* info);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static StoreTextData_t oStoreTextData = nullptr;
static void* gTargetStoreTextData = nullptr;
static SetupRubyFontGroupInfo_t oSetupRubyFontGroupInfo = nullptr;
static void* gTargetSetupRubyFontGroupInfo = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static const uint8_t kStoreTextDataPrologue[] = {
    0x48, 0x8B, 0xC4, 0xF3, 0x0F, 0x11, 0x58, 0x20, 0xF3, 0x0F, 0x11, 0x50, 0x18, 0x55, 0x53, 0x56, 0x57,
};
static const uint8_t kSetupRubyFontGroupInfoStub[] = { 0xE9 };

static constexpr size_t NODE_FLAGS = 0x90;
static constexpr size_t NODE_ALT_FONT = 0xA0;
static constexpr size_t NODE_FONT = 0xA8;
static constexpr size_t NODE_RUBY_FONT = 0xB0;
static constexpr size_t NODE_VERTEX_COUNT = 0x108;
static constexpr size_t NODE_VERTEX_POS = 0x110;
static constexpr uint16_t NODE_RUBY_CENTRED = 0x1;
static constexpr uint16_t NODE_USE_ALT_FONT = 0x200;

static constexpr size_t UNIT_SIZE = 0x20;
static constexpr size_t UNIT_FLAGS = 0x0C;
static constexpr size_t UNIT_WIDTH = 0x14;
static constexpr size_t UNIT_HEIGHT = 0x18;
static constexpr size_t UNIT_LINE = 0x12;
static constexpr uint32_t UNIT_LAST = 0x2;
static constexpr uint32_t UNIT_LINE_START = 0x4;
static constexpr uint32_t UNIT_RUBY_BASE = 0x10;
static constexpr uint32_t UNIT_RUBY = 0x20;
static constexpr uint32_t UNIT_SPREAD = 0x400;

static constexpr size_t ENTRY_X = 0x10;
static constexpr size_t ENTRY_HEIGHT = 0x18;

static constexpr float DEFAULT_FONT_HEIGHT = 20.0f;
static constexpr float RUBY_CLEARANCE = 0.06f;
static constexpr float RUBY_SCALE = 0.7f;
static constexpr float RUBY_GAP = 0.25f;

struct RubyFontGroup
{
    uint64_t font;
    float width;
    float height;
    float spacing;
    float gap;
    uint8_t spare[0x28];
};

struct RubyBase
{
    const uint8_t* node;
    float dropOnScreen;
};

struct RubyMetrics
{
    float gap;
    float baseSize;
    float baseHeight;
    float rubyHeight;
};

struct RubyRow
{
    const uint8_t* node;
    uint16_t line;
    float lastRight;
    float neededEnd;
    bool active;
};

static thread_local RubyBase tRubyBase{};
static thread_local RubyRow tRubyRow{};
static std::mutex gCentredMtx;
static std::unordered_set<const uint8_t*> gCentredNodes;
static std::atomic<bool> gAnyCentred{ false };
static std::atomic<int> gRubyLogBudget{ 4 };
static std::mutex gGroupMtx;
static std::unordered_map<const uint8_t*, RubyFontGroup> gRubyGroups;
static std::atomic<bool> gLoggedRubyGroup{ false };

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static bool IsArabicSafe()
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

static bool ReadUnitFlags(const uint8_t* unit, uint32_t& flags)
{
    __try
    {
        flags = *reinterpret_cast<const uint32_t*>(unit + UNIT_FLAGS);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadNodeFlags(const uint8_t* node, uint16_t& flags)
{
    __try
    {
        flags = *reinterpret_cast<const uint16_t*>(node + NODE_FLAGS);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool SetNodeCentred(uint8_t* node, bool centred)
{
    __try
    {
        uint16_t* flags = reinterpret_cast<uint16_t*>(node + NODE_FLAGS);
        *flags = centred ? static_cast<uint16_t>(*flags | NODE_RUBY_CENTRED)
                         : static_cast<uint16_t>(*flags & ~NODE_RUBY_CENTRED);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void CentreRubyOnNode(uint8_t* node, uint16_t nodeFlags)
{
    if (nodeFlags & NODE_RUBY_CENTRED)
        return;
    if (!SetNodeCentred(node, true))
        return;
    std::lock_guard<std::mutex> lk(gCentredMtx);
    gCentredNodes.insert(node);
    gAnyCentred.store(true);
}

static void ReleaseCentredNode(uint8_t* node)
{
    if (!gAnyCentred.load())
        return;
    {
        std::lock_guard<std::mutex> lk(gCentredMtx);
        if (gCentredNodes.erase(node) == 0)
            return;
        gAnyCentred.store(!gCentredNodes.empty());
    }
    SetNodeCentred(node, false);
}

static bool ClearSpread(uint8_t* unit)
{
    __try
    {
        uint32_t* baseFlags = reinterpret_cast<uint32_t*>(unit + UNIT_FLAGS);
        uint32_t* rubyFlags = reinterpret_cast<uint32_t*>(unit + UNIT_SIZE + UNIT_FLAGS);
        if (!(*rubyFlags & UNIT_RUBY))
            return false;
        *baseFlags &= ~UNIT_SPREAD;
        *rubyFlags &= ~UNIT_SPREAD;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadRubyMetrics(const uint8_t* node, uint16_t nodeFlags, const uint8_t* unit, RubyMetrics& out)
{
    __try
    {
        const uint8_t* alt = (nodeFlags & NODE_USE_ALT_FONT)
                                 ? *reinterpret_cast<const uint8_t* const*>(node + NODE_ALT_FONT)
                                 : nullptr;
        const uint8_t* font = *reinterpret_cast<const uint8_t* const*>(node + NODE_FONT);
        const uint8_t* ruby = *reinterpret_cast<const uint8_t* const*>(node + NODE_RUBY_FONT);

        if (ruby)
            out.gap = *reinterpret_cast<const float*>(ruby + 0x14);
        else if (alt)
            out.gap = *reinterpret_cast<const float*>(alt + 0x0C);
        else
            out.gap = font ? *reinterpret_cast<const float*>(font + 0x14) : 0.0f;

        if (alt)
            out.baseSize = *reinterpret_cast<const float*>(alt + 0x04);
        else
            out.baseSize = font ? *reinterpret_cast<const float*>(font + 0x0C) : DEFAULT_FONT_HEIGHT;

        out.baseHeight = *reinterpret_cast<const float*>(unit + UNIT_HEIGHT);
        out.rubyHeight = *reinterpret_cast<const float*>(unit + UNIT_SIZE + UNIT_HEIGHT);
        return out.baseSize > 0.0f;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool WriteEntryHeight(uint8_t* entry, float height)
{
    __try
    {
        *reinterpret_cast<float*>(entry + ENTRY_HEIGHT) = height;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static float RubyOverhang(const uint8_t* unit)
{
    __try
    {
        const float base = *reinterpret_cast<const float*>(unit + UNIT_WIDTH);
        const float ruby = *reinterpret_cast<const float*>(unit + UNIT_SIZE + UNIT_WIDTH);
        return ruby > base ? (ruby - base) * 0.5f : 0.0f;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0.0f;
    }
}

static bool ReadUnitLine(const uint8_t* unit, uint16_t& line)
{
    __try
    {
        line = *reinterpret_cast<const uint16_t*>(unit + UNIT_LINE);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool EndsLine(const uint8_t* unit)
{
    __try
    {
        if (*reinterpret_cast<const uint32_t*>(unit + UNIT_FLAGS) & UNIT_LAST)
            return true;
        return (*reinterpret_cast<const uint32_t*>(unit + UNIT_SIZE + UNIT_FLAGS) & UNIT_LINE_START) != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
}

static void CloseRubyRow(const uint8_t* node, const uint8_t* unit, float* pen)
{
    if (!tRubyRow.active || tRubyRow.node != node || !pen || !EndsLine(unit))
        return;
    if (tRubyRow.neededEnd > *pen)
        *pen = tRubyRow.neededEnd;
    tRubyRow = {};
}

static bool ShiftEntry(uint8_t* entry, float by)
{
    __try
    {
        *reinterpret_cast<float*>(entry + ENTRY_X) += by;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool LowerQuads(uint8_t* node, uint32_t first, uint32_t end, float drop)
{
    __try
    {
        float* pos = *reinterpret_cast<float* const*>(node + NODE_VERTEX_POS);
        if (!pos)
            return false;
        for (uint32_t v = first; v < end; ++v)
            pos[static_cast<size_t>(v) * 2 + 1] -= drop;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static uint32_t VertexCount(const uint8_t* node)
{
    __try
    {
        return *reinterpret_cast<const uint32_t*>(node + NODE_VERTEX_COUNT);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static bool ReadScaledBaseGroup(const uint8_t* node, RubyFontGroup& out)
{
    __try
    {
        const uint16_t flags = *reinterpret_cast<const uint16_t*>(node + NODE_FLAGS);
        const uint8_t* font = *reinterpret_cast<const uint8_t* const*>(node + NODE_FONT);
        if (!font)
            return false;
        const uint8_t* alt =
            (flags & NODE_USE_ALT_FONT) ? *reinterpret_cast<const uint8_t* const*>(node + NODE_ALT_FONT) : nullptr;
        const float* sizes = reinterpret_cast<const float*>(alt ? alt : font + 0x08);
        out.font = *reinterpret_cast<const uint64_t*>(font);
        out.width = sizes[0] * RUBY_SCALE;
        out.height = sizes[1] * RUBY_SCALE;
        out.spacing = sizes[2] * RUBY_SCALE;
        out.gap = sizes[3];
        return out.width > 0.0f && out.height > 0.0f;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadRubySlot(const uint8_t* node, const void*& current)
{
    __try
    {
        current = *reinterpret_cast<const void* const*>(node + NODE_RUBY_FONT);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool WriteRubySlot(uint8_t* node, const void* value)
{
    __try
    {
        *reinterpret_cast<const void**>(node + NODE_RUBY_FONT) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static RubyFontGroup* RubyGroupFor(const uint8_t* node, bool create)
{
    std::lock_guard<std::mutex> lk(gGroupMtx);
    const auto it = gRubyGroups.find(node);
    if (it != gRubyGroups.end())
        return &it->second;
    return create ? &gRubyGroups[node] : nullptr;
}

static void ApplyArabicRubyGroup(uint8_t* node, bool arabic)
{
    const void* current = nullptr;
    if (!ReadRubySlot(node, current))
        return;

    RubyFontGroup* mine = RubyGroupFor(node, false);
    if (!arabic)
    {
        if (mine && current == mine)
            WriteRubySlot(node, nullptr);
        return;
    }
    if (current && current != mine)
        return;

    RubyFontGroup scaled{};
    if (!ReadScaledBaseGroup(node, scaled))
        return;
    if (!mine)
        mine = RubyGroupFor(node, true);

    mine->font = scaled.font;
    mine->width = scaled.width;
    mine->height = scaled.height;
    mine->spacing = scaled.spacing;
    mine->gap = scaled.gap;
    if (current != mine && WriteRubySlot(node, mine) && !gLoggedRubyGroup.exchange(true))
        Log("[ModelNodeText::SetupRubyFontGroupInfo] Arabic ruby drawn at %.0f%% of the text size (%.1f)\n",
            RUBY_SCALE * 100.0f, scaled.height);
}

static void __fastcall hkSetupRubyFontGroupInfo(uint8_t* node, uint8_t* info)
{
    if (node)
        ApplyArabicRubyGroup(node, IsArabicSafe());
    oSetupRubyFontGroupInfo(node, info);
}

static uint64_t StoreRubyBase(
    uint8_t* node, uint16_t nodeFlags, uint8_t* unit, float fontWidth, float fontHeight, float spacing,
    float lineGap, char measureOnly, float* pen, float* lineHeight, uint8_t* entry)
{
    RubyMetrics m{};
    if (!lineHeight || !ClearSpread(unit) || !ReadRubyMetrics(node, nodeFlags, unit, m))
        return oStoreTextData(node, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen, lineHeight,
                              entry);

    CentreRubyOnNode(node, nodeFlags);

    uint16_t line = 0;
    ReadUnitLine(unit, line);
    if (!tRubyRow.active || tRubyRow.node != node || tRubyRow.line != line)
        tRubyRow = { node, line, -FLT_MAX, 0.0f, true };

    const float overhang = RubyOverhang(unit);
    float shift = 0.0f;
    if (pen)
    {
        const float clear = tRubyRow.lastRight + m.baseSize * RUBY_GAP;
        if (*pen - overhang < clear)
            shift = clear - (*pen - overhang);
    }
    if (shift > 0.0f && (!entry || !ShiftEntry(entry, shift)))
        shift = 0.0f;
    if (shift > 0.0f)
        *pen += shift;

    const float before = *lineHeight;
    const uint64_t result =
        oStoreTextData(node, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen, lineHeight, entry);
    if (!result)
        return result;
    if (pen)
    {
        tRubyRow.lastRight = *pen + overhang;
        if (tRubyRow.lastRight > tRubyRow.neededEnd)
            tRubyRow.neededEnd = tRubyRow.lastRight;
    }

    const float lift = m.baseSize * (1.0f + RUBY_CLEARANCE);
    const float reserved = lift + m.rubyHeight;
    if (measureOnly)
    {
        WriteEntryHeight(entry, lift - m.gap);
        float height = before > m.baseHeight ? before : m.baseHeight;
        *lineHeight = height > reserved ? height : reserved;
    }
    else if (*lineHeight < reserved)
    {
        *lineHeight = reserved;
    }

    tRubyBase = { node, m.gap + m.baseSize - lift };

    if (gRubyLogBudget.load() > 0)
    {
        gRubyLogBudget.fetch_sub(1);
        Log("[ModelNodeText::StoreTextData] Arabic ruby: font %.1f, engine lift %.1f -> %.1f, line %.1f -> %.1f, "
            "ruby %.1f wider each side, base moved %.1f to clear the previous ruby%s\n",
            m.baseSize, m.gap + (measureOnly ? m.baseHeight : m.baseSize), lift, before, *lineHeight, overhang, shift,
            measureOnly ? "" : " (vertex path)");
    }
    return result;
}

static uint64_t __fastcall hkStoreTextData(
    uint8_t* node,
    uint8_t* unit,
    float fontWidth,
    float fontHeight,
    float spacing,
    float lineGap,
    char measureOnly,
    float* pen,
    float* lineHeight,
    uint8_t* entry)
{
    uint32_t flags = 0;
    uint16_t nodeFlags = 0;
    if (!node || !unit || !ReadUnitFlags(unit, flags) || !(flags & (UNIT_RUBY_BASE | UNIT_RUBY)) ||
        !ReadNodeFlags(node, nodeFlags))
    {
        tRubyBase = {};
        const uint64_t result =
            oStoreTextData(node, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen, lineHeight, entry);
        if (result && tRubyRow.active)
            CloseRubyRow(node, unit, pen);
        return result;
    }

    if (!IsArabicSafe())
    {
        tRubyBase = {};
        tRubyRow = {};
        ReleaseCentredNode(node);
        return oStoreTextData(node, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen, lineHeight,
                              entry);
    }

    if (flags & UNIT_RUBY_BASE)
    {
        tRubyBase = {};
        return StoreRubyBase(node, nodeFlags, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen,
                             lineHeight, entry);
    }

    const RubyBase base = tRubyBase;
    tRubyBase = {};
    const uint32_t first = measureOnly ? 0 : VertexCount(node);
    const float before = lineHeight ? *lineHeight : 0.0f;
    const uint64_t result =
        oStoreTextData(node, unit, fontWidth, fontHeight, spacing, lineGap, measureOnly, pen, lineHeight, entry);
    if (result && base.node == node && lineHeight)
    {
        *lineHeight = before;
        if (!measureOnly)
            LowerQuads(node, first, VertexCount(node), base.dropOnScreen);
    }
    if (result)
        CloseRubyRow(node, unit, pen);
    return result;
}

static bool CodeMatches(const void* target, const uint8_t* expected, size_t size)
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

bool InstallArabicRubyLayoutHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.StoreTextData)
    {
        Log("[ModelNodeText::StoreTextData] address missing - ruby keeps the engine layout.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.StoreTextData));
    if (!CodeMatches(target, kStoreTextDataPrologue, sizeof(kStoreTextDataPrologue)))
    {
        Log("[ModelNodeText::StoreTextData] code is not what this build should have - not hooked.\n");
        return true;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkStoreTextData),
                      reinterpret_cast<void**>(&oStoreTextData)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[ModelNodeText::StoreTextData] hook failed.\n");
        return false;
    }

    gTargetStoreTextData = target;
    Log("[ModelNodeText::StoreTextData] Arabic ruby centred just above its base, no letter spreading.\n");

    void* setup = gAddr.SetupRubyFontGroupInfo
                      ? reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetupRubyFontGroupInfo))
                      : nullptr;
    if (!setup || !CodeMatches(setup, kSetupRubyFontGroupInfoStub, sizeof(kSetupRubyFontGroupInfoStub)))
    {
        Log("[ModelNodeText::SetupRubyFontGroupInfo] code is not what this build should have - ruby keeps half size.\n");
        return true;
    }
    if (MH_CreateHook(setup, reinterpret_cast<void*>(&hkSetupRubyFontGroupInfo),
                      reinterpret_cast<void**>(&oSetupRubyFontGroupInfo)) != MH_OK ||
        MH_EnableHook(setup) != MH_OK)
    {
        Log("[ModelNodeText::SetupRubyFontGroupInfo] hook failed.\n");
        return true;
    }
    gTargetSetupRubyFontGroupInfo = setup;
    return true;
}

void RemoveArabicRubyLayoutHook()
{
    if (gTargetSetupRubyFontGroupInfo)
    {
        MH_DisableHook(gTargetSetupRubyFontGroupInfo);
        MH_RemoveHook(gTargetSetupRubyFontGroupInfo);
        gTargetSetupRubyFontGroupInfo = nullptr;
    }

    {
        std::lock_guard<std::mutex> lk(gGroupMtx);
        for (auto& entry : gRubyGroups)
        {
            const void* current = nullptr;
            uint8_t* node = const_cast<uint8_t*>(entry.first);
            if (ReadRubySlot(node, current) && current == &entry.second)
                WriteRubySlot(node, nullptr);
        }
    }

    if (gTargetStoreTextData)
    {
        MH_DisableHook(gTargetStoreTextData);
        MH_RemoveHook(gTargetStoreTextData);
        gTargetStoreTextData = nullptr;
    }

    {
        std::lock_guard<std::mutex> lk(gCentredMtx);
        for (const uint8_t* node : gCentredNodes)
            SetNodeCentred(const_cast<uint8_t*>(node), false);
        gCentredNodes.clear();
        gAnyCentred.store(false);
    }

    oStoreTextData = nullptr;
    oSetupRubyFontGroupInfo = nullptr;
    gIsArabLanguage = nullptr;
}
