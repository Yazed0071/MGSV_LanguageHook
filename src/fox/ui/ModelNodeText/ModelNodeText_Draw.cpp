#include "pch.h"
#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void DriveStalledArabicScroll(void* node);
bool ArabicMarqueeOverflowing(void* node);
void AuditArabicTextNode(uint8_t* node);
void CloseArabicTextAudit();

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using ModelNodeTextDraw_t = void(__fastcall*)(uint8_t* node, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                                                  uint64_t a6, uint64_t a7);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_FLAGS = 0x90;
    constexpr size_t OFF_ALIGN = 0xD8;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t TEXT_ALIGN_RIGHT = 2;
    constexpr size_t MAX_LEASED_NODES = 16;

    const uint8_t kDrawPrologue[] = {
        0x48, 0x8B, 0xC4, 0x55, 0x53, 0x57, 0x48, 0x8D, 0x68, 0xD8, 0x48, 0x81, 0xEC, 0x10, 0x01, 0x00, 0x00,
    };

    struct LeasedNode
    {
        std::atomic<void*> node{ nullptr };
        std::atomic<uint64_t> until{ 0 };
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    ModelNodeTextDraw_t oDraw = nullptr;
    void* gTarget = nullptr;

    std::array<LeasedNode, MAX_LEASED_NODES> gLeased{};
    std::atomic<size_t> gNextSlot{ 0 };
    std::atomic<uint64_t> gLatestLease{ 0 };
    std::atomic<int> gFixLogBudget{ 6 };

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

    constexpr uint64_t LANGUAGE_RECHECK_MS = 100;
    std::atomic<uint64_t> gLanguageCheckedAt{ 0 };
    std::atomic<bool> gLanguageIsArabic{ false };

    bool IsArabicThisFrame()
    {
        const uint64_t now = GetTickCount64();
        if (now - gLanguageCheckedAt.load(std::memory_order_relaxed) < LANGUAGE_RECHECK_MS)
            return gLanguageIsArabic.load(std::memory_order_relaxed);
        const bool arabic = IsArabicSafe();
        gLanguageIsArabic.store(arabic, std::memory_order_relaxed);
        gLanguageCheckedAt.store(now, std::memory_order_relaxed);
        return arabic;
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

    bool IsLeased(const void* node, uint64_t now)
    {
        for (const LeasedNode& slot : gLeased)
        {
            if (slot.node.load(std::memory_order_relaxed) == node)
                return slot.until.load(std::memory_order_relaxed) >= now;
        }
        return false;
    }

    bool ForceRightAndRebuild(uint8_t* node, uint8_t& was)
    {
        __try
        {
            was = node[OFF_ALIGN];
            if (was == TEXT_ALIGN_RIGHT)
                return false;
            node[OFF_ALIGN] = TEXT_ALIGN_RIGHT;
            *reinterpret_cast<uint16_t*>(node + OFF_FLAGS) |= FLAG_REBUILD;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    constexpr uint16_t FLAG_STENCIL = 0x2;
    constexpr size_t OFF_UNITS = 0x138;
    constexpr size_t OFF_UNIT_COUNT = 0x140;
    constexpr size_t OFF_LINE_HEIGHT_COUNT = 0x168;
    constexpr size_t OFF_LINE_HEIGHT_DATA = 0x170;
    constexpr size_t OFF_TEXT_HEIGHT = 0x178;
    constexpr size_t OFF_AREA_HEIGHT = 0xEC;
    constexpr size_t OFF_STENCIL_TOP = 0x1B8;
    constexpr size_t UNIT_STRIDE = 0x20;
    constexpr size_t UNIT_FLAGS = 0x0C;
    constexpr size_t UNIT_LINE = 0x12;
    constexpr size_t UNIT_HEIGHT = 0x18;
    constexpr uint32_t UNIT_RUBY_BASE = 0x10 | 0x40;
    constexpr uint32_t MAX_SCANNED_UNITS = 256;
    constexpr uint32_t MAX_RUBY_LINES = 32;
    constexpr size_t MAX_STENCIL_NODES = 16;

    struct StencilNode
    {
        uint8_t* node;
        float authored;
    };

    StencilNode gStencilNodes[MAX_STENCIL_NODES] = {};
    std::atomic<bool> gStencilLogged{ false };

    bool ReadFlags(const uint8_t* node, uint16_t& flags)
    {
        __try
        {
            flags = *reinterpret_cast<const uint16_t*>(node + OFF_FLAGS);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    float RubyExtraHeight(const uint8_t* node)
    {
        __try
        {
            const uint8_t* units = *reinterpret_cast<const uint8_t* const*>(node + OFF_UNITS);
            const uint32_t count = *reinterpret_cast<const uint32_t*>(node + OFF_UNIT_COUNT);
            const uint32_t lines = *reinterpret_cast<const uint32_t*>(node + OFF_LINE_HEIGHT_COUNT);
            const float* heights = *reinterpret_cast<const float* const*>(node + OFF_LINE_HEIGHT_DATA);
            if (!units || !heights || count == 0 || count > MAX_SCANNED_UNITS || lines == 0)
                return 0.0f;
            float extraPerLine[MAX_RUBY_LINES] = {};
            for (uint32_t u = 0; u < count; ++u)
            {
                const uint8_t* unit = units + static_cast<size_t>(u) * UNIT_STRIDE;
                if (!(*reinterpret_cast<const uint32_t*>(unit + UNIT_FLAGS) & UNIT_RUBY_BASE))
                    continue;
                const uint16_t line = *reinterpret_cast<const uint16_t*>(unit + UNIT_LINE);
                if (line >= lines || line >= MAX_RUBY_LINES)
                    continue;
                const float extra = heights[line] - *reinterpret_cast<const float*>(unit + UNIT_HEIGHT);
                if (extra > extraPerLine[line])
                    extraPerLine[line] = extra;
            }
            float total = 0.0f;
            for (float extra : extraPerLine)
                total += extra;
            return total;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0.0f;
        }
    }

    StencilNode* StencilEntry(uint8_t* node, bool create)
    {
        for (StencilNode& entry : gStencilNodes)
        {
            if (entry.node == node)
                return &entry;
        }
        if (!create)
            return nullptr;
        for (StencilNode& entry : gStencilNodes)
        {
            if (!entry.node)
            {
                __try
                {
                    entry = { node, *reinterpret_cast<const float*>(node + OFF_STENCIL_TOP) };
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return nullptr;
                }
                return &entry;
            }
        }
        return nullptr;
    }

    void WriteStencilTop(uint8_t* node, float value)
    {
        __try
        {
            *reinterpret_cast<float*>(node + OFF_STENCIL_TOP) = value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void LogStencil(const uint8_t* node, float extra, float authored)
    {
        if (gStencilLogged.exchange(true))
            return;
        float area = 0.0f, text = 0.0f;
        __try
        {
            area = *reinterpret_cast<const float*>(node + OFF_AREA_HEIGHT);
            text = *reinterpret_cast<const float*>(node + OFF_TEXT_HEIGHT);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        Log("[fox::ui::ModelNodeText::Draw] Arabic ruby text %p clips to its box (area height %.1f, text %.1f): "
            "clip raised by %.1f for the ruby rows (was %.1f)\n",
            node, area, text, extra, authored);
    }

    void KeepRubyLinesInsideStencil(uint8_t* node)
    {
        uint16_t flags = 0;
        if (!ReadFlags(node, flags) || !(flags & FLAG_STENCIL))
            return;
        const float extra = RubyExtraHeight(node);
        StencilNode* entry = StencilEntry(node, extra > 0.0f);
        if (!entry)
            return;
        if (extra > 0.0f)
        {
            WriteStencilTop(node, entry->authored + extra);
            LogStencil(node, extra, entry->authored);
            return;
        }
        WriteStencilTop(node, entry->authored);
        entry->node = nullptr;
    }

    void PutBackAuthoredStencil(uint8_t* node)
    {
        if (StencilNode* entry = StencilEntry(node, false))
        {
            WriteStencilTop(node, entry->authored);
            entry->node = nullptr;
        }
    }

    using SetTextAlign_t = void(__fastcall*)(void* uix, uint8_t* node, uint8_t align);

    constexpr size_t OFF_DATA = 0x60;
    constexpr size_t OFF_DATA_FLAGS = 0x4;
    constexpr size_t OFF_NAME = 0x6C;
    constexpr size_t OFF_BLOCK_ALIGN = 0xDA;
    constexpr size_t ALIGN_TABLE_SIZE = 1024;
    constexpr size_t ALIGN_TABLE_SHIFT = 54;
    constexpr size_t ALIGN_TABLE_PROBES = 16;
    constexpr uint8_t BLOCK_FOLLOWS_LINE = 3;
    constexpr uint8_t ALIGN_UNKNOWN = 0xFF;

    const uint8_t kSetTextAlignBody[] = {
        0x48, 0x85, 0xD2, 0x74, 0x07, 0x44, 0x88, 0x82, 0xD8, 0x00, 0x00, 0x00,
    };

    struct GameAlign
    {
        uint8_t* node;
        uint32_t name;
        uint8_t line;
    };

    struct ArabicAlignedNode
    {
        uint8_t* node;
        uint32_t name;
        uint64_t seen;
        uint8_t line;
        uint8_t block;
    };

    struct NodeAlign
    {
        uint32_t name;
        uint16_t flags;
        uint8_t line;
        uint8_t block;
        uint8_t originLine;
        uint8_t originBlock;
    };

    uint8_t* const REMOVED_NODE = reinterpret_cast<uint8_t*>(1);

    SRWLOCK gAlignLock = SRWLOCK_INIT;
    GameAlign gGameAligns[ALIGN_TABLE_SIZE] = {};
    ArabicAlignedNode gArabicAligned[ALIGN_TABLE_SIZE] = {};
    std::atomic<int> gArabicAlignedCount{ 0 };
    std::atomic<int> gRestoreLogBudget{ 8 };
    std::atomic<bool> gTableFullLogged{ false };
    SetTextAlign_t oSetTextAlign = nullptr;
    uintptr_t* gSetTextAlignSlot = nullptr;

    size_t AlignBucket(const void* node)
    {
        return static_cast<size_t>((reinterpret_cast<uintptr_t>(node) >> 4) * 0x9E3779B97F4A7C15ull >>
                                   ALIGN_TABLE_SHIFT);
    }

    bool ReadNodeAlign(const uint8_t* node, NodeAlign& out)
    {
        __try
        {
            out.name = *reinterpret_cast<const uint32_t*>(node + OFF_NAME);
            out.flags = *reinterpret_cast<const uint16_t*>(node + OFF_FLAGS);
            out.line = node[OFF_ALIGN];
            out.block = node[OFF_BLOCK_ALIGN];
            out.originLine = 0;
            out.originBlock = BLOCK_FOLLOWS_LINE;
            const uint8_t* data = *reinterpret_cast<const uint8_t* const*>(node + OFF_DATA);
            if (!data)
                return true;
            const uint32_t bits = *reinterpret_cast<const uint32_t*>(data + OFF_DATA_FLAGS);
            if (bits & (1u << 20))
                out.originLine = 0;
            else if (bits & (1u << 21))
                out.originLine = 1;
            else if (bits & (1u << 22))
                out.originLine = 2;
            if (!(bits & (1u << 26)))
                out.originBlock = BLOCK_FOLLOWS_LINE;
            else if (bits & (1u << 27))
                out.originBlock = 0;
            else if (bits & (1u << 28))
                out.originBlock = 1;
            else if (bits & (1u << 29))
                out.originBlock = 2;
            else
                out.originBlock = ALIGN_UNKNOWN;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void WriteNodeAlign(uint8_t* node, uint8_t line, uint8_t block)
    {
        __try
        {
            node[OFF_ALIGN] = line;
            if (block != ALIGN_UNKNOWN)
                node[OFF_BLOCK_ALIGN] = block;
            *reinterpret_cast<uint16_t*>(node + OFF_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    bool FindGameLineAlign(const uint8_t* node, uint32_t name, uint8_t& line)
    {
        const size_t home = AlignBucket(node);
        for (size_t i = 0; i < ALIGN_TABLE_PROBES; ++i)
        {
            const GameAlign& entry = gGameAligns[(home + i) % ALIGN_TABLE_SIZE];
            if (entry.node == node)
            {
                if (entry.name != name)
                    return false;
                line = entry.line;
                return true;
            }
            if (!entry.node)
                return false;
        }
        return false;
    }

    void RememberGameLineAlign(uint8_t* node, uint32_t name, uint8_t line)
    {
        const size_t home = AlignBucket(node);
        GameAlign* free = nullptr;
        for (size_t i = 0; i < ALIGN_TABLE_PROBES; ++i)
        {
            GameAlign& entry = gGameAligns[(home + i) % ALIGN_TABLE_SIZE];
            if (entry.node == node)
            {
                entry.name = name;
                entry.line = line;
                return;
            }
            if (!entry.node)
            {
                if (!free)
                    free = &entry;
                break;
            }
        }
        if (!free)
            free = &gGameAligns[home];
        *free = { node, name, line };
    }

    ArabicAlignedNode* FindArabicAligned(const uint8_t* node)
    {
        const size_t home = AlignBucket(node);
        for (size_t i = 0; i < ALIGN_TABLE_PROBES; ++i)
        {
            ArabicAlignedNode& entry = gArabicAligned[(home + i) % ALIGN_TABLE_SIZE];
            if (entry.node == node)
                return &entry;
            if (!entry.node)
                return nullptr;
        }
        return nullptr;
    }

    void ForgetArabicAligned(ArabicAlignedNode* entry)
    {
        entry->node = REMOVED_NODE;
        entry->name = 0;
        entry->seen = 0;
        gArabicAlignedCount.fetch_sub(1, std::memory_order_relaxed);
    }

    void RememberArabicAligned(uint8_t* node, uint32_t name, uint64_t now, uint8_t line, uint8_t block)
    {
        if (ArabicAlignedNode* entry = FindArabicAligned(node))
        {
            entry->name = name;
            entry->seen = now;
            entry->line = line;
            entry->block = block;
            return;
        }
        const size_t home = AlignBucket(node);
        ArabicAlignedNode* oldest = nullptr;
        for (size_t i = 0; i < ALIGN_TABLE_PROBES; ++i)
        {
            ArabicAlignedNode& entry = gArabicAligned[(home + i) % ALIGN_TABLE_SIZE];
            if (!entry.node || entry.node == REMOVED_NODE)
            {
                entry = { node, name, now, line, block };
                gArabicAlignedCount.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (!oldest || entry.seen < oldest->seen)
                oldest = &entry;
        }
        if (!gTableFullLogged.exchange(true))
            Log("[fox::ui::ModelNodeText::Draw] Arabic-aligned node list is full - the oldest entries are dropped.\n");
        *oldest = { node, name, now, line, block };
    }

    uint8_t GameLineAlign(const uint8_t* node, const NodeAlign& align)
    {
        uint8_t line = align.originLine;
        FindGameLineAlign(node, align.name, line);
        return line;
    }

    bool IsGameMarquee(const NodeAlign& align)
    {
        return (align.flags & FLAG_STENCIL) && align.line == 0;
    }

    bool DiffersFromGame(const NodeAlign& align, uint8_t gameLine)
    {
        if (align.line != gameLine)
            return true;
        return align.originBlock != ALIGN_UNKNOWN && align.block != align.originBlock;
    }

    void NoteArabicAlignment(uint8_t* node)
    {
        NodeAlign align{};
        if (!ReadNodeAlign(node, align) || IsGameMarquee(align))
            return;
        AcquireSRWLockExclusive(&gAlignLock);
        const uint8_t gameLine = GameLineAlign(node, align);
        if (DiffersFromGame(align, gameLine))
            RememberArabicAligned(node, align.name, GetTickCount64(), align.line, align.block);
        else if (gArabicAlignedCount.load(std::memory_order_relaxed) > 0)
        {
            if (ArabicAlignedNode* entry = FindArabicAligned(node))
                ForgetArabicAligned(entry);
        }
        ReleaseSRWLockExclusive(&gAlignLock);
    }

    void PutBackGameAlignment(uint8_t* node)
    {
        NodeAlign align{};
        if (!ReadNodeAlign(node, align))
            return;
        AcquireSRWLockExclusive(&gAlignLock);
        ArabicAlignedNode* entry = FindArabicAligned(node);
        if (!entry)
        {
            ReleaseSRWLockExclusive(&gAlignLock);
            return;
        }
        const bool sameNode = entry->name == align.name;
        const uint8_t arabicLine = entry->line;
        const uint8_t arabicBlock = entry->block;
        ForgetArabicAligned(entry);
        const uint8_t gameLine = GameLineAlign(node, align);
        ReleaseSRWLockExclusive(&gAlignLock);
        if (!sameNode)
            return;
        const uint8_t line = align.line == arabicLine && !IsGameMarquee(align) ? gameLine : align.line;
        const uint8_t block = align.block == arabicBlock && align.originBlock != ALIGN_UNKNOWN ? align.originBlock
                                                                                               : align.block;
        WriteNodeAlign(node, line, block);
        if ((line != align.line || block != align.block) && gRestoreLogBudget.load() > 0)
        {
            gRestoreLogBudget.fetch_sub(1);
            Log("[fox::ui::ModelNodeText::Draw] node %p (%08X) still had the Arabic alignment %u/%u after the language "
                "changed - put back to %u/%u\n",
                node, align.name, static_cast<unsigned>(align.line), static_cast<unsigned>(align.block),
                static_cast<unsigned>(line), static_cast<unsigned>(block));
        }
    }

    void __fastcall hkSetTextAlign(void* uix, uint8_t* node, uint8_t align)
    {
        oSetTextAlign(uix, node, align);
        NodeAlign current{};
        if (!node || !ReadNodeAlign(node, current))
            return;
        const bool arabic = IsArabicThisFrame();
        bool putBack = false;
        uint8_t arabicBlock = ALIGN_UNKNOWN;
        AcquireSRWLockExclusive(&gAlignLock);
        RememberGameLineAlign(node, current.name, align);
        if (!arabic && gArabicAlignedCount.load(std::memory_order_relaxed) > 0)
        {
            if (ArabicAlignedNode* entry = FindArabicAligned(node))
            {
                putBack = entry->name == current.name;
                arabicBlock = entry->block;
                ForgetArabicAligned(entry);
            }
        }
        ReleaseSRWLockExclusive(&gAlignLock);
        if (putBack)
            WriteNodeAlign(node, align,
                           current.block == arabicBlock && current.originBlock != ALIGN_UNKNOWN ? current.originBlock
                                                                                                 : current.block);
    }

    constexpr size_t OFF_FONT_NAME = 0x9C;
    constexpr size_t OFF_ALT_FONT = 0xA0;
    constexpr size_t OFF_FONT_GROUP = 0xA8;
    constexpr size_t OFF_TEXT_SCALE = 0xF0;
    constexpr size_t OFF_AREA_WIDTH = 0xE8;
    constexpr size_t OFF_TEXT_WIDTH = 0x17C;
    constexpr size_t OFF_VERTEX_COUNT = 0x108;
    constexpr size_t OFF_VERTEX_POS = 0x110;
    constexpr uint16_t FLAG_ALT_FONT = 0x200;
    constexpr size_t MAX_PROBED_NODES = 24;

    std::atomic<int> gNumberProbeBudget{ static_cast<int>(MAX_PROBED_NODES) };
    std::atomic<uint64_t> gProbedFonts[MAX_PROBED_NODES] = {};

    bool DigitsOnly(const char* text, size_t& length)
    {
        length = 0;
        for (; text[length]; ++length)
        {
            const char c = text[length];
            if (!(c >= '0' && c <= '9') && c != '+' && c != '-' && c != ',' && c != '/')
                return false;
            if (length > 32)
                return false;
        }
        return length >= 3;
    }

    bool ProbedBefore(uint64_t key)
    {
        for (auto& slot : gProbedFonts)
        {
            if (slot.load(std::memory_order_relaxed) == key)
                return true;
        }
        return false;
    }

    void ProbeNumberNode(const uint8_t* node)
    {
        char text[40] = {};
        uint32_t name = 0, fontName = 0, vertexCount = 0;
        uint16_t flags = 0;
        const uint8_t* group = nullptr;
        const float* alt = nullptr;
        const float* verts = nullptr;
        uint64_t font = 0, fontFile = 0;
        float sizes[4] = {}, altSizes[4] = {}, scale[2] = {}, area = 0.0f, width = 0.0f, quad[16] = {};
        __try
        {
            const uint8_t* units = *reinterpret_cast<const uint8_t* const*>(node + OFF_UNITS);
            if (!units || *reinterpret_cast<const uint32_t*>(node + OFF_UNIT_COUNT) == 0)
                return;
            const char* unitText = *reinterpret_cast<const char* const*>(units);
            size_t length = 0;
            if (!unitText || !DigitsOnly(unitText, length))
                return;
            std::memcpy(text, unitText, length);
            name = *reinterpret_cast<const uint32_t*>(node + OFF_NAME);
            fontName = *reinterpret_cast<const uint32_t*>(node + OFF_FONT_NAME);
            flags = *reinterpret_cast<const uint16_t*>(node + OFF_FLAGS);
            group = *reinterpret_cast<const uint8_t* const*>(node + OFF_FONT_GROUP);
            if (group)
            {
                font = *reinterpret_cast<const uint64_t*>(group);
                std::memcpy(sizes, group + 0x08, sizeof(sizes));
                if (font)
                    fontFile = *reinterpret_cast<const uint64_t*>(font + 0x10);
            }
            if (flags & FLAG_ALT_FONT)
            {
                alt = *reinterpret_cast<const float* const*>(node + OFF_ALT_FONT);
                if (alt)
                    std::memcpy(altSizes, alt, sizeof(altSizes));
            }
            std::memcpy(scale, node + OFF_TEXT_SCALE, sizeof(scale));
            area = *reinterpret_cast<const float*>(node + OFF_AREA_WIDTH);
            width = *reinterpret_cast<const float*>(node + OFF_TEXT_WIDTH);
            vertexCount = *reinterpret_cast<const uint32_t*>(node + OFF_VERTEX_COUNT);
            verts = *reinterpret_cast<const float* const*>(node + OFF_VERTEX_POS);
            if (verts && vertexCount >= 8)
                std::memcpy(quad, verts, sizeof(quad));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return;
        }
        const bool arabicNow = IsArabicThisFrame();
        const uint64_t key = (static_cast<uint64_t>(arabicNow ? 1 : 2) << 32) | fontName;
        if (ProbedBefore(key))
            return;
        const int slot = gNumberProbeBudget.fetch_sub(1) - 1;
        if (slot < 0)
            return;
        gProbedFonts[slot].store(key, std::memory_order_relaxed);
        LogDetail("[NumberFontProbe] arabic=%d node=%p name=%08X text=[%s] fontName=%08X group=%p font=%p fnt=%d "
            "w=%.2f h=%.2f ts=%.2f ls=%.2f alt=%d (%.2f %.2f %.2f) scale=%.1f,%.1f area=%.4f textW=%.2f "
            "verts=%u q0=[%.2f %.2f %.2f %.2f %.2f %.2f %.2f %.2f] q1=[%.2f %.2f %.2f %.2f %.2f %.2f %.2f %.2f]\n",
            arabicNow ? 1 : 0, node, name, text, fontName, group, reinterpret_cast<void*>(font),
            fontFile ? 1 : 0, sizes[0], sizes[1], sizes[2], sizes[3], (flags & FLAG_ALT_FONT) ? 1 : 0, altSizes[0],
            altSizes[1], altSizes[2], scale[0], scale[1], area, width, vertexCount, quad[0], quad[1], quad[2],
            quad[3], quad[4], quad[5], quad[6], quad[7], quad[8], quad[9], quad[10], quad[11], quad[12], quad[13],
            quad[14], quad[15]);
    }

    constexpr size_t OFF_NODE_PARENT = 0x10;
    constexpr uint8_t TEXT_ALIGN_LEFT = 0;
    constexpr uint32_t ORIGIN_LINE_RIGHT = 1u << 22;
    constexpr float WIDE_TEXT_COLUMNS = 2.0f;
    constexpr int MAX_PARENT_DEPTH = 32;
    constexpr uint32_t kWideTextNodes[] = { 0xF71AE296, 0xDE6A4DD8 };
    constexpr uint32_t kWideTextRoots[] = { 0xD221E258, 0xE0327FF1 };
    std::atomic<int> gWideTextLogBudget{ 2 };

    bool ListHas(const uint32_t* list, size_t count, uint32_t value)
    {
        for (size_t i = 0; i < count; ++i)
        {
            if (list[i] == value)
                return true;
        }
        return false;
    }

    void GrowWideColumnTextIntoRow(uint8_t* node)
    {
        uint32_t name = 0;
        uint8_t want = TEXT_ALIGN_RIGHT;
        float width = 0.0f;
        float column = 0.0f;
        __try
        {
            name = *reinterpret_cast<const uint32_t*>(node + OFF_NAME);
            if (!ListHas(kWideTextNodes, _countof(kWideTextNodes), name))
                return;
            const uint8_t* data = *reinterpret_cast<const uint8_t* const*>(node + OFF_DATA);
            if (!data || !(*reinterpret_cast<const uint32_t*>(data + OFF_DATA_FLAGS) & ORIGIN_LINE_RIGHT))
                return;
            const uint8_t* walk = node;
            for (int depth = 0; depth < MAX_PARENT_DEPTH; ++depth)
            {
                const uint8_t* up = *reinterpret_cast<const uint8_t* const*>(walk + OFF_NODE_PARENT);
                if (!up)
                    break;
                walk = up;
            }
            if (!ListHas(kWideTextRoots, _countof(kWideTextRoots), *reinterpret_cast<const uint32_t*>(walk + OFF_NAME)))
                return;
            column = *reinterpret_cast<const float*>(node + OFF_TEXT_SCALE) *
                     *reinterpret_cast<const float*>(node + OFF_AREA_WIDTH) * 10.0f;
            width = *reinterpret_cast<const float*>(node + OFF_TEXT_WIDTH);
            if (!(column > 0.0f))
                return;
            want = width > column * WIDE_TEXT_COLUMNS ? TEXT_ALIGN_LEFT : TEXT_ALIGN_RIGHT;
            if (node[OFF_ALIGN] == want)
                return;
            node[OFF_ALIGN] = want;
            *reinterpret_cast<uint16_t*>(node + OFF_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return;
        }
        if (want == TEXT_ALIGN_LEFT && gWideTextLogBudget.load() > 0 && gWideTextLogBudget.fetch_sub(1) > 0)
            Log("[fox::ui::ModelNodeText::Draw] FOB list column %08X holds text %.1f wide in a %.1f column - drawn "
                "from the column's left edge so it stays in the row\n",
                name, width, column);
    }

    std::atomic<void*> gTextVtable{ nullptr };

    void __fastcall hkDraw(uint8_t* node, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                           uint64_t a7)
    {
        if (!node)
        {
            oDraw(node, a2, a3, a4, a5, a6, a7);
            return;
        }
        if (!gTextVtable.load(std::memory_order_relaxed))
        {
            __try
            {
                gTextVtable.store(*reinterpret_cast<void**>(node));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
        if (gNumberProbeBudget.load(std::memory_order_relaxed) > 0 && RL_DiagnosticsEnabled())
            ProbeNumberNode(node);
        const bool arabic = IsArabicThisFrame();
        if (!arabic)
        {
            PutBackAuthoredStencil(node);
            if (gArabicAlignedCount.load(std::memory_order_relaxed) > 0)
                PutBackGameAlignment(node);
            oDraw(node, a2, a3, a4, a5, a6, a7);
            return;
        }
        uint16_t flags = 0;
        if (ReadFlags(node, flags) && (flags & FLAG_STENCIL))
            KeepRubyLinesInsideStencil(node);
        if (gLatestLease.load(std::memory_order_relaxed) != 0)
        {
            const uint64_t now = GetTickCount64();
            if (gLatestLease.load(std::memory_order_relaxed) >= now && IsLeased(node, now) &&
                !ArabicMarqueeOverflowing(node))
            {
                uint8_t was = 0;
                if (ForceRightAndRebuild(node, was) && gFixLogBudget.load() > 0)
                {
                    gFixLogBudget.fetch_sub(1);
                    Log("[fox::ui::ModelNodeText::Draw] node %p drew with align %u - set right and rebuilt its lines\n",
                        node, static_cast<unsigned>(was));
                }
            }
        }
        GrowWideColumnTextIntoRow(node);
        NoteArabicAlignment(node);
        if (flags & FLAG_STENCIL)
            DriveStalledArabicScroll(node);
        oDraw(node, a2, a3, a4, a5, a6, a7);
        AuditArabicTextNode(node);
    }

    bool ReadSlot(const uintptr_t* slot, uintptr_t& value)
    {
        __try
        {
            value = *slot;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SwapSlot(uintptr_t* slot, uintptr_t value)
    {
        DWORD oldProtect = 0;
        if (!slot || !VirtualProtect(slot, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect))
            return false;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(slot), static_cast<LONG64>(value));
        DWORD ignored = 0;
        VirtualProtect(slot, sizeof(uintptr_t), oldProtect, &ignored);
        return true;
    }

    void WatchGameTextAlign(HMODULE hGame)
    {
        if (!gAddr.UixSetTextAlign || !gAddr.UixSetTextAlignVtSlot)
        {
            Log("[fox::uix::UixUtility::SetTextAlign] address missing - Arabic alignment is put back from the layout only.\n");
            return;
        }
        auto* slot = reinterpret_cast<uintptr_t*>(
            reinterpret_cast<uintptr_t>(hGame) + (gAddr.UixSetTextAlignVtSlot - IDA_IMAGE_BASE));
        const uintptr_t expected = reinterpret_cast<uintptr_t>(hGame) + (gAddr.UixSetTextAlign - IDA_IMAGE_BASE);
        uintptr_t current = 0;
        if (!ReadSlot(slot, current) || current != expected ||
            !CodeMatches(reinterpret_cast<const void*>(expected), kSetTextAlignBody, sizeof(kSetTextAlignBody)))
        {
            Log("[fox::uix::UixUtility::SetTextAlign] slot is not what this build should have - left alone.\n");
            return;
        }
        oSetTextAlign = reinterpret_cast<SetTextAlign_t>(expected);
        if (!SwapSlot(slot, reinterpret_cast<uintptr_t>(&hkSetTextAlign)))
        {
            oSetTextAlign = nullptr;
            Log("[fox::uix::UixUtility::SetTextAlign] slot swap failed.\n");
            return;
        }
        gSetTextAlignSlot = slot;
        Log("[fox::uix::UixUtility::SetTextAlign] watched - Arabic alignment is put back after a language change.\n");
    }
}

void* GetModelNodeTextVtable()
{
    return gTextVtable.load(std::memory_order_relaxed);
}

void KeepArabicLinesRightAlignedWhileShown(void* node, uint32_t leaseMs)
{
    if (!node || !gTarget)
        return;

    const uint64_t until = GetTickCount64() + leaseMs;
    LeasedNode* target = nullptr;
    for (LeasedNode& slot : gLeased)
    {
        if (slot.node.load(std::memory_order_relaxed) == node)
        {
            target = &slot;
            break;
        }
    }
    if (!target)
    {
        target = &gLeased[gNextSlot.fetch_add(1) % MAX_LEASED_NODES];
        target->until.store(0);
        target->node.store(node);
    }
    target->until.store(until);
    gLatestLease.store(until);
}

bool InstallModelNodeTextDrawArabicAlignHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.ModelNodeText_Draw)
    {
        Log("[fox::ui::ModelNodeText::Draw] address missing - box text keeps the alignment it was built with.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(hGame) + (gAddr.ModelNodeText_Draw - IDA_IMAGE_BASE));

    if (!CodeMatches(target, kDrawPrologue, sizeof(kDrawPrologue)))
    {
        Log("[fox::ui::ModelNodeText::Draw] code is not what this build should have - not hooked.\n");
        return true;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkDraw), reinterpret_cast<void**>(&oDraw)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[fox::ui::ModelNodeText::Draw] hook failed.\n");
        return false;
    }

    gTarget = target;
    Log("[fox::ui::ModelNodeText::Draw] Arabic box text kept right-aligned while its screen is shown.\n");
    WatchGameTextAlign(hGame);
    return true;
}

void RemoveModelNodeTextDrawArabicAlignHook()
{
    if (gSetTextAlignSlot && oSetTextAlign)
        SwapSlot(gSetTextAlignSlot, reinterpret_cast<uintptr_t>(oSetTextAlign));
    gSetTextAlignSlot = nullptr;
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    CloseArabicTextAudit();
    for (LeasedNode& slot : gLeased)
    {
        slot.node.store(nullptr);
        slot.until.store(0);
    }
    gLatestLease.store(0);
    for (StencilNode& entry : gStencilNodes)
    {
        if (entry.node)
            WriteStencilTop(entry.node, entry.authored);
        entry = {};
    }
    gStencilLogged = false;
    AcquireSRWLockExclusive(&gAlignLock);
    for (GameAlign& entry : gGameAligns)
        entry = {};
    for (ArabicAlignedNode& entry : gArabicAligned)
        entry = {};
    gArabicAlignedCount.store(0);
    ReleaseSRWLockExclusive(&gAlignLock);
    oSetTextAlign = nullptr;
    oDraw = nullptr;
    gIsArabLanguage = nullptr;
}
