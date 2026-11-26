#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using LoadFontData_t = uint64_t(__fastcall*)(uint8_t* font, const char* path, const char* defaultChar);
    using Rasterize_t = void(__fastcall*)(uintptr_t render, uint32_t pitch, uint32_t height, uint8_t* mapped,
                                          const uint8_t* request);
    using GlyphMetrics_t = void(__fastcall*)(float* out, const uint8_t* glyph, float halfTexelU, float halfTexelV,
                                             float scale);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

    constexpr size_t FONT_GLYP_VERSION = 0x08;
    constexpr size_t FONT_RECORD_SIZE = 0x09;
    constexpr size_t FONT_GLYPH_COUNT = 0x0E;
    constexpr size_t FONT_PADDING = 0x14;
    constexpr size_t FONT_RECORDS = 0x18;
    constexpr size_t FONT_ATLAS_LOG2_WIDTH = 0x21;
    constexpr size_t FONT_ATLAS_LOG2_HEIGHT = 0x22;
    constexpr size_t FONT_ATLAS_SIZE = 0x24;
    constexpr size_t FONT_ATLAS = 0x28;
    constexpr size_t FONT_SYSTEM_FONTS = 0x08;
    constexpr int FONT_SYSTEM_SLOTS = 8;

    constexpr size_t RECORD_SIZE = 20;
    constexpr size_t REC_CP = 0;
    constexpr size_t REC_X = 4;
    constexpr size_t REC_Y = 6;
    constexpr size_t REC_W = 8;
    constexpr size_t REC_H = 9;
    constexpr size_t REC_PLANE = 10;
    constexpr size_t REC_ADVANCE = 11;
    constexpr size_t REC_XOFF = 12;
    constexpr size_t REC_YOFF = 13;
    constexpr size_t REC_FLAGS = 14;

    constexpr size_t REQ_PLANE = 0x04;
    constexpr size_t REQ_FLAGS = 0x06;
    constexpr size_t REQ_ATLAS_X = 0x08;
    constexpr size_t REQ_ATLAS_Y = 0x0A;
    constexpr size_t REQ_CACHE_X = 0x0C;
    constexpr size_t REQ_CACHE_Y = 0x0E;
    constexpr size_t REQ_WIDTH = 0x10;
    constexpr size_t REQ_HEIGHT = 0x12;
    constexpr size_t REQ_ATLAS = 0x18;
    constexpr size_t REQ_ATLAS_PITCH = 0x28;

    constexpr size_t QUAD_U0 = 0;
    constexpr size_t QUAD_V0 = 1;
    constexpr size_t QUAD_U1 = 2;
    constexpr size_t QUAD_V1 = 3;
    constexpr size_t QUAD_WIDTH = 4;
    constexpr size_t QUAD_HEIGHT = 5;
    constexpr size_t QUAD_XOFF = 6;
    constexpr size_t QUAD_TOP = 7;
    constexpr size_t QUAD_ADVANCE = 8;

    constexpr uint8_t JOINS_LEFT = 0x1;
    constexpr uint8_t JOINS_RIGHT = 0x2;
    constexpr int JOIN_EXTENSION = 3;
    constexpr int STROKE_REACH = 2;
    constexpr int MIN_ARABIC_FORMS = 32;
    constexpr uint32_t CODEPOINT_MASK = 0x0FFFFFFF;
    constexpr uint32_t SHADDA = 0x0651;
    constexpr float GLYPH_PAD = 1.0f;
    constexpr float MARK_GAP = 2.0f;
    constexpr float LINE_MIDDLE = -0.5f;

    const uint8_t kLoadFontDataPrologue[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x40, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54 };
    const uint8_t kRasterizePrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    };
    const uint8_t kGlyphMetricsPrologue[] = {
        0xF3, 0x0F, 0x10, 0x42, 0x10, 0xF3, 0x0F, 0x5C, 0xC2, 0xF3, 0x0F, 0x11, 0x01,
    };

    struct JoinForm
    {
        uint16_t cp;
        uint8_t flags;
    };

    const JoinForm kJoinForms[] = {
        { 0x0640, 3 }, { 0xFE77, 3 }, { 0xFE79, 3 }, { 0xFE7B, 3 }, { 0xFE7D, 3 }, { 0xFE7F, 3 },
        { 0xFE82, 2 }, { 0xFE84, 2 }, { 0xFE86, 2 }, { 0xFE88, 2 }, { 0xFE8A, 2 }, { 0xFE8B, 1 },
        { 0xFE8C, 3 }, { 0xFE8E, 2 }, { 0xFE90, 2 }, { 0xFE91, 1 }, { 0xFE92, 3 }, { 0xFE94, 2 },
        { 0xFE96, 2 }, { 0xFE97, 1 }, { 0xFE98, 3 }, { 0xFE9A, 2 }, { 0xFE9B, 1 }, { 0xFE9C, 3 },
        { 0xFE9E, 2 }, { 0xFE9F, 1 }, { 0xFEA0, 3 }, { 0xFEA2, 2 }, { 0xFEA3, 1 }, { 0xFEA4, 3 },
        { 0xFEA6, 2 }, { 0xFEA7, 1 }, { 0xFEA8, 3 }, { 0xFEAA, 2 }, { 0xFEAC, 2 }, { 0xFEAE, 2 },
        { 0xFEB0, 2 }, { 0xFEB2, 2 }, { 0xFEB3, 1 }, { 0xFEB4, 3 }, { 0xFEB6, 2 }, { 0xFEB7, 1 },
        { 0xFEB8, 3 }, { 0xFEBA, 2 }, { 0xFEBB, 1 }, { 0xFEBC, 3 }, { 0xFEBE, 2 }, { 0xFEBF, 1 },
        { 0xFEC0, 3 }, { 0xFEC2, 2 }, { 0xFEC3, 1 }, { 0xFEC4, 3 }, { 0xFEC6, 2 }, { 0xFEC7, 1 },
        { 0xFEC8, 3 }, { 0xFECA, 2 }, { 0xFECB, 1 }, { 0xFECC, 3 }, { 0xFECE, 2 }, { 0xFECF, 1 },
        { 0xFED0, 3 }, { 0xFED2, 2 }, { 0xFED3, 1 }, { 0xFED4, 3 }, { 0xFED6, 2 }, { 0xFED7, 1 },
        { 0xFED8, 3 }, { 0xFEDA, 2 }, { 0xFEDB, 1 }, { 0xFEDC, 3 }, { 0xFEDE, 2 }, { 0xFEDF, 1 },
        { 0xFEE0, 3 }, { 0xFEE2, 2 }, { 0xFEE3, 1 }, { 0xFEE4, 3 }, { 0xFEE6, 2 }, { 0xFEE7, 1 },
        { 0xFEE8, 3 }, { 0xFEEA, 2 }, { 0xFEEB, 1 }, { 0xFEEC, 3 }, { 0xFEEE, 2 }, { 0xFEF0, 2 },
        { 0xFEF2, 2 }, { 0xFEF3, 1 }, { 0xFEF4, 3 }, { 0xFEF6, 2 }, { 0xFEF8, 2 }, { 0xFEFA, 2 },
        { 0xFEFC, 2 },
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    LoadFontData_t oLoadFontData = nullptr;
    Rasterize_t oRasterize = nullptr;
    GlyphMetrics_t oGlyphMetrics = nullptr;
    void* gTargetLoadFontData = nullptr;
    void* gTargetRasterize = nullptr;
    void* gTargetGlyphMetrics = nullptr;

    std::mutex gFontMtx;
    std::unordered_set<const void*> gPatchedRecords;

    std::atomic<bool> gLoggedJoin{ false };
    std::atomic<bool> gLoggedMark{ false };

    thread_local float tBaseCenter = 0.0f;
    thread_local bool tHaveBase = false;
    thread_local float tBaseInkTop = 0.0f;
    thread_local float tBaseInkBottom = 0.0f;
    thread_local float tAboveTop = 0.0f;
    thread_local bool tHaveAbove = false;
    thread_local float tBelowBottom = 0.0f;
    thread_local bool tHaveBelow = false;

    uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
    {
        return absVa ? reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE) : 0;
    }

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

    bool IsArabicMark(uint32_t cp)
    {
        return (cp >= 0x0610 && cp <= 0x061A) || (cp >= 0x064B && cp <= 0x065F) || cp == 0x0670 ||
               (cp >= 0x06D6 && cp <= 0x06DC) || (cp >= 0x06DF && cp <= 0x06E4) || cp == 0x06E7 ||
               cp == 0x06E8 || (cp >= 0x06EA && cp <= 0x06ED);
    }

    uint8_t UnicodeJoinFlags(uint32_t cp)
    {
        size_t lo = 0;
        size_t hi = sizeof(kJoinForms) / sizeof(kJoinForms[0]);
        while (lo < hi)
        {
            const size_t mid = (lo + hi) / 2;
            if (kJoinForms[mid].cp < cp)
                lo = mid + 1;
            else
                hi = mid;
        }
        return lo < sizeof(kJoinForms) / sizeof(kJoinForms[0]) && kJoinForms[lo].cp == cp ? kJoinForms[lo].flags : 0;
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

    bool CopyFromGame(void* dst, const void* src, size_t size)
    {
        __try
        {
            std::memcpy(dst, src, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadPointer(uintptr_t address, uint8_t*& out)
    {
        __try
        {
            out = *reinterpret_cast<uint8_t* const*>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out = nullptr;
            return false;
        }
    }

    struct FontImage
    {
        uint8_t* records = nullptr;
        uint8_t* atlas = nullptr;
        int count = 0;
        int pad = 0;
        int width = 0;
        int height = 0;
        std::vector<uint8_t> recordCopy;
        std::vector<uint8_t> atlasCopy;
    };

    struct Glyph
    {
        uint32_t cp = 0;
        int x = 0;
        int y = 0;
        int w = 0;
        int h = 0;
        int plane = 0;
        uint8_t mask = 0;
        int adv = 0;
        int xoff = 0;
        int yoff = 0;
        uint8_t flags = 0;
        int box[4] = {};
        bool valid = false;
    };

    struct PatchStats
    {
        int flags = 0;
        int trimmedRight = 0;
        int trimmedLeft = 0;
        int offsetsMoved = 0;
        int strokeExtended = 0;
        int edgeCleared = 0;
        int sharedSkipped = 0;
        int advances = 0;
        int bandFirst = 0;
        int bandLast = 0;
    };

    bool ReadFontImage(uint8_t* font, FontImage& image)
    {
        uint8_t header[0x30] = {};
        if (!CopyFromGame(header, font, sizeof(header)))
            return false;
        if (header[FONT_GLYP_VERSION] != 2 || header[FONT_RECORD_SIZE] != RECORD_SIZE)
            return false;

        image.count = *reinterpret_cast<const uint16_t*>(header + FONT_GLYPH_COUNT);
        image.pad = header[FONT_PADDING];
        image.records = *reinterpret_cast<uint8_t* const*>(header + FONT_RECORDS);
        image.atlas = *reinterpret_cast<uint8_t* const*>(header + FONT_ATLAS);
        const uint8_t log2Width = header[FONT_ATLAS_LOG2_WIDTH];
        const uint8_t log2Height = header[FONT_ATLAS_LOG2_HEIGHT];
        const uint32_t atlasSize = *reinterpret_cast<const uint32_t*>(header + FONT_ATLAS_SIZE);
        if (!image.records || !image.atlas || image.count <= 0 || log2Width > 12 || log2Height > 12)
            return false;

        image.width = 1 << log2Width;
        image.height = 1 << log2Height;
        if (static_cast<uint64_t>(image.width) * image.height > atlasSize)
            return false;

        image.recordCopy.resize(static_cast<size_t>(image.count) * RECORD_SIZE);
        image.atlasCopy.resize(static_cast<size_t>(image.width) * image.height);
        return CopyFromGame(image.recordCopy.data(), image.records, image.recordCopy.size()) &&
               CopyFromGame(image.atlasCopy.data(), image.atlas, image.atlasCopy.size());
    }

    class FontPatcher
    {
    public:
        explicit FontPatcher(FontImage& image) : image_(image) {}

        bool IsArabicFont() const
        {
            int forms = 0;
            for (int i = 0; i < image_.count; ++i)
            {
                const uint32_t cp = *reinterpret_cast<const uint32_t*>(Record(i) + REC_CP);
                if (cp >= 0xFE70 && cp <= 0xFEFC)
                    ++forms;
            }
            return forms >= MIN_ARABIC_FORMS;
        }

        bool Run(PatchStats& stats)
        {
            LoadGlyphs();
            for (Glyph& g : glyphs_)
            {
                const uint8_t flags = HasInk(g) ? UnicodeJoinFlags(g.cp) : 0;
                if (flags != g.flags)
                {
                    g.flags = flags;
                    ++stats.flags;
                }
            }

            for (Glyph& g : glyphs_)
            {
                if (g.flags & JOINS_RIGHT)
                    stats.trimmedRight += TrimRight(g) ? 1 : 0;
                if (g.flags & JOINS_LEFT)
                {
                    stats.trimmedLeft += TrimLeft(g) ? 1 : 0;
                    if (g.xoff)
                    {
                        g.adv -= g.xoff;
                        g.xoff = 0;
                        ++stats.offsetsMoved;
                    }
                }
            }

            if (!FindStrokeBand(stats.bandFirst, stats.bandLast))
                return false;

            for (Glyph& g : glyphs_)
            {
                if (g.flags & JOINS_RIGHT)
                {
                    FixSide(g, true, stats);
                    stats.trimmedRight += TrimRight(g) ? 1 : 0;
                }
                if (g.flags & JOINS_LEFT)
                {
                    FixSide(g, false, stats);
                    if (!ColumnHasInk(g, 0))
                        return false;
                }
            }

            for (Glyph& g : glyphs_)
            {
                int advance = g.adv;
                if (IsArabicMark(g.cp))
                    advance = 0;
                else if (g.flags & JOINS_RIGHT)
                    advance = g.xoff + g.w - ((g.flags & JOINS_LEFT) ? 0 : image_.pad);
                if (advance < 0 || advance > 255)
                    return false;
                g.adv = advance;
            }


            for (int i = 0; i < image_.count; ++i)
            {
                const Glyph& g = glyphs_[i];
                uint8_t* rec = Record(i);
                if (rec[REC_ADVANCE] != static_cast<uint8_t>(g.adv))
                    ++stats.advances;
                *reinterpret_cast<uint16_t*>(rec + REC_X) = static_cast<uint16_t>(g.x);
                rec[REC_W] = static_cast<uint8_t>(g.w);
                rec[REC_ADVANCE] = static_cast<uint8_t>(g.adv);
                rec[REC_XOFF] = static_cast<uint8_t>(g.xoff & 0xFF);
                rec[REC_FLAGS] = static_cast<uint8_t>((rec[REC_FLAGS] & ~3) | g.flags);
            }
            return true;
        }

    private:
        uint8_t* Record(int i) { return image_.recordCopy.data() + static_cast<size_t>(i) * RECORD_SIZE; }
        const uint8_t* Record(int i) const { return image_.recordCopy.data() + static_cast<size_t>(i) * RECORD_SIZE; }

        void LoadGlyphs()
        {
            glyphs_.resize(image_.count);
            for (int i = 0; i < image_.count; ++i)
            {
                const uint8_t* rec = Record(i);
                Glyph& g = glyphs_[i];
                g.cp = *reinterpret_cast<const uint32_t*>(rec + REC_CP);
                g.x = *reinterpret_cast<const uint16_t*>(rec + REC_X);
                g.y = *reinterpret_cast<const uint16_t*>(rec + REC_Y);
                g.w = rec[REC_W];
                g.h = rec[REC_H];
                g.plane = rec[REC_PLANE];
                g.mask = g.plane < 8 ? static_cast<uint8_t>(1u << g.plane) : 0;
                g.adv = rec[REC_ADVANCE];
                g.xoff = static_cast<int8_t>(rec[REC_XOFF]);
                g.yoff = rec[REC_YOFF];
                g.flags = rec[REC_FLAGS] & 3;
                g.box[0] = g.x;
                g.box[1] = g.y;
                g.box[2] = g.x + g.w;
                g.box[3] = g.y + g.h;
                g.valid = g.mask && g.x + g.w <= image_.width && g.y + g.h <= image_.height;
            }
        }

        bool Ink(const Glyph& g, int col, int row) const
        {
            if (!g.valid)
                return false;
            return (image_.atlasCopy[static_cast<size_t>(g.y + row) * image_.width + g.x + col] & g.mask) != 0;
        }

        bool ColumnHasInk(const Glyph& g, int col) const
        {
            for (int r = 0; r < g.h; ++r)
            {
                if (Ink(g, col, r))
                    return true;
            }
            return false;
        }

        bool HasInk(const Glyph& g) const
        {
            if (!g.valid || g.w <= 0 || g.h <= 0)
                return false;
            for (int c = 0; c < g.w; ++c)
            {
                if (ColumnHasInk(g, c))
                    return true;
            }
            return false;
        }

        bool TrimRight(Glyph& g) const
        {
            int trimmed = g.w;
            while (trimmed > 1 && !ColumnHasInk(g, trimmed - 1))
                --trimmed;
            if (trimmed == g.w)
                return false;
            g.w = trimmed;
            return true;
        }

        bool TrimLeft(Glyph& g) const
        {
            int lead = 0;
            while (lead < g.w - 1 && !ColumnHasInk(g, lead))
                ++lead;
            if (!lead)
                return false;
            g.x += lead;
            g.w -= lead;
            g.xoff += lead;
            return true;
        }

        bool FindStrokeBand(int& first, int& last) const
        {
            std::vector<int> rows(512, 0);
            int sides = 0;
            for (const Glyph& g : glyphs_)
            {
                for (int side = 0; side < 2; ++side)
                {
                    const uint8_t flag = side ? JOINS_RIGHT : JOINS_LEFT;
                    if (!(g.flags & flag) || !g.valid || g.w <= 0)
                        continue;
                    ++sides;
                    const int edge = side ? g.w - 1 : 0;
                    for (int r = 0; r < g.h; ++r)
                    {
                        if (Ink(g, edge, r) && g.yoff + r < static_cast<int>(rows.size()))
                            ++rows[g.yoff + r];
                    }
                }
            }
            first = -1;
            last = -1;
            for (int row = 0; row < static_cast<int>(rows.size()); ++row)
            {
                if (sides == 0 || rows[row] * 2 < sides)
                    continue;
                if (first < 0)
                    first = row;
                else if (row != last + 1)
                    return false;
                last = row;
            }
            return first >= 0;
        }

        bool OwnedOnlyBy(const Glyph& g, int col, int row) const
        {
            const int px = g.x + col;
            const int py = g.y + row;
            for (const Glyph& other : glyphs_)
            {
                if (&other == &g || other.plane != g.plane)
                    continue;
                if (px >= other.box[0] && px < other.box[2] && py >= other.box[1] && py < other.box[3])
                    return false;
            }
            return true;
        }

        void SetInk(const Glyph& g, int col, int row, bool value, int& counter, PatchStats& stats)
        {
            if (!OwnedOnlyBy(g, col, row))
            {
                ++stats.sharedSkipped;
                return;
            }
            uint8_t& pixel = image_.atlasCopy[static_cast<size_t>(g.y + row) * image_.width + g.x + col];
            pixel = value ? static_cast<uint8_t>(pixel | g.mask) : static_cast<uint8_t>(pixel & ~g.mask);
            ++counter;
        }

        void FixSide(const Glyph& g, bool right, PatchStats& stats)
        {
            if (!g.valid || g.w <= 0)
                return;
            const int edge = right ? g.w - 1 : 0;
            for (int r = 0; r < g.h; ++r)
            {
                const int row = g.yoff + r;
                const bool inBand = row >= stats.bandFirst && row <= stats.bandLast;
                int nearest = -1;
                for (int c = 0; c < g.w; ++c)
                {
                    if (!Ink(g, c, r))
                        continue;
                    if (right || nearest < 0)
                        nearest = c;
                    if (!right)
                        break;
                }
                if (inBand && nearest >= 0)
                {
                    const int distance = right ? edge - nearest : nearest - edge;
                    if (distance <= STROKE_REACH)
                    {
                        const int from = right ? nearest + 1 : edge;
                        const int to = right ? edge + 1 : nearest;
                        for (int c = from; c < to; ++c)
                            SetInk(g, c, r, true, stats.strokeExtended, stats);
                    }
                }
                else if (!inBand && Ink(g, edge, r))
                {
                    SetInk(g, edge, r, false, stats.edgeCleared, stats);
                }
            }
        }

        FontImage& image_;
        std::vector<Glyph> glyphs_;
    };

    bool WriteFontImage(const FontImage& image)
    {
        __try
        {
            std::memcpy(image.records, image.recordCopy.data(), image.recordCopy.size());
            const size_t size = image.atlasCopy.size();
            for (size_t i = 0; i < size; ++i)
            {
                if (image.atlas[i] != image.atlasCopy[i])
                    image.atlas[i] = image.atlasCopy[i];
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void PatchArabicFontOnce(uint8_t* font, const char* when, bool freshLoad)
    {
        if (!font)
            return;

        FontImage image;
        if (!ReadFontImage(font, image))
            return;

        FontPatcher patcher(image);
        if (!patcher.IsArabicFont())
            return;

        std::lock_guard<std::mutex> lk(gFontMtx);
        if (freshLoad && gPatchedRecords.erase(image.records))
            when = "reloaded";
        if (!gPatchedRecords.insert(image.records).second)
            return;

        PatchStats stats{};
        if (!patcher.Run(stats))
        {
            Log("[ArabicGlyphs] %s Arabic font %p left unchanged: no consistent joining stroke found\n", when, font);
            return;
        }
        if (!WriteFontImage(image))
        {
            Log("[ArabicGlyphs] %s Arabic font %p could not be written\n", when, font);
            return;
        }

        Log("[ArabicGlyphs] %s Arabic font %p fixed: %d join flags from Unicode, stroke rows %d-%d, "
            "%d+%d empty join columns trimmed, %d offsets moved, %d stroke pixels extended, %d edge pixels cleared, "
            "%d shared pixels skipped, %d advances\n",
            when, font, stats.flags, stats.bandFirst, stats.bandLast, stats.trimmedLeft, stats.trimmedRight,
            stats.offsetsMoved, stats.strokeExtended, stats.edgeCleared, stats.sharedSkipped, stats.advances);
    }

    void PatchLoadedFonts(HMODULE hGame)
    {
        uint8_t* system = nullptr;
        const uintptr_t instance = ToRuntimeVA(hGame, gAddr.FontSystemInstance);
        if (!instance || !ReadPointer(instance, system) || !system)
            return;

        for (int slot = 0; slot < FONT_SYSTEM_SLOTS; ++slot)
        {
            uint8_t* font = nullptr;
            if (ReadPointer(reinterpret_cast<uintptr_t>(system + FONT_SYSTEM_FONTS) + slot * sizeof(void*), font))
                PatchArabicFontOnce(font, "already loaded", false);
        }
    }

    template <typename T>
    T Field(const uint8_t* base, size_t offset)
    {
        return *reinterpret_cast<const T*>(base + offset);
    }

    struct GlyphSource
    {
        const uint8_t* atlas;
        uint32_t pitch;
        uint32_t x;
        uint32_t y;
        int width;
        int height;
        uint8_t mask;
        uint8_t flags;
    };

    int SourceInk(const GlyphSource& g, int row, int col)
    {
        if (row < 0 || row > g.height)
            return 0;
        if (col < 0)
        {
            if (!(g.flags & JOINS_LEFT))
                return 0;
            col = 0;
        }
        else if (col >= g.width)
        {
            if (!(g.flags & JOINS_RIGHT))
                return 0;
            col = g.width - 1;
        }
        return (g.atlas[(g.y + row) * g.pitch + g.x + col] & g.mask) ? 1 : 0;
    }

    uint8_t Blurred(const GlyphSource& g, int row, int col)
    {
        static const int kWeights[3] = { 1, 2, 1 };
        int sum = 0;
        for (int dr = -1; dr <= 1; ++dr)
        {
            for (int dc = -1; dc <= 1; ++dc)
                sum += kWeights[dr + 1] * kWeights[dc + 1] * SourceInk(g, row + dr, col + dc);
        }
        return static_cast<uint8_t>(sum * 255 / 16);
    }

    bool ContinueJoins(uint32_t pitch, uint8_t* mapped, const uint8_t* request)
    {
        __try
        {
            GlyphSource g{};
            g.flags = Field<uint8_t>(request, REQ_FLAGS) & (JOINS_LEFT | JOINS_RIGHT);
            g.atlas = Field<const uint8_t*>(request, REQ_ATLAS);
            g.pitch = Field<uint16_t>(request, REQ_ATLAS_PITCH);
            g.x = Field<uint16_t>(request, REQ_ATLAS_X);
            g.y = Field<uint16_t>(request, REQ_ATLAS_Y);
            g.width = Field<uint16_t>(request, REQ_WIDTH);
            g.height = Field<uint16_t>(request, REQ_HEIGHT);
            g.mask = static_cast<uint8_t>(1u << (Field<uint8_t>(request, REQ_PLANE) & 0x1F));
            const int cacheX = Field<uint16_t>(request, REQ_CACHE_X);
            const int cacheY = Field<uint16_t>(request, REQ_CACHE_Y);

            if (!g.flags || !g.atlas || !g.mask || g.width <= 0 || g.height <= 0 || pitch == 0 ||
                cacheX < JOIN_EXTENSION || cacheX + g.width + JOIN_EXTENSION > static_cast<int>(pitch))
                return false;

            for (int row = 0; row < g.height; ++row)
            {
                uint8_t* line = mapped + static_cast<size_t>(cacheY + row) * pitch + cacheX;
                if (g.flags & JOINS_LEFT)
                {
                    for (int col = -JOIN_EXTENSION; col <= 0; ++col)
                        line[col] = Blurred(g, row, col);
                }
                if (g.flags & JOINS_RIGHT)
                {
                    for (int col = g.width - 1; col < g.width + JOIN_EXTENSION; ++col)
                        line[col] = Blurred(g, row, col);
                }
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void RememberBase(const float* out, float scale)
    {
        const float pad = GLYPH_PAD * scale;
        const float top = -out[QUAD_TOP];
        tBaseInkTop = top + pad;
        tBaseInkBottom = top + out[QUAD_HEIGHT] - pad;
        tHaveAbove = false;
        tHaveBelow = false;
    }

    void PlaceMarkVertically(float* out, float scale)
    {
        const float pad = GLYPH_PAD * scale;
        const float gap = MARK_GAP * scale;
        const float top = -out[QUAD_TOP];
        const float height = out[QUAD_HEIGHT];
        const float inkHeight = height - 2.0f * pad;

        float inkTop = 0.0f;
        if (top + height * 0.5f < LINE_MIDDLE)
        {
            const float ceiling = tHaveAbove ? tAboveTop : tBaseInkTop;
            inkTop = ceiling - gap - inkHeight;
            tAboveTop = inkTop;
            tHaveAbove = true;
        }
        else
        {
            const float floor = tHaveBelow ? tBelowBottom : tBaseInkBottom;
            inkTop = floor + gap;
            tBelowBottom = inkTop + inkHeight;
            tHaveBelow = true;
        }
        out[QUAD_TOP] = -(inkTop - pad);
    }

    uint64_t __fastcall hkLoadFontData(uint8_t* font, const char* path, const char* defaultChar)
    {
        const uint64_t loaded = oLoadFontData(font, path, defaultChar);
        if (loaded & 0xFF)
            PatchArabicFontOnce(font, "loaded", true);
        return loaded;
    }

    void __fastcall hkRasterize(uintptr_t render, uint32_t pitch, uint32_t height, uint8_t* mapped,
                                const uint8_t* request)
    {
        oRasterize(render, pitch, height, mapped, request);
        if (!mapped || !request || !(request[REQ_FLAGS] & (JOINS_LEFT | JOINS_RIGHT)) || !IsArabicSafe())
            return;
        if (ContinueJoins(pitch & 0xFFFF, mapped, request) && !gLoggedJoin.exchange(true))
            Log("[ArabicGlyphs] joined letters continue into their neighbours in the glyph cache\n");
    }

    void __fastcall hkGlyphMetrics(float* out, const uint8_t* glyph, float halfTexelU, float halfTexelV, float scale)
    {
        oGlyphMetrics(out, glyph, halfTexelU, halfTexelV, scale);
        if (!out || !glyph || !IsArabicSafe())
            return;

        out[QUAD_U0] += halfTexelU;
        out[QUAD_V0] += halfTexelV;
        out[QUAD_U1] -= halfTexelU;
        out[QUAD_V1] -= halfTexelV;

        const uint32_t cp = *reinterpret_cast<const uint32_t*>(glyph) & CODEPOINT_MASK;
        if (!IsArabicMark(cp))
        {
            tBaseCenter = out[QUAD_XOFF] + out[QUAD_WIDTH] * 0.5f - out[QUAD_ADVANCE];
            tHaveBase = true;
            RememberBase(out, scale);
            return;
        }
        if (!tHaveBase)
            return;

        out[QUAD_XOFF] = tBaseCenter - out[QUAD_WIDTH] * 0.5f;
        out[QUAD_ADVANCE] = 0.0f;
        PlaceMarkVertically(out, scale);
        if (!gLoggedMark.exchange(true))
            Log("[ArabicGlyphs] Arabic marks are placed over their letters%s\n",
                cp == SHADDA ? " (shadda seen)" : "");
    }

    bool Hook(void* target, const uint8_t* prologue, size_t prologueSize, void* detour, void** original,
              void** installed, const char* name)
    {
        if (!target)
            return false;
        if (!CodeMatches(target, prologue, prologueSize))
        {
            Log("[ArabicGlyphs] %s code at %p is not what this build should have - not hooked\n", name, target);
            return false;
        }
        if (MH_CreateHook(target, detour, original) != MH_OK || MH_EnableHook(target) != MH_OK)
        {
            Log("[ArabicGlyphs] %s hook FAILED at %p\n", name, target);
            return false;
        }
        *installed = target;
        return true;
    }
}

bool InstallArabicGlyphRenderingHooks(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.FontDataLoad || !gAddr.GlyphCacheRasterize || !gAddr.GlyphMetrics)
    {
        Log("[ArabicGlyphs] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_UsesArabicScript;

    const bool fonts = Hook(reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.FontDataLoad)), kLoadFontDataPrologue,
                            sizeof(kLoadFontDataPrologue), reinterpret_cast<void*>(&hkLoadFontData),
                            reinterpret_cast<void**>(&oLoadFontData), &gTargetLoadFontData, "font load");
    const bool joins = Hook(reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.GlyphCacheRasterize)), kRasterizePrologue,
                            sizeof(kRasterizePrologue), reinterpret_cast<void*>(&hkRasterize),
                            reinterpret_cast<void**>(&oRasterize), &gTargetRasterize, "glyph cache");
    const bool marks = Hook(reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.GlyphMetrics)), kGlyphMetricsPrologue,
                            sizeof(kGlyphMetricsPrologue), reinterpret_cast<void*>(&hkGlyphMetrics),
                            reinterpret_cast<void**>(&oGlyphMetrics), &gTargetGlyphMetrics, "glyph metrics");

    PatchLoadedFonts(hGame);

    Log("[ArabicGlyphs] font fix %s, join continuation %s, mark placement %s\n", fonts ? "on" : "OFF",
        joins ? "on" : "OFF", marks ? "on" : "OFF");
    return fonts && joins && marks;
}

void RemoveArabicGlyphRenderingHooks()
{
    void* targets[] = { gTargetLoadFontData, gTargetRasterize, gTargetGlyphMetrics };
    for (void* target : targets)
    {
        if (!target)
            continue;
        MH_DisableHook(target);
        MH_RemoveHook(target);
    }
    gTargetLoadFontData = nullptr;
    gTargetRasterize = nullptr;
    gTargetGlyphMetrics = nullptr;
    oLoadFontData = nullptr;
    oRasterize = nullptr;
    oGlyphMetrics = nullptr;
    gIsArabLanguage = nullptr;
}
