#include "pch.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using CreateText_t = uint8_t(__fastcall*)(uintptr_t font, const char* text, float width, float height, float space,
                                              float* xy, float* uv, float* penX, float* maxHeight);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t FONT_RECORDS = 0x28;
    constexpr size_t FONT_EM_W = 0x30;
    constexpr size_t FONT_EM_H = 0x34;
    constexpr size_t FONT_CELL_W = 0x38;
    constexpr size_t FONT_CELL_H = 0x3C;
    constexpr size_t FONT_COUNT = 0x40;
    constexpr int MARK_GAP = 2;
    constexpr size_t FLOATS_PER_GLYPH = 8;

    struct FontRecord
    {
        uint32_t code;
        uint16_t y;
        uint16_t x;
        uint16_t padTop;
        uint16_t padBottom;
        uint16_t padLeft;
        uint16_t padRight;
    };
    static_assert(sizeof(FontRecord) == 16, "fnt record is 16 bytes");

    struct FontView
    {
        const FontRecord* records;
        uint32_t count;
        uint32_t emW;
        uint32_t emH;
        uint16_t cellW;
        uint16_t cellH;
    };

    struct BaseGlyph
    {
        bool valid;
        float centerX;
        int aboveTop;
        int belowBottom;
    };

    constexpr uint32_t INK_SIGNATURE_CODE = 0xE000;
    constexpr uint16_t INK_SIGNATURE_Y = 0x494E;
    constexpr uint16_t INK_SIGNATURE_X = 0x4B31;
    constexpr uint16_t INK_VERSION = 1;

    struct GlyphInk
    {
        uint32_t code;
        uint8_t left;
        uint8_t top;
        uint8_t right;
        uint8_t bottom;
    };

    struct FontInk
    {
        const FontRecord* records;
        uint32_t count;
        std::vector<GlyphInk> glyphs;
    };

    CreateText_t oCreateText = nullptr;
    void* gTarget = nullptr;
    std::atomic<uintptr_t> gInkFont{ 0 };
    std::atomic<const FontInk*> gInk{ nullptr };
    SRWLOCK gInkLock = SRWLOCK_INIT;
    std::unordered_map<uintptr_t, const FontInk*> gInkByFont;
    std::atomic<int> gInkLogBudget{ 8 };
    std::atomic<int> gLogBudget{ 3 };

    bool IsMark(uint32_t c)
    {
        return (c >= 0x0610 && c <= 0x061A) || (c >= 0x064B && c <= 0x065F) || c == 0x0670 ||
               (c >= 0x06D6 && c <= 0x06DC) || (c >= 0x06DF && c <= 0x06E4) || c == 0x06E7 || c == 0x06E8 ||
               (c >= 0x06EA && c <= 0x06ED);
    }

    bool IsBelowMark(uint32_t c)
    {
        return c == 0x064D || c == 0x0650 || c == 0x0655 || c == 0x0656 || c == 0x061A || c == 0x065C ||
               c == 0x065F || c == 0x06E3 || c == 0x06EA || c == 0x06ED;
    }

    bool MayContainMark(const unsigned char* p)
    {
        for (; *p; ++p)
        {
            if (p[0] == 0xD8 && p[1] >= 0x90 && p[1] <= 0x9A)
                return true;
            if (p[0] == 0xD9 && ((p[1] >= 0x8B && p[1] <= 0x9F) || p[1] == 0xB0))
                return true;
            if (p[0] == 0xDB && p[1] >= 0x96 && p[1] <= 0xAD)
                return true;
        }
        return false;
    }

    bool NextCodePoint(const unsigned char*& p, uint32_t& out)
    {
        const unsigned c = *p++;
        if (c < 0x80)
        {
            out = c;
            return true;
        }
        int extra = 0;
        if (c >= 0xC0 && c < 0xE0)
            extra = 1;
        else if (c >= 0xE0 && c < 0xF0)
            extra = 2;
        else if (c >= 0xF0 && c < 0xF8)
            extra = 3;
        else
            return false;
        uint32_t cp = c & (0x3Fu >> extra);
        for (int i = 0; i < extra; ++i)
        {
            if ((*p & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (*p++ & 0x3Fu);
        }
        out = cp;
        return true;
    }

    bool ReadFont(uintptr_t font, FontView& view)
    {
        __try
        {
            view.records = *reinterpret_cast<const FontRecord* const*>(font + FONT_RECORDS);
            view.count = *reinterpret_cast<const uint32_t*>(font + FONT_COUNT);
            view.emW = *reinterpret_cast<const uint32_t*>(font + FONT_EM_W);
            view.emH = *reinterpret_cast<const uint32_t*>(font + FONT_EM_H);
            view.cellW = *reinterpret_cast<const uint16_t*>(font + FONT_CELL_W);
            view.cellH = *reinterpret_cast<const uint16_t*>(font + FONT_CELL_H);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return view.records && view.count && view.emW && view.emH && view.cellW && view.cellH;
    }

    const FontRecord* FindRecord(const FontView& view, uint32_t code)
    {
        for (uint32_t i = 0; i < view.count; ++i)
        {
            if (view.records[i].code == code)
                return &view.records[i];
        }
        return &view.records[0];
    }

    void ReadInkRecords(const FontView& view, std::vector<GlyphInk>& out)
    {
        for (uint32_t i = 0; i < view.count; ++i)
        {
            const FontRecord& sig = view.records[i];
            if (sig.code != INK_SIGNATURE_CODE || sig.y != INK_SIGNATURE_Y || sig.x != INK_SIGNATURE_X ||
                sig.padTop != INK_VERSION)
                continue;
            const uint32_t n = sig.padBottom;
            if (n == 0 || i + 1 + n > view.count)
                return;
            out.reserve(n);
            for (uint32_t k = 0; k < n; ++k)
            {
                const FontRecord& g = view.records[i + 1 + k];
                if (g.code != INK_SIGNATURE_CODE + 1 + k || g.x > 0xFF || g.padTop > 0xFF || g.padBottom > 0xFF ||
                    g.padLeft > 0xFF)
                {
                    out.clear();
                    return;
                }
                out.push_back({ g.y, static_cast<uint8_t>(g.x), static_cast<uint8_t>(g.padTop),
                                static_cast<uint8_t>(g.padBottom), static_cast<uint8_t>(g.padLeft) });
            }
            std::sort(out.begin(), out.end(), [](const GlyphInk& a, const GlyphInk& b) { return a.code < b.code; });
            return;
        }
    }

    bool ReadInkRecordsSafe(const FontView& view, std::vector<GlyphInk>& out)
    {
        __try
        {
            ReadInkRecords(view, out);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    const FontInk* FindInk(uintptr_t font, const FontView& view)
    {
        const FontInk* ink = nullptr;
        if (gInkFont.load() == font)
        {
            ink = gInk.load();
            if (ink && ink->records == view.records && ink->count == view.count)
                return ink->glyphs.empty() ? nullptr : ink;
            ink = nullptr;
        }
        AcquireSRWLockShared(&gInkLock);
        const auto it = gInkByFont.find(font);
        if (it != gInkByFont.end() && it->second->records == view.records && it->second->count == view.count)
            ink = it->second;
        ReleaseSRWLockShared(&gInkLock);
        if (!ink)
        {
            FontInk* built = new FontInk{ view.records, view.count, {} };
            if (!ReadInkRecordsSafe(view, built->glyphs))
                built->glyphs.clear();
            AcquireSRWLockExclusive(&gInkLock);
            gInkByFont[font] = built;
            ReleaseSRWLockExclusive(&gInkLock);
            ink = built;
            if (gInkLogBudget.load() > 0)
            {
                gInkLogBudget.fetch_sub(1);
                Log("[fox::ui::Font::CreateText] font %p (em %u, cell %ux%u): %zu letter measurements read from its .fnt\n",
                    reinterpret_cast<void*>(font), view.emW, view.cellW, view.cellH, built->glyphs.size());
            }
        }
        gInk.store(ink);
        gInkFont.store(font);
        return ink->glyphs.empty() ? nullptr : ink;
    }

    const GlyphInk* FindGlyphInk(const FontInk* ink, uint32_t code)
    {
        if (!ink)
            return nullptr;
        const auto it = std::lower_bound(ink->glyphs.begin(), ink->glyphs.end(), code,
                                         [](const GlyphInk& g, uint32_t c) { return g.code < c; });
        return it != ink->glyphs.end() && it->code == code ? &*it : nullptr;
    }

    bool PlaceMarks(uintptr_t font, const char* text, float width, float space, float height, float* xy, float* penX)
    {
        FontView view{};
        if (!ReadFont(font, view))
            return false;
        const FontInk* ink = FindInk(font, view);
        const float sx = width / static_cast<float>(view.emW);
        const float sy = height / static_cast<float>(view.emH);

        const unsigned char* p = reinterpret_cast<const unsigned char*>(text);
        size_t index = 0;
        float shift = 0.0f;
        int moved = 0;
        BaseGlyph base{};
        while (*p)
        {
            uint32_t code = 0;
            if (!NextCodePoint(p, code))
                return false;
            const FontRecord* rec = FindRecord(view, code);
            const float advance = static_cast<float>(view.cellW - rec->padLeft - rec->padRight) * sx;
            float* q = xy ? xy + index * FLOATS_PER_GLYPH : nullptr;
            ++index;

            if (IsMark(code) && base.valid && advance > 0.0f)
            {
                if (q)
                {
                    const GlyphInk* mark = FindGlyphInk(ink, code);
                    const float w = q[4] - q[0];
                    const float markCenter = mark
                        ? ((mark->left + mark->right) * 0.5f - static_cast<float>(rec->padLeft)) * sx
                        : w * 0.5f;
                    const float x0 = base.centerX - markCenter;
                    q[0] = x0;
                    q[2] = x0;
                    q[4] = x0 + w;
                    q[6] = x0 + w;
                    if (mark)
                    {
                        float dy = 0.0f;
                        if (IsBelowMark(code))
                        {
                            const int rows = base.belowBottom + MARK_GAP - mark->top;
                            dy = -static_cast<float>(rows) * sy;
                            base.belowBottom = mark->bottom + rows;
                        }
                        else
                        {
                            const int rows = mark->bottom - (base.aboveTop - MARK_GAP);
                            dy = static_cast<float>(rows) * sy;
                            base.aboveTop = mark->top - rows;
                        }
                        q[1] += dy;
                        q[3] += dy;
                        q[5] += dy;
                        q[7] += dy;
                    }
                }
                shift += advance + space;
                ++moved;
                continue;
            }

            if (q && shift != 0.0f)
            {
                q[0] -= shift;
                q[2] -= shift;
                q[4] -= shift;
                q[6] -= shift;
            }

            if (IsMark(code))
                continue;

            const GlyphInk* glyph = FindGlyphInk(ink, code);
            base.valid = code != 0x20 && (glyph != nullptr || !ink);
            if (base.valid && q)
            {
                base.centerX = glyph ? q[0] + ((glyph->left + glyph->right) * 0.5f - static_cast<float>(rec->padLeft)) * sx
                                     : (q[0] + q[4]) * 0.5f;
                base.aboveTop = glyph ? glyph->top : 0;
                base.belowBottom = glyph ? glyph->bottom : view.cellH;
            }
        }

        if (penX && shift != 0.0f)
            *penX -= shift;

        if (moved && gLogBudget.load() > 0)
        {
            gLogBudget.fetch_sub(1);
            Log("[fox::ui::Font::CreateText] %d haraka(s) placed over their letters (%s, em %u cell %ux%u)\n", moved,
                ink ? "measurements from the .fnt" : "no measurements in the .fnt", view.emW, view.cellW, view.cellH);
        }
        return true;
    }

    bool PlaceMarksSafe(uintptr_t font, const char* text, float width, float space, float height, float* xy, float* penX)
    {
        __try
        {
            return PlaceMarks(font, text, width, space, height, xy, penX);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    constexpr size_t MAX_SPACED_GLYPHS = 1024;

    bool IsLatinGlyph(uint32_t c)
    {
        return c >= 0x21 && c <= 0x7E;
    }

    bool NextNonMarkIsLatin(const uint32_t* codes, size_t count, size_t from)
    {
        for (size_t i = from; i < count; ++i)
        {
            if (!IsMark(codes[i]))
                return IsLatinGlyph(codes[i]);
        }
        return false;
    }

    bool KeepSpacingForLatinOnly(uintptr_t font, const char* text, float space, float* xy, float* penX)
    {
        FontView view{};
        if (!ReadFont(font, view) || !FindInk(font, view))
            return false;

        static thread_local uint32_t codes[MAX_SPACED_GLYPHS];
        size_t count = 0;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(text);
        while (*p)
        {
            if (count == MAX_SPACED_GLYPHS || !NextCodePoint(p, codes[count]))
                return false;
            ++count;
        }

        float shift = 0.0f;
        bool previousLatin = false;
        for (size_t i = 0; i < count; ++i)
        {
            const uint32_t c = codes[i];
            if (xy && shift != 0.0f)
            {
                float* q = xy + i * FLOATS_PER_GLYPH;
                q[0] -= shift;
                q[2] -= shift;
                q[4] -= shift;
                q[6] -= shift;
            }
            if (IsMark(c))
                continue;
            const bool latin = IsLatinGlyph(c) || (c == 0x20 && previousLatin && NextNonMarkIsLatin(codes, count, i + 1));
            if (!latin)
                shift += space;
            previousLatin = IsLatinGlyph(c);
        }
        if (penX && shift != 0.0f)
            *penX -= shift;
        return shift != 0.0f;
    }

    bool KeepSpacingForLatinOnlySafe(uintptr_t font, const char* text, float space, float* xy, float* penX)
    {
        __try
        {
            return KeepSpacingForLatinOnly(font, text, space, xy, penX);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    std::atomic<int> gSpacingLogBudget{ 2 };

    uint8_t __fastcall hkCreateText(uintptr_t font, const char* text, float width, float height, float space, float* xy,
                                    float* uv, float* penX, float* maxHeight)
    {
        const uint8_t result = oCreateText(font, text, width, height, space, xy, uv, penX, maxHeight);
        if (!result || !text)
            return result;
        if (space != 0.0f && KeepSpacingForLatinOnlySafe(font, text, space, xy, penX) && gSpacingLogBudget.load() > 0)
        {
            gSpacingLogBudget.fetch_sub(1);
            Log("[fox::ui::Font::CreateText] letter spacing %.1f kept for Latin and digits only, Arabic letters keep their joins\n",
                space);
        }
        if (!MayContainMark(reinterpret_cast<const unsigned char*>(text)))
            return result;
        PlaceMarksSafe(font, text, width, space, height, xy, penX);
        return result;
    }
}

bool InstallFntHarakatHook(HMODULE hGame)
{
    if (!hGame || !gAddr.FontCreateText)
    {
        Log("[fox::ui::Font::CreateText] address missing - harakat in .fnt text are not placed.\n");
        return false;
    }
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (gAddr.FontCreateText - IDA_IMAGE_BASE));
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkCreateText), reinterpret_cast<void**>(&oCreateText)) != MH_OK)
    {
        Log("[fox::ui::Font::CreateText] MH_CreateHook failed.\n");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[fox::ui::Font::CreateText] MH_EnableHook failed.\n");
        return false;
    }
    gTarget = target;
    Log("[fox::ui::Font::CreateText] harakat placement hooked at %p (letter measurements come from each .fnt).\n", target);
    return true;
}

void RemoveFntHarakatHook()
{
    if (!gTarget)
        return;
    MH_DisableHook(gTarget);
    MH_RemoveHook(gTarget);
    gTarget = nullptr;
    oCreateText = nullptr;
    gInkFont.store(0);
    gInk.store(nullptr);
}
