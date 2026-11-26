#include <windows.h>
#include <cstdint>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

using IsArabLanguage_t = bool(__cdecl*)();
using CreateTextUnits_t = int(__fastcall*)(
    char* text,
    float* fontGroup,
    float* rubyFontGroup,
    unsigned int fontId,
    unsigned int flags,
    float displayWidth,
    void* textUnits,
    int maxUnits);

using TextUnitSetting_t = void(__fastcall*)(
    void* unit,
    const char* text,
    uint32_t flags,
    uint16_t charCount,
    uint64_t line,
    uint64_t width,
    uint64_t height,
    uint64_t extra,
    uint64_t color);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static CreateTextUnits_t oCreateTextUnits = nullptr;
static void* gTargetCreateTextUnits = nullptr;
static TextUnitSetting_t oTextUnitSetting = nullptr;
static void* gTargetTextUnitSetting = nullptr;

static thread_local int tCreateTextUnitsDepth = 0;
static thread_local uint32_t tTextUnitBuilds = 0;
static thread_local uint32_t tArabicTextUnitBuilds = 0;

struct TextUnitsSource
{
    std::atomic<const void*> units{ nullptr };
    std::atomic<bool> arabic{ false };
};

static constexpr size_t MAX_TEXT_UNIT_SOURCES = 64;
static TextUnitsSource gTextUnitSources[MAX_TEXT_UNIT_SOURCES];
static std::atomic<size_t> gNextTextUnitSource{ 0 };
static std::mutex gHarakatTextMtx;
static std::unordered_set<std::string> gHarakatTexts;

static const uint8_t kTextUnitSettingPrologue[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20,
};

struct CreateTextUnitsScope
{
    CreateTextUnitsScope() { ++tCreateTextUnitsDepth; }
    ~CreateTextUnitsScope() { --tCreateTextUnitsDepth; }
};

static const char* PersistentHarakatText(std::string&& text);
static bool IsAttachedText(const std::string& text);
static void NoteTextUnitsSource(const void* units, bool arabic);
const char* FindFullArabicStaffName(const char* text);

static constexpr unsigned int FLAG_INLINE_RUBY = 0x2;
static constexpr size_t RUBY_MODE_OPCODE = 8;
static constexpr uint8_t OPCODE_CMOVNZ = 0x45;
static constexpr uint8_t OPCODE_CMOVO = 0x40;
static const uint8_t kRubyForceInlineCode[] = {
    0x84, 0xDB, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x45, 0xC1, 0x88, 0x45, 0xC0,
};

static uint8_t* gRubyModeOpcode = nullptr;
static std::mutex gRubyModeMtx;
static std::atomic<int> gRubyAboveState{ -1 };

static void SetArabicRubyAbove(bool enable)
{
    if (!gRubyModeOpcode)
        return;
    const int want = enable ? 1 : 0;
    if (gRubyAboveState.load() == want)
        return;

    std::lock_guard<std::mutex> lk(gRubyModeMtx);
    if (gRubyAboveState.load() == want)
        return;
    DWORD oldProtect = 0;
    if (!VirtualProtect(gRubyModeOpcode, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return;
    *gRubyModeOpcode = enable ? OPCODE_CMOVO : OPCODE_CMOVNZ;
    VirtualProtect(gRubyModeOpcode, 1, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), gRubyModeOpcode, 1);
    gRubyAboveState.store(want);
    Log("[TextAnalysis::CreateTextUnits] ruby %s\n",
        enable ? "drawn above the text for Arabic" : "back to the engine's own rule");
}

static bool MoveLeadingServerIconToEnd(std::string& text)
{
    static const char kServerIcon[] = "<I=G=SERVER_WALLET>";
    constexpr size_t kServerIconLength = sizeof(kServerIcon) - 1;
    if (text.size() <= kServerIconLength || text.compare(0, kServerIconLength, kServerIcon) != 0)
        return false;
    if (text.find_first_of("<\r\n", kServerIconLength) != std::string::npos)
        return false;
    text = text.substr(kServerIconLength) + kServerIcon;
    return true;
}

static bool IsAsciiDigit(char c)
{
    return c >= '0' && c <= '9';
}

static bool IsAsciiLetter(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool StartsSignedNumber(const std::string& text, size_t sign)
{
    if (text[sign] != '+' && text[sign] != '-')
        return false;
    if (sign == 0)
        return true;
    const char before = text[sign - 1];
    return before == ' ' || before == '(' || before == '[' || before == '\n' || before == '\r';
}

static bool MovePercentSignsBeforeNumbers(std::string& text)
{
    bool moved = false;
    bool inTag = false;
    for (size_t i = 0; i < text.size(); ++i)
    {
        const char c = text[i];
        if (inTag)
        {
            if (c == '>')
                inTag = false;
            continue;
        }
        if (c == '<')
        {
            inTag = true;
            continue;
        }
        if (c != '%' || i == 0 || !IsAsciiDigit(text[i - 1]))
            continue;
        size_t start = i - 1;
        while (start > 0 && (IsAsciiDigit(text[start - 1]) ||
                             ((text[start - 1] == '.' || text[start - 1] == ',') && start >= 2 &&
                              IsAsciiDigit(text[start - 2]))))
            --start;
        if (start > 0 && StartsSignedNumber(text, start - 1))
            --start;
        text.erase(i, 1);
        text.insert(start, 1, '%');
        moved = true;
    }
    return moved;
}

static bool RewriteInlineRuby(std::string& text)
{
    bool changed = false;
    size_t pos = 0;
    while ((pos = text.find("<I=R=", pos)) != std::string::npos)
    {
        const size_t bar = text.find('|', pos + 5);
        const size_t close = text.find('>', pos + 5);
        if (bar == std::string::npos || close == std::string::npos || bar > close)
        {
            pos += 5;
            continue;
        }
        const std::string base = text.substr(pos + 5, bar - pos - 5);
        const std::string gloss = text.substr(bar + 1, close - bar - 1);
        const std::string inlineForm = "(" + gloss + ") " + base;
        text.replace(pos, close + 1 - pos, inlineForm);
        pos += inlineForm.size();
        changed = true;
    }
    return changed;
}

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

static constexpr size_t UNIT_SIZE = 0x20;
static constexpr size_t UNIT_TEXT = 0x00;
static constexpr size_t UNIT_FLAGS = 0x0C;
static constexpr size_t UNIT_LINE = 0x12;
static constexpr unsigned int FLAG_WRAP = 0x1;
static constexpr uint32_t UNIT_ICON = 0x8;
static constexpr uint32_t UNIT_RUBY_BASE = 0x10 | 0x40;
static constexpr uint32_t UNIT_RUBY_TEXT = 0x20 | 0x80;
static constexpr uint32_t UNIT_COLOUR = 0x1000;

static std::atomic<int> gWrapLogBudget{ 6 };
static std::atomic<int> gFallbackLogBudget{ 12 };
static std::atomic<int> gBudgetLogBudget{ 12 };
static std::atomic<int> gHarakatLogBudget{ 1 };
static std::atomic<int> gServerIconLogBudget{ 3 };
static std::atomic<int> gPercentLogBudget{ 3 };
static std::mutex gPercentTextMtx;
static std::unordered_set<std::string> gPercentTexts;
static constexpr size_t MAX_PERCENT_TEXTS = 8192;
static constexpr ptrdiff_t MAX_PERCENT_TEXT_LENGTH = 128;
static constexpr ptrdiff_t MAX_PERCENT_ARABIC_TEXT_LENGTH = 1024;

struct UnitView
{
    std::string text;
    uint32_t flags;
    uint16_t line;
};

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static __forceinline bool IsArabicSafe()
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

static bool HasArabicTextSafe(const char* text)
{
    __try
    {
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p)
        {
            if (*p >= 0xD8 && *p <= 0xDB)
                return true;
            if (*p == 0xEF && ((p[1] >= 0xAD && p[1] <= 0xB7) || (p[1] >= 0xB9 && p[1] <= 0xBB)))
                return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return false;
}

static bool IsPercentNumberTextSafe(const char* text, bool arabicText)
{
    __try
    {
        const ptrdiff_t maxLength = arabicText ? MAX_PERCENT_ARABIC_TEXT_LENGTH : MAX_PERCENT_TEXT_LENGTH;
        bool percentAfterNumber = false;
        bool inTag = false;
        for (const char* p = text; *p; ++p)
        {
            if (p - text > maxLength)
                return false;
            const char c = *p;
            if (inTag)
            {
                if (c == '>')
                    inTag = false;
                continue;
            }
            if (c == '<')
                inTag = true;
            else if (!arabicText && IsAsciiLetter(c))
                return false;
            else if (c == '%' && p > text && IsAsciiDigit(p[-1]))
                percentAfterNumber = true;
        }
        return percentAfterNumber;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void NotePercentMoved(const std::string& text)
{
    if (gPercentLogBudget.load() > 0)
    {
        gPercentLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] percent sign moved before its number for Arabic: %.160s\n", text.c_str());
    }
}

static const char* PercentFirstText(const char* text)
{
    std::string reordered(text);
    if (!MovePercentSignsBeforeNumbers(reordered))
        return nullptr;
    const char* stable = nullptr;
    bool added = false;
    {
        std::lock_guard<std::mutex> lk(gPercentTextMtx);
        const auto found = gPercentTexts.find(reordered);
        if (found != gPercentTexts.end())
            stable = found->c_str();
        else if (gPercentTexts.size() < MAX_PERCENT_TEXTS)
        {
            stable = gPercentTexts.insert(reordered).first->c_str();
            added = true;
        }
    }
    if (added)
        NotePercentMoved(reordered);
    return stable;
}

const char* PercentFirstDirectText(const char* text)
{
    if (!text || !IsArabicSafe() || !RL_UsesArabicScript())
        return nullptr;
    if (!IsPercentNumberTextSafe(text, HasArabicTextSafe(text)))
        return nullptr;
    return PercentFirstText(text);
}

static bool IsRubyTagAt(const std::string& text, size_t open)
{
    return text.compare(open, 5, "<I=R=") == 0 || text.compare(open, 5, "<I=r=") == 0;
}

static bool IsColourTagAt(const std::string& text, size_t open)
{
    return text.compare(open, 5, "<I=C=") == 0 || text.compare(open, 5, "<i=C=") == 0;
}

static bool HasColourTag(const std::string& text)
{
    for (size_t open = text.find('<'); open != std::string::npos; open = text.find('<', open + 1))
    {
        if (IsColourTagAt(text, open))
            return true;
    }
    return false;
}

static bool HasTagWithSpace(const std::string& text)
{
    size_t open = text.find('<');
    while (open != std::string::npos)
    {
        const size_t close = text.find('>', open);
        if (close == std::string::npos)
            return true;
        if (text.find(' ', open) < close && !IsRubyTagAt(text, open) && !IsColourTagAt(text, open))
            return true;
        open = text.find('<', close);
    }
    return false;
}

struct ColouredText
{
    std::string text;
    std::vector<int> colour;
};

static bool StripColourTags(const std::string& text, ColouredText& out, std::vector<std::string>& keys)
{
    out.text.clear();
    out.colour.clear();
    size_t i = 0;
    while (i < text.size())
    {
        if (text[i] != '<')
        {
            out.text += text[i];
            out.colour.push_back(-1);
            ++i;
            continue;
        }
        const size_t close = text.find('>', i);
        if (close == std::string::npos)
            return false;
        if (!IsColourTagAt(text, i))
        {
            out.text.append(text, i, close + 1 - i);
            out.colour.insert(out.colour.end(), close + 1 - i, -1);
            i = close + 1;
            continue;
        }
        const size_t bar = text.find('|', i + 5);
        if (bar == std::string::npos || bar > close || text.find('<', i + 1) < close)
            return false;
        const std::string key = text.substr(i + 5, bar - i - 5);
        int index = -1;
        for (size_t k = 0; k < keys.size(); ++k)
        {
            if (keys[k] == key)
                index = static_cast<int>(k);
        }
        if (index < 0)
        {
            keys.push_back(key);
            index = static_cast<int>(keys.size() - 1);
        }
        out.text.append(text, bar + 1, close - bar - 1);
        out.colour.insert(out.colour.end(), close - bar - 1, index);
        i = close + 1;
    }
    return true;
}

static void ReverseColouredWords(const ColouredText& in, size_t from, size_t to, ColouredText& out)
{
    std::vector<std::pair<size_t, size_t>> words;
    size_t start = from;
    bool inTag = false;
    for (size_t i = from; i < to; ++i)
    {
        const char c = in.text[i];
        if (c == '<')
            inTag = true;
        else if (c == '>')
            inTag = false;
        else if (c == ' ' && !inTag)
        {
            words.emplace_back(start, i);
            start = i + 1;
        }
    }
    words.emplace_back(start, to);

    for (size_t w = words.size(); w-- > 0;)
    {
        const size_t a = words[w].first;
        const size_t b = words[w].second;
        out.text.append(in.text, a, b - a);
        out.colour.insert(out.colour.end(), in.colour.begin() + a, in.colour.begin() + b);
        if (w != 0)
        {
            const int left = b > a ? in.colour[b - 1] : -1;
            const size_t na = words[w - 1].first;
            const size_t nb = words[w - 1].second;
            const int right = nb > na ? in.colour[na] : -1;
            out.text += ' ';
            out.colour.push_back(left == right ? left : -1);
        }
    }
}

static ColouredText ReverseColouredWordsPerParagraph(const ColouredText& in)
{
    ColouredText out;
    out.text.reserve(in.text.size());
    out.colour.reserve(in.colour.size());
    size_t pos = 0;
    while (pos < in.text.size())
    {
        size_t end = pos;
        while (end < in.text.size() && in.text[end] != '\r' && in.text[end] != '\n')
            ++end;
        ReverseColouredWords(in, pos, end, out);
        while (end < in.text.size() && (in.text[end] == '\r' || in.text[end] == '\n'))
        {
            out.text += in.text[end];
            out.colour.push_back(-1);
            ++end;
        }
        pos = end;
    }
    return out;
}

static std::string WithColourTags(const ColouredText& in, const std::vector<std::string>& keys)
{
    std::string out;
    out.reserve(in.text.size() + 32);
    int current = -1;
    for (size_t i = 0; i < in.text.size(); ++i)
    {
        const int c = in.text[i] == '\r' || in.text[i] == '\n' ? -1 : in.colour[i];
        if (c != current)
        {
            if (current >= 0)
                out += '>';
            if (c >= 0)
                out += "<I=C=" + keys[static_cast<size_t>(c)] + "|";
            current = c;
        }
        out += in.text[i];
    }
    if (current >= 0)
        out += '>';
    return out;
}

struct LineColours
{
    const ColouredText* text;
    const std::vector<std::string>* keys;
};

static std::string ReverseWords(const std::string& line)
{
    std::vector<std::string> words;
    size_t start = 0;
    bool inTag = false;
    for (size_t i = 0; i < line.size(); ++i)
    {
        if (line[i] == '<')
            inTag = true;
        else if (line[i] == '>')
            inTag = false;
        else if (line[i] == ' ' && !inTag)
        {
            words.emplace_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    words.emplace_back(line.substr(start));

    std::string out;
    out.reserve(line.size());
    for (size_t i = words.size(); i-- > 0;)
    {
        out += words[i];
        if (i != 0)
            out += ' ';
    }
    return out;
}

static std::string ReverseWordsPerParagraph(const std::string& text)
{
    std::string out;
    out.reserve(text.size());
    size_t pos = 0;
    while (pos < text.size())
    {
        size_t end = pos;
        while (end < text.size() && text[end] != '\r' && text[end] != '\n')
            ++end;
        out += ReverseWords(text.substr(pos, end - pos));
        while (end < text.size() && (text[end] == '\r' || text[end] == '\n'))
            out += text[end++];
        pos = end;
    }
    return out;
}

static bool RestoreCrLfOrder(std::string& text)
{
    bool changed = false;
    for (size_t i = 0; i + 1 < text.size(); ++i)
    {
        if (text[i] == '\n' && text[i + 1] == '\r' && (i == 0 || text[i - 1] != '\r'))
        {
            text[i] = '\r';
            text[i + 1] = '\n';
            changed = true;
            ++i;
        }
    }
    return changed;
}

static bool HasRubyTag(const std::string& text)
{
    for (size_t open = text.find('<'); open != std::string::npos; open = text.find('<', open + 1))
    {
        if (IsRubyTagAt(text, open))
            return true;
    }
    return false;
}

static bool IsPunctuationOnly(const std::string& s, size_t from, size_t to)
{
    static const char* const kMarks[] = { "\xD8\x8C", "\xD8\x9B", "\xD8\x9F", "\xC2\xAB", "\xC2\xBB", "\xE2\x80\xA6" };
    bool any = false;
    size_t i = from;
    while (i < to)
    {
        const char c = s[i];
        if (c == ' ')
        {
            ++i;
            continue;
        }
        if (static_cast<unsigned char>(c) < 0x80)
        {
            if (!std::strchr(".,!?:;'\"()-", c))
                return false;
            any = true;
            ++i;
            continue;
        }
        bool matched = false;
        for (const char* mark : kMarks)
        {
            const size_t n = std::strlen(mark);
            if (i + n <= to && s.compare(i, n, mark) == 0)
            {
                i += n;
                matched = true;
                any = true;
                break;
            }
        }
        if (!matched)
            return false;
    }
    return any;
}

static std::string TrimSpaces(const std::string& s)
{
    const size_t first = s.find_first_not_of(' ');
    if (first == std::string::npos)
        return std::string();
    return s.substr(first, s.find_last_not_of(' ') - first + 1);
}

static bool IsSegmentBoundary(char c)
{
    return c == '\n' || c == '\r' || c == '>';
}

static bool FoldPunctuationIntoRuby(std::string& s)
{
    bool changed = false;
    for (size_t open = s.find('<'); open != std::string::npos; open = s.find('<', open + 1))
    {
        if (!IsRubyTagAt(s, open))
            continue;
        const size_t bar = s.find('|', open);
        const size_t close = s.find('>', open);
        if (bar == std::string::npos || close == std::string::npos || bar > close)
            return changed;

        size_t right = close + 1;
        while (right < s.size() && !IsSegmentBoundary(s[right]) && s[right] != '<')
            ++right;
        if (right > close + 1 && IsPunctuationOnly(s, close + 1, right))
        {
            const std::string mark = TrimSpaces(s.substr(close + 1, right - close - 1));
            s.erase(close + 1, right - close - 1);
            s.insert(bar, mark);
            changed = true;
        }

        size_t left = open;
        while (left > 0 && !IsSegmentBoundary(s[left - 1]))
            --left;
        if (left < open && IsPunctuationOnly(s, left, open))
        {
            const std::string mark = TrimSpaces(s.substr(left, open - left));
            s.erase(left, open - left);
            s.insert(left + 5, mark);
            open = left;
            changed = true;
        }
    }
    return changed;
}

static bool DropLastRubyGloss(std::string& s)
{
    size_t open = s.rfind('<');
    while (open != std::string::npos)
    {
        if (IsRubyTagAt(s, open))
        {
            const size_t bar = s.find('|', open);
            const size_t close = s.find('>', open);
            if (bar == std::string::npos || close == std::string::npos || bar > close)
                return false;
            s.replace(open, close - open + 1, s.substr(open + 5, bar - open - 5));
            return true;
        }
        if (open == 0)
            break;
        open = s.rfind('<', open - 1);
    }
    return false;
}

static constexpr int TRIAL_UNITS = 256;

static int TrialUnits(std::string measured, float* fontGroup, float* rubyFontGroup, unsigned int fontId,
                      unsigned int flags, float displayWidth)
{
    static thread_local std::vector<uint8_t> trial;
    trial.assign(static_cast<size_t>(TRIAL_UNITS) * UNIT_SIZE, 0);
    const int built = oCreateTextUnits(&measured[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth,
                                       trial.data(), TRIAL_UNITS);
    const int counted = oCreateTextUnits(&measured[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, nullptr, 0);
    return built > counted ? built : counted;
}

static int CountRubyLineUnits(const std::string& s, float* fontGroup, float* rubyFontGroup, unsigned int fontId,
                              unsigned int flags, float displayWidth)
{
    const int plain = TrialUnits(s, fontGroup, rubyFontGroup, fontId, flags, displayWidth);
    const bool reversed = (flags & FLAG_WRAP) && displayWidth > 0.0f && !HasTagWithSpace(s);
    if (!reversed)
        return plain;
    const int flipped = TrialUnits(ReverseWordsPerParagraph(s), fontGroup, rubyFontGroup, fontId, flags, displayWidth);
    return flipped > plain ? flipped : plain;
}

static std::atomic<int> gRubyFitLogBudget{ 8 };
static std::atomic<int> gRubySizeLogBudget{ 8 };

static bool FitRubyToBudget(std::string& s, float* fontGroup, float* rubyFontGroup, unsigned int fontId,
                            unsigned int flags, float displayWidth, int maxUnits)
{
    const int needed = CountRubyLineUnits(s, fontGroup, rubyFontGroup, fontId, flags, displayWidth);
    if (needed <= maxUnits)
        return false;

    std::string fitted = s;
    int now = needed;
    const bool folded = FoldPunctuationIntoRuby(fitted);
    if (folded)
        now = CountRubyLineUnits(fitted, fontGroup, rubyFontGroup, fontId, flags, displayWidth);
    int dropped = 0;
    while (now > maxUnits && DropLastRubyGloss(fitted))
    {
        ++dropped;
        now = CountRubyLineUnits(fitted, fontGroup, rubyFontGroup, fontId, flags, displayWidth);
    }
    if (fitted == s)
        return false;

    if (gRubyFitLogBudget.load() > 0)
    {
        gRubyFitLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] ruby text needed %d units but the box allows %d: %s%d glosses dropped, "
            "now %d units\n",
            needed, maxUnits, folded ? "punctuation joined to the ruby word, " : "", dropped, now);
    }
    s.swap(fitted);
    return true;
}

static bool ReadUnitRaw(const uint8_t* unit, const char*& text, size_t& length, uint32_t& flags, uint16_t& line)
{
    __try
    {
        text = *reinterpret_cast<const char* const*>(unit + UNIT_TEXT);
        flags = *reinterpret_cast<const uint32_t*>(unit + UNIT_FLAGS);
        line = *reinterpret_cast<const uint16_t*>(unit + UNIT_LINE);
        length = 0;
        if (text)
        {
            while (text[length] && length < 0x1000)
                ++length;
            if (text[length])
                return false;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadUnits(const uint8_t* units, int count, std::vector<UnitView>& out)
{
    for (int i = 0; i < count; ++i)
    {
        const char* text = nullptr;
        size_t length = 0;
        UnitView view{};
        if (!ReadUnitRaw(units + static_cast<size_t>(i) * UNIT_SIZE, text, length, view.flags, view.line))
            return false;
        if (text)
            view.text.assign(text, length);
        out.push_back(std::move(view));
    }
    return true;
}

static bool OnlyBreakChars(const std::string& s, size_t from, size_t to)
{
    for (size_t i = from; i < to; ++i)
    {
        if (s[i] != ' ' && s[i] != '\r' && s[i] != '\n')
            return false;
    }
    return true;
}

static bool BuildVisualLines(const std::string& flipped, const std::vector<UnitView>& units, bool cutAtCovered,
                             std::string& out, size_t& lineCount, bool& coveredAll, const char*& why,
                             const LineColours* colours = nullptr)
{
    coveredAll = false;
    why = "could not map wrapped units back to the text";
    std::vector<size_t> starts;
    std::vector<uint16_t> lines;
    size_t cursor = 0;
    size_t rubyOpen = std::string::npos;

    for (const UnitView& unit : units)
    {
        if (unit.flags & UNIT_COLOUR)
        {
            why = "a unit uses colour flags";
            return false;
        }

        size_t start = cursor;
        if (unit.flags & UNIT_RUBY_BASE)
        {
            const size_t open = flipped.find('<', cursor);
            const size_t close = open == std::string::npos ? open : flipped.find('>', open);
            if (close == std::string::npos || !OnlyBreakChars(flipped, cursor, open) || !IsRubyTagAt(flipped, open))
            {
                why = "a ruby unit has no matching tag";
                return false;
            }
            start = open;
            cursor = close + 1;
            rubyOpen = open;
        }
        else if (unit.flags & UNIT_RUBY_TEXT)
        {
            if (rubyOpen == std::string::npos)
            {
                why = "a ruby reading has no base";
                return false;
            }
            start = rubyOpen;
        }
        else if (unit.flags & UNIT_ICON)
        {
            const size_t open = flipped.find('<', cursor);
            const size_t close = open == std::string::npos ? open : flipped.find('>', open);
            if (close == std::string::npos || !OnlyBreakChars(flipped, cursor, open))
            {
                why = "an icon unit has no matching tag";
                return false;
            }
            start = open;
            cursor = close + 1;
        }
        else if (!unit.text.empty())
        {
            const size_t found = flipped.find(unit.text, cursor);
            if (found == std::string::npos || !OnlyBreakChars(flipped, cursor, found))
            {
                why = "a text unit is not found in the text";
                return false;
            }
            start = found;
            cursor = found + unit.text.size();
        }

        starts.push_back(start);
        lines.push_back(unit.line);
    }

    coveredAll = OnlyBreakChars(flipped, cursor, flipped.size());
    const size_t end = cutAtCovered && !coveredAll ? cursor : flipped.size();

    std::vector<size_t> breaks;
    breaks.push_back(0);
    for (size_t i = 1; i < units.size(); ++i)
    {
        if (lines[i] != lines[i - 1])
            breaks.push_back(starts[i]);
    }

    lineCount = breaks.size();
    if (lineCount < 2)
    {
        why = "single line";
        return false;
    }

    out.clear();
    for (size_t i = 0; i < breaks.size(); ++i)
    {
        const size_t from = breaks[i];
        const size_t to = i + 1 < breaks.size() ? breaks[i + 1] : end;
        if (to < from)
        {
            why = "wrapped units are out of order";
            return false;
        }

        std::string line = flipped.substr(from, to - from);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos)
        {
            why = "a wrapped line still holds a line break";
            return false;
        }

        if (i != 0)
            out += '\n';
        if (!colours)
        {
            out += ReverseWords(line);
            continue;
        }
        ColouredText visualLine;
        ReverseColouredWords(*colours->text, from, from + line.size(), visualLine);
        out += WithColourTags(visualLine, *colours->keys);
    }
    return true;
}

struct Utf8Char
{
    uint32_t cp;
    size_t start;
    size_t length;
};

static bool DecodeUtf8(const std::string& text, std::vector<Utf8Char>& out)
{
    for (size_t i = 0; i < text.size();)
    {
        const unsigned char lead = static_cast<unsigned char>(text[i]);
        size_t length = 1;
        uint32_t cp = lead;
        if (lead >= 0xF0 && lead < 0xF8)
        {
            length = 4;
            cp = lead & 0x07;
        }
        else if (lead >= 0xE0)
        {
            length = 3;
            cp = lead & 0x0F;
        }
        else if (lead >= 0xC0)
        {
            length = 2;
            cp = lead & 0x1F;
        }
        else if (lead >= 0x80)
        {
            return false;
        }
        if (i + length > text.size())
            return false;
        for (size_t k = 1; k < length; ++k)
        {
            const unsigned char next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (next & 0x3F);
        }
        out.push_back({ cp, i, length });
        i += length;
    }
    return true;
}

static bool IsHaraka(uint32_t cp)
{
    return (cp >= 0x0610 && cp <= 0x061A) || (cp >= 0x064B && cp <= 0x065F) || cp == 0x0670 ||
           (cp >= 0x06D6 && cp <= 0x06DC) || (cp >= 0x06DF && cp <= 0x06E4) || cp == 0x06E7 || cp == 0x06E8 ||
           (cp >= 0x06EA && cp <= 0x06ED);
}

static bool IsArabicLetter(uint32_t cp)
{
    if (IsHaraka(cp))
        return false;
    return (cp >= 0x0620 && cp <= 0x064A) || (cp >= 0x066E && cp <= 0x06D3) || cp == 0x06D5 ||
           (cp >= 0xFB50 && cp <= 0xFDFF) || (cp >= 0xFE70 && cp <= 0xFEFC);
}

static bool AttachHarakatToLetters(std::string& text)
{
    std::vector<Utf8Char> chars;
    if (!DecodeUtf8(text, chars))
        return false;

    std::string out;
    out.reserve(text.size());
    bool changed = false;
    size_t i = 0;
    while (i < chars.size())
    {
        if (!IsHaraka(chars[i].cp))
        {
            out.append(text, chars[i].start, chars[i].length);
            ++i;
            continue;
        }

        size_t end = i;
        while (end < chars.size() && IsHaraka(chars[end].cp))
            ++end;

        const bool hasLetter = end < chars.size() && IsArabicLetter(chars[end].cp);
        if (hasLetter)
        {
            out.append(text, chars[end].start, chars[end].length);
            changed = true;
        }
        for (int pass = 0; pass < 2; ++pass)
        {
            for (size_t k = i; k < end; ++k)
            {
                const bool shadda = chars[k].cp == 0x0651;
                if ((pass == 0) == shadda)
                    out.append(text, chars[k].start, chars[k].length);
            }
        }
        i = hasLetter ? end + 1 : end;
    }

    if (!changed)
        return false;
    text.swap(out);
    return true;
}

static std::atomic<int> gBoxTraceBudget{ 10 };
static std::mutex gBoxTraceMtx;
static std::unordered_set<uintptr_t> gBoxTraceSeen;

static void NoteBoxTextCaller(int maxUnits, const char* text)
{
    const bool question = text && std::strstr(text, "\xD8\x9F") != nullptr;
    if ((maxUnits != 0x10 && !question) || gBoxTraceBudget.load() <= 0 || !RL_DiagnosticsEnabled())
        return;

    void* frames[24] = {};
    const USHORT n = RtlCaptureStackBackTrace(1, 24, frames, nullptr);
    const uintptr_t lo = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const uintptr_t hi = lo + 0xA01D000;

    char line[512] = {};
    size_t used = 0;
    uintptr_t key = 0;
    int kept = 0;
    for (USHORT i = 0; i < n && kept < 8; ++i)
    {
        const uintptr_t a = reinterpret_cast<uintptr_t>(frames[i]);
        if (a < lo || a >= hi)
            continue;
        if (kept == 2)
            key = a;
        used += static_cast<size_t>(_snprintf_s(line + used, sizeof(line) - used, _TRUNCATE, " %llX",
                                                static_cast<unsigned long long>(a - lo + 0x140000000ull)));
        ++kept;
    }
    {
        std::lock_guard<std::mutex> lk(gBoxTraceMtx);
        if (!gBoxTraceSeen.insert(key).second)
            return;
    }
    if (gBoxTraceBudget.fetch_sub(1) > 0)
        LogDetail("[BoxTextTrace] Arabic box text (%d units%s) built from:%s\n", maxUnits,
            question ? ", has a question mark" : "", line);
}

static void NoteFallback(const char* why, const std::string& text, int units, float width)
{
    if (gFallbackLogBudget.load() <= 0)
        return;
    gFallbackLogBudget.fetch_sub(1);

    size_t lf = 0;
    size_t cr = 0;
    for (char c : text)
    {
        lf += c == '\n';
        cr += c == '\r';
    }
    std::string sample;
    for (char c : text.substr(0, 480))
        sample += c == '\n' ? '|' : (c == '\r' ? '~' : c);
    Log("[TextAnalysis::CreateTextUnits] left as-is: %s (%d units, width %.0f, %zu LF, %zu CR) text: %s\n", why, units,
        width, lf, cr, sample.c_str());
}

static constexpr uint32_t UNIT_LINE_START = 0x4;
static constexpr size_t UNIT_CHARS = 0x10;
static constexpr uint32_t UNIT_ICON_OR_RUBY = 0x1F8;

static bool MoveLineStartsOffEmptyUnits(uint8_t* units, int count)
{
    __try
    {
        bool moved = false;
        for (int i = 0; i + 1 < count; ++i)
        {
            uint8_t* unit = units + static_cast<size_t>(i) * UNIT_SIZE;
            uint8_t* next = unit + UNIT_SIZE;
            auto& flags = *reinterpret_cast<uint32_t*>(unit + UNIT_FLAGS);
            auto& nextFlags = *reinterpret_cast<uint32_t*>(next + UNIT_FLAGS);
            const uint16_t chars = *reinterpret_cast<uint16_t*>(unit + UNIT_CHARS);
            const uint16_t line = *reinterpret_cast<uint16_t*>(unit + UNIT_LINE);
            const uint16_t nextLine = *reinterpret_cast<uint16_t*>(next + UNIT_LINE);
            if ((flags & UNIT_LINE_START) && !(flags & UNIT_ICON_OR_RUBY) && chars == 0 && nextLine == line &&
                !(nextFlags & UNIT_LINE_START) && !(nextFlags & UNIT_ICON_OR_RUBY))
            {
                flags &= ~UNIT_LINE_START;
                nextFlags |= UNIT_LINE_START;
                moved = true;
            }
        }
        return moved;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static std::atomic<int> gLineStartLogBudget{ 4 };

static int CreateTextUnitsArabic(char* text, float* fontGroup, float* rubyFontGroup, unsigned int fontId,
                                 unsigned int flags, float displayWidth, void* textUnits, int maxUnits);

static std::atomic<int> gColourWrapLogBudget{ 4 };

static int CreateColouredTextUnitsArabic(const std::string& original, char* text, float* fontGroup,
                                         float* rubyFontGroup, unsigned int fontId, unsigned int flags,
                                         float displayWidth, void* textUnits, int maxUnits)
{
    std::vector<std::string> keys;
    ColouredText stripped;
    if (!StripColourTags(original, stripped, keys))
    {
        if (textUnits)
            NoteFallback("a colour tag is not closed", original, 0, displayWidth);
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    }

    ColouredText flipped = ReverseColouredWordsPerParagraph(stripped);
    if (!textUnits)
    {
        std::string tagged = WithColourTags(flipped, keys);
        return oCreateTextUnits(&tagged[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits,
                                maxUnits);
    }

    const int firstPass =
        oCreateTextUnits(&flipped.text[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    if (firstPass <= 1)
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);

    const bool atBudget = maxUnits > 0 && firstPass >= maxUnits;
    std::vector<UnitView> views;
    views.reserve(static_cast<size_t>(firstPass));
    std::string visual;
    size_t lineCount = 0;
    bool coveredAll = false;
    const char* why = "could not read the wrapped units";
    const LineColours colours{ &flipped, &keys };
    if (!ReadUnits(static_cast<const uint8_t*>(textUnits), firstPass, views) ||
        !BuildVisualLines(flipped.text, views, atBudget, visual, lineCount, coveredAll, why, &colours))
    {
        if (lineCount >= 2 || views.empty() || std::strcmp(why, "single line") != 0)
            NoteFallback(why, original, firstPass, displayWidth);
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    }

    if (gColourWrapLogBudget.load() > 0)
    {
        gColourWrapLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] re-wrapped coloured Arabic text right-to-left: %zu lines, %zu colours, "
            "font %u, width %.0f\n",
            lineCount, keys.size(), fontId, displayWidth);
    }

    return oCreateTextUnits(&visual[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
}

static std::atomic<int> gRubyCapLogBudget{ 10 };

static bool HasRubyTagSafe(const char* text)
{
    __try
    {
        return text && (std::strstr(text, "<I=R=") || std::strstr(text, "<I=r="));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static int __fastcall hkCreateTextUnits(
    char* text,
    float* fontGroup,
    float* rubyFontGroup,
    unsigned int fontId,
    unsigned int flags,
    float displayWidth,
    void* textUnits,
    int maxUnits)
{
    const int count = CreateTextUnitsArabic(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    if (textUnits && gRubyCapLogBudget.load() > 0 && IsArabicSafe() && HasRubyTagSafe(text))
    {
        gRubyCapLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] ruby text: %d units (box cap %d), flags %u, font %u, width %.0f: %.240s\n",
            count, maxUnits, flags, fontId, displayWidth, text);
    }
    if (textUnits && count > 1 && IsArabicSafe() &&
        MoveLineStartsOffEmptyUnits(static_cast<uint8_t*>(textUnits), count) && gLineStartLogBudget.load() > 0)
    {
        gLineStartLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] a new line began on an empty unit - moved its line start onto the text after it\n");
    }
    return count;
}

static int CreateTextUnitsArabic(
    char* text,
    float* fontGroup,
    float* rubyFontGroup,
    unsigned int fontId,
    unsigned int flags,
    float displayWidth,
    void* textUnits,
    int maxUnits)
{
    const CreateTextUnitsScope scope;
    const bool arabic = IsArabicSafe();
    SetArabicRubyAbove(arabic);
    if (arabic)
    {
        if (const char* full = FindFullArabicStaffName(text))
            text = const_cast<char*>(full);
    }
    const bool arabicText = arabic && text && HasArabicTextSafe(text);
    if (textUnits)
    {
        ++tTextUnitBuilds;
        if (arabicText)
            ++tArabicTextUnitBuilds;
        NoteTextUnitsSource(textUnits, arabicText);
    }
    if (!arabicText)
    {
        if (arabic && text && RL_UsesArabicScript() && IsPercentNumberTextSafe(text, false))
        {
            if (const char* reordered = PercentFirstText(text))
                text = const_cast<char*>(reordered);
        }
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    }

    if (textUnits)
        NoteBoxTextCaller(maxUnits, text);

    std::string original(text);
    if (MoveLeadingServerIconToEnd(original))
    {
        text = &original[0];
        if (gServerIconLogBudget.load() > 0)
        {
            gServerIconLogBudget.fetch_sub(1);
            Log("[TextAnalysis::CreateTextUnits] online icon moved after the Arabic label: %.160s\n", text);
        }
    }
    if (RL_UsesArabicScript() && MovePercentSignsBeforeNumbers(original))
    {
        text = &original[0];
        NotePercentMoved(original);
    }
    if (RestoreCrLfOrder(original))
        text = &original[0];
    if ((flags & FLAG_INLINE_RUBY) && RewriteInlineRuby(original))
        text = &original[0];
    if (!IsAttachedText(original) && AttachHarakatToLetters(original))
    {
        PersistentHarakatText(std::string(original));
        text = &original[0];
        if (gHarakatLogBudget.load() > 0)
        {
            gHarakatLogBudget.fetch_sub(1);
            Log("[TextAnalysis::CreateTextUnits] harakat moved after their letters (shadda first)\n");
        }
    }

    if (textUnits && maxUnits > 0 && HasRubyTag(original) && !HasColourTag(original) &&
        FitRubyToBudget(original, fontGroup, rubyFontGroup, fontId, flags, displayWidth, maxUnits))
        text = &original[0];

    if (!(flags & FLAG_WRAP) || !(displayWidth > 0.0f))
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    if (HasTagWithSpace(original))
    {
        if (textUnits)
            NoteFallback("a tag holds a space", original, 0, displayWidth);
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    }

    if (HasColourTag(original))
        return CreateColouredTextUnitsArabic(original, text, fontGroup, rubyFontGroup, fontId, flags, displayWidth,
                                             textUnits, maxUnits);

    std::string flipped = ReverseWordsPerParagraph(original);

    if (!textUnits)
    {
        if (HasRubyTag(original))
        {
            const int needed = CountRubyLineUnits(original, fontGroup, rubyFontGroup, fontId, flags, displayWidth);
            if (gRubySizeLogBudget.load() > 0)
            {
                gRubySizeLogBudget.fetch_sub(1);
                Log("[TextAnalysis::CreateTextUnits] ruby text sized for %d units (the word-flipped copy alone "
                    "would have asked for %d)\n",
                    needed, oCreateTextUnits(&flipped[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth,
                                             nullptr, maxUnits));
            }
            return needed;
        }
        return oCreateTextUnits(&flipped[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits,
                                maxUnits);
    }

    const int firstPass =
        oCreateTextUnits(&flipped[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    if (firstPass <= 1)
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);

    const bool atBudget = maxUnits > 0 && firstPass >= maxUnits;
    std::vector<UnitView> views;
    views.reserve(static_cast<size_t>(firstPass));
    std::string visual;
    size_t lineCount = 0;
    bool coveredAll = false;
    const char* why = "could not read the wrapped units";
    if (!ReadUnits(static_cast<const uint8_t*>(textUnits), firstPass, views) ||
        !BuildVisualLines(flipped, views, atBudget, visual, lineCount, coveredAll, why))
    {
        if (lineCount >= 2 || views.empty() || std::strcmp(why, "single line") != 0)
            NoteFallback(why, original, firstPass, displayWidth);
        return oCreateTextUnits(text, fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
    }

    if (atBudget && !coveredAll && gBudgetLogBudget.load() > 0)
    {
        gBudgetLogBudget.fetch_sub(1);
        const int needed =
            oCreateTextUnits(&flipped[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, nullptr, 0);
        Log("[TextAnalysis::CreateTextUnits] text needs %d units but the box allows %d: kept the first %zu lines "
            "right-to-left, font %u, width %.0f\n",
            needed, maxUnits, lineCount, fontId, displayWidth);
    }

    if (gWrapLogBudget.load() > 0)
    {
        gWrapLogBudget.fetch_sub(1);
        Log("[TextAnalysis::CreateTextUnits] re-wrapped Arabic text right-to-left: %zu lines, font %u, width %.0f\n",
            lineCount, fontId, displayWidth);
    }

    return oCreateTextUnits(&visual[0], fontGroup, rubyFontGroup, fontId, flags, displayWidth, textUnits, maxUnits);
}

void CountTextUnitBuildsOnThisThread(uint32_t& all, uint32_t& arabic)
{
    all = tTextUnitBuilds;
    arabic = tArabicTextUnitBuilds;
}

static void NoteTextUnitsSource(const void* units, bool arabic)
{
    for (TextUnitsSource& source : gTextUnitSources)
    {
        if (source.units.load(std::memory_order_relaxed) == units)
        {
            source.arabic.store(arabic, std::memory_order_relaxed);
            return;
        }
    }
    TextUnitsSource& slot =
        gTextUnitSources[gNextTextUnitSource.fetch_add(1, std::memory_order_relaxed) % MAX_TEXT_UNIT_SOURCES];
    slot.units.store(nullptr, std::memory_order_relaxed);
    slot.arabic.store(arabic, std::memory_order_relaxed);
    slot.units.store(units, std::memory_order_relaxed);
}

bool TextUnitsWereBuiltFromArabic(const void* units, bool& arabic)
{
    if (!units)
        return false;
    for (const TextUnitsSource& source : gTextUnitSources)
    {
        if (source.units.load(std::memory_order_relaxed) == units)
        {
            arabic = source.arabic.load(std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}

static const char* PersistentHarakatText(std::string&& text)
{
    std::lock_guard<std::mutex> lk(gHarakatTextMtx);
    return gHarakatTexts.insert(std::move(text)).first->c_str();
}

static bool IsAttachedText(const std::string& text)
{
    std::lock_guard<std::mutex> lk(gHarakatTextMtx);
    return gHarakatTexts.find(text) != gHarakatTexts.end();
}

static void __fastcall hkTextUnitSetting(
    void* unit,
    const char* text,
    uint32_t flags,
    uint16_t charCount,
    uint64_t line,
    uint64_t width,
    uint64_t height,
    uint64_t extra,
    uint64_t color)
{
    if (tCreateTextUnitsDepth == 0 && text && HasArabicTextSafe(text) && IsArabicSafe())
    {
        std::string attached(text);
        if (!IsAttachedText(attached) && AttachHarakatToLetters(attached))
            text = PersistentHarakatText(std::move(attached));
    }
    oTextUnitSetting(unit, text, flags, charCount, line, width, height, extra, color);
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

static void InstallTextUnitSettingHook(HMODULE hGame)
{
    if (!gAddr.TextUnitSetting)
    {
        Log("[TextAnalysis::CreateTextUnits] TextUnit::Setting address missing - harakat only fixed in wrapped text.\n");
        return;
    }

    void* target = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.TextUnitSetting));
    if (!CodeMatches(target, kTextUnitSettingPrologue, sizeof(kTextUnitSettingPrologue)))
    {
        Log("[TextAnalysis::CreateTextUnits] TextUnit::Setting code is not what this build should have - not hooked.\n");
        return;
    }

    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkTextUnitSetting),
                      reinterpret_cast<void**>(&oTextUnitSetting)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[TextAnalysis::CreateTextUnits] TextUnit::Setting hook failed.\n");
        return;
    }

    gTargetTextUnitSetting = target;
    Log("[TextAnalysis::CreateTextUnits] harakat also attached in directly set text units.\n");
}

static void InstallArabicRubyAbove(HMODULE hGame)
{
    if (!gAddr.RubyForceInline)
        return;
    uint8_t* code = reinterpret_cast<uint8_t*>(ToRuntimeVA(hGame, gAddr.RubyForceInline));
    uint8_t expected[sizeof(kRubyForceInlineCode)];
    std::memcpy(expected, kRubyForceInlineCode, sizeof(expected));
    if (!CodeMatches(code, expected, sizeof(expected)))
    {
        expected[RUBY_MODE_OPCODE] = OPCODE_CMOVO;
        if (!CodeMatches(code, expected, sizeof(expected)))
        {
            Log("[TextAnalysis::CreateTextUnits] ruby mode code is not what this build should have - left alone.\n");
            return;
        }
    }
    gRubyModeOpcode = code + RUBY_MODE_OPCODE;
}

bool InstallCreateTextUnitsArabicWrapHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.CreateTextUnits)
    {
        Log("[TextAnalysis::CreateTextUnits] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;

    gTargetCreateTextUnits =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.CreateTextUnits));

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetCreateTextUnits,
            reinterpret_cast<void*>(&hkCreateTextUnits),
            reinterpret_cast<void**>(&oCreateTextUnits));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[TextAnalysis::CreateTextUnits] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        gTargetCreateTextUnits = nullptr;
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetCreateTextUnits);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[TextAnalysis::CreateTextUnits] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        gTargetCreateTextUnits = nullptr;
        return false;
    }

    Log("[TextAnalysis::CreateTextUnits] Arabic right-to-left wrap enabled.\n");
    InstallTextUnitSettingHook(hGame);
    InstallArabicRubyAbove(hGame);
    return true;
}

void RemoveCreateTextUnitsArabicWrapHook()
{
    if (gTargetCreateTextUnits)
    {
        MH_DisableHook(gTargetCreateTextUnits);
        MH_RemoveHook(gTargetCreateTextUnits);
        gTargetCreateTextUnits = nullptr;
    }

    if (gTargetTextUnitSetting)
    {
        MH_DisableHook(gTargetTextUnitSetting);
        MH_RemoveHook(gTargetTextUnitSetting);
        gTargetTextUnitSetting = nullptr;
    }

    SetArabicRubyAbove(false);
    gRubyModeOpcode = nullptr;

    oCreateTextUnits = nullptr;
    oTextUnitSetting = nullptr;
    gIsArabLanguage = nullptr;
}
