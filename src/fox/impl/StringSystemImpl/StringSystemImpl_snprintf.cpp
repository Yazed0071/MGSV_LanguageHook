#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <string>
#include <unordered_set>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using FoxVsnprintf_t = int(__cdecl*)(char* buf, size_t size, const char* fmt, va_list args);
    using AnnounceLogView_t = uint64_t(__fastcall*)(void* self, const char* text, uint8_t a, uint8_t b, uint8_t c);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t FULL_TEXT_LIMIT = 4096;

    const uint8_t kSnprintfPrologue[] = { 0x4C, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x83, 0xEC, 0x28, 0x4D, 0x8B, 0xD9 };
    const uint8_t kAnnouncePrologue[] = { 0x40, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x40 };

    struct LongText
    {
        const char* buffer = nullptr;
        std::string shortened;
        std::string full;
        bool label = false;
    };

    using SnprintfObserver_t = void(*)(const char* fmt, const void* const* args, size_t count);

    IsArabLanguage_t gIsArabLanguage = nullptr;
    FoxVsnprintf_t gFoxVsnprintf = nullptr;
    std::atomic<SnprintfObserver_t> gObserver{ nullptr };
    constexpr size_t OBSERVED_ARGS = 4;
    void* gSnprintfOriginal = nullptr;
    AnnounceLogView_t oAnnounceLogView = nullptr;
    void* gSnprintfTarget = nullptr;
    void* gAnnounceTarget = nullptr;
    thread_local LongText tLongText;
    std::atomic<int> gCutLogBudget{ 4 };
    std::atomic<int> gRestoreLogBudget{ 4 };
    std::atomic<int> gAnnouncePairLogBudget{ 3 };
    std::atomic<int> gPairSwapLogBudget{ 2 };
    std::mutex gLabelStoreMutex;
    std::unordered_set<std::string> gLabelStore;
    constexpr size_t LABEL_STORE_CAP = 8192;
    std::atomic<int> gAmmoSwapLogBudget{ 1 };
    std::atomic<int> gSlotLabelLogBudget{ 1 };

    constexpr char kAmmoPairFormat[] = "%d/%d";
    constexpr char kAmmoDiffFormat[] = "%d/%d(%s/%s)";
    constexpr char kAmmoDiffMirroredFormat[] = "(%s/%s) %d/%d";
    std::atomic<int> gAmmoDiffLogBudget{ 1 };
    constexpr char kSlotLabelFormat[] = "%s %d";
    const uint8_t kAmmoCallTail[] = { 0x41, 0xFF, 0x52, 0x18 };
    const uint8_t kSlotLabelCallTail[] = { 0xFF, 0x57, 0x18 };
    constexpr int64_t kAmmoSiteOffsets[] = { 0x64CC, 0x675C, 0xE0A0 };
    constexpr int64_t SLOT_LABEL_SITE_OFFSET = -0x3C4;
    constexpr size_t AMMO_LEA_DISTANCE = 0x14;
    constexpr size_t SLOT_LABEL_LEA_DISTANCE = 0x18;
    constexpr int64_t SITE_SEARCH_RANGE = 0x40;
    const void* gAmmoSites[_countof(kAmmoSiteOffsets)] = {};
    const void* gSlotLabelSite = nullptr;

    bool IsAmmoSite(const void* caller)
    {
        for (const void* site : gAmmoSites)
        {
            if (site && site == caller)
                return true;
        }
        return false;
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

    bool HasArabic(const std::string& text)
    {
        for (size_t i = 0; i + 1 < text.size(); ++i)
        {
            const uint8_t lead = static_cast<uint8_t>(text[i]);
            if (lead == 0xD8 || lead == 0xD9 || lead == 0xDA || lead == 0xDB)
                return true;
            if (lead == 0xEF && i + 2 < text.size())
            {
                const uint8_t second = static_cast<uint8_t>(text[i + 1]);
                if (second >= 0xAD && second <= 0xBB)
                    return true;
            }
        }
        return false;
    }

    std::string KeepVisualRightEnd(const std::string& full, size_t capacity)
    {
        if (capacity == 0)
            return std::string();
        size_t start = full.size() - capacity;
        while (start < full.size() && (static_cast<uint8_t>(full[start]) & 0xC0) == 0x80)
            ++start;
        const size_t space = full.find(' ', start);
        if (space != std::string::npos && space + 1 < full.size() && space - start < capacity / 3)
            start = space + 1;
        return full.substr(start);
    }

    int CallFoxVsnprintf(char* buf, size_t size, const char* fmt, va_list args)
    {
        return gFoxVsnprintf(buf, size, fmt, args);
    }

    int FormatArgs(char* buf, size_t size, const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        const int written = CallFoxVsnprintf(buf, size, fmt, args);
        va_end(args);
        return written;
    }

    void StoreShortened(char* buf, unsigned int size, std::string full, bool label)
    {
        const std::string kept = KeepVisualRightEnd(full, size - 1);
        std::memcpy(buf, kept.c_str(), kept.size() + 1);
        tLongText.buffer = buf;
        tLongText.shortened = kept;
        tLongText.full = std::move(full);
        tLongText.label = label;
    }

    bool ReadLabel(const char* label, char* out, size_t size)
    {
        __try
        {
            size_t i = 0;
            for (; i + 1 < size && label[i]; ++i)
                out[i] = label[i];
            out[i] = '\0';
            return label[i] == '\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    constexpr char kLabelSignedFormat[] = "%s%d";
    constexpr char kLabelUnsignedFormat[] = "%s%u";
    constexpr char kLabelDashFormat[] = "%s--";

    bool FormatNumberBeforeArabicLabel(char* buf, unsigned int size, const char* fmt, va_list args, int& written)
    {
        const bool isSigned = std::strcmp(fmt, kLabelSignedFormat) == 0;
        const bool isUnsigned = !isSigned && std::strcmp(fmt, kLabelUnsignedFormat) == 0;
        if (!isSigned && !isUnsigned && std::strcmp(fmt, kLabelDashFormat) != 0)
            return false;
        va_list peek;
        va_copy(peek, args);
        const char* label = va_arg(peek, const char*);
        char number[16] = "--";
        if (isSigned)
            sprintf_s(number, "%d", va_arg(peek, int));
        else if (isUnsigned)
            sprintf_s(number, "%u", va_arg(peek, unsigned int));
        va_end(peek);
        char text[256];
        if (!label || !ReadLabel(label, text, sizeof(text)))
            return false;
        std::string full = std::string(number) + " " + text;
        if (!HasArabic(full) || !IsArabicSafe())
            return false;
        written = static_cast<int>(full.size());
        if (full.size() < size)
            std::memcpy(buf, full.c_str(), full.size() + 1);
        else
            StoreShortened(buf, size, std::move(full), true);
        return true;
    }

    constexpr char kSortTitleFormat[] = "%s(%s%s)";
    constexpr char kAccuracyFormat[] = "%.2f%%(%d/%d)";
    constexpr char kLabelCountLimitFormat[] = "%s (%d/%d)";
    constexpr uint64_t LANG_REWARD_TAB_ALL = 0xAF798798522Eull;
    std::atomic<int> gRewardCountLogBudget{ 1 };

    bool IsRewardTabLabel(const char* label)
    {
        const char* rewards = RL_LangText(LANG_REWARD_TAB_ALL);
        char text[128];
        return label && rewards && ReadLabel(label, text, sizeof(text)) && std::strcmp(text, rewards) == 0;
    }

    bool TwoNumberFormat(const char* fmt)
    {
        int numbers = 0;
        for (const char* p = fmt; *p; ++p)
        {
            if (*p != '%')
                continue;
            if (p[1] == '%')
            {
                ++p;
                continue;
            }
            if (p[1] != 'd' && p[1] != 'u')
                return false;
            ++numbers;
            ++p;
        }
        return numbers == 2;
    }

    const char* SwappedTimeFormat(const char* fmt)
    {
        const char* hourMinute = RL_LangText(LanguageProfileKeys::TimeHourMinute);
        if (hourMinute && std::strcmp(fmt, hourMinute) == 0)
            return RL_LangText(LanguageProfileKeys::TimeMinuteHour);
        const char* dayHour = RL_LangText(LanguageProfileKeys::TimeDayHour);
        if (dayHour && std::strcmp(fmt, dayHour) == 0)
            return RL_LangText(LanguageProfileKeys::TimeHourDay);
        return nullptr;
    }

    bool FormatTimeLargestUnitFirst(char* buf, size_t size, const char* fmt, va_list args, int& written)
    {
        if (!buf || !fmt || static_cast<uint8_t>(fmt[0]) < 0x80 || !gFoxVsnprintf || !IsArabicSafe())
            return false;
        const char* swapped = SwappedTimeFormat(fmt);
        if (!swapped || !TwoNumberFormat(swapped))
            return false;
        va_list peek;
        va_copy(peek, args);
        const unsigned int larger = va_arg(peek, unsigned int);
        const unsigned int smaller = va_arg(peek, unsigned int);
        va_end(peek);
        written = FormatArgs(buf, size, swapped, smaller, larger);
        return true;
    }

    bool BracketedPairFormat(const char* fmt)
    {
        int strings = 0;
        for (const char* p = fmt; *p; ++p)
        {
            if (*p != '%')
                continue;
            if (p[1] == '%')
            {
                ++p;
                continue;
            }
            if (p[1] != 's' || p == fmt || p[-1] != '[' || p[2] != ']')
                return false;
            ++strings;
            ++p;
        }
        return strings == 2;
    }

    bool FormatBracketedPairRightToLeft(char* buf, size_t size, const char* fmt, va_list args, int& written)
    {
        if (!buf || size < 2 || !fmt || !gFoxVsnprintf || !BracketedPairFormat(fmt) || !IsArabicSafe() ||
            !HasArabic(std::string(fmt)))
            return false;
        va_list peek;
        va_copy(peek, args);
        const char* first = va_arg(peek, const char*);
        const char* second = va_arg(peek, const char*);
        va_end(peek);
        written = FormatArgs(buf, size, fmt, second, first);
        if (gPairSwapLogBudget.load() > 0)
        {
            gPairSwapLogBudget.fetch_sub(1);
            Log("[fox::impl::StringSystemImpl::snprintf] Arabic \"[%%s] ... [%%s]\" format: arguments swapped to match "
                "the right-to-left slots\n");
        }
        return true;
    }

    int __cdecl hkSnprintf(void* self, char* buf, unsigned int size, const char* fmt, ...)
    {
        (void)self;
        va_list args;
        va_start(args, fmt);
        if (const SnprintfObserver_t observer = gObserver.load(std::memory_order_relaxed))
        {
            va_list peek;
            va_copy(peek, args);
            const void* observed[OBSERVED_ARGS];
            for (size_t i = 0; i < OBSERVED_ARGS; ++i)
                observed[i] = va_arg(peek, const void*);
            va_end(peek);
            observer(fmt, observed, OBSERVED_ARGS);
        }
        const void* caller = _ReturnAddress();
        if (buf && size > 1 && fmt && IsAmmoSite(caller) && std::strcmp(fmt, kAmmoPairFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const int loaded = va_arg(peek, int);
            const int reserve = va_arg(peek, int);
            va_end(peek);
            va_end(args);
            if (gAmmoSwapLogBudget.load() > 0 && gAmmoSwapLogBudget.fetch_sub(1) > 0)
                Log("[fox::impl::StringSystemImpl::snprintf] customize ammo %d/%d shown reserve first\n", loaded, reserve);
            return FormatArgs(buf, size, kAmmoPairFormat, reserve, loaded);
        }
        if (buf && size > 1 && fmt && std::strcmp(fmt, kAmmoDiffFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const int first = va_arg(peek, int);
            const int second = va_arg(peek, int);
            const char* firstDiff = va_arg(peek, const char*);
            const char* secondDiff = va_arg(peek, const char*);
            va_end(peek);
            va_end(args);
            if (gAmmoDiffLogBudget.load() > 0 && gAmmoDiffLogBudget.fetch_sub(1) > 0)
                Log("[fox::impl::StringSystemImpl::snprintf] ammo comparison %d/%d mirrored to (diff) %d/%d\n", first,
                    second, second, first);
            return FormatArgs(buf, size, kAmmoDiffMirroredFormat, secondDiff ? secondDiff : "",
                              firstDiff ? firstDiff : "", second, first);
        }
        if (buf && size > 1 && fmt && gSlotLabelSite && caller == gSlotLabelSite &&
            std::strcmp(fmt, kSlotLabelFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const char* label = va_arg(peek, const char*);
            const int number = va_arg(peek, int);
            va_end(peek);
            char text[64];
            if (label && ReadLabel(label, text, sizeof(text)) && HasArabic(std::string(text)))
            {
                va_end(args);
                if (gSlotLabelLogBudget.load() > 0 && gSlotLabelLogBudget.fetch_sub(1) > 0)
                    Log("[fox::impl::StringSystemImpl::snprintf] customize setup label %d shown number first\n", number);
                return FormatArgs(buf, size, "%d %s", number, text);
            }
        }
        if (buf && size > 1 && fmt && std::strcmp(fmt, kSortTitleFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const char* title = va_arg(peek, const char*);
            const char* label = va_arg(peek, const char*);
            const char* sort = va_arg(peek, const char*);
            va_end(peek);
            if (title && label && sort)
            {
                va_end(args);
                return FormatArgs(buf, size, "(%s %s) %s", sort, label, title);
            }
        }
        if (buf && size > 1 && fmt && std::strcmp(fmt, kAccuracyFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const double percent = va_arg(peek, double);
            const int hits = va_arg(peek, int);
            const int shots = va_arg(peek, int);
            va_end(peek);
            va_end(args);
            return FormatArgs(buf, size, "(%d/%d) %%%.2f", shots, hits, percent);
        }
        if (buf && size > 1 && fmt && std::strcmp(fmt, kLabelCountLimitFormat) == 0 && IsArabicSafe())
        {
            va_list peek;
            va_copy(peek, args);
            const char* label = va_arg(peek, const char*);
            const int count = va_arg(peek, int);
            const int limit = va_arg(peek, int);
            va_end(peek);
            if (IsRewardTabLabel(label))
            {
                if (gRewardCountLogBudget.load() > 0 && gRewardCountLogBudget.fetch_sub(1) > 0)
                    Log("[fox::impl::StringSystemImpl::snprintf] rewards title count shown limit first (%d/%d)\n",
                        limit, count);
                va_end(args);
                return FormatArgs(buf, size, kLabelCountLimitFormat, label, limit, count);
            }
        }
        int labelWritten = 0;
        if (buf && size > 1 && fmt && FormatNumberBeforeArabicLabel(buf, size, fmt, args, labelWritten))
        {
            va_end(args);
            return labelWritten;
        }
        int timeWritten = 0;
        if (FormatTimeLargestUnitFirst(buf, size, fmt, args, timeWritten))
        {
            va_end(args);
            return timeWritten;
        }
        int pairWritten = 0;
        if (FormatBracketedPairRightToLeft(buf, size, fmt, args, pairWritten))
        {
            va_end(args);
            return pairWritten;
        }
        va_list again;
        va_copy(again, args);
        const int written = CallFoxVsnprintf(buf, size, fmt, args);
        va_end(args);

        const bool fitted = written >= 0 && static_cast<unsigned int>(written) < size;
        if (fitted || !buf || size < 2 || !fmt || !IsArabicSafe())
        {
            va_end(again);
            return written;
        }

        static thread_local char full[FULL_TEXT_LIMIT];
        const int needed = CallFoxVsnprintf(full, sizeof(full), fmt, again);
        va_end(again);
        if (needed < 0 || static_cast<size_t>(needed) >= sizeof(full) || static_cast<unsigned int>(needed) < size)
            return written;

        std::string text(full, static_cast<size_t>(needed));
        if (!HasArabic(text))
            return written;

        StoreShortened(buf, size, std::move(text), false);

        if (gCutLogBudget.load() > 0)
        {
            gCutLogBudget.fetch_sub(1);
            Log("[fox::impl::StringSystemImpl::snprintf] Arabic text of %zu bytes did not fit a %u-byte buffer: "
                "kept its first words, full text kept for the announce log\n",
                tLongText.full.size(), size);
        }
        return written;
    }

    bool IsDigitChar(char c)
    {
        return c >= '0' && c <= '9';
    }

    bool IsNumberGlue(char c)
    {
        return IsDigitChar(c) || c == '/' || c == '.' || c == ':' || c == ',';
    }

    size_t NumberEnd(const std::string& s, size_t i)
    {
        size_t j = i;
        while (j < s.size() && IsDigitChar(s[j]))
            ++j;
        if (j + 1 < s.size() && s[j] == '.' && IsDigitChar(s[j + 1]))
        {
            ++j;
            while (j < s.size() && IsDigitChar(s[j]))
                ++j;
        }
        return j;
    }

    bool SwapCountPairs(std::string& s)
    {
        bool changed = false;
        size_t i = 0;
        while (i < s.size())
        {
            if (s[i] == '<')
            {
                const size_t close = s.find('>', i);
                if (close == std::string::npos)
                    break;
                i = close + 1;
                continue;
            }
            if (!IsDigitChar(s[i]) || (i > 0 && IsNumberGlue(s[i - 1])))
            {
                ++i;
                continue;
            }
            const size_t firstEnd = NumberEnd(s, i);
            if (firstEnd + 1 >= s.size() || s[firstEnd] != '/' || !IsDigitChar(s[firstEnd + 1]))
            {
                i = firstEnd;
                continue;
            }
            const size_t secondEnd = NumberEnd(s, firstEnd + 1);
            if (secondEnd < s.size() && IsNumberGlue(s[secondEnd]))
            {
                i = secondEnd;
                continue;
            }
            const std::string first = s.substr(i, firstEnd - i);
            const std::string second = s.substr(firstEnd + 1, secondEnd - firstEnd - 1);
            s.replace(i, secondEnd - i, second + "/" + first);
            changed = true;
            i = secondEnd;
        }
        return changed;
    }

    constexpr uint64_t LANG_IH_BEST_TIME = 0xDFE17A2D82C1ull;
    constexpr uint64_t LANG_IH_NO_BEST_TIME = 0x4781804193F4ull;
    constexpr char kIhBestTimePrefix[] = "Best time ";
    constexpr char kIhNoBestTime[] = "No best time set";

    bool TranslateInfiniteHeavenText(std::string& text)
    {
        if (text == kIhNoBestTime)
        {
            const char* translated = RL_LangText(LANG_IH_NO_BEST_TIME);
            if (!translated || !*translated)
                return false;
            text = translated;
            return true;
        }
        const size_t prefix = sizeof(kIhBestTimePrefix) - 1;
        if (text.compare(0, prefix, kIhBestTimePrefix) != 0 || text.size() == prefix)
            return false;
        const char* label = RL_LangText(LANG_IH_BEST_TIME);
        if (!label || !*label)
            return false;
        const std::string value = text.substr(prefix);
        text = IsArabicSafe() ? value + " " + label : std::string(label) + " " + value;
        return true;
    }

    uint64_t ShowAnnouncement(void* self, std::string text, uint8_t a, uint8_t b, uint8_t c)
    {
        TranslateInfiniteHeavenText(text);
        if (IsArabicSafe() && HasArabic(text) && SwapCountPairs(text) && gAnnouncePairLogBudget.load() > 0)
        {
            gAnnouncePairLogBudget.fetch_sub(1);
            Log("[tpp::ui::hud::CommonDataManager::AnnounceLogView] count pair shown limit first: %s\n", text.c_str());
        }
        return oAnnounceLogView(self, text.c_str(), a, b, c);
    }

    bool ReadAnnouncement(const char* text, std::string& out)
    {
        char copy[FULL_TEXT_LIMIT];
        __try
        {
            const size_t length = strnlen(text, sizeof(copy));
            if (length >= sizeof(copy))
                return false;
            std::memcpy(copy, text, length + 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        out.assign(copy);
        return true;
    }

    uint64_t __fastcall hkAnnounceLogView(void* self, const char* text, uint8_t a, uint8_t b, uint8_t c)
    {
        if (text && tLongText.buffer == text && !tLongText.full.empty() && tLongText.shortened == text)
        {
            std::string full = std::move(tLongText.full);
            tLongText = LongText{};
            if (gRestoreLogBudget.load() > 0)
            {
                gRestoreLogBudget.fetch_sub(1);
                Log("[tpp::ui::hud::CommonDataManager::AnnounceLogView] Arabic announcement shown in full (%zu bytes)\n",
                    full.size());
            }
            return ShowAnnouncement(self, std::move(full), a, b, c);
        }
        std::string copy;
        if (text && IsArabicSafe() && ReadAnnouncement(text, copy))
            return ShowAnnouncement(self, std::move(copy), a, b, c);
        return oAnnounceLogView(self, text, a, b, c);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    bool CallSiteMatches(const uint8_t* ret, const uint8_t* tail, size_t tailSize, size_t leaDistance,
                         const char* format)
    {
        __try
        {
            if (std::memcmp(ret - tailSize, tail, tailSize) != 0)
                return false;
            const uint8_t* lea = ret - leaDistance;
            if (lea[0] != 0x4C || lea[1] != 0x8D || lea[2] != 0x0D)
                return false;
            int32_t disp = 0;
            std::memcpy(&disp, lea + 3, sizeof(disp));
            return std::strcmp(reinterpret_cast<const char*>(lea + 7 + disp), format) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    const void* FindCallSite(HMODULE hGame, uintptr_t anchor, int64_t offset, const uint8_t* tail, size_t tailSize,
                             size_t leaDistance, const char* format)
    {
        if (!anchor)
            return nullptr;
        const uint8_t* predicted = static_cast<const uint8_t*>(Resolve(hGame, anchor)) + offset;
        for (int64_t d = 0; d <= SITE_SEARCH_RANGE; ++d)
        {
            if (CallSiteMatches(predicted + d, tail, tailSize, leaDistance, format))
                return predicted + d;
            if (d != 0 && CallSiteMatches(predicted - d, tail, tailSize, leaDistance, format))
                return predicted - d;
        }
        return nullptr;
    }

    void ResolveCustomizeCallSites(HMODULE hGame)
    {
        size_t found = 0;
        for (size_t i = 0; i < _countof(kAmmoSiteOffsets); ++i)
        {
            gAmmoSites[i] = FindCallSite(hGame, gAddr.EquipDetailsCallbackImpl_CreateBulletDifferenceText,
                                         kAmmoSiteOffsets[i], kAmmoCallTail, sizeof(kAmmoCallTail), AMMO_LEA_DISTANCE,
                                         kAmmoPairFormat);
            if (gAmmoSites[i])
                ++found;
        }
        gSlotLabelSite = FindCallSite(hGame, gAddr.SetupListElementWalkerGear, SLOT_LABEL_SITE_OFFSET,
                                      kSlotLabelCallTail, sizeof(kSlotLabelCallTail), SLOT_LABEL_LEA_DISTANCE,
                                      kSlotLabelFormat);
        Log("[fox::impl::StringSystemImpl::snprintf] customize call sites: ammo %zu/%zu, setup label %s\n", found,
            _countof(kAmmoSiteOffsets), gSlotLabelSite ? "found" : "not found");
    }
}

bool FormatArabicTimeLargestUnitFirst(char* buf, size_t size, const char* fmt, va_list args, int& written)
{
    return FormatTimeLargestUnitFirst(buf, size, fmt, args, written) ||
           FormatBracketedPairRightToLeft(buf, size, fmt, args, written);
}

const char* FullArabicTextForShortenedBuffer(const char* buffer)
{
    if (!buffer || tLongText.buffer != buffer || tLongText.full.empty())
        return nullptr;
    __try
    {
        if (std::strcmp(tLongText.shortened.c_str(), buffer) != 0)
            return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
    return tLongText.full.c_str();
}

const char* FullArabicLabelForShortenedBuffer(const char* buffer)
{
    if (!tLongText.label)
        return nullptr;
    const char* full = FullArabicTextForShortenedBuffer(buffer);
    if (!full)
        return nullptr;
    std::lock_guard<std::mutex> lock(gLabelStoreMutex);
    auto found = gLabelStore.find(full);
    if (found != gLabelStore.end())
        return found->c_str();
    if (gLabelStore.size() >= LABEL_STORE_CAP)
        return nullptr;
    return gLabelStore.insert(full).first->c_str();
}

bool SetStringSystemSnprintfObserver(void(*observer)(const char* fmt, const void* const* args, size_t count))
{
    if (!gSnprintfTarget)
        return false;
    gObserver.store(observer);
    return true;
}

bool InstallLongArabicAnnounceTextHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.StringSystemImpl_snprintf || !gAddr.FoxVsnprintf ||
        !gAddr.CommonDataManager_AnnounceLogView)
    {
        Log("[fox::impl::StringSystemImpl::snprintf] address missing - long Arabic announcements stay cut.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gFoxVsnprintf = reinterpret_cast<FoxVsnprintf_t>(Resolve(hGame, gAddr.FoxVsnprintf));
    void* snprintfTarget = Resolve(hGame, gAddr.StringSystemImpl_snprintf);
    void* announceTarget = Resolve(hGame, gAddr.CommonDataManager_AnnounceLogView);
    if (!CodeMatches(snprintfTarget, kSnprintfPrologue, sizeof(kSnprintfPrologue)) ||
        !CodeMatches(announceTarget, kAnnouncePrologue, sizeof(kAnnouncePrologue)))
    {
        Log("[fox::impl::StringSystemImpl::snprintf] code is not what this build should have - long Arabic announcements stay cut.\n");
        return true;
    }

    ResolveCustomizeCallSites(hGame);

    if (MH_CreateHook(announceTarget, reinterpret_cast<void*>(&hkAnnounceLogView),
                      reinterpret_cast<void**>(&oAnnounceLogView)) != MH_OK)
    {
        Log("[tpp::ui::hud::CommonDataManager::AnnounceLogView] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_CreateHook(snprintfTarget, reinterpret_cast<void*>(&hkSnprintf), &gSnprintfOriginal) != MH_OK)
    {
        MH_RemoveHook(announceTarget);
        Log("[fox::impl::StringSystemImpl::snprintf] MH_CreateHook failed.\n");
        return true;
    }
    if (MH_EnableHook(announceTarget) != MH_OK || MH_EnableHook(snprintfTarget) != MH_OK)
    {
        MH_RemoveHook(snprintfTarget);
        MH_RemoveHook(announceTarget);
        Log("[fox::impl::StringSystemImpl::snprintf] MH_EnableHook failed.\n");
        return true;
    }

    gSnprintfTarget = snprintfTarget;
    gAnnounceTarget = announceTarget;
    Log("[fox::impl::StringSystemImpl::snprintf] long Arabic announcements kept whole (hooked at %p and %p).\n",
        snprintfTarget, announceTarget);
    return true;
}

void RemoveLongArabicAnnounceTextHook()
{
    if (gSnprintfTarget)
    {
        MH_DisableHook(gSnprintfTarget);
        MH_RemoveHook(gSnprintfTarget);
        gSnprintfTarget = nullptr;
    }
    if (gAnnounceTarget)
    {
        MH_DisableHook(gAnnounceTarget);
        MH_RemoveHook(gAnnounceTarget);
        gAnnounceTarget = nullptr;
    }
    gObserver.store(nullptr);
    for (const void*& site : gAmmoSites)
        site = nullptr;
    gSlotLabelSite = nullptr;
    gSnprintfOriginal = nullptr;
    oAnnounceLogView = nullptr;
    gFoxVsnprintf = nullptr;
    gIsArabLanguage = nullptr;
}
