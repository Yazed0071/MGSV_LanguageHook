#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();

    using MbDvcMissionListRecordCallFunc_Start_t =
        void(__fastcall*)(void* thisPtr, uint64_t param_2);

    using UiApply708_t =
        void(__fastcall*)(void* uiObj, void* owner, uint64_t node, uint64_t textUnit, const char* text, uint64_t flag1, uint64_t flag2);

    using UiApply718_t =
        void(__fastcall*)(void* uiObj, void* owner, uint64_t node, uint64_t textUnit, const char* text, uint64_t flag1, uint64_t flag2);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static MbDvcMissionListRecordCallFunc_Start_t gOrigStart = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t kForcedMainTextAlign = 2; // 0=left, 1=center, 2=right

    static constexpr bool kEnableReapplyMainText = false;
    static constexpr bool kEnableSlashFix = false;
    static constexpr bool kEnableForcedAlignment = true;
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

static bool SafeReadPtr(const void* addr, void*& out)
{
    __try
    {
        out = *reinterpret_cast<void* const*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = nullptr;
        return false;
    }
}

static bool SafeReadU64(const void* addr, uint64_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint64_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static bool SafeWriteU8(void* addr, uint8_t value)
{
    __try
    {
        *reinterpret_cast<uint8_t*>(addr) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool SafeReadCString(const char* src, size_t maxLen, std::string& out)
{
    __try
    {
        if (!src || maxLen == 0)
        {
            out.clear();
            return false;
        }

        size_t len = 0;
        while (len < maxLen && src[len] != '\0')
            ++len;

        out.assign(src, len);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out.clear();
        return false;
    }
}

static bool SafeWriteCString(char* dst, size_t dstSize, const char* src)
{
    __try
    {
        if (!dst || dstSize == 0)
            return false;

        if (!src)
        {
            dst[0] = '\0';
            return true;
        }

        _snprintf_s(dst, dstSize, _TRUNCATE, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static std::string TrimAscii(const std::string& s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])) != 0)
        ++start;

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0)
        --end;

    return s.substr(start, end - start);
}

static bool IsAsciiDigitsOnly(const std::string& s)
{
    const std::string trimmed = TrimAscii(s);
    if (trimmed.empty())
        return false;

    for (char c : trimmed)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }

    return true;
}

static std::vector<std::string> SplitWords(const std::string& s)
{
    std::vector<std::string> parts;
    std::string current;

    for (char c : s)
    {
        if (c == ' ')
        {
            if (!current.empty())
            {
                parts.push_back(current);
                current.clear();
            }
        }
        else
        {
            current.push_back(c);
        }
    }

    if (!current.empty())
        parts.push_back(current);

    return parts;
}

static std::string JoinWords(const std::vector<std::string>& parts)
{
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        if (i != 0)
            out += " ";
        out += parts[i];
    }
    return out;
}

static std::string SwapNumericDashFormat(const std::string& src)
{
    const size_t sep = src.find(" - ");
    if (sep == std::string::npos)
        return src;

    const std::string left = TrimAscii(src.substr(0, sep));
    const std::string right = TrimAscii(src.substr(sep + 3));

    if (right.empty())
        return src;
    if (left.empty())
        return right + " -" + std::string(sep + 1, ' ');
    if (!IsAsciiDigitsOnly(left))
        return src;

    return right + " - " + left;
}

/* "2 / 5" -> "5 / 2" */
static bool HasArabicBytes(const std::string& s)
{
    for (size_t i = 0; i < s.size(); ++i)
    {
        const uint8_t c = static_cast<uint8_t>(s[i]);
        if (c >= 0xD8 && c <= 0xDB)
            return true;
        if (c == 0xEF && i + 1 < s.size())
        {
            const uint8_t n = static_cast<uint8_t>(s[i + 1]);
            if (n >= 0xAD && n <= 0xBB)
                return true;
        }
    }
    return false;
}

static std::string MoveLeadingTagAfterName(const std::string& src)
{
    const size_t sep = src.rfind(" - ");
    if (sep == std::string::npos)
        return src;

    const std::string name = src.substr(0, sep);
    if (name.size() < 3 || name[0] != '[')
        return src;

    const size_t close = name.find(']');
    if (close == std::string::npos || close + 1 >= name.size() || name[close + 1] != ' ')
        return src;

    const std::string tag = name.substr(0, close + 1);
    const std::string rest = TrimAscii(name.substr(close + 2));
    if (rest.empty() || !HasArabicBytes(tag))
        return src;

    return rest + " " + tag + src.substr(sep);
}

static std::string SwapSlashFormat(const std::string& src)
{
    const size_t sep = src.find(" / ");
    if (sep == std::string::npos)
        return src;

    const std::string left = TrimAscii(src.substr(0, sep));
    const std::string right = TrimAscii(src.substr(sep + 3));

    if (!IsAsciiDigitsOnly(left) || !IsAsciiDigitsOnly(right))
        return src;

    return right + " / " + left;
}

static bool ReapplyMainText718(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* ctx = nullptr;
        if (!SafeReadPtr(base + 0xD8, ctx) || !ctx)
            return false;

        void* uiObj = nullptr;
        if (!SafeReadPtr(reinterpret_cast<uint8_t*>(ctx) + 0x20, uiObj) || !uiObj)
            return false;

        auto** uiVt = *reinterpret_cast<void***>(uiObj);
        if (!uiVt)
            return false;

        auto fn718 = reinterpret_cast<UiApply718_t>(uiVt[0x718 / 8]);
        if (!fn718)
            return false;

        uint64_t node = 0;
        uint64_t textUnit = 0;

        if (!SafeReadU64(base + 0xF8, node) || node == 0)
            return false;

        if (!SafeReadU64(base + 0xE8, textUnit) || textUnit == 0)
            return false;

        const char* mainBuf = reinterpret_cast<const char*>(base + 0x30);
        fn718(uiObj, thisPtr, node, textUnit, mainBuf, 1, 0);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReapplySlashText708(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* ctx = nullptr;
        if (!SafeReadPtr(base + 0xD8, ctx) || !ctx)
            return false;

        void* uiObj = nullptr;
        if (!SafeReadPtr(reinterpret_cast<uint8_t*>(ctx) + 0x20, uiObj) || !uiObj)
            return false;

        auto** uiVt = *reinterpret_cast<void***>(uiObj);
        if (!uiVt)
            return false;

        auto fn708 = reinterpret_cast<UiApply708_t>(uiVt[0x708 / 8]);
        if (!fn708)
            return false;

        uint64_t node = 0;
        uint64_t textUnit = 0;

        if (!SafeReadU64(base + 0x108, node) || node == 0)
            return false;

        if (!SafeReadU64(base + 0xE8, textUnit) || textUnit == 0)
            return false;

        const char* slashBuf = reinterpret_cast<const char*>(base + 0xC4);
        fn708(uiObj, thisPtr, node, textUnit, slashBuf, 1, 0);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ForceMainTextAlignment(void* thisPtr, uint8_t alignValue)
{
    if (!thisPtr)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* mainNode = nullptr;
    if (!SafeReadPtr(base + 0xF8, mainNode) || !mainNode)
        return false;

    return SafeWriteU8(reinterpret_cast<uint8_t*>(mainNode) + 0xD8, alignValue);
}

static bool ContainsArabicMark(const std::string& s)
{
    for (size_t i = 0; i + 1 < s.size(); ++i)
    {
        const uint8_t lead = static_cast<uint8_t>(s[i]);
        const uint8_t next = static_cast<uint8_t>(s[i + 1]);
        if (lead == 0xD9 && ((next >= 0x8B && next <= 0x9F) || next == 0xB0))
            return true;
    }
    return false;
}

static void ApplyArabicMissionListMainText(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* mainBuf = reinterpret_cast<char*>(base + 0x30);

    std::string before;
    if (!SafeReadCString(mainBuf, 0x80, before))
        return;

    const std::string after = MoveLeadingTagAfterName(SwapNumericDashFormat(before));
    if (after == before)
        return;

    if (after.size() + 1 > 0x80)
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] main rewrite skipped: output too large.\n");
        return;
    }

    if (!SafeWriteCString(mainBuf, 0x80, after.c_str()))
        return;

    if (kEnableReapplyMainText || ContainsArabicMark(after))
    {
        if (!ReapplyMainText718(thisPtr))
        {
            Log("[MbDvcMissionListRecordCallFunc::Start] ReapplyMainText718 failed.\n");
        }
    }

    LogDetail("[MbDvcMissionListRecordCallFunc::Start] main before: %s\n", before.c_str());
    LogDetail("[MbDvcMissionListRecordCallFunc::Start] main after : %s\n", after.c_str());
}

static void ApplyArabicMissionListSlashText(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* slashBuf = reinterpret_cast<char*>(base + 0xC4);

    std::string before;
    if (!SafeReadCString(slashBuf, 0x40, before))
        return;

    const std::string after = SwapSlashFormat(before);
    if (after == before)
        return;

    if (!kEnableSlashFix)
        return;

    if (after.size() + 1 > 0x40)
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] slash rewrite skipped: output too large.\n");
        return;
    }

    if (!SafeWriteCString(slashBuf, 0x40, after.c_str()))
        return;

    if (!ReapplySlashText708(thisPtr))
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] ReapplySlashText708 failed.\n");
        return;
    }

    LogDetail("[MbDvcMissionListRecordCallFunc::Start] slash before: %s\n", before.c_str());
    LogDetail("[MbDvcMissionListRecordCallFunc::Start] slash after : %s\n", after.c_str());
}

static void __fastcall hkMbDvcMissionListRecordCallFunc_Start(void* thisPtr, uint64_t param_2)
{
    LogDetail("[MbDvcMissionListRecordCallFunc::Start] hk hit.\n");

    if (gOrigStart)
        gOrigStart(thisPtr, param_2);

    if (!IsArabicSafe())
        return;

    ApplyArabicMissionListMainText(thisPtr);
    ApplyArabicMissionListSlashText(thisPtr);

    if (kEnableForcedAlignment && !(gAddr.MbDvcMissionListRecord_Vtable && gAddr.UixUtility_RefreshRecordTextScroll))
    {
        if (!ForceMainTextAlignment(thisPtr, kForcedMainTextAlign))
            Log("[MbDvcMissionListRecordCallFunc::Start] ForceMainTextAlignment failed.\n");
    }
}

bool InstallMbDvcMissionListRecordCallFuncStartArabicFormatHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.MbDvcMissionListRecordCallFuncStart)
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gTarget = reinterpret_cast<void*>(gAddr.MbDvcMissionListRecordCallFuncStart);

    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkMbDvcMissionListRecordCallFunc_Start, reinterpret_cast<LPVOID*>(&gOrigStart)) != MH_OK)
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcMissionListRecordCallFunc::Start] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MbDvcMissionListRecordCallFunc::Start] Arabic hook enabled.\n");
    return true;
}

void RemoveMbDvcMissionListRecordCallFuncStartArabicFormatHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigStart = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MbDvcMissionListRecordCallFunc::Start] Arabic hook removed.\n");
}