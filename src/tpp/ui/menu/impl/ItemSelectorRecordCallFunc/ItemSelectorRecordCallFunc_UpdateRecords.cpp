#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cctype>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();

    using ItemSelectorRecordCallFunc_UpdateRecords_t =
        void(__fastcall*)(void* thisPtr);

    using UiApply708_t =
        void(__fastcall*)(void* uiObj, uint64_t node, uint64_t textUnit, const char* text, uint8_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static ItemSelectorRecordCallFunc_UpdateRecords_t gOrigUpdateRecords = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. Takes no parameters. */
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

/* Reads one qword safely. addr = source address, out = destination value. */
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

/* Reads a bounded c-string safely. src = source buffer, maxLen = max bytes, out = destination string. */
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

/* Writes a bounded c-string safely. dst = target buffer, dstSize = buffer size, src = source text. */
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

/* Trims ASCII whitespace from both ends. s = source string. */
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

/* Returns true if the string is ASCII digits only. s = source string. */
static bool IsAsciiDigitsOnly(const std::string& s)
{
    if (s.empty())
        return false;

    for (char c : s)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }

    return true;
}

/* Rewrites only:
   "Name 3"   -> "3 Name"
   "Name 3 *" -> "* 3 Name" */
static std::string RewriteRecordTextArabic(const std::string& src)
{
    if (src.empty())
        return src;

    std::string work = TrimAscii(src);
    bool hasStar = false;

    if (work.size() >= 2 && work.substr(work.size() - 2) == " *")
    {
        hasStar = true;
        work = TrimAscii(work.substr(0, work.size() - 2));
    }

    if (work.empty())
        return src;

    size_t end = work.size();
    size_t numberStart = end;

    while (numberStart > 0 && std::isdigit(static_cast<unsigned char>(work[numberStart - 1])) != 0)
        --numberStart;

    if (numberStart == end || numberStart == 0)
        return src;

    if (std::isspace(static_cast<unsigned char>(work[numberStart - 1])) == 0)
        return src;

    const std::string left = TrimAscii(work.substr(0, numberStart));
    const std::string right = work.substr(numberStart, end - numberStart);

    if (left.empty() || !IsAsciiDigitsOnly(right))
        return src;

    if (hasStar)
        return "* " + right + " " + left;

    return right + " " + left;
}

/* Reapplies the patched main record text to the node at +0x88. thisPtr = ItemSelectorRecordCallFunc*. */
static bool ReapplyMainRecordText(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        uint64_t uiObj = 0;
        uint64_t node = 0;
        uint64_t textUnit = 0;

        if (!SafeReadU64(base + 0x38, uiObj) || !uiObj)
            return false;

        if (!SafeReadU64(base + 0x88, node) || !node)
            return false;

        if (!SafeReadU64(base + 0x80, textUnit) || !textUnit)
            return false;

        auto** vt = *reinterpret_cast<void***>(uiObj);
        if (!vt)
            return false;

        auto fn708 = reinterpret_cast<UiApply708_t>(vt[0x708 / 8]);
        if (!fn708)
            return false;

        const char* text = reinterpret_cast<const char*>(base + 0x19F);
        fn708(reinterpret_cast<void*>(uiObj), node, textUnit, text, 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Applies the Arabic reorder to the already-built main record buffer. thisPtr = ItemSelectorRecordCallFunc*. */
static void ApplyArabicUpdateRecordsFix(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* textBuf = reinterpret_cast<char*>(base + 0x19F);

    std::string before;
    if (!SafeReadCString(textBuf, 0x40, before))
        return;

    const std::string after = RewriteRecordTextArabic(before);
    if (after == before)
        return;

    if (!SafeWriteCString(textBuf, 0x40, after.c_str()))
        return;

    if (!ReapplyMainRecordText(thisPtr))
    {
        Log("[ItemSelectorRecordCallFunc::UpdateRecords] ReapplyMainRecordText failed.\n");
        return;
    }

    Log("[ItemSelectorRecordCallFunc::UpdateRecords] before: %s\n", before.c_str());
    Log("[ItemSelectorRecordCallFunc::UpdateRecords] after : %s\n", after.c_str());
}

/* Hook for ItemSelectorRecordCallFunc::UpdateRecords(this). */
static void __fastcall hkItemSelectorRecordCallFunc_UpdateRecords(void* thisPtr)
{
    if (gOrigUpdateRecords)
        gOrigUpdateRecords(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicUpdateRecordsFix(thisPtr);
}

/* Installs the UpdateRecords Arabic hook. hGame = game module handle. */
bool InstallItemSelectorRecordCallFuncUpdateRecordsArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.ItemSelectorRecordCallFunc_UpdateRecords)
    {
        Log("[ItemSelectorRecordCallFunc::UpdateRecords] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.ItemSelectorRecordCallFunc_UpdateRecords);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkItemSelectorRecordCallFunc_UpdateRecords,
        reinterpret_cast<LPVOID*>(&gOrigUpdateRecords)) != MH_OK)
    {
        Log("[ItemSelectorRecordCallFunc::UpdateRecords] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[ItemSelectorRecordCallFunc::UpdateRecords] MH_EnableHook failed.\n");
        return false;
    }

    Log("[ItemSelectorRecordCallFunc::UpdateRecords] Arabic hook enabled.\n");
    return true;
}

/* Removes the UpdateRecords Arabic hook. */
void RemoveItemSelectorRecordCallFuncUpdateRecordsArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigUpdateRecords = nullptr;
    gIsArabLanguage = nullptr;

    Log("[ItemSelectorRecordCallFunc::UpdateRecords] Arabic hook removed.\n");
}