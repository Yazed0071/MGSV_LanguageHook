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
    using MbDvcSideOpsRecordCallFunc_ViewRecord_t = void(__fastcall*)(void* thisPtr);

    using OwnerGetLayoutRoot_t = void* (__fastcall*)(void* ownerMgr);
    using OwnerGetTextUnit_t = uint64_t(__fastcall*)(void* ownerMgr);

    using UiApply718_t =
        void(__fastcall*)(void* uiObj, void* owner, uint64_t node, uint64_t textUnit, const char* text, uint64_t flag1, uint64_t flag2);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static MbDvcSideOpsRecordCallFunc_ViewRecord_t gOrigViewRecord = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t kAlignLeft = 0;
    static constexpr uint8_t kAlignCenter = 1;
    static constexpr uint8_t kAlignRight = 2;

    static constexpr uint8_t kForcedMainTextAlign = kAlignRight;
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

/* Reads one pointer safely. addr = source address, out = destination pointer. */
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

/* Writes one byte safely. addr = destination address, value = byte to write. */
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

/* Reads a bounded c-string safely. src = string address, maxLen = max bytes, out = destination string. */
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

/* Trims ASCII whitespace. s = source string. */
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

/* Checks whether the string is ASCII digits only. s = source string. */
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

/* Swaps only the number position. src = text like "12 - Side Op". */
static std::string SwapNumericDashFormat(const std::string& src)
{
    const size_t sep = src.find(" - ");
    if (sep == std::string::npos)
        return src;

    const std::string left = TrimAscii(src.substr(0, sep));
    const std::string right = TrimAscii(src.substr(sep + 3));

    if (!IsAsciiDigitsOnly(left) || right.empty())
        return src;

    return right + " - " + left;
}

/* Gets the live UI object and text unit. thisPtr = row object, uiObj = result UI object, textUnit = result text unit. */
static bool GetUiObjAndTextUnitFromOwner(void* thisPtr, void*& uiObj, uint64_t& textUnit)
{
    uiObj = nullptr;
    textUnit = 0;

    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* ownerMgr = nullptr;
        if (!SafeReadPtr(base + 0xC8, ownerMgr) || !ownerMgr)
            return false;

        auto** ownerVt = *reinterpret_cast<void***>(ownerMgr);
        if (!ownerVt)
            return false;

        auto fnGetLayoutRoot = reinterpret_cast<OwnerGetLayoutRoot_t>(ownerVt[0x30 / 8]);
        auto fnGetTextUnit = reinterpret_cast<OwnerGetTextUnit_t>(ownerVt[0x38 / 8]);
        if (!fnGetLayoutRoot || !fnGetTextUnit)
            return false;

        void* layoutRoot = fnGetLayoutRoot(ownerMgr);
        if (!layoutRoot)
            return false;

        if (!SafeReadPtr(reinterpret_cast<uint8_t*>(layoutRoot) + 0x20, uiObj) || !uiObj)
            return false;

        textUnit = fnGetTextUnit(ownerMgr);
        if (!textUnit)
            return false;

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        uiObj = nullptr;
        textUnit = 0;
        return false;
    }
}

/* Reapplies the main title text through the same +0x718 UI path. thisPtr = row object. */
static bool ReapplyMainTitleText(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* uiObj = nullptr;
        uint64_t textUnit = 0;
        if (!GetUiObjAndTextUnitFromOwner(thisPtr, uiObj, textUnit))
            return false;

        auto** uiVt = *reinterpret_cast<void***>(uiObj);
        if (!uiVt)
            return false;

        auto fn718 = reinterpret_cast<UiApply718_t>(uiVt[0x718 / 8]);
        if (!fn718)
            return false;

        uint64_t node = 0;
        if (!SafeReadU64(base + 0xD8, node) || !node)
            return false;

        const char* titleBuf = reinterpret_cast<const char*>(base + 0x30);
        fn718(uiObj, thisPtr, node, textUnit, titleBuf, 1, 0);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Forces the main text-node alignment. thisPtr = row object, alignValue = 0 left / 1 center / 2 right. */
static bool ForceMainTextAlignment(void* thisPtr, uint8_t alignValue)
{
    if (!thisPtr)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* mainNode = nullptr;
    if (!SafeReadPtr(base + 0xD8, mainNode) || !mainNode)
        return false;

    return SafeWriteU8(reinterpret_cast<uint8_t*>(mainNode) + 0xD8, alignValue);
}

/* Rewrites the built title buffer from "12 - Name" to "Name - 12" and reapplies it. thisPtr = row object. */
static void ApplyArabicSideOpsTitleFix(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* titleBuf = reinterpret_cast<char*>(base + 0x30);

    std::string before;
    if (!SafeReadCString(titleBuf, 0x80, before))
        return;

    const std::string after = SwapNumericDashFormat(before);
    if (after == before)
        return;

    if (!SafeWriteCString(titleBuf, 0x80, after.c_str()))
        return;

    if (!ReapplyMainTitleText(thisPtr))
    {
        Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] ReapplyMainTitleText failed.\n");
        return;
    }

    Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] before: %s\n", before.c_str());
    Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] after : %s\n", after.c_str());
}

/* Hook for MbDvcSideOpsRecordCallFunc::ViewRecord(this). */
static void __fastcall hkMbDvcSideOpsRecordCallFunc_ViewRecord(void* thisPtr)
{
    if (gOrigViewRecord)
        gOrigViewRecord(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicSideOpsTitleFix(thisPtr);

    if (!ForceMainTextAlignment(thisPtr, kForcedMainTextAlign))
        Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] ForceMainTextAlignment failed.\n");
}

/* Installs the Side Ops record Arabic hook. hGame = game module handle. */
bool InstallMbDvcSideOpsRecordCallFuncViewRecordArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.MbDvcSideOpsRecordCallFuncViewRecord)
    {
        Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.MbDvcSideOpsRecordCallFuncViewRecord);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkMbDvcSideOpsRecordCallFunc_ViewRecord,
        reinterpret_cast<LPVOID*>(&gOrigViewRecord)) != MH_OK)
    {
        Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] Arabic hook enabled.\n");
    return true;
}

/* Removes the Side Ops record Arabic hook. */
void RemoveMbDvcSideOpsRecordCallFuncViewRecordArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigViewRecord = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MbDvcSideOpsRecordCallFunc::ViewRecord] Arabic hook removed.\n");
}