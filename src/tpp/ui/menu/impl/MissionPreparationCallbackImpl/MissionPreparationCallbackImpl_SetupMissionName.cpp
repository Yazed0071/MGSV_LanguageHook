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
    using SetupMissionName_t = void(__fastcall*)(void* thisPtr);

    using UiApply708_t =
        void(__fastcall*)(void* uiObj, uint64_t node, uint64_t textUnit, const char* text, uint8_t flag);

    using UiApply710_t =
        void(__fastcall*)(void* uiObj, uint64_t node, uint64_t textUnit, const char* text, uint8_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static SetupMissionName_t gOrigSetupMissionName = nullptr;
    static void* gTarget = nullptr;

    static constexpr uint8_t kAlignLeft = 0;
    static constexpr uint8_t kAlignCenter = 1;
    static constexpr uint8_t kAlignRight = 2;

    static constexpr uint8_t kForcedMainAlign = kAlignRight;
    static constexpr uint8_t kForcedSubAlign = kAlignRight;
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

static bool ReapplyMainMissionLine(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* uiObj = nullptr;
        if (!SafeReadPtr(base + 0x38, uiObj) || !uiObj)
            return false;

        uint64_t node = 0;
        if (!SafeReadU64(base + 0x4398, node) || !node)
            return false;

        uint64_t textUnit = 0;
        if (!SafeReadU64(base + 0x2C08, textUnit) || !textUnit)
            return false;

        auto** uiVt = *reinterpret_cast<void***>(uiObj);
        if (!uiVt)
            return false;

        auto fn708 = reinterpret_cast<UiApply708_t>(uiVt[0x708 / 8]);
        if (!fn708)
            return false;

        const char* text = reinterpret_cast<const char*>(base + 0x43A8);
        fn708(uiObj, node, textUnit, text, 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Reapplies the secondary mission-name line through the same +0x710 UI path. thisPtr = MissionPreparationCallbackImpl*. */
static bool ReapplySubMissionLine(void* thisPtr)
{
    if (!thisPtr)
        return false;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        void* uiObj = nullptr;
        if (!SafeReadPtr(base + 0x38, uiObj) || !uiObj)
            return false;

        uint64_t node = 0;
        if (!SafeReadU64(base + 0x43A0, node) || !node)
            return false;

        uint64_t textUnit = 0;
        if (!SafeReadU64(base + 0x2C08, textUnit) || !textUnit)
            return false;

        auto** uiVt = *reinterpret_cast<void***>(uiObj);
        if (!uiVt)
            return false;

        auto fn710 = reinterpret_cast<UiApply710_t>(uiVt[0x710 / 8]);
        if (!fn710)
            return false;

        const char* text = reinterpret_cast<const char*>(base + 0x44A7);
        fn710(uiObj, node, textUnit, text, 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Forces alignment on the main mission-name node. thisPtr = MissionPreparationCallbackImpl*, alignValue = 0 left / 1 center / 2 right. */
static bool ForceMainMissionLineAlignment(void* thisPtr, uint8_t alignValue)
{
    if (!thisPtr)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* node = nullptr;
    if (!SafeReadPtr(base + 0x4398, node) || !node)
        return false;

    return SafeWriteU8(reinterpret_cast<uint8_t*>(node) + 0xD8, alignValue);
}

/* Forces alignment on the secondary mission-name node. thisPtr = MissionPreparationCallbackImpl*, alignValue = 0 left / 1 center / 2 right. */
static bool ForceSubMissionLineAlignment(void* thisPtr, uint8_t alignValue)
{
    if (!thisPtr)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* node = nullptr;
    if (!SafeReadPtr(base + 0x43A0, node) || !node)
        return false;

    return SafeWriteU8(reinterpret_cast<uint8_t*>(node) + 0xD8, alignValue);
}

/* Rewrites the built main mission-name line from "12 - Name" to "Name - 12". thisPtr = MissionPreparationCallbackImpl*. */
static void ApplyArabicMissionPreparationNameFix(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* mainBuf = reinterpret_cast<char*>(base + 0x43A8);

    std::string before;
    if (!SafeReadCString(mainBuf, 0xFF, before))
        return;

    const std::string after = SwapNumericDashFormat(before);
    if (after != before)
    {
        if (SafeWriteCString(mainBuf, 0xFF, after.c_str()))
        {
            if (!ReapplyMainMissionLine(thisPtr))
                Log("[MissionPreparationCallbackImpl::SetupMissionName] ReapplyMainMissionLine failed.\n");
            else
                Log("[MissionPreparationCallbackImpl::SetupMissionName] before: %s | after: %s\n", before.c_str(), after.c_str());
        }
    }

    if (!ReapplySubMissionLine(thisPtr))
        Log("[MissionPreparationCallbackImpl::SetupMissionName] ReapplySubMissionLine failed.\n");

    if (!ForceMainMissionLineAlignment(thisPtr, kForcedMainAlign))
        Log("[MissionPreparationCallbackImpl::SetupMissionName] ForceMainMissionLineAlignment failed.\n");

    if (!ForceSubMissionLineAlignment(thisPtr, kForcedSubAlign))
        Log("[MissionPreparationCallbackImpl::SetupMissionName] ForceSubMissionLineAlignment failed.\n");
}

/* Hook for MissionPreparationCallbackImpl::SetupMissionName(this). */
static void __fastcall hkMissionPreparationCallbackImpl_SetupMissionName(void* thisPtr)
{
    if (gOrigSetupMissionName)
        gOrigSetupMissionName(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicMissionPreparationNameFix(thisPtr);
}

/* Installs the Mission Preparation Arabic hook. hGame = game module handle. */
bool InstallMissionPreparationCallbackImplSetupMissionNameArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.MissionPreparationCallbackImpl_SetupMissionName)
    {
        Log("[MissionPreparationCallbackImpl::SetupMissionName] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.MissionPreparationCallbackImpl_SetupMissionName);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkMissionPreparationCallbackImpl_SetupMissionName,
        reinterpret_cast<LPVOID*>(&gOrigSetupMissionName)) != MH_OK)
    {
        Log("[MissionPreparationCallbackImpl::SetupMissionName] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MissionPreparationCallbackImpl::SetupMissionName] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MissionPreparationCallbackImpl::SetupMissionName] Arabic hook enabled.\n");
    return true;
}

/* Removes the Mission Preparation Arabic hook. */
void RemoveMissionPreparationCallbackImplSetupMissionNameArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetupMissionName = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MissionPreparationCallbackImpl::SetupMissionName] Arabic hook removed.\n");
}