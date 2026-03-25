#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetMissionInfoTexts_t = void(__fastcall*)(void* thisPtr);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetMissionInfoTexts_t oSetMissionInfoTexts = nullptr;
static void* gTargetSetMissionInfoTexts = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

static constexpr size_t kTitleBufferOffset = 0x250;
static constexpr size_t kTitleBufferSize = 0xFF;

static constexpr size_t kMissionCategoryNodeOffset = 0x570;
static constexpr size_t kMissionTitleNodeOffset = 0x578;
static constexpr size_t kMissionSubgoalNodeOffset = 0x580;
static constexpr size_t kMissionInfoNodeOffset = 0x588;
static constexpr size_t kHardModeNodeOffset = 0x590;

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

static void ForceRightAlignNode(void* node)
{
    if (!node)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(node) + 0xD8, TEXT_ALIGN_RIGHT);
}

static void ApplyArabicAlignment(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    void* node = nullptr;

    if (SafeReadPtr(base + kMissionCategoryNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionTitleNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionSubgoalNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kMissionInfoNodeOffset, node))
        ForceRightAlignNode(node);

    if (SafeReadPtr(base + kHardModeNodeOffset, node))
        ForceRightAlignNode(node);
}

static void TrimAsciiSpaces(char* s)
{
    if (!s)
        return;

    size_t len = std::strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
    {
        s[len - 1] = '\0';
        --len;
    }
}

static void RewriteMissionTitleBufferArabic(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* outBuf = reinterpret_cast<char*>(reinterpret_cast<uint8_t*>(thisPtr) + kTitleBufferOffset);
    if (!outBuf || !outBuf[0])
        return;

    char original[kTitleBufferSize + 1]{};
    strncpy_s(original, outBuf, _TRUNCATE);

    char* firstSpace = std::strchr(original, ' ');
    if (!firstSpace)
        return;

    *firstSpace = '\0';
    char* partA = original;
    char* partB = firstSpace + 1;

    while (*partB == ' ' || *partB == '\t')
        ++partB;

    if (!partA[0] || !partB[0])
        return;

    TrimAsciiSpaces(partA);
    TrimAsciiSpaces(partB);

    if (!partA[0] || !partB[0])
        return;

    char rebuilt[kTitleBufferSize + 1]{};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "%s %s", partB, partA);
    strncpy_s(outBuf, kTitleBufferSize + 1, rebuilt, _TRUNCATE);
}

static void __fastcall hkSetMissionInfoTexts(void* thisPtr)
{
    if (!thisPtr || !oSetMissionInfoTexts)
        return;

    oSetMissionInfoTexts(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicAlignment(thisPtr);
}

bool InstallMbDvcMissionInfoSetMissionInfoTextsArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetMissionInfoTexts =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMissionInfoTexts));

    if (!gTargetSetMissionInfoTexts)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetMissionInfoTexts,
            reinterpret_cast<void*>(&hkSetMissionInfoTexts),
            reinterpret_cast<void**>(&oSetMissionInfoTexts));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetMissionInfoTexts);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[MbDvcMissionInfoCallback::SetMissionInfoTexts] Hook enabled.\n");
    return true;
}

void RemoveMbDvcMissionInfoSetMissionInfoTextsArabicHook()
{
    if (gTargetSetMissionInfoTexts)
    {
        MH_DisableHook(gTargetSetMissionInfoTexts);
        MH_RemoveHook(gTargetSetMissionInfoTexts);
        gTargetSetMissionInfoTexts = nullptr;
    }

    oSetMissionInfoTexts = nullptr;
    gIsArabLanguage = nullptr;
}