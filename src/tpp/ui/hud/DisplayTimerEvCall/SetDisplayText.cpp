#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetDisplayText_t = void(__fastcall*)(void* thisPtr);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetDisplayText_t oSetDisplayText = nullptr;
static void* gTargetSetDisplayText = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint64_t SPECIAL_FORMAT_HASH = 0x0000F43081F30D87ull;

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

static void SafeCopy(char* dst, size_t dstSize, const char* src)
{
    if (!dst || !src || dstSize == 0)
        return;

    size_t i = 0;
    for (; i + 1 < dstSize && src[i] != '\0'; ++i)
        dst[i] = src[i];

    dst[i] = '\0';
}

static void __fastcall hkSetDisplayText(void* thisPtr)
{
    if (!thisPtr || !oSetDisplayText)
        return;

    oSetDisplayText(thisPtr);

    if (!IsArabicSafe())
        return;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);

        const uint64_t currentHash =
            (*reinterpret_cast<uint64_t*>(base + 0x1D8)) & 0x0000FFFFFFFFFFFFull;

        if (currentHash != SPECIAL_FORMAT_HASH)
            return;

        const int iVar1 = *reinterpret_cast<int*>(base + 0xDC);
        const int iVar2 = *reinterpret_cast<int*>(base + 0xE0);
        char* outBuf = reinterpret_cast<char*>(base + 0x1E0);

        if (!outBuf || !outBuf[0] || iVar2 <= 0)
            return;

        const char* openParen = std::strchr(outBuf, '(');
        if (!openParen)
            return;

        char title[100] = {};
        size_t titleLen = static_cast<size_t>(openParen - outBuf);
        if (titleLen >= sizeof(title))
            titleLen = sizeof(title) - 1;

        std::memcpy(title, outBuf, titleLen);
        title[titleLen] = '\0';

        char rebuilt[100] = {};
        _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "(%d/%d) %s", iVar2, iVar1, title);
        SafeCopy(outBuf, 100, rebuilt);

        Log("[DisplayTimerEvCall::SetDisplayText] Arabic rebuild applied: %s\n", outBuf);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log("[DisplayTimerEvCall::SetDisplayText] Exception in hook.\n");
    }
}

bool InstallDisplayTimerEvCallSetDisplayTextHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetDisplayText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetDisplayText));

    if (!gTargetSetDisplayText)
    {
        Log("[DisplayTimerEvCall::SetDisplayText] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetDisplayText,
            reinterpret_cast<void*>(&hkSetDisplayText),
            reinterpret_cast<void**>(&oSetDisplayText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[DisplayTimerEvCall::SetDisplayText] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetDisplayText);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[DisplayTimerEvCall::SetDisplayText] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[DisplayTimerEvCall::SetDisplayText] Hook enabled.\n");
    return true;
}

void RemoveDisplayTimerEvCallSetDisplayTextHook()
{
    if (gTargetSetDisplayText)
    {
        MH_DisableHook(gTargetSetDisplayText);
        MH_RemoveHook(gTargetSetDisplayText);
        gTargetSetDisplayText = nullptr;
    }

    oSetDisplayText = nullptr;
    gIsArabLanguage = nullptr;
}