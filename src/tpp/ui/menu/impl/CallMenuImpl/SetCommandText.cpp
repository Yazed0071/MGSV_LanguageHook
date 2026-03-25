#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetCommandText_t = void(__fastcall*)(void* thisPtr, void* recordUi, void* recordData);
using SetTextNodeText_t = void(__fastcall*)(void* langSys, void* node, void* ctx, const char* text, int unk);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetCommandText_t oSetCommandText = nullptr;
static void* gTargetSetCommandText = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

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

static bool IsAsciiDigit(char c)
{
    return c >= '0' && c <= '9';
}

static bool RewriteNumberedCommandText(char* buf, size_t bufSize)
{
    if (!buf || !buf[0] || bufSize == 0)
        return false;

    const char* colon = std::strchr(buf, ':');
    if (!colon || colon == buf || !colon[1])
        return false;

    for (const char* p = buf; p < colon; ++p)
    {
        if (!IsAsciiDigit(*p))
            return false;
    }

    char numberPart[16]{};
    char textPart[100]{};

    const size_t numberLen = static_cast<size_t>(colon - buf);
    if (numberLen == 0 || numberLen >= sizeof(numberPart))
        return false;

    memcpy(numberPart, buf, numberLen);
    numberPart[numberLen] = '\0';

    strncpy_s(textPart, colon + 1, _TRUNCATE);

    char rebuilt[100]{};
    _snprintf_s(rebuilt, sizeof(rebuilt), _TRUNCATE, "%s:%s", textPart, numberPart);

    if (std::strcmp(rebuilt, buf) == 0)
        return false;

    strncpy_s(buf, bufSize, rebuilt, _TRUNCATE);
    return true;
}

static void __fastcall hkSetCommandText(void* thisPtr, void* recordUi, void* recordData)
{
    if (!oSetCommandText)
        return;

    oSetCommandText(thisPtr, recordUi, recordData);

    if (!IsArabicSafe() || !thisPtr || !recordUi || !recordData)
        return;

    __try
    {
        auto* thisBase = reinterpret_cast<uint8_t*>(thisPtr);
        auto* dataBase = reinterpret_cast<uint8_t*>(recordData);
        auto* uiBase = reinterpret_cast<uint8_t*>(recordUi);

        char* outBuf = reinterpret_cast<char*>(dataBase + 0x70);
        if (!outBuf || !outBuf[0])
            return;

        if (!RewriteNumberedCommandText(outBuf, 100))
            return;

        void* targetNode = nullptr;
        void* langSys = nullptr;
        void* ctx = nullptr;

        SafeReadPtr(uiBase + 0x20, targetNode);
        SafeReadPtr(thisBase + 0x68, langSys);
        SafeReadPtr(thisBase + 0x48, ctx);

        if (!targetNode || !langSys)
            return;

        void** langVt = *reinterpret_cast<void***>(langSys);
        if (!langVt)
            return;

        auto setNodeText = reinterpret_cast<SetTextNodeText_t>(langVt[0x708 / 8]);
        if (!setNodeText)
            return;

        setNodeText(langSys, targetNode, ctx, outBuf, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

bool InstallCallMenuImplSetCommandTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetCommandText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetCommandText));

    if (!gTargetSetCommandText)
    {
        Log("[CallMenuImpl::SetCommandText] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetCommandText,
            reinterpret_cast<void*>(&hkSetCommandText),
            reinterpret_cast<void**>(&oSetCommandText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[CallMenuImpl::SetCommandText] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetCommandText);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[CallMenuImpl::SetCommandText] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[CallMenuImpl::SetCommandText] Hook enabled.\n");
    return true;
}

void RemoveCallMenuImplSetCommandTextArabicHook()
{
    if (gTargetSetCommandText)
    {
        MH_DisableHook(gTargetSetCommandText);
        MH_RemoveHook(gTargetSetCommandText);
        gTargetSetCommandText = nullptr;
    }

    oSetCommandText = nullptr;
    gIsArabLanguage = nullptr;
}