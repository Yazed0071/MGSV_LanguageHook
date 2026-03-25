#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetMainText_t = void(__fastcall*)(void* thisPtr, void* textUnit, unsigned int maxUnits, const char* text);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetMainText_t oSetMainText = nullptr;
static void* gTargetSetMainText = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uint8_t TEXT_ALIGN_RIGHT = 2;

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

static void ForceNodeAlign(void* modelNodeText, uint8_t align)
{
    if (!modelNodeText)
        return;

    SafeWriteU8(reinterpret_cast<uint8_t*>(modelNodeText) + 0xD8, align);
}

static void* GetBodyTextNode(void* thisPtr)
{
    if (!thisPtr)
        return nullptr;

    void* node = nullptr;
    SafeReadPtr(reinterpret_cast<uint8_t*>(thisPtr) + 0x18, node);
    return node;
}

static void __fastcall hkSetMainText(void* thisPtr, void* textUnit, unsigned int maxUnits, const char* text)
{
    if (!oSetMainText)
        return;

    if (IsArabicSafe())
    {
        void* nodeBefore = GetBodyTextNode(thisPtr);
        ForceNodeAlign(nodeBefore, TEXT_ALIGN_RIGHT);
    }

    oSetMainText(thisPtr, textUnit, maxUnits, text);

    if (!IsArabicSafe())
        return;

    void* nodeAfter = GetBodyTextNode(thisPtr);
    ForceNodeAlign(nodeAfter, TEXT_ALIGN_RIGHT);
}

bool InstallMbLogViewerBodyLayoutSetMainTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetMainText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetMainText));

    if (!gTargetSetMainText)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetMainText,
            reinterpret_cast<void*>(&hkSetMainText),
            reinterpret_cast<void**>(&oSetMainText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetMainText);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[MbLogViewerEv::BodyLayout::SetMainText] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[MbLogViewerEv::BodyLayout::SetMainText] Hook enabled.\n");
    return true;
}

void RemoveMbLogViewerBodyLayoutSetMainTextArabicHook()
{
    if (gTargetSetMainText)
    {
        MH_DisableHook(gTargetSetMainText);
        MH_RemoveHook(gTargetSetMainText);
        gTargetSetMainText = nullptr;
    }

    oSetMainText = nullptr;
    gIsArabLanguage = nullptr;
}