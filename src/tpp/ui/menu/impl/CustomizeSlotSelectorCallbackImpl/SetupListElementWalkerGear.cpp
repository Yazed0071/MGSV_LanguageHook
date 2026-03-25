#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

using IsArabLanguage_t = bool(__cdecl*)();
using SetupListElementWalkerGear_t = void(__fastcall*)(void* thisPtr);
using GetCurrentGearSlot_t = uint8_t(__fastcall*)(void* obj);

static IsArabLanguage_t gIsArabLanguage = nullptr;
static SetupListElementWalkerGear_t oSetupListElementWalkerGear = nullptr;
static void* gTargetSetupListElementWalkerGear = nullptr;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr size_t kSlotCount = 3;
static constexpr size_t kLabelOffset = 0x118;
static constexpr size_t kLabelStride = 0x40;
static constexpr size_t kSelectionObjOffset = 0x5C8;
static constexpr size_t kGetCurrentSlotVtableOffset = 0x138;

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

static uint8_t GetSelectedSlotSafe(void* thisPtr)
{
    if (!thisPtr)
        return 0;

    __try
    {
        void* selectionObj =
            *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(thisPtr) + kSelectionObjOffset);
        if (!selectionObj)
            return 0;

        void** vtbl = *reinterpret_cast<void***>(selectionObj);
        if (!vtbl)
            return 0;

        void* fnAddr =
            *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(vtbl) + kGetCurrentSlotVtableOffset);
        if (!fnAddr)
            return 0;

        auto fn = reinterpret_cast<GetCurrentGearSlot_t>(fnAddr);
        return fn(selectionObj);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static void TrimRight(std::string& s)
{
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
}

static std::string ExtractBaseLabel(const char* label)
{
    if (!label || !label[0])
        return {};

    std::string s(label);
    TrimRight(s);

    if (!s.empty() && s.back() == '*')
    {
        s.pop_back();
        TrimRight(s);
    }

    while (!s.empty() && s.back() >= '0' && s.back() <= '9')
        s.pop_back();

    TrimRight(s);
    return s;
}

static void RewriteWalkerGearLabels(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    char* firstLabel = reinterpret_cast<char*>(base + kLabelOffset);
    const std::string baseLabel = ExtractBaseLabel(firstLabel);

    if (baseLabel.empty())
        return;

    const uint8_t selectedSlot = GetSelectedSlotSafe(thisPtr);

    for (size_t i = 0; i < kSlotCount; ++i)
    {
        char* label = reinterpret_cast<char*>(base + kLabelOffset + (i * kLabelStride));
        if (!label)
            continue;

        if (i == selectedSlot)
            _snprintf_s(label, kLabelStride, _TRUNCATE, "%u %s *", static_cast<unsigned>(i + 1), baseLabel.c_str());
        else
            _snprintf_s(label, kLabelStride, _TRUNCATE, "%u %s", static_cast<unsigned>(i + 1), baseLabel.c_str());
    }
}

static void __fastcall hkSetupListElementWalkerGear(void* thisPtr)
{
    if (!oSetupListElementWalkerGear)
        return;

    oSetupListElementWalkerGear(thisPtr);

    if (!IsArabicSafe())
        return;

    RewriteWalkerGearLabels(thisPtr);
}

bool InstallCustomizeSlotSelectorSetupListElementWalkerGearHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargetSetupListElementWalkerGear =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetupListElementWalkerGear));

    if (!gTargetSetupListElementWalkerGear)
    {
        Log("[CustomizeSlotSelectorCallbackImpl::SetupListElementWalkerGear] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetSetupListElementWalkerGear,
            reinterpret_cast<void*>(&hkSetupListElementWalkerGear),
            reinterpret_cast<void**>(&oSetupListElementWalkerGear));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[CustomizeSlotSelectorCallbackImpl::SetupListElementWalkerGear] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetSetupListElementWalkerGear);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[CustomizeSlotSelectorCallbackImpl::SetupListElementWalkerGear] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[CustomizeSlotSelectorCallbackImpl::SetupListElementWalkerGear] Hook enabled.\n");
    return true;
}

void RemoveCustomizeSlotSelectorSetupListElementWalkerGearHook()
{
    if (gTargetSetupListElementWalkerGear)
    {
        MH_DisableHook(gTargetSetupListElementWalkerGear);
        MH_RemoveHook(gTargetSetupListElementWalkerGear);
        gTargetSetupListElementWalkerGear = nullptr;
    }

    oSetupListElementWalkerGear = nullptr;
    gIsArabLanguage = nullptr;
}