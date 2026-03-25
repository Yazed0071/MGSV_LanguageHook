#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetLangText_t = const char* (__fastcall*)(uint64_t langId);
    using ShowCompleteRatio_t = void(__fastcall*)(void* thisPtr);
    using UiApply708_t = void(__fastcall*)(void* uiObj, void* node, void* textUnit, const char* text, uint8_t flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static GetLangText_t gGetLangText = nullptr;
    static ShowCompleteRatio_t gOrigShowCompleteRatio = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. */
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

/* Reads a pointer safely. */
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

/* Reads one byte safely. */
static bool SafeReadU8(const void* addr, uint8_t& out)
{
    __try
    {
        out = *reinterpret_cast<const uint8_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out = 0;
        return false;
    }
}

static void ApplyArabicCompleteRatioText(void* thisPtr)
{
    if (!thisPtr || !gGetLangText)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint8_t currentCount = 0;
    uint8_t totalCount = 0;

    if (!SafeReadU8(base + 0x151B, currentCount))
        return;
    if (!SafeReadU8(base + 0x151C, totalCount))
        return;

    char* textBuffer = reinterpret_cast<char*>(base + 0x1550);

    const char* ratioLabel = gGetLangText(0x59b1755fb751ull);
    if (!ratioLabel)
        return;

    if (totalCount == 0)
    {
        textBuffer[0] = '\0';
    }
    else
    {
        const uint32_t percentValue =
            (static_cast<uint32_t>(currentCount) * 100u) / static_cast<uint32_t>(totalCount);

        _snprintf_s(
            textBuffer,
            0x40,
            _TRUNCATE,
            "(%%%3u) %3u / %3u %s",
            static_cast<unsigned>(percentValue),
            static_cast<unsigned>(totalCount),
            static_cast<unsigned>(currentCount),
            ratioLabel);
    }

    void* frameworkRoot = nullptr;
    if (!SafeReadPtr(base + 0x38, frameworkRoot) || !frameworkRoot)
        return;

    void* uiObj = nullptr;
    if (!SafeReadPtr(reinterpret_cast<uint8_t*>(frameworkRoot) + 0x20, uiObj) || !uiObj)
        return;

    void* textNode = nullptr;
    if (!SafeReadPtr(base + 0x1530, textNode) || !textNode)
        return;

    void* textUnit = nullptr;
    if (!SafeReadPtr(base + 0x48, textUnit) || !textUnit)
        return;

    __try
    {
        auto** vtbl = *reinterpret_cast<void***>(uiObj);
        if (!vtbl)
            return;

        using UiApply708_t = void(__fastcall*)(void* uiObj, void* node, void* textUnit, const char* text, uint8_t flag);
        auto fn708 = reinterpret_cast<UiApply708_t>(vtbl[0x708 / 8]);
        if (!fn708)
            return;

        fn708(uiObj, textNode, textUnit, textBuffer, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] Exception during reapply.\n");
        return;
    }

    Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] rebuilt text: %s\n", textBuffer);
}

/* Hook for MbDvcSideOpsCallbackImpl::ShowCompleteRatio(this). */
static void __fastcall hkMbDvcSideOpsCallbackImpl_ShowCompleteRatio(void* thisPtr)
{
    if (gOrigShowCompleteRatio)
        gOrigShowCompleteRatio(thisPtr);

    if (!IsArabicSafe())
        return;

    ApplyArabicCompleteRatioText(thisPtr);
}

/* Installs the ShowCompleteRatio Arabic text hook. */
bool InstallMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage ||
        !gAddr.GetLangText ||
        !gAddr.MbDvcSideOpsCallbackImpl_ShowCompleteRatio)
    {
        Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gGetLangText = reinterpret_cast<GetLangText_t>(gAddr.GetLangText);
    gTarget = reinterpret_cast<void*>(gAddr.MbDvcSideOpsCallbackImpl_ShowCompleteRatio);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkMbDvcSideOpsCallbackImpl_ShowCompleteRatio,
        reinterpret_cast<LPVOID*>(&gOrigShowCompleteRatio)) != MH_OK)
    {
        Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] MH_EnableHook failed.\n");
        return false;
    }

    Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] Arabic text hook enabled.\n");
    return true;
}

/* Removes the ShowCompleteRatio Arabic text hook. */
void RemoveMbDvcSideOpsCallbackImplShowCompleteRatioArabicTextHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigShowCompleteRatio = nullptr;
    gGetLangText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[MbDvcSideOpsCallbackImpl::ShowCompleteRatio] Arabic text hook removed.\n");
}