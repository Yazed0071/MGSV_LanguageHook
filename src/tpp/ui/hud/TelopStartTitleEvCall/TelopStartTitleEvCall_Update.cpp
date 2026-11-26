#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using tpp_ui_hud_TelopStartTitleEvCall_Update_t = void(__fastcall*)(void* thisPtr);

    using SetTranslateX_t = void(__fastcall*)(void* node, float x);
    using UixGetScaleInfo_t = uint8_t*(__fastcall*)(void* uix);

    constexpr size_t OFF_STATE = 0x18B;
    constexpr uint8_t STATE_TYPING = 0x0D;
    constexpr size_t OFF_UIX = 0xD0;
    constexpr size_t UIX_SCALE_INFO_SLOT = 0x548;
    constexpr size_t SCALE_INFO_SCALE = 0x2C;
    constexpr float kWidthOrigin = 256.0f;
    constexpr float kWidthToTranslate = 0.1f;

    struct TypingLine
    {
        size_t node;
        size_t twin;
        size_t base;
        size_t twinBase;
        size_t width;
    };

    constexpr TypingLine kTypingLines[] = {
        { 0x130, 0x148, 0x26C, 0x274, 0x2D4 },
        { 0x138, 0x150, 0x270, 0x278, 0x2F4 },
    };

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_hud_TelopStartTitleEvCall_Update_t gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update = nullptr;
    static SetTranslateX_t gSetTranslateX = nullptr;
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

/* Reads one byte safely. addr = source address, out = destination byte. */
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

/* Writes one byte safely. addr = target address, value = byte to write. */
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

/* Forces the telop typing-direction flag to the RTL path. thisPtr = TelopStartTitleEvCall*. */
static void ForceArabicTypingDirection(void* thisPtr)
{
    if (!thisPtr)
        return;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    // +0x189 is the flag that makes Update use GetUTF8TextFromBack(...)
    SafeWriteU8(base + 0x189, 1);
}

static bool SafeReadF32(const void* addr, float& out)
{
    __try
    {
        out = *reinterpret_cast<const float*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool ReadUiScale(uint8_t* base, float& scale)
{
    __try
    {
        void* uix = *reinterpret_cast<void**>(base + OFF_UIX);
        if (!uix)
            return false;
        auto getScaleInfo = *reinterpret_cast<UixGetScaleInfo_t*>(*reinterpret_cast<uint8_t**>(uix) +
                                                                  UIX_SCALE_INFO_SLOT);
        uint8_t* info = getScaleInfo ? getScaleInfo(uix) : nullptr;
        if (!info)
            return false;
        scale = *reinterpret_cast<float*>(info + SCALE_INFO_SCALE);
        return scale > 0.0f;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void PlaceLine(uint8_t* base, size_t nodeOffset, size_t baseOffset, float shift)
{
    __try
    {
        void* node = *reinterpret_cast<void**>(base + nodeOffset);
        if (node)
            gSetTranslateX(node, *reinterpret_cast<float*>(base + baseOffset) - shift);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void PinTypingLinesRightEdge(void* thisPtr)
{
    if (!gSetTranslateX)
        return;
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    uint8_t state = 0;
    if (!SafeReadU8(base + OFF_STATE, state) || state != STATE_TYPING)
        return;
    float scale = 0.0f;
    if (!ReadUiScale(base, scale))
        return;
    for (const TypingLine& line : kTypingLines)
    {
        float width = 0.0f;
        if (!SafeReadF32(base + line.width, width) || !(width > 0.0f))
            continue;
        const float shift = (width * scale - kWidthOrigin) * kWidthToTranslate;
        PlaceLine(base, line.node, line.base, shift);
        PlaceLine(base, line.twin, line.twinBase, shift);
    }
}

/* Hook for tpp::ui::hud::TelopStartTitleEvCall::Update(this). */
static void __fastcall hk_tpp_ui_hud_TelopStartTitleEvCall_Update(void* thisPtr)
{
    uint8_t originalDirection = 0;
    bool hadOriginalDirection = false;

    if (IsArabicSafe() && thisPtr)
    {
        hadOriginalDirection = SafeReadU8(reinterpret_cast<uint8_t*>(thisPtr) + 0x189, originalDirection);
        ForceArabicTypingDirection(thisPtr);
    }

    if (gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update)
        gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update(thisPtr);

    if (IsArabicSafe() && thisPtr && hadOriginalDirection)
    {
        SafeWriteU8(reinterpret_cast<uint8_t*>(thisPtr) + 0x189, originalDirection);
        PinTypingLinesRightEdge(thisPtr);
    }
}

/* Installs the Arabic telop typing-direction hook. hGame = game module handle. */
bool InstallTelopStartTitleEvCallUpdateArabicTypingDirectionHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.TelopStartTitleEvCallUpdate)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gSetTranslateX = gAddr.ModelNode_SetTranslateX ? reinterpret_cast<SetTranslateX_t>(gAddr.ModelNode_SetTranslateX)
                                                   : nullptr;
    gTarget = reinterpret_cast<void*>(gAddr.TelopStartTitleEvCallUpdate);

    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hk_tpp_ui_hud_TelopStartTitleEvCall_Update,
        reinterpret_cast<LPVOID*>(&gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update)) != MH_OK)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] MH_EnableHook failed.\n");
        return false;
    }

    Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Arabic typing-direction hook enabled.\n");
    return true;
}

/* Removes the Arabic telop typing-direction hook. */
void RemoveTelopStartTitleEvCallUpdateArabicTypingDirectionHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrig_tpp_ui_hud_TelopStartTitleEvCall_Update = nullptr;
    gSetTranslateX = nullptr;
    gIsArabLanguage = nullptr;

    Log("[tpp::ui::hud::TelopStartTitleEvCall::Update] Arabic typing-direction hook removed.\n");
}