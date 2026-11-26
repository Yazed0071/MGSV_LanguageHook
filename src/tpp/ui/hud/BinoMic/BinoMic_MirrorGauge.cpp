#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

using UpdateMic_t = void(__fastcall*)(void* self);
using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

static UpdateMic_t oUpdateMic = nullptr;
static void* gTargetUpdateMic = nullptr;
static bool gBarsMoved = false;
static bool gLoggedFirst = false;

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr float kPeakRange = 13.5f;
static constexpr float kPeakOffset = 2.7f;
static constexpr float kDefaultBarScale = 32.0f;

static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

static __forceinline float ReadF(const uint8_t* p, size_t off)
{
    return *reinterpret_cast<const float*>(p + off);
}

static void* GetUix(const uint8_t* self)
{
    const uint8_t* owner = *reinterpret_cast<uint8_t* const*>(self + 0x48);
    if (!owner)
        return nullptr;
    return *reinterpret_cast<void* const*>(owner + 0x20);
}

static void SetX(void* uix, void* node, float x)
{
    if (!uix || !node)
        return;
    auto fn = reinterpret_cast<SetTranslateX_t>((*reinterpret_cast<void***>(uix))[0x350 / sizeof(void*)]);
    fn(uix, node, x);
}

static void ApplyMirror(uint8_t* self)
{
    void* uix = GetUix(self);
    void* barA = *reinterpret_cast<void**>(self + 0x5E8);
    void* barB = *reinterpret_cast<void**>(self + 0x5F0);
    void* mark = *reinterpret_cast<void**>(self + 0x5F8);
    if (!uix || !barA)
        return;

    const float minFill = ReadF(self, 0x98C);
    const float maxFill = ReadF(self, 0x990);
    if (!(maxFill > 0.0f))
        return;

    float scale = ReadF(reinterpret_cast<const uint8_t*>(barA), 0x40);
    if (scale < 0.0f)
        scale = -scale;
    if (!(scale > 1.0f && scale < 1000.0f))
        scale = kDefaultBarScale;

    const float rightEnd = scale * maxFill;

    float fill = ReadF(self, 0x99C) + ReadF(self, 0x994);
    if (fill < minFill)
        fill = minFill;
    if (fill > maxFill)
        fill = maxFill;

    const float barX = rightEnd - scale * fill;
    SetX(uix, barA, barX);
    SetX(uix, barB, barX);
    gBarsMoved = true;

    const float peak = ReadF(self, 0x9A0);
    const float markX = kPeakOffset + rightEnd - peak * (rightEnd / kPeakRange);
    SetX(uix, mark, markX);

    if (!gLoggedFirst)
    {
        gLoggedFirst = true;
        Log("[BinoMic] right-to-left gauge: bar scale %.2f, right end %.2f, fill %.3f -> bar x %.2f, mark x %.2f\n",
            scale, rightEnd, fill, barX, markX);
    }
}

static void RestoreBars(uint8_t* self)
{
    void* uix = GetUix(self);
    SetX(uix, *reinterpret_cast<void**>(self + 0x5E8), 0.0f);
    SetX(uix, *reinterpret_cast<void**>(self + 0x5F0), 0.0f);
    gBarsMoved = false;
}

static void __fastcall hkUpdateMic(void* self)
{
    oUpdateMic(self);

    if (!self)
        return;

    __try
    {
        auto* p = reinterpret_cast<uint8_t*>(self);
        if (!*reinterpret_cast<void**>(p + 0x5B0))
            return;
        if (*(p + 0x950) == 0)
            return;

        if (RL_IsRightToLeft())
            ApplyMirror(p);
        else if (gBarsMoved)
            RestoreBars(p);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

bool InstallBinoMicMirrorGaugeHook(HMODULE hGame)
{
    if (!hGame || !gAddr.TppUIBinoSubjective_UpdateMic)
        return false;

    gTargetUpdateMic = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.TppUIBinoSubjective_UpdateMic));

    const MH_STATUS createSt = MH_CreateHook(
        gTargetUpdateMic,
        reinterpret_cast<void*>(&hkUpdateMic),
        reinterpret_cast<void**>(&oUpdateMic));
    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[BinoMic] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetUpdateMic);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[BinoMic] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[BinoMic] Hook enabled.\n");
    return true;
}

void RemoveBinoMicMirrorGaugeHook()
{
    if (gTargetUpdateMic)
    {
        MH_DisableHook(gTargetUpdateMic);
        MH_RemoveHook(gTargetUpdateMic);
        gTargetUpdateMic = nullptr;
    }
    oUpdateMic = nullptr;
    gBarsMoved = false;
}
