#include "pch.h"
#include <Windows.h>
#include <intrin.h>
#include <atomic>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "HookUtils.h"
#include "LanguageProfile.h"

#pragma intrinsic(_ReturnAddress)

namespace
{
    using SetMaskOffset_t = void(__fastcall*)(void* uix, void* node, float x, float y);

    SetMaskOffset_t gOrigSetMaskOffset = nullptr;
    void* gTarget = nullptr;
    uintptr_t gMapCodeBegin = 0;
    uintptr_t gMapCodeEnd = 0;
    std::atomic<int> gLogBudget{ 24 };

    bool IsRightToLeftSafe()
    {
        __try
        {
            return RL_IsRightToLeft();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkSetMaskOffset(void* uix, void* node, float x, float y)
    {
        const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
        if (node && caller >= gMapCodeBegin && caller < gMapCodeEnd && x != 0.0f && IsRightToLeftSafe())
        {
            if (gLogBudget.load() > 0 && gLogBudget.fetch_sub(1) > 0)
                Log("[MbDvcMap] map mask offset (%.3f, %.3f) mirrored to (%.3f, %.3f), node %p, caller +0x%llX\n", x, y,
                    -x, y, node, static_cast<unsigned long long>(caller - GetExeBase()));
            x = -x;
        }
        gOrigSetMaskOffset(uix, node, x, y);
    }
}

bool InstallMapMaskMirrorHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.UiUtility_SetMaskOffset || !gAddr.MbDvcMapCodeBegin || gAddr.MbDvcMapCodeEnd <= gAddr.MbDvcMapCodeBegin)
    {
        Log("[MbDvcMap] Missing address, the split-map mask keeps the game side.\n");
        return false;
    }

    gMapCodeBegin = reinterpret_cast<uintptr_t>(ResolveGameAddress(gAddr.MbDvcMapCodeBegin));
    gMapCodeEnd = reinterpret_cast<uintptr_t>(ResolveGameAddress(gAddr.MbDvcMapCodeEnd));
    gTarget = ResolveGameAddress(gAddr.UiUtility_SetMaskOffset);
    if (!gTarget || !gMapCodeBegin || gMapCodeEnd <= gMapCodeBegin)
    {
        Log("[MbDvcMap] Could not resolve the mask addresses.\n");
        gTarget = nullptr;
        return false;
    }
    if (MH_CreateHook(gTarget, &hkSetMaskOffset, reinterpret_cast<LPVOID*>(&gOrigSetMaskOffset)) != MH_OK)
    {
        Log("[MbDvcMap] MH_CreateHook failed.\n");
        gTarget = nullptr;
        return false;
    }
    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcMap] MH_EnableHook failed.\n");
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
        return false;
    }

    Log("[MbDvcMap] Split-map mask mirror hook enabled.\n");
    return true;
}

void RemoveMapMaskMirrorHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    gOrigSetMaskOffset = nullptr;
}
