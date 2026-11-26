#include "pch.h"
#include <Windows.h>
#include <intrin.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "HookUtils.h"
#include "LanguageProfile.h"

#pragma intrinsic(_ReturnAddress)

namespace
{
    using SetTranslateX_t = uint64_t(__fastcall*)(void* uix, void* node, float x);

    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t NODE_AREA_LEFT = 0xE0;
    constexpr size_t NODE_AREA_WIDTH = 0xE8;
    constexpr size_t NODE_TEXT_SCALE = 0xF0;
    constexpr uint32_t VALUE_NODE = 0x021A32E0;
    constexpr float GAME_VALUE_X = 34.2f;
    constexpr float ROW_AXIS = 21.0f;
    constexpr float FALLBACK_CENTRE_OFFSET = -1.2f;
    constexpr float MAX_CENTRE_OFFSET = 50.0f;
    constexpr float MATCH = 0.01f;

    SetTranslateX_t gOrigSetTranslateX = nullptr;
    void* gTarget = nullptr;
    uintptr_t gValueXReturn = 0;
    std::atomic<int> gLogBudget{ 4 };

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

    bool IsValueNode(const void* node)
    {
        __try
        {
            return *reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(node) + NODE_NAME) == VALUE_NODE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    float BoxCentreOffset(const void* node)
    {
        float offset = FALLBACK_CENTRE_OFFSET;
        __try
        {
            const uint8_t* bytes = static_cast<const uint8_t*>(node);
            const float scale = *reinterpret_cast<const float*>(bytes + NODE_TEXT_SCALE);
            const float left = *reinterpret_cast<const float*>(bytes + NODE_AREA_LEFT);
            const float width = *reinterpret_cast<const float*>(bytes + NODE_AREA_WIDTH);
            const float measured = scale * (left + width * 0.5f);
            if (std::isfinite(measured) && std::fabs(measured) < MAX_CENTRE_OFFSET)
                offset = measured;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return offset;
    }

    uint64_t __fastcall hkSetTranslateX(void* uix, void* node, float x)
    {
        if (node && reinterpret_cast<uintptr_t>(_ReturnAddress()) == gValueXReturn &&
            std::fabs(x - GAME_VALUE_X) < MATCH && IsValueNode(node) && IsRightToLeftSafe())
        {
            const float offset = BoxCentreOffset(node);
            const float mirrored = 2.0f * ROW_AXIS - x - 2.0f * offset;
            if (gLogBudget.load() > 0 && gLogBudget.fetch_sub(1) > 0)
                Log("[SecurityDetailRecord] icon-row value x %.2f mirrored to %.2f (box centre %.2f -> %.2f, node %p)\n",
                    x, mirrored, x + offset, mirrored + offset, node);
            x = mirrored;
        }
        return gOrigSetTranslateX(uix, node, x);
    }
}

bool InstallSecurityDetailValueXMirrorHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.UixUtility_SetTranslateX || !gAddr.SecurityDetailIconRow_ValueXReturn)
    {
        Log("[SecurityDetailRecord] Missing address, scrolled security rows keep the game's value x.\n");
        return true;
    }

    gTarget = ResolveGameAddress(gAddr.UixUtility_SetTranslateX);
    gValueXReturn = reinterpret_cast<uintptr_t>(ResolveGameAddress(gAddr.SecurityDetailIconRow_ValueXReturn));
    if (!gTarget || !gValueXReturn)
    {
        Log("[SecurityDetailRecord] Could not resolve the addresses.\n");
        gTarget = nullptr;
        return false;
    }
    if (MH_CreateHook(gTarget, &hkSetTranslateX, reinterpret_cast<LPVOID*>(&gOrigSetTranslateX)) != MH_OK)
    {
        Log("[SecurityDetailRecord] MH_CreateHook failed.\n");
        gTarget = nullptr;
        return false;
    }
    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[SecurityDetailRecord] MH_EnableHook failed.\n");
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
        return false;
    }

    Log("[SecurityDetailRecord] Icon-row value x mirror hook enabled.\n");
    return true;
}

void RemoveSecurityDetailValueXMirrorHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    gOrigSetTranslateX = nullptr;
    gValueXReturn = 0;
}
