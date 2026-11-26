#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using SetupPanel_t = void(__fastcall*)(void* inner);

    SetupPanel_t gOrigSetupPanel = nullptr;
    void* gTarget = nullptr;

    constexpr size_t OFF_PANEL_BUTTON_TYPES = 0x518;
    constexpr int PANEL_SLOT_COUNT = 7;
    constexpr int BUTTON_REWIND = 0;
    constexpr int BUTTON_FAST_FORWARD = 3;

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

    bool SwapSeekButtons(void* inner)
    {
        __try
        {
            int* types = reinterpret_cast<int*>(reinterpret_cast<char*>(inner) + OFF_PANEL_BUTTON_TYPES);
            int rewindSlot = -1;
            int forwardSlot = -1;
            for (int i = 0; i < PANEL_SLOT_COUNT; ++i)
            {
                if (types[i] == BUTTON_REWIND && rewindSlot < 0)
                    rewindSlot = i;
                else if (types[i] == BUTTON_FAST_FORWARD && forwardSlot < 0)
                    forwardSlot = i;
            }
            if (rewindSlot < 0 || forwardSlot < 0 || rewindSlot > forwardSlot)
                return false;
            types[rewindSlot] = BUTTON_FAST_FORWARD;
            types[forwardSlot] = BUTTON_REWIND;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkSetupPanel(void* inner)
    {
        gOrigSetupPanel(inner);
        if (!inner || !IsRightToLeftSafe())
            return;
        if (SwapSeekButtons(inner))
            Log("[MbDvcCassetteTape] Right-to-left player: the left seek button now fast-forwards and the right one rewinds.\n");
    }
}

bool InstallCassetteSeekButtonSwapHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.MbDvcCassetteTape_SetupPanel)
    {
        Log("[MbDvcCassetteTape] Missing address, seek buttons keep the game order.\n");
        return false;
    }

    gTarget = reinterpret_cast<void*>(gAddr.MbDvcCassetteTape_SetupPanel);
    if (MH_CreateHook(gTarget, &hkSetupPanel, reinterpret_cast<LPVOID*>(&gOrigSetupPanel)) != MH_OK)
    {
        Log("[MbDvcCassetteTape] MH_CreateHook failed.\n");
        gTarget = nullptr;
        return false;
    }
    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[MbDvcCassetteTape] MH_EnableHook failed.\n");
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
        return false;
    }

    Log("[MbDvcCassetteTape] Seek button swap hook enabled.\n");
    return true;
}

void RemoveCassetteSeekButtonSwapHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    gOrigSetupPanel = nullptr;
}
