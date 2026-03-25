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
    using tpp_ui_menu_TitleLayoutController_SetText_t =
        void(__fastcall*)(void* thisPtr, void* textContext, const char* mainText, const char* extraText);

    using tpp_ui_utility_SetTextForModelNodeText_t =
        void(__fastcall*)(void* modelNodeText, void* textContext, const char* text, int flag);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static tpp_ui_menu_TitleLayoutController_SetText_t otpp_ui_menu_TitleLayoutController_SetText = nullptr;
    static tpp_ui_utility_SetTextForModelNodeText_t gtpp_ui_utility_SetTextForModelNodeText = nullptr;
    static void* gTargettpp_ui_menu_TitleLayoutController_SetText = nullptr;

    static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    static constexpr uintptr_t ABS_tpp_ui_menu_TitleLayoutController_SetText = 0x140884930ull;
}

// Function: converts an IDA absolute address into a runtime address.
// Params:
// - hGame: game module base
// - absVa: IDA absolute address
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// Function: safely checks whether Arabic is active.
// Params:
// - none
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

// Function: hook for tpp::ui::menu::TitleLayoutController::SetText.
// Params:
// - thisPtr: TitleLayoutController
// - textContext: text context passed by game
// - mainText: first text
// - extraText: second text
static void __fastcall hktpp_ui_menu_TitleLayoutController_SetText(
    void* thisPtr,
    void* textContext,
    const char* mainText,
    const char* extraText)
{
    if (!otpp_ui_menu_TitleLayoutController_SetText)
        return;

    otpp_ui_menu_TitleLayoutController_SetText(thisPtr, textContext, mainText, extraText);

    if (!IsArabicSafe() || !thisPtr || !textContext || !extraText || !gtpp_ui_utility_SetTextForModelNodeText)
        return;

    __try
    {
        auto* base = reinterpret_cast<uint8_t*>(thisPtr);
        char* buffer = reinterpret_cast<char*>(base + 0x40);

        _snprintf_s(
            buffer,
            0x80,
            _TRUNCATE,
            "%s%8s%s",
            extraText,
            "",
            mainText ? mainText : "");

        uint32_t index = *reinterpret_cast<uint32_t*>(base + 0x10);
        auto* listBase = *reinterpret_cast<uint8_t**>(base + 0x20);
        if (!listBase)
            return;

        while (index != 0xFFFFFFFF)
        {
            void* modelNodeText =
                *reinterpret_cast<void**>(listBase + static_cast<uint64_t>(index) * 0x10);

            gtpp_ui_utility_SetTextForModelNodeText(
                modelNodeText,
                textContext,
                buffer,
                1);

            index = *reinterpret_cast<uint32_t*>(
                listBase + 0x0C + static_cast<uint64_t>(index) * 0x10);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log("[tpp::ui::menu::TitleLayoutController::SetText] Exception in hook.\n");
    }
}

// Function: installs the Arabic hook for tpp::ui::menu::TitleLayoutController::SetText.
// Params:
// - hGame: game module base
bool InstallTitleLayoutControllerSetTextArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTargettpp_ui_menu_TitleLayoutController_SetText =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_tpp_ui_menu_TitleLayoutController_SetText));

    gtpp_ui_utility_SetTextForModelNodeText =
        reinterpret_cast<tpp_ui_utility_SetTextForModelNodeText_t>(
            ToRuntimeVA(hGame, gAddr.SetTextForModelNodeText));

    if (!gTargettpp_ui_menu_TitleLayoutController_SetText || !gtpp_ui_utility_SetTextForModelNodeText)
    {
        Log("[tpp::ui::menu::TitleLayoutController::SetText] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargettpp_ui_menu_TitleLayoutController_SetText,
            reinterpret_cast<void*>(&hktpp_ui_menu_TitleLayoutController_SetText),
            reinterpret_cast<void**>(&otpp_ui_menu_TitleLayoutController_SetText));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[tpp::ui::menu::TitleLayoutController::SetText] MH_CreateHook failed: %d\n",
            static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargettpp_ui_menu_TitleLayoutController_SetText);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[tpp::ui::menu::TitleLayoutController::SetText] MH_EnableHook failed: %d\n",
            static_cast<int>(enableSt));
        return false;
    }

    Log("[tpp::ui::menu::TitleLayoutController::SetText] Hook enabled.\n");
    return true;
}

// Function: removes the Arabic hook for tpp::ui::menu::TitleLayoutController::SetText.
// Params:
// - none
void RemoveTitleLayoutControllerSetTextArabicHook()
{
    if (gTargettpp_ui_menu_TitleLayoutController_SetText)
    {
        MH_DisableHook(gTargettpp_ui_menu_TitleLayoutController_SetText);
        MH_RemoveHook(gTargettpp_ui_menu_TitleLayoutController_SetText);
        gTargettpp_ui_menu_TitleLayoutController_SetText = nullptr;
    }

    otpp_ui_menu_TitleLayoutController_SetText = nullptr;
    gtpp_ui_utility_SetTextForModelNodeText = nullptr;
    gIsArabLanguage = nullptr;
}