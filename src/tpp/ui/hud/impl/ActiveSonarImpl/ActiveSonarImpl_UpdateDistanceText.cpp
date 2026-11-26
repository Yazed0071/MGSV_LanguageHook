#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using UpdateDistanceText_t = void(__fastcall*)(uint8_t* self);
    using UixSetText_t = void(__fastcall*)(void* uix, void* node, void* textUnit, const char* text, uint8_t flag);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_TEXT_UNIT = 0x38;
    constexpr size_t OFF_UIX = 0x50;
    constexpr size_t OFF_ENTRIES = 0x88;
    constexpr size_t ENTRY_SIZE = 0x90;
    constexpr size_t OFF_ENTRY_NODE = 0x20;
    constexpr size_t OFF_ENTRY_DISTANCE = 0x68;
    constexpr size_t OFF_ENTRY_COUNT = 0x981;
    constexpr size_t UIX_SET_TEXT = 0x708;
    constexpr size_t MAX_ENTRIES = 32;
    constexpr size_t TEXT_SIZE = 16;

    const uint8_t kPrologue[] = { 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00 };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    UpdateDistanceText_t oUpdateDistanceText = nullptr;
    void* gTarget = nullptr;
    char gTexts[MAX_ENTRIES][TEXT_SIZE] = {};
    std::atomic<bool> gLogged{ false };

    bool IsArabicSafe()
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

    bool CodeMatches(const void* target, const uint8_t* expected, size_t size)
    {
        __try
        {
            return std::memcmp(target, expected, size) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    size_t RewriteDistances(uint8_t* self)
    {
        size_t rewritten = 0;
        const char* unit = RL_LangText(LanguageProfileKeys::UnitMeter);
        if (!unit)
            unit = "m";
        __try
        {
            void* uix = *reinterpret_cast<void**>(self + OFF_UIX);
            void* textUnit = *reinterpret_cast<void**>(self + OFF_TEXT_UNIT);
            if (!uix)
                return 0;
            const auto setText =
                reinterpret_cast<UixSetText_t>((*reinterpret_cast<void***>(uix))[UIX_SET_TEXT / sizeof(void*)]);
            const size_t count = self[OFF_ENTRY_COUNT];
            for (size_t i = 0; i < count && i < MAX_ENTRIES; ++i)
            {
                uint8_t* entry = self + OFF_ENTRIES + i * ENTRY_SIZE;
                void* node = *reinterpret_cast<void**>(entry + OFF_ENTRY_NODE);
                if (!node)
                    continue;
                const int distance = static_cast<int>(*reinterpret_cast<const float*>(entry + OFF_ENTRY_DISTANCE));
                _snprintf_s(gTexts[i], TEXT_SIZE, _TRUNCATE, "%s%d", unit, distance);
                setText(uix, node, textUnit, gTexts[i], 1);
                ++rewritten;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return rewritten;
    }

    void __fastcall hkUpdateDistanceText(uint8_t* self)
    {
        oUpdateDistanceText(self);
        if (!self || !IsArabicSafe())
            return;
        if (RewriteDistances(self) > 0 && !gLogged.exchange(true))
            Log("[tpp::ui::hud::impl::ActiveSonarImpl] sonar distance drawn as metre sign + digits for Arabic.\n");
    }
}

bool InstallActiveSonarDistanceArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.ActiveSonarImpl_UpdateDistanceText)
    {
        Log("[tpp::ui::hud::impl::ActiveSonarImpl] address missing - sonar distances keep the unit after the digits.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) +
                                           (gAddr.ActiveSonarImpl_UpdateDistanceText - IDA_IMAGE_BASE));
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        Log("[tpp::ui::hud::impl::ActiveSonarImpl] prologue mismatch at %p - sonar distances keep the unit after the digits.\n",
            target);
        return false;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdateDistanceText),
                      reinterpret_cast<void**>(&oUpdateDistanceText)) != MH_OK)
    {
        Log("[tpp::ui::hud::impl::ActiveSonarImpl] MH_CreateHook failed.\n");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::hud::impl::ActiveSonarImpl] MH_EnableHook failed.\n");
        return false;
    }
    gTarget = target;
    Log("[tpp::ui::hud::impl::ActiveSonarImpl] sonar distance hook installed at %p.\n", target);
    return true;
}

void RemoveActiveSonarDistanceArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdateDistanceText = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
}
