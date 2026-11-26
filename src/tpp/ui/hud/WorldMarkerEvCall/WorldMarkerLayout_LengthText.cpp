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
    using LengthText_t = void(__fastcall*)(uint8_t* layout, void* textUnit, uint32_t distance, const char* unit,
                                           uint32_t markerId);
    using SetTextForModelNodeText_t = void(__fastcall*)(void* node, void* textUnit, const char* text, uint8_t flag);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_DISTANCE = 0x14;
    constexpr size_t OFF_LENGTH_NODE = 0xD8;
    constexpr size_t OFF_LENGTH_TEXT = 0xF0;
    constexpr size_t LENGTH_TEXT_SIZE = 0xF;
    constexpr size_t UNIT_SIZE = 9;
    char gLastRtlUnit[UNIT_SIZE] = {};

    const uint8_t kLengthTextOnPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x4D, 0x8B, 0xF1,
    };
    const uint8_t kLengthTextOnWithIdPrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x30,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    SetTextForModelNodeText_t gSetText = nullptr;
    LengthText_t oLengthTextOn = nullptr;
    LengthText_t oLengthTextOnWithId = nullptr;
    void* gTargetLengthTextOn = nullptr;
    void* gTargetLengthTextOnWithId = nullptr;
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

    bool ReadLength(const uint8_t* layout, uint32_t& distance, void*& node, char* text)
    {
        __try
        {
            distance = *reinterpret_cast<const uint32_t*>(layout + OFF_DISTANCE);
            node = *reinterpret_cast<void* const*>(layout + OFF_LENGTH_NODE);
            std::memcpy(text, layout + OFF_LENGTH_TEXT, LENGTH_TEXT_SIZE);
            text[LENGTH_TEXT_SIZE - 1] = '\0';
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool WriteLength(uint8_t* layout, const char* text)
    {
        __try
        {
            std::memcpy(layout + OFF_LENGTH_TEXT, text, std::strlen(text) + 1);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    constexpr size_t MAX_FONT_LOGS = 8;
    const void* gLoggedGroups[MAX_FONT_LOGS] = {};
    size_t gLoggedGroupCount = 0;

    void LogMarkerFont(const uint8_t* node)
    {
        const uint8_t* group = nullptr;
        uint32_t name = 0;
        float width = 0.0f, space = 0.0f;
        uint32_t em = 0;
        uint16_t cellW = 0, cellH = 0;
        bool fnt = false;
        __try
        {
            name = *reinterpret_cast<const uint32_t*>(node + 0x9C);
            group = *reinterpret_cast<const uint8_t* const*>(node + 0xA8);
            if (group)
            {
                width = *reinterpret_cast<const float*>(group + 0x08);
                space = *reinterpret_cast<const float*>(group + 0x10);
                const uint8_t* font = *reinterpret_cast<const uint8_t* const*>(group);
                if (font && *reinterpret_cast<const void* const*>(font + 0x08))
                {
                    fnt = true;
                    em = *reinterpret_cast<const uint32_t*>(font + 0x30);
                    cellW = *reinterpret_cast<const uint16_t*>(font + 0x38);
                    cellH = *reinterpret_cast<const uint16_t*>(font + 0x3C);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return;
        }
        for (size_t i = 0; i < gLoggedGroupCount; ++i)
        {
            if (gLoggedGroups[i] == group)
                return;
        }
        if (gLoggedGroupCount >= MAX_FONT_LOGS)
            return;
        gLoggedGroups[gLoggedGroupCount++] = group;
        if (fnt)
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] distance node %p font 0x%08X group %p w %.1f ts %.1f: "
                "fnt em %u cell %ux%u\n",
                node, name, group, width, space, em, cellW, cellH);
        else
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] distance node %p font 0x%08X group %p w %.1f ts %.1f: "
                "system font\n",
                node, name, group, width, space);
    }

    void SetNodeText(void* node, void* textUnit, const char* text)
    {
        __try
        {
            gSetText(node, textUnit, text, 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void ApplyUnit(uint8_t* layout, void* textUnit, const char* unit)
    {
        if (!layout || !textUnit || !gSetText)
            return;
        uint32_t distance = 0;
        void* node = nullptr;
        char current[LENGTH_TEXT_SIZE] = {};
        if (!ReadLength(layout, distance, node, current) || !node || current[0] == '\0' || distance == 0)
            return;

        const bool arabic = IsArabicSafe();
        char rtlUnit[UNIT_SIZE] = {};
        if (arabic)
        {
            const char* fromLang = RL_LangText(LanguageProfileKeys::UnitMeter);
            strncpy_s(rtlUnit, sizeof(rtlUnit), fromLang ? fromLang : (unit && unit[0] ? unit : "m"), _TRUNCATE);
            strncpy_s(gLastRtlUnit, sizeof(gLastRtlUnit), rtlUnit, _TRUNCATE);
        }
        const char* shownUnit = arabic ? rtlUnit : gLastRtlUnit;
        const size_t shownLength = std::strlen(shownUnit);
        const bool showsArabic = shownLength && std::strncmp(current, shownUnit, shownLength) == 0;
        if (arabic == showsArabic)
            return;

        char text[LENGTH_TEXT_SIZE] = {};
        if (arabic)
            std::snprintf(text, sizeof(text), "%s%u", rtlUnit, distance);
        else
            std::snprintf(text, sizeof(text), "%u%s", distance, unit ? unit : "");
        if (!WriteLength(layout, text))
            return;
        SetNodeText(node, textUnit, reinterpret_cast<const char*>(layout + OFF_LENGTH_TEXT));
        if (arabic)
            LogMarkerFont(static_cast<const uint8_t*>(node));

        if (arabic && !gLogged.exchange(true))
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] marker distance %u shown with the Arabic metre sign\n",
                distance);
    }

    void __fastcall hkLengthTextOn(uint8_t* layout, void* textUnit, uint32_t distance, const char* unit,
                                   uint32_t markerId)
    {
        oLengthTextOn(layout, textUnit, distance, unit, markerId);
        ApplyUnit(layout, textUnit, unit);
    }

    void __fastcall hkLengthTextOnWithId(uint8_t* layout, void* textUnit, uint32_t distance, const char* unit,
                                         uint32_t markerId)
    {
        oLengthTextOnWithId(layout, textUnit, distance, unit, markerId);
        ApplyUnit(layout, textUnit, unit);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    void* HookOne(HMODULE hGame, uintptr_t va, const uint8_t* prologue, size_t size, void* detour, void** original,
                  const char* name)
    {
        void* target = Resolve(hGame, va);
        if (!CodeMatches(target, prologue, size))
        {
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] %s prologue mismatch at %p - its distance keeps \"m\".\n",
                name, target);
            return nullptr;
        }
        if (MH_CreateHook(target, detour, original) != MH_OK)
        {
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] MH_CreateHook failed for %s.\n", name);
            return nullptr;
        }
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] MH_EnableHook failed for %s.\n", name);
            return nullptr;
        }
        return target;
    }
}

bool InstallWorldMarkerLengthTextArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.SetTextForModelNodeText || !gAddr.WorldMarkerLayout_LengthTextOn ||
        !gAddr.WorldMarkerLayout_LengthTextOnWithID)
    {
        Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] address missing - marker distances keep \"m\".\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gSetText = reinterpret_cast<SetTextForModelNodeText_t>(Resolve(hGame, gAddr.SetTextForModelNodeText));
    gTargetLengthTextOn = HookOne(hGame, gAddr.WorldMarkerLayout_LengthTextOn, kLengthTextOnPrologue,
                                  sizeof(kLengthTextOnPrologue), reinterpret_cast<void*>(&hkLengthTextOn),
                                  reinterpret_cast<void**>(&oLengthTextOn), "LengthTextOn");
    gTargetLengthTextOnWithId = HookOne(hGame, gAddr.WorldMarkerLayout_LengthTextOnWithID, kLengthTextOnWithIdPrologue,
                                        sizeof(kLengthTextOnWithIdPrologue),
                                        reinterpret_cast<void*>(&hkLengthTextOnWithId),
                                        reinterpret_cast<void**>(&oLengthTextOnWithId), "LengthTextOnWithID");
    Log("[tpp::ui::hud::WorldMarkerEvCall::WorldMarkerLayout] Arabic metre sign on marker distances: LengthTextOn %s, LengthTextOnWithID %s.\n",
        gTargetLengthTextOn ? "hooked" : "not hooked", gTargetLengthTextOnWithId ? "hooked" : "not hooked");
    return true;
}

void RemoveWorldMarkerLengthTextArabicHook()
{
    for (void** target : { &gTargetLengthTextOn, &gTargetLengthTextOnWithId })
    {
        if (*target)
        {
            MH_DisableHook(*target);
            MH_RemoveHook(*target);
            *target = nullptr;
        }
    }
    oLengthTextOn = nullptr;
    oLengthTextOnWithId = nullptr;
    gSetText = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
    gLoggedGroupCount = 0;
}
