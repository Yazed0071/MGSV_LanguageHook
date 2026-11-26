#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using ShowSkills_t = void(__fastcall*)(uint8_t* self);
    using GetDisplayWidth_t = float(__fastcall*)(void* node);
    using GetUix_t = void*(__cdecl*)();
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t SLOT_COUNT = 4;
    constexpr size_t SLOT_STRIDE = 0x20;
    constexpr size_t SLOT_GROUP = 0x00;
    constexpr size_t SLOT_TEXT = 0x10;
    constexpr size_t SLOT_ICON = 0x18;
    constexpr size_t LIST_SLOTS = 0x1268;
    constexpr size_t INFO_SLOTS = 0xA30;
    constexpr size_t LIST_TITLE = 0x1260;
    constexpr size_t INFO_TITLE = 0xA28;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_LINE_ALIGN = 0xD8;
    constexpr size_t NODE_BLOCK_ALIGN = 0xDA;
    constexpr size_t NODE_TEXT_WIDTH = 0x17C;
    constexpr size_t NODE_FLAGS = 0x90;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint8_t ALIGN_LEFT = 0;
    constexpr uint8_t ALIGN_CENTRE = 1;
    constexpr uint8_t ALIGN_RIGHT = 2;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr float WIDTH_TO_TRANSLATE = 0.1f;
    constexpr size_t MAX_AUTHORED = 32;

    const uint8_t kListPrologue[] = {
        0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x78, 0x83, 0xB9, 0xAC, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t kInfoPrologue[] = {
        0x40, 0x55, 0x56, 0x57, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x78, 0x4C, 0x8B, 0xE9,
    };

    struct Panel
    {
        const char* name;
        size_t slots;
        size_t title;
        ShowSkills_t original;
        void* target;
        std::atomic<bool> logged;
    };

    struct Authored
    {
        void* node;
        float x;
        uint8_t line;
        bool moved;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    GetUix_t gGetUix = nullptr;
    Authored gAuthored[MAX_AUTHORED] = {};
    size_t gAuthoredNext = 0;
    std::atomic<bool> gMirrorLogged{ false };
    Panel gList{ "mission list", LIST_SLOTS, LIST_TITLE, nullptr, nullptr, { false } };
    Panel gInfo{ "mission info", INFO_SLOTS, INFO_TITLE, nullptr, nullptr, { false } };

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

    bool SwapSlotPairs(uint8_t* slots)
    {
        __try
        {
            uint8_t temp[SLOT_STRIDE];
            for (size_t pair = 0; pair + 1 < SLOT_COUNT; pair += 2)
            {
                uint8_t* a = slots + pair * SLOT_STRIDE;
                uint8_t* b = a + SLOT_STRIDE;
                std::memcpy(temp, a, SLOT_STRIDE);
                std::memcpy(a, b, SLOT_STRIDE);
                std::memcpy(b, temp, SLOT_STRIDE);
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    float DisplayWidth(void* node)
    {
        if (!gGetDisplayWidth || !node)
            return -1.0f;
        __try
        {
            return gGetDisplayWidth(node);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1.0f;
        }
    }

    void LogSlot(const Panel& panel, const uint8_t* slots, size_t index)
    {
        const uint8_t* slot = slots + index * SLOT_STRIDE;
        uint8_t* group = nullptr;
        uint8_t* text = nullptr;
        uint8_t* icon = nullptr;
        float groupX = 0.0f, groupY = 0.0f, textX = 0.0f, textY = 0.0f, iconX = 0.0f, iconY = 0.0f, textWidth = 0.0f;
        unsigned line = 0xFF, block = 0xFF;
        __try
        {
            group = *reinterpret_cast<uint8_t* const*>(slot + SLOT_GROUP);
            text = *reinterpret_cast<uint8_t* const*>(slot + SLOT_TEXT);
            icon = *reinterpret_cast<uint8_t* const*>(slot + SLOT_ICON);
            if (group)
            {
                groupX = *reinterpret_cast<const float*>(group + NODE_TRANSLATION);
                groupY = *reinterpret_cast<const float*>(group + NODE_TRANSLATION + 4);
            }
            if (text)
            {
                textX = *reinterpret_cast<const float*>(text + NODE_TRANSLATION);
                textY = *reinterpret_cast<const float*>(text + NODE_TRANSLATION + 4);
                textWidth = *reinterpret_cast<const float*>(text + NODE_TEXT_WIDTH);
                line = text[NODE_LINE_ALIGN];
                block = text[NODE_BLOCK_ALIGN];
            }
            if (icon)
            {
                iconX = *reinterpret_cast<const float*>(icon + NODE_TRANSLATION);
                iconY = *reinterpret_cast<const float*>(icon + NODE_TRANSLATION + 4);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        Log("[tpp::ui::menu::impl::ShowSkillView] %s slot %zu: group %p at %.2f,%.2f; name %p at %.2f,%.2f text %.1f of %.1f "
            "(line %u block %u); icon %p at %.2f,%.2f\n",
            panel.name, index, group, groupX, groupY, text, textX, textY, textWidth, DisplayWidth(text), line, block,
            icon, iconX, iconY);
    }

    bool ReadNodeX(const uint8_t* node, float& x, uint8_t& line)
    {
        __try
        {
            x = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            line = node[NODE_LINE_ALIGN];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    Authored* AuthoredFor(uint8_t* node)
    {
        if (!node)
            return nullptr;
        for (Authored& entry : gAuthored)
        {
            if (entry.node == node)
                return &entry;
        }
        float x = 0.0f;
        uint8_t line = 0;
        if (!ReadNodeX(node, x, line))
            return nullptr;
        Authored& slot = gAuthored[gAuthoredNext++ % MAX_AUTHORED];
        slot = { node, x, line, false };
        return &slot;
    }

    void SetNodeX(void* node, float x)
    {
        if (!gGetUix || !node)
            return;
        __try
        {
            void* uix = gGetUix();
            if (!uix)
                return;
            void** vt = *reinterpret_cast<void***>(uix);
            reinterpret_cast<SetTranslateX_t>(vt[VT_SET_TRANSLATE_X / sizeof(void*)])(uix, node, x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void SetLineAlign(uint8_t* node, uint8_t align)
    {
        __try
        {
            if (node[NODE_LINE_ALIGN] == align)
                return;
            node[NODE_LINE_ALIGN] = align;
            *reinterpret_cast<uint16_t*>(node + NODE_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    bool ReadSlotNodes(const uint8_t* slot, uint8_t*& text, uint8_t*& icon)
    {
        __try
        {
            text = *reinterpret_cast<uint8_t* const*>(slot + SLOT_TEXT);
            icon = *reinterpret_cast<uint8_t* const*>(slot + SLOT_ICON);
            return text && icon;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void MirrorSlot(const Panel& panel, const uint8_t* slot, bool arabic)
    {
        uint8_t* text = nullptr;
        uint8_t* icon = nullptr;
        if (!ReadSlotNodes(slot, text, icon))
            return;
        Authored* textAuthored = AuthoredFor(text);
        Authored* iconAuthored = AuthoredFor(icon);
        if (!textAuthored || !iconAuthored)
            return;

        if (!arabic)
        {
            if (textAuthored->moved)
            {
                SetNodeX(text, textAuthored->x);
                SetLineAlign(text, textAuthored->line);
                textAuthored->moved = false;
            }
            if (iconAuthored->moved)
            {
                SetNodeX(icon, iconAuthored->x);
                iconAuthored->moved = false;
            }
            return;
        }

        const float box = DisplayWidth(text) * WIDTH_TO_TRANSLATE;
        if (!(box > 0.0f) || iconAuthored->x >= textAuthored->x)
            return;
        const float right = textAuthored->x + box;
        const float iconX = right - iconAuthored->x;
        const float textX = right - (textAuthored->x + box);
        SetNodeX(icon, iconX);
        SetNodeX(text, textX);
        SetLineAlign(text, ALIGN_RIGHT);
        textAuthored->moved = true;
        iconAuthored->moved = true;

        if (!gMirrorLogged.exchange(true))
            Log("[tpp::ui::menu::impl::ShowSkillView] Arabic %s skill slots mirrored: icon %.2f -> %.2f, name %.2f -> %.2f "
                "(box %.2f), names right-aligned\n",
                panel.name, iconAuthored->x, iconX, textAuthored->x, textX, box);
    }

    uint8_t* ReadTitle(const uint8_t* self, size_t offset)
    {
        __try
        {
            return *reinterpret_cast<uint8_t* const*>(self + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void AlignTitle(const Panel& panel, const uint8_t* self, bool arabic)
    {
        uint8_t* title = ReadTitle(self, panel.title);
        Authored* authored = AuthoredFor(title);
        if (!authored)
            return;
        if (arabic)
        {
            SetLineAlign(title, ALIGN_CENTRE);
            authored->moved = true;
        }
        else if (authored->moved)
        {
            SetLineAlign(title, authored->line);
            authored->moved = false;
        }
    }

    void Show(Panel& panel, uint8_t* self)
    {
        if (!self || !IsArabicSafe())
        {
            panel.original(self);
            if (self)
            {
                for (size_t i = 0; i < SLOT_COUNT; ++i)
                    MirrorSlot(panel, self + panel.slots + i * SLOT_STRIDE, false);
                AlignTitle(panel, self, false);
            }
            return;
        }
        uint8_t* slots = self + panel.slots;
        const bool swapped = SwapSlotPairs(slots);
        panel.original(self);
        if (swapped)
            SwapSlotPairs(slots);
        for (size_t i = 0; i < SLOT_COUNT; ++i)
            MirrorSlot(panel, slots + i * SLOT_STRIDE, true);
        AlignTitle(panel, self, true);

        if (!panel.logged.exchange(true))
        {
            Log("[tpp::ui::menu::impl::ShowSkillView] Arabic %s skills fill the right column first\n", panel.name);
            for (size_t i = 0; i < SLOT_COUNT; ++i)
                LogSlot(panel, slots, i);
        }
    }

    void __fastcall hkListShow(uint8_t* self)
    {
        Show(gList, self);
    }

    void __fastcall hkInfoShow(uint8_t* self)
    {
        Show(gInfo, self);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    void Hook(HMODULE hGame, Panel& panel, uintptr_t va, const uint8_t* prologue, size_t size, void* detour)
    {
        if (!va)
            return;
        void* target = Resolve(hGame, va);
        if (!CodeMatches(target, prologue, size))
        {
            Log("[tpp::ui::menu::impl::ShowSkillView] %s prologue mismatch at %p - skills keep the stock order.\n",
                panel.name, target);
            return;
        }
        if (MH_CreateHook(target, detour, reinterpret_cast<void**>(&panel.original)) != MH_OK)
            return;
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            return;
        }
        panel.target = target;
    }
}

bool InstallMissionSkillViewArabicHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || (!gAddr.MbDvcMissionListCallbackImpl_ShowSkillView &&
                                            !gAddr.MbDvcMissionInfoCallback_ShowSkillLayout))
    {
        Log("[tpp::ui::menu::impl::ShowSkillView] address missing - skills keep the stock order.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    if (gAddr.ModelNodeText_GetDisplayWidth)
        gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    if (gAddr.GetUixUtilityToFeedQuarkEnvironment)
        gGetUix = reinterpret_cast<GetUix_t>(Resolve(hGame, gAddr.GetUixUtilityToFeedQuarkEnvironment));
    Hook(hGame, gList, gAddr.MbDvcMissionListCallbackImpl_ShowSkillView, kListPrologue, sizeof(kListPrologue),
         reinterpret_cast<void*>(&hkListShow));
    Hook(hGame, gInfo, gAddr.MbDvcMissionInfoCallback_ShowSkillLayout, kInfoPrologue, sizeof(kInfoPrologue),
         reinterpret_cast<void*>(&hkInfoShow));
    Log("[tpp::ui::menu::impl::ShowSkillView] Arabic skills right column first: mission list %s, mission info %s.\n",
        gList.target ? "hooked" : "not hooked", gInfo.target ? "hooked" : "not hooked");
    return true;
}

void RemoveMissionSkillViewArabicHook()
{
    for (Panel* panel : { &gList, &gInfo })
    {
        if (panel->target)
        {
            MH_DisableHook(panel->target);
            MH_RemoveHook(panel->target);
            panel->target = nullptr;
        }
        panel->original = nullptr;
        panel->logged = false;
    }
    gGetDisplayWidth = nullptr;
    gGetUix = nullptr;
    gIsArabLanguage = nullptr;
    gAuthoredNext = 0;
    for (Authored& entry : gAuthored)
        entry = {};
    gMirrorLogged = false;
}
