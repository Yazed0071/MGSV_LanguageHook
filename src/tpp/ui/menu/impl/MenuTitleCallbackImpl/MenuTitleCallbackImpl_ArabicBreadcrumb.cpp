#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using SetMenuNameText_t = void(__fastcall*)(uint8_t* self, const uint64_t* ids);
    using GetTypingText_t = uint8_t(__fastcall*)(uint8_t* self, char* outText, const char* fullText);
    using GetLangText_t = const char*(__fastcall*)(uint64_t langId);
    using SetTextForModelNodeText_t = void(__fastcall*)(void* node, void* textUnit, const char* text, uint8_t flag);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t OFF_TEXT_UNIT = 0x78;
    constexpr size_t OFF_FULL_TEXT = 0xA2;
    constexpr size_t OFF_TYPED_TEXT = 0x1A2;
    constexpr size_t TEXT_SIZE = 0x100;
    constexpr size_t OFF_REVEAL_COUNT = 0x2B8;
    constexpr size_t OFF_TYPING = 0x2BC;
    constexpr size_t OFF_TITLE_NODE = 0x330;
    constexpr int MAX_PARTS = 5;
    constexpr uint64_t ID_MASK = 0xFFFFFFFFFFFFull;
    constexpr uint64_t EMPTY_ID = 0xB8A0BF169F98ull;
    constexpr char kSeparator[] = " < ";

    const uint8_t kSetMenuNameTextPrologue[] = { 0x40, 0x53, 0x56, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x89, 0x7C, 0x24, 0x68 };
    const uint8_t kGetTypingTextPrologue[] = {
        0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x48, 0x83, 0xEC, 0x20,
        0x80, 0xB9, 0xBC, 0x02, 0x00, 0x00, 0x00,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetLangText_t gGetLangText = nullptr;
    SetTextForModelNodeText_t gSetText = nullptr;
    SetMenuNameText_t oSetMenuNameText = nullptr;
    GetTypingText_t oGetTypingText = nullptr;
    void* gSetMenuNameTextTarget = nullptr;
    void* gGetTypingTextTarget = nullptr;
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

    bool ReadIds(const uint64_t* ids, uint64_t (&out)[MAX_PARTS])
    {
        __try
        {
            for (int i = 0; i < MAX_PARTS; ++i)
                out[i] = ids[i];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    const char* LangText(uint64_t id)
    {
        __try
        {
            return gGetLangText(id);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    bool ReadText(const uint8_t* self, size_t offset, char* out)
    {
        __try
        {
            std::memcpy(out, self + offset, TEXT_SIZE);
            out[TEXT_SIZE - 1] = '\0';
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool WriteText(uint8_t* self, size_t offset, const std::string& text)
    {
        if (text.size() >= TEXT_SIZE)
            return false;
        __try
        {
            std::memcpy(self + offset, text.c_str(), text.size() + 1);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadTyping(const uint8_t* self, uint16_t& revealCount, uint8_t& typing)
    {
        __try
        {
            revealCount = *reinterpret_cast<const uint16_t*>(self + OFF_REVEAL_COUNT);
            typing = self[OFF_TYPING];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint8_t* ReadPointer(const uint8_t* self, size_t offset)
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

    void CopyOut(char* out, const char* text, size_t size)
    {
        __try
        {
            std::memcpy(out, text, size + 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void SetNodeText(uint8_t* node, void* textUnit, const char* text)
    {
        __try
        {
            gSetText(node, textUnit, text, 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    std::string ReversedBreadcrumb(const uint64_t (&ids)[MAX_PARTS])
    {
        std::vector<std::string> parts;
        for (uint64_t id : ids)
        {
            if ((id & ID_MASK) == EMPTY_ID)
                break;
            const char* text = LangText(id);
            if (!text)
                break;
            parts.emplace_back(text);
        }
        std::string out;
        for (size_t i = parts.size(); i-- > 0;)
        {
            if (!out.empty())
                out += kSeparator;
            out += parts[i];
        }
        return out;
    }

    std::string RightmostChars(const char* text, size_t count)
    {
        std::vector<size_t> starts;
        for (size_t i = 0; text[i]; ++i)
        {
            if ((static_cast<uint8_t>(text[i]) & 0xC0) != 0x80)
                starts.push_back(i);
        }
        if (count >= starts.size())
            return std::string(text);
        if (count == 0)
            return std::string();
        return std::string(text + starts[starts.size() - count]);
    }

    std::string VisibleTyping(const char* full, uint16_t revealCount, uint8_t typing)
    {
        std::string visible = RightmostChars(full, revealCount);
        if (typing)
            visible.insert(0, "_");
        return visible;
    }

    uint8_t __fastcall hkGetTypingText(uint8_t* self, char* outText, const char* fullText)
    {
        const uint8_t changed = oGetTypingText(self, outText, fullText);
        if (!self || !outText || !fullText || !IsArabicSafe())
            return changed;
        uint16_t revealCount = 0;
        uint8_t typing = 0;
        if (!ReadTyping(self, revealCount, typing) || (!changed && !typing))
            return changed;
        char full[TEXT_SIZE];
        if (!ReadText(reinterpret_cast<const uint8_t*>(fullText), 0, full))
            return changed;
        const std::string visible = VisibleTyping(full, revealCount, typing);
        if (visible.size() < TEXT_SIZE)
            CopyOut(outText, visible.c_str(), visible.size());
        return changed;
    }

    void __fastcall hkSetMenuNameText(uint8_t* self, const uint64_t* ids)
    {
        oSetMenuNameText(self, ids);
        if (!self || !ids || !IsArabicSafe())
            return;
        uint8_t* node = ReadPointer(self, OFF_TITLE_NODE);
        if (!node)
            return;

        uint64_t idCopy[MAX_PARTS] = {};
        char current[TEXT_SIZE];
        if (!ReadIds(ids, idCopy) || !ReadText(self, OFF_FULL_TEXT, current))
            return;
        const std::string reversed = ReversedBreadcrumb(idCopy);
        if (reversed.empty() || reversed == current || !WriteText(self, OFF_FULL_TEXT, reversed))
            return;

        uint16_t revealCount = 0;
        uint8_t typing = 0;
        if (!ReadTyping(self, revealCount, typing))
            return;
        const std::string visible = VisibleTyping(reversed.c_str(), revealCount, typing);
        uint8_t* textUnit = ReadPointer(self, OFF_TEXT_UNIT);
        if (!textUnit || !WriteText(self, OFF_TYPED_TEXT, visible))
            return;
        SetNodeText(node, textUnit, reinterpret_cast<const char*>(self + OFF_TYPED_TEXT));
        if (!gLogged.exchange(true))
            Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] Arabic menu title path reversed, kept at its English position (%zu bytes)\n",
                reversed.size());
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
            Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] %s prologue mismatch at %p - menu title path stays left to right.\n",
                name, target);
            return nullptr;
        }
        if (MH_CreateHook(target, detour, original) != MH_OK)
        {
            Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] MH_CreateHook failed for %s.\n", name);
            return nullptr;
        }
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] MH_EnableHook failed for %s.\n", name);
            return nullptr;
        }
        return target;
    }
}

bool InstallMenuTitleArabicBreadcrumbHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.GetLangText || !gAddr.SetTextForModelNodeText ||
        !gAddr.MenuTitleCallbackImpl_SetMenuNameText || !gAddr.MenuTitleCallbackImpl_GetTypingText)
    {
        Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] address missing - menu title path stays left to right.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gGetLangText = reinterpret_cast<GetLangText_t>(Resolve(hGame, gAddr.GetLangText));
    gSetText = reinterpret_cast<SetTextForModelNodeText_t>(Resolve(hGame, gAddr.SetTextForModelNodeText));
    gGetTypingTextTarget = HookOne(hGame, gAddr.MenuTitleCallbackImpl_GetTypingText, kGetTypingTextPrologue,
                                   sizeof(kGetTypingTextPrologue), reinterpret_cast<void*>(&hkGetTypingText),
                                   reinterpret_cast<void**>(&oGetTypingText), "GetTypingText");
    if (!gGetTypingTextTarget)
        return true;
    gSetMenuNameTextTarget = HookOne(hGame, gAddr.MenuTitleCallbackImpl_SetMenuNameText, kSetMenuNameTextPrologue,
                                     sizeof(kSetMenuNameTextPrologue), reinterpret_cast<void*>(&hkSetMenuNameText),
                                     reinterpret_cast<void**>(&oSetMenuNameText), "SetMenuNameText");
    if (!gSetMenuNameTextTarget)
    {
        MH_DisableHook(gGetTypingTextTarget);
        MH_RemoveHook(gGetTypingTextTarget);
        gGetTypingTextTarget = nullptr;
        return true;
    }
    Log("[tpp::ui::menu::impl::MenuTitleCallbackImpl] Arabic menu title path right to left (hooked at %p and %p).\n",
        gSetMenuNameTextTarget, gGetTypingTextTarget);
    return true;
}

void RemoveMenuTitleArabicBreadcrumbHook()
{
    for (void** target : { &gSetMenuNameTextTarget, &gGetTypingTextTarget })
    {
        if (*target)
        {
            MH_DisableHook(*target);
            MH_RemoveHook(*target);
            *target = nullptr;
        }
    }
    oSetMenuNameText = nullptr;
    oGetTypingText = nullptr;
    gGetLangText = nullptr;
    gSetText = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
}
