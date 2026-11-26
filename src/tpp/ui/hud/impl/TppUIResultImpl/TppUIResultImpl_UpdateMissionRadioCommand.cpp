#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_set>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

const char* FullArabicTextForShortenedBuffer(const char* buffer);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using UpdateMissionRadioCommand_t = void(__fastcall*)(void* self);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

    const uint8_t kUpdatePrologue[] = {
        0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x60, 0x4C, 0x8B, 0xE9,
    };

    struct FileLabel
    {
        const char* english;
        uint64_t langId;
    };

    const FileLabel kFileLabels[] = {
        { "FILE NUMBER", LanguageProfileKeys::LabelFileNumber },
        { "CAT.", LanguageProfileKeys::LabelCategory },
        { "STS.", LanguageProfileKeys::LabelStatus },
        { "MPA", 0x7041E7230B57ull },
        { "MPB", 0x73DE59E2B91Aull },
        { "MPC", 0xFCD993DE607Cull },
        { "MPD", 0x8FA0C1D45FDBull },
        { "MPE", 0x0C1C8BE90F62ull },
        { "MPF", 0xA7A2F0C916BFull },
        { "MPG", 0x012E3CDDE04Full },
        { "MPH", 0x2C33318019BCull },
        { "MPI", 0xACBE103A3648ull },
        { "MPJ", 0x1C07448A7335ull },
        { "MPK", 0xE2F81E2990E2ull },
        { "SPL", 0x480F9043F0C4ull },
        { "SPM", 0x6F2F1F822406ull },
        { "SPN", 0xCF9F09E678C0ull },
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    UpdateMissionRadioCommand_t oUpdate = nullptr;
    void* gTarget = nullptr;
    thread_local int tInRadioCommand = 0;
    std::atomic<bool> gLogged{ false };
    std::atomic<int> gNameLogBudget{ 4 };
    std::mutex gNamesMutex;
    std::unordered_set<std::string> gFullNames;

    const char* PersistentName(const char* full)
    {
        std::lock_guard<std::mutex> lock(gNamesMutex);
        return gFullNames.insert(full).first->c_str();
    }

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

    bool SameText(const char* text, const char* expected)
    {
        __try
        {
            return std::strcmp(text, expected) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkUpdate(void* self)
    {
        ++tInRadioCommand;
        oUpdate(self);
        --tInRadioCommand;
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

const char* ArabicRadioFileLabel(const char* text)
{
    if (tInRadioCommand == 0 || !text)
        return nullptr;
    if (const char* full = FullArabicTextForShortenedBuffer(text))
    {
        const char* name = PersistentName(full);
        if (gNameLogBudget.load() > 0 && gNameLogBudget.fetch_sub(1) > 0)
            Log("[tpp::ui::hud::impl::TppUIResultImpl] radio file card name shown in full (%zu bytes, the card buffer holds 49)\n",
                std::strlen(name));
        return name;
    }
    for (const FileLabel& label : kFileLabels)
    {
        if (!SameText(text, label.english))
            continue;
        if (!IsArabicSafe())
            return nullptr;
        const char* translated = RL_LangText(label.langId);
        if (!translated)
            return nullptr;
        if (!gLogged.exchange(true))
            Log("[tpp::ui::hud::impl::TppUIResultImpl] radio file card label \"%s\" shown from the language's lng2\n",
                label.english);
        return translated;
    }
    return nullptr;
}

bool InstallTppUIResultImplRadioFileLabelsHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.TppUIResultImpl_UpdateMissionRadioCommand)
    {
        Log("[tpp::ui::hud::impl::TppUIResultImpl] address missing - radio file card labels stay English.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    void* target = Resolve(hGame, gAddr.TppUIResultImpl_UpdateMissionRadioCommand);
    if (!CodeMatches(target, kUpdatePrologue, sizeof(kUpdatePrologue)))
    {
        Log("[tpp::ui::hud::impl::TppUIResultImpl] UpdateMissionRadioCommand prologue mismatch at %p - radio file card labels stay English.\n", target);
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkUpdate), reinterpret_cast<void**>(&oUpdate)) != MH_OK)
    {
        Log("[tpp::ui::hud::impl::TppUIResultImpl] MH_CreateHook failed - radio file card labels stay English.\n");
        return true;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[tpp::ui::hud::impl::TppUIResultImpl] MH_EnableHook failed - radio file card labels stay English.\n");
        return true;
    }
    gTarget = target;
    Log("[tpp::ui::hud::impl::TppUIResultImpl] radio file card labels translated in Arabic (hooked at %p).\n", target);
    return true;
}

void RemoveTppUIResultImplRadioFileLabelsHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oUpdate = nullptr;
    gIsArabLanguage = nullptr;
    gLogged = false;
    gNameLogBudget = 4;
}
