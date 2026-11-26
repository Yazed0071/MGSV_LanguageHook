#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using GetLanguage_t = void* (__fastcall*)();
    using CString_t = const char* (__fastcall*)(void* shared);
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetLangText_t = const char* (__fastcall*)(uint64_t langId);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint8_t FLAG_RTL = 1;
    constexpr uint8_t FLAG_ARABIC_SCRIPT = 2;
    constexpr uint64_t RETRY_MS = 250;
    constexpr uint64_t SLOW_RETRY_MS = 2000;
    constexpr uint32_t MAX_TRIES = 40;
    constexpr size_t MAX_PROFILES = 16;
    constexpr size_t CODE_CHARS = 8;

    const uint8_t kIsArabHead[] = { 0x48, 0x83, 0xEC, 0x28, 0xE8 };
    const uint8_t kMovRcxRax[] = { 0x48, 0x8B, 0xC8, 0xE8 };

    struct Profile
    {
        char code[CODE_CHARS];
        uint8_t flags;
        bool resolved;
        bool fromLng2;
        bool busy;
        uint32_t tries;
        uint64_t nextTry;
    };

    constexpr size_t MAX_LANG_TEXT = 128;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetLanguage_t gGetLanguage = nullptr;
    CString_t gCString = nullptr;
    GetLangText_t gGetLangText = nullptr;
    std::atomic<bool> gInstalled{ false };
    SRWLOCK gLock = SRWLOCK_INIT;
    Profile gProfiles[MAX_PROFILES] = {};
    size_t gProfileCount = 0;
    std::atomic<uint64_t> gCached{ 0 };
    std::atomic<uint64_t> gCachedNextTry{ 0 };

    uint32_t PackCode(const char* s)
    {
        uint32_t v = 0;
        for (int i = 0; i < 4 && s[i]; ++i)
            v |= static_cast<uint32_t>(static_cast<uint8_t>(s[i])) << (8 * i);
        return v;
    }

    bool ReadCodeText(char* out)
    {
        if (!gGetLanguage || !gCString)
            return false;
        __try
        {
            void* shared = gGetLanguage();
            const char* text = shared ? gCString(shared) : nullptr;
            if (!text || !text[0])
                return false;
            size_t i = 0;
            for (; i + 1 < CODE_CHARS && text[i]; ++i)
                out[i] = text[i];
            out[i] = 0;
            return text[i] == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool LegacyIsArabic()
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

    uint8_t DefaultFlags(const char* code)
    {
        return std::strcmp(code, "ara") == 0 ? static_cast<uint8_t>(FLAG_RTL | FLAG_ARABIC_SCRIPT) : 0;
    }

    bool TryResolve(const char* code, uint8_t& flags)
    {
        char value[CODE_CHARS] = {};
        if (!RL_ReadLangValue(LanguageProfileKeys::LanguageCode, value, sizeof(value)) || std::strcmp(value, code) != 0)
            return false;
        char direction[8] = {};
        if (!RL_ReadLangValue(LanguageProfileKeys::TextDirection, direction, sizeof(direction)))
            return false;
        const bool rtl = std::strcmp(direction, "rtl") == 0;
        if (!rtl && std::strcmp(direction, "ltr") != 0)
            return false;
        char script[16] = {};
        const bool arabic = RL_ReadLangValue(LanguageProfileKeys::Script, script, sizeof(script)) &&
                            std::strcmp(script, "arabic") == 0;
        flags = static_cast<uint8_t>((rtl ? FLAG_RTL : 0) | (arabic ? FLAG_ARABIC_SCRIPT : 0));
        return true;
    }

    Profile& ProfileFor(const char* code)
    {
        for (size_t i = 0; i < gProfileCount; ++i)
        {
            if (std::strcmp(gProfiles[i].code, code) == 0)
                return gProfiles[i];
        }
        const size_t slot = gProfileCount < MAX_PROFILES ? gProfileCount++ : MAX_PROFILES - 1;
        Profile& p = gProfiles[slot];
        std::memset(&p, 0, sizeof(p));
        std::memcpy(p.code, code, CODE_CHARS);
        p.flags = DefaultFlags(code);
        return p;
    }

    uint64_t Pack(uint32_t code, uint8_t flags, bool resolved)
    {
        return code | (static_cast<uint64_t>(flags) << 32) | (static_cast<uint64_t>(resolved ? 1 : 0) << 40) |
               (1ull << 41);
    }

    uint8_t SlowFlags(const char* code)
    {
        const uint64_t now = GetTickCount64();
        bool attempt = false;
        AcquireSRWLockExclusive(&gLock);
        Profile& p = ProfileFor(code);
        if (!p.resolved && !p.busy && now >= p.nextTry)
        {
            p.busy = true;
            p.nextTry = now + RETRY_MS;
            attempt = true;
        }
        uint8_t flags = p.flags;
        bool resolved = p.resolved;
        uint64_t next = p.nextTry;
        ReleaseSRWLockExclusive(&gLock);

        if (attempt)
        {
            uint8_t found = 0;
            const bool ok = TryResolve(code, found);
            bool gaveUp = false;
            AcquireSRWLockExclusive(&gLock);
            Profile& q = ProfileFor(code);
            q.busy = false;
            if (ok)
            {
                q.flags = found;
                q.resolved = true;
                q.fromLng2 = true;
            }
            else if (++q.tries >= MAX_TRIES)
            {
                q.nextTry = now + SLOW_RETRY_MS;
                gaveUp = q.tries == MAX_TRIES;
            }
            flags = q.flags;
            resolved = q.resolved;
            next = q.nextTry;
            ReleaseSRWLockExclusive(&gLock);
            if (ok)
                Log("[LanguageProfile] '%s': %s, %s (from its lng2)\n", code, flags & FLAG_RTL ? "right-to-left" : "left-to-right",
                    flags & FLAG_ARABIC_SCRIPT ? "Arabic script" : "no Arabic shaping");
            else if (gaveUp)
                Log("[LanguageProfile] '%s': no rlang settings in its lng2 yet - %s by default, still checking every %llu ms\n",
                    code, flags & FLAG_RTL ? "right-to-left" : "left-to-right",
                    static_cast<unsigned long long>(SLOW_RETRY_MS));
        }
        gCachedNextTry.store(next, std::memory_order_relaxed);
        gCached.store(Pack(PackCode(code), flags, resolved), std::memory_order_release);
        return flags;
    }

    bool CurrentProfileFromLng2()
    {
        char code[CODE_CHARS] = {};
        if (!ReadCodeText(code))
            return false;
        bool fromLng2 = false;
        AcquireSRWLockShared(&gLock);
        for (size_t i = 0; i < gProfileCount; ++i)
        {
            if (std::strcmp(gProfiles[i].code, code) == 0)
            {
                fromLng2 = gProfiles[i].fromLng2;
                break;
            }
        }
        ReleaseSRWLockShared(&gLock);
        return fromLng2;
    }

    const char* EngineLangText(uint64_t langId)
    {
        if (!gGetLangText)
            return nullptr;
        __try
        {
            const char* v = gGetLangText(langId);
            if (!v || !v[0])
                return nullptr;
            for (size_t i = 0; i < MAX_LANG_TEXT; ++i)
            {
                if (!v[i])
                    return v;
            }
            return nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    uint8_t CurrentFlags()
    {
        char code[CODE_CHARS] = {};
        if (!ReadCodeText(code))
            return LegacyIsArabic() ? static_cast<uint8_t>(FLAG_RTL | FLAG_ARABIC_SCRIPT) : 0;
        const uint64_t cached = gCached.load(std::memory_order_acquire);
        if ((cached >> 41 & 1) && static_cast<uint32_t>(cached) == PackCode(code) &&
            ((cached >> 40 & 1) || GetTickCount64() < gCachedNextTry.load(std::memory_order_relaxed)))
            return static_cast<uint8_t>(cached >> 32);
        return SlowFlags(code);
    }

    bool ReadBytes(const void* at, void* out, size_t size)
    {
        __try
        {
            std::memcpy(out, at, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool InImage(HMODULE hGame, uintptr_t va)
    {
        const auto base = reinterpret_cast<uintptr_t>(hGame);
        IMAGE_DOS_HEADER dos{};
        if (!ReadBytes(hGame, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        IMAGE_NT_HEADERS64 nt{};
        if (!ReadBytes(reinterpret_cast<const uint8_t*>(hGame) + dos.e_lfanew, &nt, sizeof(nt)))
            return false;
        return va > base && va < base + nt.OptionalHeader.SizeOfImage;
    }

    uintptr_t CallTarget(uintptr_t call)
    {
        int32_t rel = 0;
        if (!ReadBytes(reinterpret_cast<const void*>(call + 1), &rel, sizeof(rel)))
            return 0;
        return call + 5 + static_cast<intptr_t>(rel);
    }
}

bool RL_ReadLangValue(uint64_t langId, char* out, size_t size)
{
    if (!gGetLangText || !out || size == 0)
        return false;
    __try
    {
        const char* v = gGetLangText(langId);
        if (!v)
            return false;
        size_t i = 0;
        for (; i + 1 < size && v[i]; ++i)
            out[i] = v[i];
        out[i] = 0;
        return i > 0 && v[i] == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

const char* RL_LangText(uint64_t langId)
{
    if (!gInstalled.load(std::memory_order_acquire))
        InstallLanguageProfile(GetModuleHandleW(nullptr));
    CurrentFlags();
    if (!CurrentProfileFromLng2())
        return nullptr;
    return EngineLangText(langId);
}

bool __cdecl RL_IsRightToLeft()
{
    if (!gInstalled.load(std::memory_order_acquire))
        InstallLanguageProfile(GetModuleHandleW(nullptr));
    return (CurrentFlags() & FLAG_RTL) != 0;
}

bool __cdecl RL_UsesArabicScript()
{
    if (!gInstalled.load(std::memory_order_acquire))
        InstallLanguageProfile(GetModuleHandleW(nullptr));
    return (CurrentFlags() & FLAG_ARABIC_SCRIPT) != 0;
}

bool InstallLanguageProfile(HMODULE hGame)
{
    if (gInstalled.load(std::memory_order_acquire))
        return true;
    AcquireSRWLockExclusive(&gLock);
    if (gInstalled.load(std::memory_order_relaxed))
    {
        ReleaseSRWLockExclusive(&gLock);
        return true;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(hGame);
    if (hGame && gAddr.IsArabLanguage)
    {
        const uintptr_t isArab = base + (gAddr.IsArabLanguage - IDA_IMAGE_BASE);
        gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(isArab);
        uint8_t head[sizeof(kIsArabHead)] = {};
        uint8_t mov[sizeof(kMovRcxRax)] = {};
        if (ReadBytes(reinterpret_cast<const void*>(isArab), head, sizeof(head)) &&
            ReadBytes(reinterpret_cast<const void*>(isArab + 9), mov, sizeof(mov)) &&
            std::memcmp(head, kIsArabHead, sizeof(head)) == 0 && std::memcmp(mov, kMovRcxRax, sizeof(mov)) == 0)
        {
            const uintptr_t getLanguage = CallTarget(isArab + 4);
            const uintptr_t cstring = CallTarget(isArab + 12);
            if (InImage(hGame, getLanguage) && InImage(hGame, cstring))
            {
                gGetLanguage = reinterpret_cast<GetLanguage_t>(getLanguage);
                gCString = reinterpret_cast<CString_t>(cstring);
            }
        }
    }
    if (hGame && gAddr.GetLangText)
        gGetLangText = reinterpret_cast<GetLangText_t>(base + (gAddr.GetLangText - IDA_IMAGE_BASE));
    gInstalled.store(true, std::memory_order_release);
    ReleaseSRWLockExclusive(&gLock);
    if (gGetLanguage)
        Log("[LanguageProfile] language code read through AssetConfiguration::GetLanguage; direction and script come from "
            "each language's lng2 (rlang_*), Arabic is right-to-left by default.\n");
    else
        Log("[LanguageProfile] could not find AssetConfiguration::GetLanguage - only Arabic is treated as right-to-left.\n");
    return gGetLanguage != nullptr;
}
