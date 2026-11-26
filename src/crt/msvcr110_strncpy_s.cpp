#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using StrncpyS_t = int(__cdecl*)(char* dst, size_t dstSize, const char* src, size_t count);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t TRUNCATE = static_cast<size_t>(-1);
    constexpr int STRUNCATE_RESULT = 80;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    StrncpyS_t oStrncpyS = nullptr;
    void* gTarget = nullptr;
    std::atomic<int> gLogBudget{ 8 };

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

    bool HasArabic(const char* s, size_t n)
    {
        const auto* p = reinterpret_cast<const unsigned char*>(s);
        for (size_t i = 0; i < n; ++i)
        {
            if ((p[i] >= 0xD8 && p[i] <= 0xDB) || (p[i] == 0xEF && i + 1 < n && p[i + 1] >= 0xAD && p[i + 1] <= 0xBB))
                return true;
        }
        return false;
    }

    bool IsContinuation(unsigned char c)
    {
        return (c & 0xC0) == 0x80;
    }

    int CopyFitting(char* dst, size_t dstSize, const char* src, size_t length)
    {
        const size_t room = dstSize - 1;
        size_t from = 0;
        size_t take = room;
        if (HasArabic(src, length))
        {
            from = length - room;
            while (from < length && IsContinuation(static_cast<unsigned char>(src[from])))
                ++from;
            take = length - from;
        }
        else
        {
            while (take > 0 && IsContinuation(static_cast<unsigned char>(src[take])))
                --take;
        }
        std::memcpy(dst, src + from, take);
        dst[take] = '\0';
        return STRUNCATE_RESULT;
    }

    int __cdecl hkStrncpyS(char* dst, size_t dstSize, const char* src, size_t count)
    {
        if (dst && src && dstSize > 0 && count != TRUNCATE && count >= dstSize)
        {
            size_t length = 0;
            __try
            {
                length = strnlen(src, count);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return oStrncpyS(dst, dstSize, src, count);
            }
            if (length >= dstSize && IsArabicSafe())
            {
                if (gLogBudget.fetch_sub(1) > 0)
                    Log("[msvcr110::strncpy_s] Arabic text of %zu bytes cut to fit a %zu-byte buffer (caller %p).\n",
                        length, dstSize, _ReturnAddress());
                return CopyFitting(dst, dstSize, src, length);
            }
        }
        return oStrncpyS(dst, dstSize, src, count);
    }
}

bool InstallStrncpySArabicGuardHook(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage)
    {
        Log("[msvcr110::strncpy_s] address missing - long Arabic text can still overflow fixed buffers.\n");
        return true;
    }
    HMODULE crt = GetModuleHandleW(L"msvcr110.dll");
    void* target = crt ? reinterpret_cast<void*>(GetProcAddress(crt, "strncpy_s")) : nullptr;
    if (!target)
    {
        Log("[msvcr110::strncpy_s] msvcr110.dll strncpy_s not found.\n");
        return false;
    }
    gIsArabLanguage = &RL_IsRightToLeft;
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkStrncpyS), reinterpret_cast<void**>(&oStrncpyS)) != MH_OK)
    {
        Log("[msvcr110::strncpy_s] MH_CreateHook failed.\n");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        Log("[msvcr110::strncpy_s] MH_EnableHook failed.\n");
        return false;
    }
    gTarget = target;
    Log("[msvcr110::strncpy_s] Arabic overflow guard installed at %p.\n", target);
    return true;
}

void RemoveStrncpySArabicGuardHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    oStrncpyS = nullptr;
    gIsArabLanguage = nullptr;
}
