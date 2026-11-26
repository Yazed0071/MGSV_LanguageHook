#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using CreateBulletDifferenceText_t =
        void(__fastcall*)(void* thisPtr, char* outText, uint16_t valueA, uint16_t valueB, uint16_t baseA, uint16_t baseB);

    constexpr size_t OUT_TEXT_SIZE = 0x80;
    constexpr int LOG_BUDGET = 3;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    CreateBulletDifferenceText_t gOrigCreateBulletDifferenceText = nullptr;
    void* gTarget = nullptr;
    std::atomic<int> gLogBudget{ LOG_BUDGET };

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

    bool SplitNumberPair(const std::string& s, std::string& first, std::string& second)
    {
        const size_t slash = s.find('/');
        if (slash == std::string::npos || slash == 0 || slash + 1 >= s.size() || s.find('/', slash + 1) != std::string::npos)
            return false;
        for (size_t i = 0; i < s.size(); ++i)
        {
            if (i != slash && (s[i] < '0' || s[i] > '9'))
                return false;
        }
        first = s.substr(0, slash);
        second = s.substr(slash + 1);
        return true;
    }

    size_t SlashOutsideTags(const std::string& s)
    {
        size_t found = std::string::npos;
        int depth = 0;
        for (size_t i = 0; i < s.size(); ++i)
        {
            if (s[i] == '<')
                ++depth;
            else if (s[i] == '>' && depth > 0)
                --depth;
            else if (s[i] == '/' && depth == 0)
            {
                if (found != std::string::npos)
                    return std::string::npos;
                found = i;
            }
        }
        return found;
    }

    bool LimitFirstBulletText(const std::string& in, std::string& out)
    {
        std::string magazine, reserve;
        const size_t open = in.find('(');
        if (open == std::string::npos)
        {
            if (!SplitNumberPair(in, magazine, reserve))
                return false;
            out = reserve + "/" + magazine;
            return true;
        }
        if (in.back() != ')' || !SplitNumberPair(in.substr(0, open), magazine, reserve))
            return false;
        const std::string inner = in.substr(open + 1, in.size() - open - 2);
        const size_t slash = SlashOutsideTags(inner);
        if (slash == std::string::npos)
            return false;
        out = reserve + "/" + magazine + "(" + inner.substr(slash + 1) + "/" + inner.substr(0, slash) + ")";
        return true;
    }

    size_t ReadOutText(const char* src, char* dst, size_t size)
    {
        __try
        {
            const size_t length = strnlen(src, size);
            if (length == 0 || length >= size)
                return 0;
            std::memcpy(dst, src, length + 1);
            return length;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    bool WriteOutText(char* dst, const char* src, size_t length)
    {
        __try
        {
            std::memcpy(dst, src, length + 1);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void ApplyLimitFirst(char* outText)
    {
        char local[OUT_TEXT_SIZE] = {};
        const size_t length = ReadOutText(outText, local, sizeof(local));
        if (length == 0)
            return;
        const std::string before(local, length);
        std::string after;
        if (!LimitFirstBulletText(before, after) || after.size() != length || after == before)
            return;
        if (!WriteOutText(outText, after.c_str(), length))
            return;
        if (gLogBudget.load() > 0 && gLogBudget.fetch_sub(1) > 0)
            Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] [%s] shown as [%s].\n", before.c_str(), after.c_str());
    }

    void __fastcall hkEquipDetailsCallbackImpl_CreateBulletDifferenceText(void* thisPtr, char* outText, uint16_t valueA,
                                                                          uint16_t valueB, uint16_t baseA, uint16_t baseB)
    {
        if (gOrigCreateBulletDifferenceText)
            gOrigCreateBulletDifferenceText(thisPtr, outText, valueA, valueB, baseA, baseB);
        if (outText && IsArabicSafe())
            ApplyLimitFirst(outText);
    }
}

bool InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.EquipDetailsCallbackImpl_CreateBulletDifferenceText)
    {
        Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gTarget = reinterpret_cast<void*>(gAddr.EquipDetailsCallbackImpl_CreateBulletDifferenceText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkEquipDetailsCallbackImpl_CreateBulletDifferenceText,
                      reinterpret_cast<LPVOID*>(&gOrigCreateBulletDifferenceText)) != MH_OK)
    {
        Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] limit-first hook enabled.\n");
    return true;
}

void RemoveEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigCreateBulletDifferenceText = nullptr;
    gIsArabLanguage = nullptr;
    gLogBudget = LOG_BUDGET;
}
