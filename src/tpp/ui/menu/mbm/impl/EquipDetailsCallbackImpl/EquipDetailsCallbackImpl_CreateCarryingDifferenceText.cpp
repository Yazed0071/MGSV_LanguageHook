#include "pch.h"
#include <Windows.h>
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
    using CreateCarryingDifferenceText_t =
        void(__fastcall*)(void* thisPtr, char* outText, uint16_t currentValue, uint16_t baseValue);

    constexpr size_t OUT_TEXT_SIZE = 0x80;

    IsArabLanguage_t gIsArabLanguage = nullptr;
    CreateCarryingDifferenceText_t gOrigCreateCarryingDifferenceText = nullptr;
    void* gTarget = nullptr;

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

    bool DifferenceFirst(const std::string& in, std::string& out)
    {
        const size_t open = in.find('(');
        if (open == std::string::npos || open == 0 || in.back() != ')' || in.size() - open < 2)
            return false;
        for (size_t i = 0; i < open; ++i)
        {
            if (in[i] < '0' || in[i] > '9')
                return false;
        }
        out = in.substr(open) + " " + in.substr(0, open);
        return true;
    }

    void ApplyDifferenceFirst(char* outText)
    {
        char local[OUT_TEXT_SIZE] = {};
        const size_t length = ReadOutText(outText, local, sizeof(local));
        if (length == 0)
            return;
        std::string after;
        if (!DifferenceFirst(std::string(local, length), after) || after.size() + 1 > OUT_TEXT_SIZE)
            return;
        WriteOutText(outText, after.c_str(), after.size());
    }

    void __fastcall hkEquipDetailsCallbackImpl_CreateCarryingDifferenceText(void* thisPtr, char* outText,
                                                                            uint16_t currentValue, uint16_t baseValue)
    {
        if (gOrigCreateCarryingDifferenceText)
            gOrigCreateCarryingDifferenceText(thisPtr, outText, currentValue, baseValue);
        if (outText && IsArabicSafe())
            ApplyDifferenceFirst(outText);
    }
}

bool InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.EquipDetailsCallbackImpl_CreateCarryingDifferenceText)
    {
        Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gTarget = reinterpret_cast<void*>(gAddr.EquipDetailsCallbackImpl_CreateCarryingDifferenceText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(gTarget, &hkEquipDetailsCallbackImpl_CreateCarryingDifferenceText,
                      reinterpret_cast<LPVOID*>(&gOrigCreateCarryingDifferenceText)) != MH_OK)
    {
        Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] MH_CreateHook failed.\n");
        return false;
    }

    if (MH_EnableHook(gTarget) != MH_OK)
    {
        Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] MH_EnableHook failed.\n");
        return false;
    }

    Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] Arabic hook enabled.\n");
    return true;
}

void RemoveEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigCreateCarryingDifferenceText = nullptr;
    gIsArabLanguage = nullptr;

    Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] Arabic hook removed.\n");
}
