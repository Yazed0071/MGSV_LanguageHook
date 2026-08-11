#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();

    using EquipDetailsCallbackImpl_CreateCarryingDifferenceText_t =
        void(__fastcall*)(void* thisPtr, char* outText, uint16_t currentValue, uint16_t baseValue);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static EquipDetailsCallbackImpl_CreateCarryingDifferenceText_t gOrigCreateCarryingDifferenceText = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. Takes no parameters. */
static bool IsArabicSafe()
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

/* Reads a bounded c-string safely. src = source buffer, maxLen = max bytes, out = destination string. */
static bool SafeReadCString(const char* src, size_t maxLen, std::string& out)
{
    __try
    {
        if (!src || maxLen == 0)
        {
            out.clear();
            return false;
        }

        size_t len = 0;
        while (len < maxLen && src[len] != '\0')
            ++len;

        out.assign(src, len);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out.clear();
        return false;
    }
}

/* Writes a bounded c-string safely. dst = target buffer, dstSize = buffer size, src = source text. */
static bool SafeWriteCString(char* dst, size_t dstSize, const char* src)
{
    __try
    {
        if (!dst || dstSize == 0)
            return false;

        if (!src)
        {
            dst[0] = '\0';
            return true;
        }

        _snprintf_s(dst, dstSize, _TRUNCATE, "%s", src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

/* Rewrites "20(<...>)" into "(<...>) 20". src = original built text. */
static std::string RewriteCarryingDifferenceTextArabic(const std::string& src)
{
    if (src.empty())
        return src;

    const size_t openPos = src.find('(');
    if (openPos == std::string::npos)
        return src;

    if (src.back() != ')')
        return src;

    const std::string numberPart = src.substr(0, openPos);
    const std::string diffPart = src.substr(openPos);

    if (numberPart.empty() || diffPart.size() < 2)
        return src;

    for (char c : numberPart)
    {
        if (c < '0' || c > '9')
            return src;
    }

    return diffPart + numberPart;
}

/* Applies the Arabic reorder to the already-built output buffer. outText = destination buffer from the game. */
static void ApplyArabicCarryingDifferenceFix(char* outText)
{
    if (!outText)
        return;

    std::string before;
    if (!SafeReadCString(outText, 0x80, before))
        return;

    const std::string after = RewriteCarryingDifferenceTextArabic(before);
    if (after == before)
        return;

    if (after.size() > before.size())
        return;

    if (!SafeWriteCString(outText, before.size() + 1, after.c_str()))
        return;

}

/* Hook for CreateCarryingDifferenceText(this, outText, currentValue, baseValue). */
static void __fastcall hkEquipDetailsCallbackImpl_CreateCarryingDifferenceText(
    void* thisPtr,
    char* outText,
    uint16_t currentValue,
    uint16_t baseValue)
{
    if (gOrigCreateCarryingDifferenceText)
        gOrigCreateCarryingDifferenceText(thisPtr, outText, currentValue, baseValue);

    if (!IsArabicSafe())
        return;

    ApplyArabicCarryingDifferenceFix(outText);
}

/* Installs the carrying-difference Arabic hook. hGame = game module handle. */
bool InstallEquipDetailsCallbackImplCreateCarryingDifferenceTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.EquipDetailsCallbackImpl_CreateCarryingDifferenceText)
    {
        Log("[EquipDetailsCallbackImpl::CreateCarryingDifferenceText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.EquipDetailsCallbackImpl_CreateCarryingDifferenceText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkEquipDetailsCallbackImpl_CreateCarryingDifferenceText,
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

/* Removes the carrying-difference Arabic hook. */
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