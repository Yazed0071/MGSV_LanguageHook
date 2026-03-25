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

    using EquipDetailsCallbackImpl_CreateBulletDifferenceText_t =
        void(__fastcall*)(void* thisPtr, char* outText, uint16_t valueA, uint16_t valueB, uint16_t baseA, uint16_t baseB);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static EquipDetailsCallbackImpl_CreateBulletDifferenceText_t gOrigCreateBulletDifferenceText = nullptr;
    static void* gTarget = nullptr;
}

/* Checks Arabic state safely. */
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

/* Reads a bounded c-string safely. */
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

/* Writes a bounded c-string safely. */
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

/* Rewrites "30/120(<...>/<...>)" into "(<...>/<...>) 30/120". */
static std::string RewriteBulletDifferenceTextArabic(const std::string& src)
{
    if (src.empty())
        return src;

    const size_t openPos = src.find('(');
    if (openPos == std::string::npos)
        return src;

    if (src.back() != ')')
        return src;

    const std::string valuePart = src.substr(0, openPos);
    const std::string diffPart = src.substr(openPos);

    if (valuePart.empty() || diffPart.size() < 2)
        return src;

    bool hasSlash = false;
    for (char c : valuePart)
    {
        if (c == '/')
        {
            hasSlash = true;
            continue;
        }

        if (c < '0' || c > '9')
            return src;
    }

    if (!hasSlash)
        return src;

    return diffPart + " " + valuePart;
}

/* Applies the Arabic reorder to the already-built output buffer. */
static void ApplyArabicBulletDifferenceFix(char* outText)
{
    if (!outText)
        return;

    std::string before;
    if (!SafeReadCString(outText, 0x80, before))
        return;

    const std::string after = RewriteBulletDifferenceTextArabic(before);
    if (after == before)
        return;

    if (!SafeWriteCString(outText, 0x80, after.c_str()))
        return;

    Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] before: %s\n", before.c_str());
    Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] after : %s\n", after.c_str());
}

/* Hook for CreateBulletDifferenceText(this, outText, valueA, valueB, baseA, baseB). */
static void __fastcall hkEquipDetailsCallbackImpl_CreateBulletDifferenceText(
    void* thisPtr,
    char* outText,
    uint16_t valueA,
    uint16_t valueB,
    uint16_t baseA,
    uint16_t baseB)
{
    if (gOrigCreateBulletDifferenceText)
        gOrigCreateBulletDifferenceText(thisPtr, outText, valueA, valueB, baseA, baseB);

    if (!IsArabicSafe())
        return;

    ApplyArabicBulletDifferenceFix(outText);
}

/* Installs the bullet-difference Arabic hook. */
bool InstallEquipDetailsCallbackImplCreateBulletDifferenceTextArabicHook(HMODULE hGame)
{
    UNREFERENCED_PARAMETER(hGame);

    if (!gAddr.IsArabLanguage || !gAddr.EquipDetailsCallbackImpl_CreateBulletDifferenceText)
    {
        Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] Missing address.\n");
        return false;
    }

    gIsArabLanguage = reinterpret_cast<IsArabLanguage_t>(gAddr.IsArabLanguage);
    gTarget = reinterpret_cast<void*>(gAddr.EquipDetailsCallbackImpl_CreateBulletDifferenceText);
    if (!gTarget)
        return false;

    if (MH_CreateHook(
        gTarget,
        &hkEquipDetailsCallbackImpl_CreateBulletDifferenceText,
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

    Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] Arabic hook enabled.\n");
    return true;
}

/* Removes the bullet-difference Arabic hook. */
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

    Log("[EquipDetailsCallbackImpl::CreateBulletDifferenceText] Arabic hook removed.\n");
}