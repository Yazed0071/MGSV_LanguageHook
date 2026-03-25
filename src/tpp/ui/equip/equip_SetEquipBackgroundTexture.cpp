#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using SetEquipBackgroundTexture_t = uint64_t(__fastcall*)(int equipId, void* isSortieWeapon);
    using ModelNodeMesh_SetTextureName_t = void(__fastcall*)(void* modelNodeMesh, uint64_t textureName, uint32_t maskTextureStrCode32, int unk);

    static IsArabLanguage_t gIsArabLanguage = nullptr;
    static SetEquipBackgroundTexture_t gOrigSetEquipBackgroundTexture = nullptr;
    static ModelNodeMesh_SetTextureName_t gSetTextureName = nullptr;
    static void* gTarget = nullptr;

    static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

    static constexpr uint32_t kMaskTextureStrCode32 = 0x3BBF9889;
    static constexpr int kTextureSlot = 2;

    static constexpr int kEqpHandStunArm = 0x203;
    static constexpr int kEqpHandJehuty = 0x204;
    static constexpr int kEqpHandStunRocket = 0x205;
    static constexpr int kEqpHandKillRocket = 0x206;

    static constexpr uint64_t kDefaultDdWeaponBg = 0x15695ED8A56AE919ull;

    static constexpr uint64_t kStunArmBgOriginal = 0x15682B4E5F2626D2ull;
    static constexpr uint64_t kJehutyBgOriginal = 0x156B6BE3346D38ACull;
    static constexpr uint64_t kStunRocketBgOriginal = 0x15684206A365CA64ull;
    static constexpr uint64_t kKillRocketBgOriginal = 0x1568B462F43ED09Full;

    static constexpr uint64_t kStunArmBgArabic = 0x156B85B6A9CF5D15ull;
    static constexpr uint64_t kStunRocketBgArabic = 0x15682DC6D4FE3A2Eull;
    static constexpr uint64_t kKillRocketBgArabic = 0x15681034ABEA6A93ull;
}

/* Converts an IDA absolute VA to a runtime VA. Parameters: hGame = module base, absVa = absolute address. */
static __forceinline uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

/* Checks Arabic state safely. Parameters: none. */
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

/* Recreates the original validity gate. Parameters: equipId = equipment id, isSortieWeapon = target mesh node. */
static bool ShouldShowTexture(int equipId, void* isSortieWeapon)
{
    if (!isSortieWeapon)
        return false;

    if (equipId == 0)
        return false;

    if (static_cast<uint32_t>(equipId - 1) <= 0x47)
        return false;

    if (static_cast<uint32_t>(equipId - 0x7D) <= 3)
        return false;

    return true;
}

/* Chooses the background texture. Parameters: equipId = equipment id, useArabic = Arabic enabled or not. */
static uint64_t SelectEquipBackgroundTexture(int equipId, bool useArabic)
{
    uint64_t texture = kDefaultDdWeaponBg;

    if (equipId == kEqpHandStunArm)
    {
        texture = useArabic ? kStunArmBgArabic : kStunArmBgOriginal;
    }
    else if (equipId == kEqpHandJehuty)
    {
        texture = kJehutyBgOriginal;
    }
    else if (equipId == kEqpHandStunRocket)
    {
        texture = useArabic ? kStunRocketBgArabic : kStunRocketBgOriginal;
    }
    else if (equipId == kEqpHandKillRocket)
    {
        texture = useArabic ? kKillRocketBgArabic : kKillRocketBgOriginal;
    }

    return texture;
}

/* Hook for ui::equip::SetEquipBackgroundTexture(equipId, isSortieWeapon). */
static uint64_t __fastcall hkSetEquipBackgroundTexture(int equipId, void* isSortieWeapon)
{
    if (!gOrigSetEquipBackgroundTexture)
        return 0;

    const bool isArabic = IsArabicSafe();
    if (!isArabic)
        return gOrigSetEquipBackgroundTexture(equipId, isSortieWeapon);

    if (!ShouldShowTexture(equipId, isSortieWeapon))
        return 0;

    if (!gSetTextureName)
        return gOrigSetEquipBackgroundTexture(equipId, isSortieWeapon);

    const uint64_t texture = SelectEquipBackgroundTexture(equipId, true);

    gSetTextureName(
        isSortieWeapon,
        texture,
        kMaskTextureStrCode32,
        kTextureSlot);

    return 1;
}

/* Installs the equip background texture hook. Parameters: hGame = game module handle. */
bool InstallSetEquipBackgroundTextureArabicHook(HMODULE hGame)
{
    if (!hGame)
        return false;

    if (!gAddr.IsArabLanguage || !gAddr.SetEquipBackgroundTexture || !gAddr.ModelNodeMesh_SetTextureName)
    {
        Log("[SetEquipBackgroundTexture] Missing address.\n");
        return false;
    }

    gIsArabLanguage =
        reinterpret_cast<IsArabLanguage_t>(ToRuntimeVA(hGame, gAddr.IsArabLanguage));

    gTarget =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetEquipBackgroundTexture));

    gSetTextureName =
        reinterpret_cast<ModelNodeMesh_SetTextureName_t>(ToRuntimeVA(hGame, gAddr.ModelNodeMesh_SetTextureName));

    if (!gTarget || !gSetTextureName)
    {
        Log("[SetEquipBackgroundTexture] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTarget,
            reinterpret_cast<void*>(&hkSetEquipBackgroundTexture),
            reinterpret_cast<void**>(&gOrigSetEquipBackgroundTexture));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[SetEquipBackgroundTexture] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTarget);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[SetEquipBackgroundTexture] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    Log("[SetEquipBackgroundTexture] Arabic texture swap hook enabled.\n");
    return true;
}

/* Removes the equip background texture hook. Parameters: none. */
void RemoveSetEquipBackgroundTextureArabicHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }

    gOrigSetEquipBackgroundTexture = nullptr;
    gSetTextureName = nullptr;
    gIsArabLanguage = nullptr;

    Log("[SetEquipBackgroundTexture] Arabic texture swap hook removed.\n");
}