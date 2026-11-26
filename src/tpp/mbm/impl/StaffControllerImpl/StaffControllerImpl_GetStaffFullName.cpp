#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

const char* FindFullArabicStaffName(const char* text);
const char* PercentFirstDirectText(const char* text);

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetStaffFullNameByIndex_t = void(__fastcall*)(void* self, char** buf, uint32_t size, uint64_t index);
    using GetStaffFullNameBySeed_t = void(__fastcall*)(void* self, char** buf, uint32_t size, uint64_t seedLow,
                                                       uint64_t seedHigh);
    using SettingTextUnit_t = void(__fastcall*)(void* unit, const char* text, void* fontGroup, uint64_t fontId,
                                                uint64_t a5, uint64_t a6, uint64_t a7);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint32_t FULL_NAME_CAPACITY = 512;
    constexpr size_t MAX_REMEMBERED_NAMES = 8192;

    const uint8_t kGetStaffFullNamePrologue[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 0x54, 0x41, 0x56,
    };
    const uint8_t kSettingTextUnitPrologue[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x20, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56,
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetStaffFullNameByIndex_t oByIndex = nullptr;
    GetStaffFullNameBySeed_t oBySeed = nullptr;
    SettingTextUnit_t oSettingTextUnit = nullptr;
    void* gTargetByIndex = nullptr;
    void* gTargetBySeed = nullptr;
    void* gTargetSettingTextUnit = nullptr;

    std::mutex gNamesMtx;
    std::unordered_set<std::string> gFullNames;
    std::unordered_map<std::string, const char*> gClippedToFull;
    std::atomic<bool> gAnyClipped{ false };
    std::atomic<size_t> gShortestClip{ SIZE_MAX };
    std::atomic<size_t> gLongestClip{ 0 };
    std::atomic<int> gClipLogBudget{ 4 };
    std::atomic<bool> gLoggedSwap{ false };

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

    bool IsContinuationByte(char c)
    {
        return (static_cast<uint8_t>(c) & 0xC0) == 0x80;
    }

    bool IsArabicMarkAt(const std::string& s, size_t i)
    {
        if (i + 1 >= s.size() || static_cast<uint8_t>(s[i]) != 0xD9)
            return false;
        const uint8_t next = static_cast<uint8_t>(s[i + 1]);
        return (next >= 0x8B && next <= 0x9F) || next == 0xB0;
    }

    std::string ClipKeepingLogicalStart(const std::string& visual, size_t maxBytes)
    {
        size_t start = 0;
        while (start < visual.size() && visual.size() - start > maxBytes)
        {
            ++start;
            while (start < visual.size() && IsContinuationByte(visual[start]))
                ++start;
        }
        while (start < visual.size() && (visual[start] == ' ' || IsArabicMarkAt(visual, start)))
            start += visual[start] == ' ' ? 1 : 2;
        return visual.substr(start);
    }

    bool HasNonAscii(const char* s)
    {
        for (; *s; ++s)
        {
            if (static_cast<uint8_t>(*s) >= 0x80)
                return true;
        }
        return false;
    }

    bool ReadName(const char* src, std::string& out)
    {
        __try
        {
            size_t n = 0;
            while (n < FULL_NAME_CAPACITY && src[n])
                ++n;
            out.assign(src, n);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool WriteName(char* dst, const std::string& name)
    {
        __try
        {
            std::memcpy(dst, name.c_str(), name.size() + 1);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void RememberClipped(const std::string& clipped, const std::string& full)
    {
        std::lock_guard<std::mutex> lk(gNamesMtx);
        if (gClippedToFull.count(clipped) || gClippedToFull.size() >= MAX_REMEMBERED_NAMES)
            return;
        const char* stable = gFullNames.insert(full).first->c_str();
        gClippedToFull.emplace(clipped, stable);

        size_t shortest = gShortestClip.load();
        while (clipped.size() < shortest && !gShortestClip.compare_exchange_weak(shortest, clipped.size()))
        {
        }
        size_t longest = gLongestClip.load();
        while (clipped.size() > longest && !gLongestClip.compare_exchange_weak(longest, clipped.size()))
        {
        }
        gAnyClipped.store(true);
    }

    void DeliverName(char** buf, uint32_t size, const char* built)
    {
        if (!buf || !*buf || size == 0)
            return;

        std::string full;
        if (!ReadName(built, full))
            return;

        if (full.size() < size || !HasNonAscii(full.c_str()))
        {
            if (full.size() >= size)
                full.resize(size - 1);
            WriteName(*buf, full);
            return;
        }

        const std::string clipped = ClipKeepingLogicalStart(full, size - 1);
        if (!WriteName(*buf, clipped))
            return;
        RememberClipped(clipped, full);

        if (gClipLogBudget.load() > 0)
        {
            gClipLogBudget.fetch_sub(1);
            Log("[tpp::mbm::impl::StaffControllerImpl::GetStaffFullName] Arabic name needs %zu bytes, buffer holds %u - "
                "full name kept for display\n",
                full.size(), size - 1);
        }
    }

    void __fastcall hkByIndex(void* self, char** buf, uint32_t size, uint64_t index)
    {
        if (!buf || !*buf || size == 0 || !IsArabicSafe())
        {
            oByIndex(self, buf, size, index);
            return;
        }
        char built[FULL_NAME_CAPACITY] = {};
        char* builtPtr = built;
        oByIndex(self, &builtPtr, FULL_NAME_CAPACITY, index);
        DeliverName(buf, size, built);
    }

    void __fastcall hkBySeed(void* self, char** buf, uint32_t size, uint64_t seedLow, uint64_t seedHigh)
    {
        if (!buf || !*buf || size == 0 || !IsArabicSafe())
        {
            oBySeed(self, buf, size, seedLow, seedHigh);
            return;
        }
        char built[FULL_NAME_CAPACITY] = {};
        char* builtPtr = built;
        oBySeed(self, &builtPtr, FULL_NAME_CAPACITY, seedLow, seedHigh);
        DeliverName(buf, size, built);
    }

    bool LengthInClipRange(const char* text, size_t& len)
    {
        __try
        {
            const size_t longest = gLongestClip.load(std::memory_order_relaxed);
            len = 0;
            while (len <= longest && text[len])
                ++len;
            return len <= longest && len >= gShortestClip.load(std::memory_order_relaxed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void __fastcall hkSettingTextUnit(void* unit, const char* text, void* fontGroup, uint64_t fontId, uint64_t a5,
                                      uint64_t a6, uint64_t a7)
    {
        if (const char* full = FindFullArabicStaffName(text))
        {
            text = full;
            if (!gLoggedSwap.exchange(true))
                Log("[fox::ui::TextAnalysis::SettingTextUnit] showing the full Arabic staff name instead of the "
                    "clipped one\n");
        }
        else if (const char* percentFirst = PercentFirstDirectText(text))
        {
            text = percentFirst;
        }
        oSettingTextUnit(unit, text, fontGroup, fontId, a5, a6, a7);
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    bool HookOne(void* target, const uint8_t* prologue, size_t prologueSize, void* detour, void** original,
                 const char* name)
    {
        if (!CodeMatches(target, prologue, prologueSize))
        {
            Log("[StaffNames] %s code is not what this build should have - not hooked.\n", name);
            return false;
        }
        if (MH_CreateHook(target, detour, original) != MH_OK || MH_EnableHook(target) != MH_OK)
        {
            Log("[StaffNames] %s hook failed.\n", name);
            return false;
        }
        return true;
    }
}

const char* FindFullArabicStaffName(const char* text)
{
    if (!text || !gAnyClipped.load(std::memory_order_relaxed))
        return nullptr;

    size_t len = 0;
    if (!LengthInClipRange(text, len))
        return nullptr;

    std::string key(text, len);
    std::lock_guard<std::mutex> lk(gNamesMtx);
    const auto it = gClippedToFull.find(key);
    return it == gClippedToFull.end() ? nullptr : it->second;
}

bool InstallStaffFullNameArabicHooks(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.StaffControllerImpl_GetStaffFullNameByIndex ||
        !gAddr.StaffControllerImpl_GetStaffFullNameBySeed || !gAddr.TextAnalysis_SettingTextUnit)
    {
        Log("[StaffNames] address missing - Arabic staff names stay clipped to the game's buffers.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;

    void* settingTarget = Resolve(hGame, gAddr.TextAnalysis_SettingTextUnit);
    if (!HookOne(settingTarget, kSettingTextUnitPrologue, sizeof(kSettingTextUnitPrologue),
                 reinterpret_cast<void*>(&hkSettingTextUnit), reinterpret_cast<void**>(&oSettingTextUnit),
                 "TextAnalysis::SettingTextUnit"))
        return false;
    gTargetSettingTextUnit = settingTarget;

    void* byIndex = Resolve(hGame, gAddr.StaffControllerImpl_GetStaffFullNameByIndex);
    if (HookOne(byIndex, kGetStaffFullNamePrologue, sizeof(kGetStaffFullNamePrologue),
                reinterpret_cast<void*>(&hkByIndex), reinterpret_cast<void**>(&oByIndex),
                "StaffControllerImpl::GetStaffFullName(index)"))
        gTargetByIndex = byIndex;

    void* bySeed = Resolve(hGame, gAddr.StaffControllerImpl_GetStaffFullNameBySeed);
    if (HookOne(bySeed, kGetStaffFullNamePrologue, sizeof(kGetStaffFullNamePrologue),
                reinterpret_cast<void*>(&hkBySeed), reinterpret_cast<void**>(&oBySeed),
                "StaffControllerImpl::GetStaffFullName(seed)"))
        gTargetBySeed = bySeed;

    Log("[StaffNames] Arabic staff names longer than the game's name buffers are shown in full.\n");
    return true;
}

void RemoveStaffFullNameArabicHooks()
{
    for (void** target : { &gTargetByIndex, &gTargetBySeed, &gTargetSettingTextUnit })
    {
        if (*target)
        {
            MH_DisableHook(*target);
            MH_RemoveHook(*target);
            *target = nullptr;
        }
    }
    oByIndex = nullptr;
    oBySeed = nullptr;
    oSettingTextUnit = nullptr;
    gAnyClipped.store(false);
    std::lock_guard<std::mutex> lk(gNamesMtx);
    gClippedToFull.clear();
}
