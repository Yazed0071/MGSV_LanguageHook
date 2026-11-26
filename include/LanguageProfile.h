#pragma once
#include <Windows.h>
#include <cstdint>

namespace LanguageProfileKeys
{
    constexpr uint64_t LanguageCode = 0xCA012777D5C6ull;
    constexpr uint64_t TextDirection = 0x7C1BF5BFDF1Aull;
    constexpr uint64_t Script = 0xEC2456C176A9ull;
    constexpr uint64_t UnitMeter = 0x3CDA3BDAD76Aull;
    constexpr uint64_t TimeHourMinute = 0xBCF71310F8C1ull;
    constexpr uint64_t TimeMinuteHour = 0xB0095D6094BAull;
    constexpr uint64_t TimeDayHour = 0x9D46F44D2CDEull;
    constexpr uint64_t TimeHourDay = 0x03D3FE420D3Aull;
    constexpr uint64_t LabelFileNumber = 0x7CF6F97022A2ull;
    constexpr uint64_t LabelCategory = 0x0ED6FFB13A23ull;
    constexpr uint64_t LabelStatus = 0x72486FE142D9ull;
}

bool InstallLanguageProfile(HMODULE hGame);
bool __cdecl RL_IsRightToLeft();
bool __cdecl RL_UsesArabicScript();
bool RL_ReadLangValue(uint64_t langId, char* out, size_t size);
const char* RL_LangText(uint64_t langId);
