#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"

namespace
{
    using GetLangString_t = const char*(__cdecl*)();
    using RequestGetInformationList_t = bool(__fastcall*)(void* self, int32_t serverLang, int32_t region);
    using RequestGetCampaignDialogList_t = bool(__fastcall*)(void* self, uint8_t kind, int32_t serverLang, int32_t region);
    using GetServerText_t = const char*(__fastcall*)(void* self, uint32_t keyHash, uint32_t lang);
    using GetLangText_t = const char*(__fastcall*)(uint64_t langId);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr int32_t SERVER_LANG_EN = 0;
    constexpr int32_t SERVER_LANG_ANY = 0x12;
    constexpr int16_t ANY_BYTE = -1;
    constexpr size_t SHORT_SERVER_TEXT = 128;
    constexpr size_t SHORT_TEXT_LIMIT = 127;
    constexpr size_t LONG_TEXT_LIMIT = 1023;
    constexpr size_t MAX_LOGGED_KEYS = 64;

    const int16_t kGetServerTextCode[] = {
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF,
        0x45, 0x8B, 0xC8, 0x44, 0x8B, 0xC2, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x48, 0x8B, 0x0D,
        ANY_BYTE, ANY_BYTE, ANY_BYTE, ANY_BYTE, 0xE8,
    };

    const int16_t kGetLangStringCode[] = {
        0x48, 0x83, 0xEC, 0x28, 0xE8, ANY_BYTE, ANY_BYTE, ANY_BYTE, ANY_BYTE,
        0x48, 0x85, 0xC0, 0x74, 0x2F, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0xC8,
        0xFF, 0x92, 0x88, 0x01, 0x00, 0x00, 0x3C, 0x0B,
    };

    const int16_t kRequestGetInformationListCode[] = {
        0x40, 0x55, 0x57, 0x41, 0x56, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x50, 0x48,
        0xC7, 0x45, 0xE8, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x70, 0x48,
        0x89, 0x74, 0x24, 0x78, 0x41, 0x8B, 0xF8, 0x48, 0x63, 0xF2, 0x4C, 0x8B, 0xF1,
    };

    const int16_t kRequestGetCampaignDialogListCode[] = {
        0x40, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x50,
        0x48, 0xC7, 0x45, 0xF0, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x70,
        0x48, 0x89, 0x74, 0x24, 0x78, 0x48, 0x89, 0xBC, 0x24, 0x80, 0x00, 0x00, 0x00,
        0x41, 0x8B, 0xF9, 0x49, 0x63, 0xF0, 0x44, 0x0F, 0xB6, 0xFA, 0x4C, 0x8B, 0xF1,
    };

    GetLangString_t oGetLangString = nullptr;
    RequestGetInformationList_t oRequestGetInformationList = nullptr;
    RequestGetCampaignDialogList_t oRequestGetCampaignDialogList = nullptr;
    GetServerText_t oGetServerText = nullptr;
    GetLangText_t gGetLangText = nullptr;
    void* gGetLangStringTarget = nullptr;
    void* gRequestGetInformationListTarget = nullptr;
    void* gRequestGetCampaignDialogListTarget = nullptr;
    void* gGetServerTextTarget = nullptr;
    std::atomic<bool> gLoginLogged{ false };
    std::atomic<bool> gNewsLogged{ false };
    std::atomic<bool> gDialogsLogged{ false };
    std::atomic<uint32_t> gLoggedKeys[MAX_LOGGED_KEYS] = {};
    std::atomic<size_t> gLoggedKeyCount{ 0 };

    bool CodeMatches(const void* target, const int16_t* code, size_t count)
    {
        __try
        {
            const uint8_t* bytes = static_cast<const uint8_t*>(target);
            for (size_t i = 0; i < count; ++i)
            {
                if (code[i] != ANY_BYTE && bytes[i] != static_cast<uint8_t>(code[i]))
                    return false;
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsArabicServerCode(const char* code)
    {
        __try
        {
            return code && code[0] == 'a' && code[1] == 'r' && code[2] == '\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    int32_t ConcreteServerLang(int32_t serverLang, std::atomic<bool>& logged, const char* request)
    {
        if (serverLang != SERVER_LANG_ANY)
            return serverLang;
        if (!logged.exchange(true))
            Log("[tpp::net] %s asked in ANY (the game language has no server code) - asked in EN.\n", request);
        return SERVER_LANG_EN;
    }

    const char* __cdecl hkGetLangString()
    {
        const char* code = oGetLangString();
        if (!IsArabicServerCode(code))
            return code;
        if (!gLoginLogged.exchange(true))
            Log("[tpp::net::util] server language \"ar\" has only placeholder texts on the server - sent as \"en\".\n");
        return "en";
    }

    bool __fastcall hkRequestGetInformationList(void* self, int32_t serverLang, int32_t region)
    {
        return oRequestGetInformationList(self, ConcreteServerLang(serverLang, gNewsLogged, "Online News (CMD_GET_INFORMATIONLIST2)"), region);
    }

    bool __fastcall hkRequestGetCampaignDialogList(void* self, uint8_t kind, int32_t serverLang, int32_t region)
    {
        return oRequestGetCampaignDialogList(self, kind,
            ConcreteServerLang(serverLang, gDialogsLogged, "server messages (CMD_GET_CAMPAIGN_DIALOG_LIST)"), region);
    }

    size_t SafeLength(const char* text, size_t stopAfter)
    {
        __try
        {
            size_t length = 0;
            while (text && length <= stopAfter && text[length])
                ++length;
            return length;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return stopAfter + 1;
        }
    }

    const char* LocalLangText(uint32_t keyHash)
    {
        if (!gGetLangText)
            return nullptr;
        __try
        {
            const char* text = gGetLangText(keyHash);
            return text && text[0] ? text : nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    bool FirstTimeForKey(uint32_t keyHash)
    {
        const size_t count = gLoggedKeyCount.load();
        for (size_t i = 0; i < count && i < MAX_LOGGED_KEYS; ++i)
        {
            if (gLoggedKeys[i].load() == keyHash)
                return false;
        }
        const size_t slot = gLoggedKeyCount.fetch_add(1);
        if (slot >= MAX_LOGGED_KEYS)
            return false;
        gLoggedKeys[slot].store(keyHash);
        return true;
    }

    const char* __fastcall hkGetServerText(void* self, uint32_t keyHash, uint32_t lang)
    {
        const char* server = oGetServerText(self, keyHash, lang);
        const char* local = LocalLangText(keyHash);
        if (!local)
            return server;
        const size_t limit = SafeLength(server, SHORT_SERVER_TEXT) < SHORT_SERVER_TEXT ? SHORT_TEXT_LIMIT : LONG_TEXT_LIMIT;
        const size_t length = SafeLength(local, limit);
        if (length > limit)
        {
            if (FirstTimeForKey(keyHash))
                Log("[tpp::net] server text %08X: the language file's text is over %zu bytes - the server text is kept.\n", keyHash, limit);
            return server;
        }
        if (FirstTimeForKey(keyHash))
            Log("[tpp::net] server text %08X shown from the language file (%zu bytes).\n", keyHash, length);
        return local;
    }

    void InstallOne(HMODULE hGame, uintptr_t va, const int16_t* code, size_t count, void* detour, void** original,
                    void*& slot, const char* name)
    {
        if (!va)
        {
            Log("[tpp::net] %s address missing - the stock server language is kept.\n", name);
            return;
        }
        void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
        if (!CodeMatches(target, code, count))
        {
            Log("[tpp::net] %s code mismatch at %p - the stock server language is kept.\n", name, target);
            return;
        }
        if (MH_CreateHook(target, detour, original) != MH_OK)
        {
            Log("[tpp::net] %s: MH_CreateHook failed - the stock server language is kept.\n", name);
            return;
        }
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            Log("[tpp::net] %s: MH_EnableHook failed - the stock server language is kept.\n", name);
            return;
        }
        slot = target;
        Log("[tpp::net] %s hooked at %p.\n", name, target);
    }

    void RemoveOne(void*& slot)
    {
        if (!slot)
            return;
        MH_DisableHook(slot);
        MH_RemoveHook(slot);
        slot = nullptr;
    }
}

bool InstallServerLanguageFallbackHooks(HMODULE hGame)
{
    if (!hGame)
        return false;
    InstallOne(hGame, gAddr.NetUtil_GetLangString, kGetLangStringCode, _countof(kGetLangStringCode),
               reinterpret_cast<void*>(&hkGetLangString), reinterpret_cast<void**>(&oGetLangString),
               gGetLangStringTarget, "GetLangString");
    InstallOne(hGame, gAddr.GateServer_RequestGetInformationList, kRequestGetInformationListCode,
               _countof(kRequestGetInformationListCode), reinterpret_cast<void*>(&hkRequestGetInformationList),
               reinterpret_cast<void**>(&oRequestGetInformationList), gRequestGetInformationListTarget,
               "RequestGetInformationList");
    InstallOne(hGame, gAddr.RequestGetCampaignDialogList, kRequestGetCampaignDialogListCode,
               _countof(kRequestGetCampaignDialogListCode), reinterpret_cast<void*>(&hkRequestGetCampaignDialogList),
               reinterpret_cast<void**>(&oRequestGetCampaignDialogList), gRequestGetCampaignDialogListTarget,
               "RequestGetCampaignDialogList");
    if (gAddr.GetLangText)
    {
        gGetLangText = reinterpret_cast<GetLangText_t>(
            reinterpret_cast<uintptr_t>(hGame) + (gAddr.GetLangText - IDA_IMAGE_BASE));
        InstallOne(hGame, gAddr.NetworkSystem_GetServerText, kGetServerTextCode, _countof(kGetServerTextCode),
                   reinterpret_cast<void*>(&hkGetServerText), reinterpret_cast<void**>(&oGetServerText),
                   gGetServerTextTarget, "GetServerText");
    }
    return true;
}

void RemoveServerLanguageFallbackHooks()
{
    RemoveOne(gGetLangStringTarget);
    RemoveOne(gRequestGetInformationListTarget);
    RemoveOne(gRequestGetCampaignDialogListTarget);
    RemoveOne(gGetServerTextTarget);
    oGetLangString = nullptr;
    oRequestGetInformationList = nullptr;
    oRequestGetCampaignDialogList = nullptr;
    oGetServerText = nullptr;
    gGetLangText = nullptr;
    gLoggedKeyCount = 0;
    gLoginLogged = false;
    gNewsLogged = false;
    gDialogsLogged = false;
}
