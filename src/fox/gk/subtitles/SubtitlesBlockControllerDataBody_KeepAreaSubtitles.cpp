#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using BodyCall_t = void(__fastcall*)(void* body);
    using BodyDtor_t = void*(__fastcall*)(void* body, uint32_t flags);
    using MgrCall_t = void(__fastcall*)(void* mgr);
    using MgrCreate_t = int*(__fastcall*)(void* mgr, int* result);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t MGR_CONTROLLER = 0x128;
    constexpr size_t MGR_LOAD_PENDING = 0x194;
    constexpr size_t MGR_DELETE_PENDING = 0x195;
    constexpr size_t CTL_STATE = 0x30;
    constexpr int CTL_LOADED = 4;
    constexpr size_t BODY_HANDLE = 0x38;
    constexpr size_t HANDLE_DATA = 0x18;
    constexpr size_t DATA_NAMES = 0x78;
    constexpr int MAX_BODIES = 16;
    constexpr int MAX_FAILED_RESTORES = 3;

    struct ActiveBody
    {
        void* body;
        uint64_t order;
        int restores;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    BodyCall_t oSetup = nullptr;
    BodyCall_t oActivate = nullptr;
    BodyCall_t oDeactivate = nullptr;
    BodyCall_t oUpdate = nullptr;
    BodyDtor_t oDtor = nullptr;
    MgrCall_t oControl = nullptr;
    MgrCreate_t gCreateController = nullptr;
    BodyCall_t gSendLoadRequest = nullptr;

    void* gTargets[6] = {};
    SRWLOCK gLock = SRWLOCK_INIT;
    ActiveBody gBodies[MAX_BODIES] = {};
    int gBodyCount = 0;
    uint64_t gOrder = 0;
    void* gGaveUpOn = nullptr;

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

    void BodyNames(void* body, char* out, size_t size)
    {
        out[0] = '\0';
        size_t used = 0;
        __try
        {
            auto* handle = *reinterpret_cast<uint8_t**>(static_cast<uint8_t*>(body) + BODY_HANDLE);
            auto* data = handle ? *reinterpret_cast<uint8_t**>(handle + HANDLE_DATA) : nullptr;
            if (!data)
                return;
            const uint32_t count = *reinterpret_cast<uint32_t*>(data + DATA_NAMES);
            auto* items = *reinterpret_cast<uint8_t**>(data + DATA_NAMES + 8);
            for (uint32_t i = 0; i < count && i < 4 && items; ++i)
            {
                auto* shared = *reinterpret_cast<uint8_t**>(items + i * 8);
                const char* text = shared ? *reinterpret_cast<const char**>(shared) : nullptr;
                used += static_cast<size_t>(_snprintf_s(out + used, size - used, _TRUNCATE, "%s%s", i ? ", " : "",
                                                        text ? text : "?"));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void MarkActive(void* body)
    {
        AcquireSRWLockExclusive(&gLock);
        ++gOrder;
        int found = -1;
        for (int i = 0; i < gBodyCount; ++i)
        {
            if (gBodies[i].body == body)
            {
                found = i;
                break;
            }
        }
        if (found >= 0)
            gBodies[found].order = gOrder;
        else if (gBodyCount < MAX_BODIES)
            gBodies[gBodyCount++] = { body, gOrder, 0 };
        ReleaseSRWLockExclusive(&gLock);
    }

    void Forget(void* body)
    {
        AcquireSRWLockExclusive(&gLock);
        for (int i = 0; i < gBodyCount; ++i)
        {
            if (gBodies[i].body == body)
            {
                gBodies[i] = gBodies[--gBodyCount];
                break;
            }
        }
        if (gGaveUpOn == body)
            gGaveUpOn = nullptr;
        ReleaseSRWLockExclusive(&gLock);
    }

    ActiveBody* NewestLocked()
    {
        int newest = -1;
        for (int i = 0; i < gBodyCount; ++i)
        {
            if (newest < 0 || gBodies[i].order > gBodies[newest].order)
                newest = i;
        }
        return newest >= 0 ? &gBodies[newest] : nullptr;
    }

    bool AnyRestoresLocked()
    {
        for (int i = 0; i < gBodyCount; ++i)
        {
            if (gBodies[i].restores != 0)
                return true;
        }
        return gGaveUpOn != nullptr;
    }

    void ResetRestores()
    {
        AcquireSRWLockShared(&gLock);
        const bool any = AnyRestoresLocked();
        ReleaseSRWLockShared(&gLock);
        if (!any)
            return;
        AcquireSRWLockExclusive(&gLock);
        for (int i = 0; i < gBodyCount; ++i)
            gBodies[i].restores = 0;
        gGaveUpOn = nullptr;
        ReleaseSRWLockExclusive(&gLock);
    }

    struct ManagerState
    {
        void* controller = nullptr;
        int controllerState = -1;
        int loadPending = -1;
        int deletePending = -1;
    };

    bool ReadManager(void* mgr, ManagerState& s)
    {
        __try
        {
            auto* m = static_cast<uint8_t*>(mgr);
            s.controller = *reinterpret_cast<void**>(m + MGR_CONTROLLER);
            s.loadPending = m[MGR_LOAD_PENDING];
            s.deletePending = m[MGR_DELETE_PENDING];
            s.controllerState =
                s.controller ? *reinterpret_cast<int*>(static_cast<uint8_t*>(s.controller) + CTL_STATE) : -1;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    int Code(const int* result)
    {
        __try
        {
            return result ? *result : -1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1;
        }
    }

    bool SendLoadRequestSafe(void* body)
    {
        __try
        {
            gSendLoadRequest(body);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void RestoreAreaPack(void* mgr)
    {
        ManagerState s{};
        if (!ReadManager(mgr, s))
            return;

        if (s.controller)
        {
            if (s.controllerState == CTL_LOADED && s.loadPending == 0 && s.deletePending == 0)
                ResetRestores();
            return;
        }
        if (s.loadPending != 0 || s.deletePending != 0)
            return;

        AcquireSRWLockShared(&gLock);
        const bool anyActive = gBodyCount > 0;
        ReleaseSRWLockShared(&gLock);
        if (!anyActive || !IsArabicSafe())
            return;

        AcquireSRWLockExclusive(&gLock);
        ActiveBody* b = NewestLocked();
        if (!b || gGaveUpOn == b->body)
        {
            ReleaseSRWLockExclusive(&gLock);
            return;
        }

        char names[160];
        BodyNames(b->body, names, sizeof(names));
        if (b->restores >= MAX_FAILED_RESTORES)
        {
            gGaveUpOn = b->body;
            const int attempts = b->restores;
            ReleaseSRWLockExclusive(&gLock);
            Log("[SubtitleBlock] subtitles for [%s] failed to load %d times in a row - not retrying.\n", names,
                attempts);
            return;
        }

        const int attempt = ++b->restores;
        void* const body = b->body;
        ReleaseSRWLockExclusive(&gLock);
        int result = -1;
        bool created = Code(gCreateController(mgr, &result)) == 0;
        const bool sent = created && SendLoadRequestSafe(body);

        if (!created)
            return;
        Log("[SubtitleBlock] the subtitle loader was deleted while [%s] is still active - recreated it and %s "
            "(attempt %d).\n",
            names, sent ? "reloaded that pack" : "FAILED to request the pack", attempt);
    }

    void __fastcall hkSetup(void* body)
    {
        oSetup(body);
        MarkActive(body);
    }

    void __fastcall hkActivate(void* body)
    {
        oActivate(body);
        MarkActive(body);
    }

    void __fastcall hkUpdate(void* body)
    {
        oUpdate(body);
        MarkActive(body);
    }

    void __fastcall hkDeactivate(void* body)
    {
        Forget(body);
        oDeactivate(body);
    }

    void* __fastcall hkDtor(void* body, uint32_t flags)
    {
        Forget(body);
        return oDtor(body, flags);
    }

    void __fastcall hkControl(void* mgr)
    {
        oControl(mgr);
        RestoreAreaPack(mgr);
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

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }

    struct HookSpec
    {
        uintptr_t va;
        const uint8_t* prologue;
        size_t size;
        void* detour;
        void** original;
    };
}

bool InstallSubtitleAreaPackKeeper(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.SubtitlesManager_ControlSubtitlesBlockLoading ||
        !gAddr.SubtitlesManager_CreateSubtitlesBlockController ||
        !gAddr.SubtitlesBlockControllerDataBody_SendRequestToLoad)
    {
        Log("[SubtitleBlock] area subtitle keeper: addresses missing for this build - not installed.\n");
        return true;
    }

    static const uint8_t kSubRsp28[] = { 0x48, 0x83, 0xEC, 0x28, 0xE8 };
    static const uint8_t kPushRbx[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9 };
    static const uint8_t kDtor[] = { 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30 };
    static const uint8_t kPushRdi30[] = { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24 };
    static const uint8_t kSendLoad[] = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };

    void* create = Resolve(hGame, gAddr.SubtitlesManager_CreateSubtitlesBlockController);
    void* sendLoad = Resolve(hGame, gAddr.SubtitlesBlockControllerDataBody_SendRequestToLoad);
    if (!CodeMatches(create, kPushRdi30, sizeof(kPushRdi30)) || !CodeMatches(sendLoad, kSendLoad, sizeof(kSendLoad)))
    {
        Log("[SubtitleBlock] area subtitle keeper: code is not what this build should have - not installed.\n");
        return true;
    }

    gIsArabLanguage = &RL_IsRightToLeft;
    gCreateController = reinterpret_cast<MgrCreate_t>(create);
    gSendLoadRequest = reinterpret_cast<BodyCall_t>(sendLoad);

    const HookSpec specs[] = {
        { gAddr.SubtitlesBlockControllerDataBody_Setup, kPushRbx, sizeof(kPushRbx), reinterpret_cast<void*>(&hkSetup),
          reinterpret_cast<void**>(&oSetup) },
        { gAddr.SubtitlesBlockControllerDataBody_Activate, kPushRbx, sizeof(kPushRbx),
          reinterpret_cast<void*>(&hkActivate), reinterpret_cast<void**>(&oActivate) },
        { gAddr.SubtitlesBlockControllerDataBody_Update, kPushRbx, sizeof(kPushRbx), reinterpret_cast<void*>(&hkUpdate),
          reinterpret_cast<void**>(&oUpdate) },
        { gAddr.SubtitlesBlockControllerDataBody_Deactivate, kSubRsp28, sizeof(kSubRsp28),
          reinterpret_cast<void*>(&hkDeactivate), reinterpret_cast<void**>(&oDeactivate) },
        { gAddr.SubtitlesBlockControllerDataBody_Destructor, kDtor, sizeof(kDtor), reinterpret_cast<void*>(&hkDtor),
          reinterpret_cast<void**>(&oDtor) },
        { gAddr.SubtitlesManager_ControlSubtitlesBlockLoading, kPushRdi30, sizeof(kPushRdi30),
          reinterpret_cast<void*>(&hkControl), reinterpret_cast<void**>(&oControl) },
    };

    int hooked = 0;
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i)
    {
        const HookSpec& s = specs[i];
        void* target = s.va ? Resolve(hGame, s.va) : nullptr;
        if (!target || !CodeMatches(target, s.prologue, s.size) ||
            MH_CreateHook(target, s.detour, s.original) != MH_OK)
            continue;
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            continue;
        }
        gTargets[i] = target;
        ++hooked;
    }

    if (hooked != static_cast<int>(sizeof(specs) / sizeof(specs[0])))
    {
        for (void*& target : gTargets)
        {
            if (target)
            {
                MH_DisableHook(target);
                MH_RemoveHook(target);
                target = nullptr;
            }
        }
        Log("[SubtitleBlock] area subtitle keeper: only %d of 6 hooks took - left off.\n", hooked);
        return false;
    }

    Log("[SubtitleBlock] area subtitle keeper on: a side-op unloading its own subtitle setup no longer leaves the "
        "area without subtitles.\n");
    return true;
}

void RemoveSubtitleAreaPackKeeper()
{
    for (void*& target : gTargets)
    {
        if (target)
        {
            MH_DisableHook(target);
            MH_RemoveHook(target);
            target = nullptr;
        }
    }
    AcquireSRWLockExclusive(&gLock);
    gBodyCount = 0;
    gGaveUpOn = nullptr;
    ReleaseSRWLockExclusive(&gLock);
    gIsArabLanguage = nullptr;
}
