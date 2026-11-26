#include "pch.h"
#include <atomic>
#include "MinHook.h"

#undef MH_EnableHook

extern "C" MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget);

namespace
{
    std::atomic<bool> gBatching{ false };
}

extern "C" MH_STATUS WINAPI LangHookEnableHook(LPVOID pTarget)
{
    if (gBatching.load() && pTarget != MH_ALL_HOOKS)
        return MH_QueueEnableHook(pTarget);
    return MH_EnableHook(pTarget);
}

void BeginHookBatch()
{
    gBatching.store(true);
}

int EndHookBatch()
{
    gBatching.store(false);
    return static_cast<int>(MH_ApplyQueued());
}
