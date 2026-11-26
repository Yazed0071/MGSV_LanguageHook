#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void* GetModelNodeTextVtable();
void WriteArabicAuditLine(const char* line);
void ApplyArabicLayoutMirror(uint8_t* model, const void* param);
const void* ArabicDrawParam(uint8_t* model, const void* param, float* scratch);
void InitArabicLayoutMirror(HMODULE hGame);
void ShutdownArabicLayoutMirror();
bool InitLayoutDirectionRestore(HMODULE hGame);
void ShutdownLayoutDirectionRestore();
void RestoreLayoutDirection(uint8_t* model, bool afterMirror);
bool RL_DiagnosticsEnabled();

namespace
{
    using ModelDraw_t = uint64_t(__fastcall*)(uint8_t* model, void* matrix);
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetDisplayWidth_t = float(__fastcall*)(void* node);
    using SetTextUnits_t = uint64_t(__fastcall*)(uint8_t* node, void* units, uint32_t count, uint64_t a4, uint64_t a5,
                                                 uint64_t a6, uint64_t a7, uint64_t a8);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t MODEL_NODE_COUNT = 0x90;
    constexpr size_t MODEL_NODES = 0x98;
    constexpr size_t NODE_FLAGS = 0x08;
    constexpr size_t NODE_PARENT = 0x10;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_SCALE = 0x40;
    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t NODE_TYPE = 0x72;
    constexpr size_t TEXT_LINE_ALIGN = 0xD8;
    constexpr size_t TEXT_BLOCK_ALIGN = 0xDA;
    constexpr size_t TEXT_FLAGS = 0x90;
    constexpr size_t TEXT_SCROLL_STATE = 0x92;
    constexpr size_t TEXT_SCROLL_POS = 0x1B4;
    constexpr size_t TEXT_SCROLL_DELAY = 0x1BC;
    constexpr size_t TEXT_UNITS = 0x138;
    constexpr size_t TEXT_UNIT_COUNT = 0x140;
    constexpr size_t TEXT_WIDTH = 0x17C;
    constexpr size_t TEXT_AREA_LEFT = 0xE0;
    constexpr size_t TEXT_AREA_WIDTH = 0xE8;
    constexpr size_t TEXT_SCALE = 0xF0;
    constexpr size_t UNIT_STRIDE = 0x20;
    constexpr uint32_t MAX_NODES = 1500;
    constexpr int MAX_MODELS = 2048;
    constexpr ULONGLONG CAPTURE_MS = 150;

    const uint8_t kPrologue[] = { 0x4C, 0x8B, 0xDC, 0x56, 0x41, 0x55, 0x48, 0x81, 0xEC, 0x68, 0x01, 0x00, 0x00 };
    const uint8_t kSetTextUnitsPrologue[] = { 0x48, 0x8B, 0xC4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                              0x41, 0x57, 0x48, 0x8D, 0x68, 0x88 };
    constexpr size_t MAX_CACHED_TEXTS = 30000;

    ModelDraw_t oDraw = nullptr;
    void* gTarget = nullptr;
    uintptr_t gBase = 0;
    GetDisplayWidth_t gGetDisplayWidth = nullptr;
    std::atomic<ULONGLONG> gCaptureUntil{ 0 };
    std::atomic<int> gCaptureId{ 0 };
    std::atomic<bool> gKeyWasDown{ false };
    uint8_t* gSeen[MAX_MODELS] = {};
    int gSeenCount = 0;
    SRWLOCK gLock = SRWLOCK_INIT;
    SetTextUnits_t oSetTextUnits = nullptr;
    void* gSetTextUnitsTarget = nullptr;
    SRWLOCK gTextLock = SRWLOCK_INIT;
    std::unordered_map<const uint8_t*, std::string> gTextCache;
    constexpr size_t MAX_AUTO_ROOTS = 1500;
    IsArabLanguage_t gIsArabLanguage = nullptr;
    SRWLOCK gAutoLock = SRWLOCK_INIT;
    std::unordered_set<uint32_t> gAutoRoots;
    int gAutoIndex = 0;
    thread_local bool tToAudit = false;
    bool gDiagnostics = false;

    void Emit(const char* line)
    {
        if (tToAudit)
            WriteArabicAuditLine(line);
        else
            Log("%s", line);
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

    float DisplayWidth(void* node)
    {
        if (!gGetDisplayWidth)
            return -1.0f;
        __try
        {
            return gGetDisplayWidth(node);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1.0f;
        }
    }

    void ReadText(const uint8_t* node, char* out, size_t size)
    {
        out[0] = '\0';
        size_t used = 0;
        __try
        {
            const uint8_t* units = *reinterpret_cast<const uint8_t* const*>(node + TEXT_UNITS);
            const uint32_t count = *reinterpret_cast<const uint32_t*>(node + TEXT_UNIT_COUNT);
            if (!units || count == 0 || count > 64)
                return;
            for (uint32_t u = 0; u < count && used + 2 < size; ++u)
            {
                const char* text = *reinterpret_cast<const char* const*>(units + static_cast<size_t>(u) * UNIT_STRIDE);
                if (!text)
                    continue;
                if (u && used + 2 < size)
                    out[used++] = '|';
                for (size_t i = 0; text[i] && used + 1 < size; ++i)
                    out[used++] = text[i];
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        out[used < size ? used : size - 1] = '\0';
    }

    void RememberText(const uint8_t* node)
    {
        char text[200];
        ReadText(node, text, sizeof(text));
        AcquireSRWLockExclusive(&gTextLock);
        if (gTextCache.size() > MAX_CACHED_TEXTS)
            gTextCache.clear();
        gTextCache[node] = text;
        ReleaseSRWLockExclusive(&gTextLock);
    }

    bool CachedText(const uint8_t* node, char* out, size_t size)
    {
        bool found = false;
        AcquireSRWLockShared(&gTextLock);
        const auto it = gTextCache.find(node);
        if (it != gTextCache.end())
        {
            strncpy_s(out, size, it->second.c_str(), _TRUNCATE);
            found = true;
        }
        ReleaseSRWLockShared(&gTextLock);
        return found;
    }

    uint64_t __fastcall hkSetTextUnits(uint8_t* node, void* units, uint32_t count, uint64_t a4, uint64_t a5, uint64_t a6,
                                       uint64_t a7, uint64_t a8)
    {
        const uint64_t result = oSetTextUnits(node, units, count, a4, a5, a6, a7, a8);
        if (node)
            RememberText(node);
        return result;
    }

    bool ReadModel(const uint8_t* model, uint32_t& count, uint8_t* const*& nodes)
    {
        __try
        {
            count = *reinterpret_cast<const uint32_t*>(model + MODEL_NODE_COUNT);
            nodes = *reinterpret_cast<uint8_t* const* const*>(model + MODEL_NODES);
            return nodes && count > 0 && count <= MAX_NODES;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    int IndexOf(uint8_t* const* nodes, uint32_t count, const void* node)
    {
        for (uint32_t i = 0; i < count; ++i)
        {
            if (nodes[i] == node)
                return static_cast<int>(i);
        }
        return -1;
    }

    void DumpNode(int capture, int modelIndex, uint8_t* const* nodes, uint32_t count, uint32_t i, void* textVtable)
    {
        uint8_t* node = nodes[i];
        if (!node)
            return;
        void* vtable = nullptr;
        uint8_t* parent = nullptr;
        uint16_t flags = 0;
        uint8_t type = 0;
        uint32_t name = 0;
        float tx = 0, ty = 0, sx = 0, sy = 0, wx = 0, wy = 0;
        __try
        {
            vtable = *reinterpret_cast<void**>(node);
            flags = *reinterpret_cast<uint16_t*>(node + NODE_FLAGS);
            parent = *reinterpret_cast<uint8_t**>(node + NODE_PARENT);
            tx = *reinterpret_cast<float*>(node + NODE_TRANSLATION);
            ty = *reinterpret_cast<float*>(node + NODE_TRANSLATION + 4);
            sx = *reinterpret_cast<float*>(node + NODE_SCALE);
            sy = *reinterpret_cast<float*>(node + NODE_SCALE + 4);
            name = *reinterpret_cast<uint32_t*>(node + NODE_NAME);
            type = node[NODE_TYPE];
            const uint8_t* walk = node;
            for (int depth = 0; walk && depth < 32; ++depth)
            {
                wx += *reinterpret_cast<const float*>(walk + NODE_TRANSLATION);
                wy += *reinterpret_cast<const float*>(walk + NODE_TRANSLATION + 4);
                walk = *reinterpret_cast<uint8_t* const*>(walk + NODE_PARENT);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return;
        }

        const int parentIndex = parent ? IndexOf(nodes, count, parent) : -1;
        const uintptr_t vtRva = vtable ? reinterpret_cast<uintptr_t>(vtable) - gBase + IDA_IMAGE_BASE : 0;
        char line[768];
        if (textVtable && vtable == textVtable)
        {
            uint8_t lineAlign = 0, blockAlign = 0, scrollState = 0;
            uint16_t textFlags = 0;
            float textWidth = 0, areaLeft = 0, areaWidth = 0, scale = 0, scrollPos = 0, scrollDelay = 0;
            __try
            {
                lineAlign = node[TEXT_LINE_ALIGN];
                blockAlign = node[TEXT_BLOCK_ALIGN];
                textFlags = *reinterpret_cast<uint16_t*>(node + TEXT_FLAGS);
                scrollState = node[TEXT_SCROLL_STATE];
                scrollPos = *reinterpret_cast<float*>(node + TEXT_SCROLL_POS);
                scrollDelay = *reinterpret_cast<float*>(node + TEXT_SCROLL_DELAY);
                textWidth = *reinterpret_cast<float*>(node + TEXT_WIDTH);
                areaLeft = *reinterpret_cast<float*>(node + TEXT_AREA_LEFT);
                areaWidth = *reinterpret_cast<float*>(node + TEXT_AREA_WIDTH);
                scale = *reinterpret_cast<float*>(node + TEXT_SCALE);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            char text[200];
            if (!CachedText(node, text, sizeof(text)))
                ReadText(node, text, sizeof(text));
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "[UiInspect] #%d m%d n%u %p TEXT name=%08X parent=%d vis=%u t=(%.2f,%.2f) s=(%.2f,%.2f) w=(%.2f,%.2f) "
                        "d8=%u da=%u box=%.1f textW=%.1f area=(%.3f,%.3f)x%.2f tf=%04X st=%u pos=%.1f dly=%.2f text=[%s]\n",
                        capture, modelIndex, i, node, name, parentIndex, flags & 1u, tx, ty, sx, sy, wx, wy, lineAlign,
                        blockAlign, DisplayWidth(node), textWidth, areaLeft, areaWidth, scale, textFlags,
                        static_cast<unsigned>(scrollState), scrollPos, scrollDelay, text);
        }
        else
        {
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "[UiInspect] #%d m%d n%u %p type=%u vt=%llX name=%08X parent=%d vis=%u t=(%.2f,%.2f) s=(%.2f,%.2f) w=(%.2f,%.2f)\n",
                        capture, modelIndex, i, node, type, static_cast<unsigned long long>(vtRva), name, parentIndex,
                        flags & 1u, tx, ty, sx, sy, wx, wy);
        }
        Emit(line);
    }

    void DumpModel(uint8_t* model, const float* param, int capture, int modelIndex)
    {
        uint32_t count = 0;
        uint8_t* const* nodes = nullptr;
        if (!ReadModel(model, count, nodes))
            return;
        void* textVtable = GetModelNodeTextVtable();
        float p[16] = {};
        uint32_t drawFlags = 0;
        __try
        {
            for (int k = 0; k < 16; ++k)
                p[k] = param ? param[k] : 0.0f;
            drawFlags = *reinterpret_cast<const uint32_t*>(model + 0x74);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        char header[400];
        _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "[UiInspect] #%d m%d model %p, %u nodes param t=(%.2f,%.2f,%.2f,%.2f) r=(%.3f,%.3f,%.3f,%.3f) "
                    "s=(%.3f,%.3f,%.3f,%.3f) c=(%.2f,%.2f,%.2f,%.2f) f74=%08X\n",
                    capture, modelIndex, model, count, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
                    p[10], p[11], p[12], p[13], p[14], p[15], drawFlags);
        Emit(header);
        for (uint32_t i = 0; i < count; ++i)
            DumpNode(capture, modelIndex, nodes, count, i, textVtable);
    }

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

    bool ReadRootName(const uint8_t* model, uint32_t& root)
    {
        uint32_t count = 0;
        uint8_t* const* nodes = nullptr;
        if (!ReadModel(model, count, nodes) || count == 0)
            return false;
        __try
        {
            root = *reinterpret_cast<const uint32_t*>(nodes[0] + NODE_NAME);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ShowsText(const uint8_t* model, const float* param)
    {
        uint32_t count = 0;
        uint8_t* const* nodes = nullptr;
        if (!ReadModel(model, count, nodes) || count == 0)
            return false;
        void* textVtable = GetModelNodeTextVtable();
        if (!textVtable)
            return false;
        __try
        {
            if (param && !(param[15] > 0.5f))
                return false;
            for (uint32_t i = 0; i < count; ++i)
            {
                const uint8_t* node = nodes[i];
                if (node && *reinterpret_cast<void* const*>(node) == textVtable &&
                    (*reinterpret_cast<const uint32_t*>(node + NODE_FLAGS) & 1u) &&
                    *reinterpret_cast<const float*>(node + TEXT_WIDTH) > 0.0f)
                    return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return false;
    }

    void AutoSnapshot(uint8_t* model, const float* param)
    {
        if (!model || !IsArabicSafe())
            return;
        uint32_t root = 0;
        if (!ReadRootName(model, root))
            return;
        AcquireSRWLockShared(&gAutoLock);
        const bool known = gAutoRoots.count(root) != 0 || gAutoRoots.size() >= MAX_AUTO_ROOTS;
        ReleaseSRWLockShared(&gAutoLock);
        if (known || !ShowsText(model, param))
            return;
        AcquireSRWLockExclusive(&gAutoLock);
        if (!gAutoRoots.insert(root).second)
        {
            ReleaseSRWLockExclusive(&gAutoLock);
            return;
        }
        const int index = ++gAutoIndex;
        ReleaseSRWLockExclusive(&gAutoLock);
        char header[96];
        _snprintf_s(header, sizeof(header), _TRUNCATE, "[UiInspect] ===== auto root %08X (#0 m%d) =====\n", root, index);
        tToAudit = true;
        Emit(header);
        DumpModel(model, param, 0, index);
        tToAudit = false;
    }

    void StartCapture(const char* reason)
    {
        AcquireSRWLockExclusive(&gLock);
        gSeenCount = 0;
        const int id = gCaptureId.fetch_add(1) + 1;
        gCaptureUntil.store(GetTickCount64() + CAPTURE_MS);
        ReleaseSRWLockExclusive(&gLock);
        Log("[UiInspect] ===== capture #%d (%s) =====\n", id, reason);
    }

    void PollKey()
    {
        const bool down = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
        const bool was = gKeyWasDown.exchange(down);
        if (!down || was)
            return;
        StartCapture("F8");
    }

    struct PageTrigger
    {
        uint32_t root;
        const char* reason;
        ULONGLONG firstSeen;
        ULONGLONG lastSeen;
        ULONGLONG lastCapture;
        int captures;
    };

    constexpr ULONGLONG PAGE_SETTLE_MS = 1500;
    constexpr ULONGLONG PAGE_GONE_MS = 1000;
    constexpr ULONGLONG PAGE_REPEAT_MS = 8000;
    constexpr int PAGE_CAPTURES = 4;
    SRWLOCK gPageLock = SRWLOCK_INIT;
    PageTrigger gPageTriggers[] = {
        { 0xE758A8F0, "auto: base facilities", 0, 0, 0, 0 },
        { 0xBB6B40EF, "auto: pf rating", 0, 0, 0, 0 },
        { 0xB5BE2102, "auto: supply drop", 0, 0, 0, 0 },
        { 0x4CA0A9B2, "auto: customize", 0, 0, 0, 0 },
        { 0xD74322A4, "auto: sortie items", 0, 0, 0, 0 },
        { 0x3C0CBB73, "auto: security detail list", 0, 0, 0, 0 },
    };

    void PollPages(uint8_t* model)
    {
        uint32_t root = 0;
        if (!ReadRootName(model, root))
            return;
        const ULONGLONG now = GetTickCount64();
        const char* reason = nullptr;
        AcquireSRWLockExclusive(&gPageLock);
        for (PageTrigger& t : gPageTriggers)
        {
            if (t.root != root || t.captures >= PAGE_CAPTURES)
                continue;
            if (t.firstSeen == 0 || now - t.lastSeen > PAGE_GONE_MS)
                t.firstSeen = now;
            t.lastSeen = now;
            const bool settled = now - t.firstSeen >= PAGE_SETTLE_MS;
            const bool due = t.lastCapture == 0 || now - t.lastCapture >= PAGE_REPEAT_MS;
            if (settled && due)
            {
                t.lastCapture = now;
                ++t.captures;
                reason = t.reason;
            }
        }
        ReleaseSRWLockExclusive(&gPageLock);
        if (reason)
            StartCapture(reason);
    }

    void Capture(uint8_t* model, const float* param)
    {
        if (!model || GetTickCount64() > gCaptureUntil.load())
            return;
        AcquireSRWLockExclusive(&gLock);
        for (int i = 0; i < gSeenCount; ++i)
        {
            if (gSeen[i] == model)
            {
                ReleaseSRWLockExclusive(&gLock);
                return;
            }
        }
        if (gSeenCount >= MAX_MODELS)
        {
            ReleaseSRWLockExclusive(&gLock);
            return;
        }
        const int index = gSeenCount;
        gSeen[gSeenCount++] = model;
        const int capture = gCaptureId.load();
        DumpModel(model, param, capture, index);
        ReleaseSRWLockExclusive(&gLock);
    }

    uint64_t __fastcall hkDraw(uint8_t* model, void* matrix)
    {
        RestoreLayoutDirection(model, false);
        ApplyArabicLayoutMirror(model, matrix);
        RestoreLayoutDirection(model, true);
        alignas(16) float scratch[16];
        const void* drawParam = ArabicDrawParam(model, matrix, scratch);
        const uint64_t result = oDraw(model, const_cast<void*>(drawParam));
        if (gDiagnostics)
        {
            PollKey();
            PollPages(model);
            Capture(model, static_cast<const float*>(matrix));
            AutoSnapshot(model, static_cast<const float*>(matrix));
        }
        return result;
    }

    void* Resolve(HMODULE hGame, uintptr_t va)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (va - IDA_IMAGE_BASE));
    }
}

bool InstallUiInspectorHook(HMODULE hGame)
{
    if (!hGame || !gAddr.Model_Draw)
    {
        Log("[UiInspect] address missing - right-to-left list mirroring, layout restore after a language switch and the F8 inspector are off.\n");
        return true;
    }
    gBase = reinterpret_cast<uintptr_t>(hGame);
    if (gAddr.IsArabLanguage)
        gIsArabLanguage = &RL_IsRightToLeft;
    if (gAddr.ModelNodeText_GetDisplayWidth)
        gGetDisplayWidth = reinterpret_cast<GetDisplayWidth_t>(Resolve(hGame, gAddr.ModelNodeText_GetDisplayWidth));
    void* target = Resolve(hGame, gAddr.Model_Draw);
    if (!CodeMatches(target, kPrologue, sizeof(kPrologue)))
    {
        Log("[UiInspect] fox::ui::Model draw code is not what this build should have - right-to-left list mirroring, layout restore after a language switch and the F8 inspector are off.\n");
        return true;
    }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&hkDraw), reinterpret_cast<void**>(&oDraw)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        Log("[UiInspect] Model draw hook failed - right-to-left list mirroring, layout restore after a language "
            "switch and the F8 inspector are off.\n");
        return true;
    }
    gTarget = target;
    InitArabicLayoutMirror(hGame);
    InitLayoutDirectionRestore(hGame);
    gDiagnostics = RL_DiagnosticsEnabled();
    if (!gDiagnostics)
    {
        return true;
    }
    if (gAddr.ModelNodeText_SetTextUnits)
    {
        void* setText = Resolve(hGame, gAddr.ModelNodeText_SetTextUnits);
        if (CodeMatches(setText, kSetTextUnitsPrologue, sizeof(kSetTextUnitsPrologue)) &&
            MH_CreateHook(setText, reinterpret_cast<void*>(&hkSetTextUnits), reinterpret_cast<void**>(&oSetTextUnits)) == MH_OK &&
            MH_EnableHook(setText) == MH_OK)
            gSetTextUnitsTarget = setText;
        else
            Log("[UiInspect] text cache hook not installed - F8 texts may show shared buffers.\n");
    }
    Log("[UiInspect] press F8 to log every UI model on screen; Arabic list layouts mirrored.\n");
    return true;
}

void RemoveUiInspectorHook()
{
    if (gTarget)
    {
        MH_DisableHook(gTarget);
        MH_RemoveHook(gTarget);
        gTarget = nullptr;
    }
    if (gSetTextUnitsTarget)
    {
        MH_DisableHook(gSetTextUnitsTarget);
        MH_RemoveHook(gSetTextUnitsTarget);
        gSetTextUnitsTarget = nullptr;
    }
    AcquireSRWLockExclusive(&gTextLock);
    gTextCache.clear();
    ReleaseSRWLockExclusive(&gTextLock);
    ShutdownLayoutDirectionRestore();
    ShutdownArabicLayoutMirror();
    oDraw = nullptr;
    gGetDisplayWidth = nullptr;
    gIsArabLanguage = nullptr;
    AcquireSRWLockExclusive(&gAutoLock);
    gAutoRoots.clear();
    gAutoIndex = 0;
    ReleaseSRWLockExclusive(&gAutoLock);
}
