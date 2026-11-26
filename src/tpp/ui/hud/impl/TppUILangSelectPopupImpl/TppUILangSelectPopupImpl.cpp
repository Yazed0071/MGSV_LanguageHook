#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <algorithm>
#include <unordered_map>
#include <atomic>
#include "MinHook.h"
#include "log.h"
#include <AddressSet.h>

void NoteLanguageApplied();

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;

// Layout property hashes used by the game's +0x590 setter.
static constexpr uint64_t HASH_TRANSLATE_X = 0x1352A707068Bull;
static constexpr uint64_t HASH_TRANSLATE_Y = 0x227F987BF357ull;

// Popup constants.
static constexpr int      kPhysicalRowCount = 11;
static constexpr int      kGameRowCount = 9;
static int               gRowCapacity = kGameRowCount;
static constexpr uint32_t kInvalidLangId = 0xFFFFFFFFu;

// Rescue timeout after the first null fix.
static constexpr DWORD kApplyRescueKeepAliveMs = 10000;

// ------------------------------------------------------------
// Logical language order
// ------------------------------------------------------------

static constexpr uint32_t kBaseFullLangIds[] =
{
    0, 1, 2, 3, 4, 5, 6, 8
};

static const std::vector<uint32_t> kExtraLangIds =
{
    7,
    9,
    10
};

using SetSelectLangList_t = void(__fastcall*)(void* thisPtr);


using UpdateLangList_t = void(__fastcall*)(void* thisPtr);

using DecideLangList_t = void(__fastcall*)(void* thisPtr);

using UpdateLangPopup_t = void(__fastcall*)(void* thisPtr);

using ChangeLanguage_t = int(__fastcall*)(void* luaState);

using ApplyFormVariation_t = bool(__fastcall*)(
    void* thisPtr,
    void* model,
    void* connectPointFile,
    void* partsBuildDirector,
    void* resourceManager,
    uint32_t* groupValues,
    void* groupDestMethods,
    uint32_t  groupCount,
    bool      doReset,
    bool      resetObjects
    );

static bool __fastcall hkApplyFormVariation(
    void* thisPtr,
    void* model,
    void* connectPointFile,
    void* partsBuildDirector,
    void* resourceManager,
    uint32_t* groupValues,
    void* groupDestMethods,
    uint32_t  groupCount,
    bool      doReset,
    bool      resetObjects);

static DWORD WINAPI ApplyRescueTimeoutThread(LPVOID param);

static void StartApplyRescueTimeoutThread();

static SetSelectLangList_t  oSetSelectLangList = nullptr;
static UpdateLangList_t     oUpdateLangList = nullptr;
static DecideLangList_t     oDecideLangList = nullptr;
static UpdateLangPopup_t    oUpdateLangPopup = nullptr;
static ChangeLanguage_t     oChangeLanguage = nullptr;
static ApplyFormVariation_t oApplyFormVariation = nullptr;

static void* gTargetSetSelectLangList = nullptr;
static void* gTargetUpdateLangList = nullptr;
static void* gTargetDecideLangList = nullptr;
static void* gTargetUpdateLangPopup = nullptr;
static void* gTargetChangeLanguage = nullptr;
static void* gTargetApplyFormVariation = nullptr;

static thread_local bool gInOriginalSetSelectLangList = false;

static std::unordered_map<void*, uint32_t> gCurrentPageByPopup;

static thread_local void* gLastGoodApplyFormVariationThis = nullptr;

static std::atomic_bool gApplyRescueHookCreated{ false };
static std::atomic_bool gApplyRescueHookEnabled{ false };

static std::atomic_bool     gApplyRescueSessionActive{ false };
static std::atomic_bool     gApplyRescueTimerStarted{ false };
static std::atomic_uint64_t gApplyRescueSessionToken{ 0 };

struct PopupRowRef
{
    uint64_t enableHandle;
    uint64_t normalHandle;
    uint64_t selectHandle;
    uint64_t entryHandle;
    uint64_t layoutHandle;
};

// Function:
// - Describes the popup mode decoded from this+0xA1.
// Params:
// - none
// Returns:
// - none
enum class PopupMode
{
    Full8,
    Filtered4,
    Compact2
};

// Function:
// - Identifies what one physical popup slot represents.
// Params:
// - none
// Returns:
// - none
enum class PageItemKind
{
    Empty,
    Language,
    Prev,
    Next
};

// Function:
// - Describes one logical item rendered into one popup row.
// Params:
// - none
// Returns:
// - none
struct PageItem
{
    PageItemKind kind = PageItemKind::Empty;
    uint32_t     langId = kInvalidLangId;
};

// Function:
// - Holds one rendered popup page across the 9 real rows.
// Params:
// - none
// Returns:
// - none
struct PopupPage
{
    std::array<PageItem, kPhysicalRowCount> slots{};
    uint32_t visibleCount = 0;
};

// Function:
// - Temporary 16-byte aligned float payload used by the engine UI setter.
// Params:
// - none
// Returns:
// - none
struct alignas(16) UiFloatParam
{
    float x;
    float y;
    float z;
    float w;
};

static_assert(sizeof(UiFloatParam) == 16, "UiFloatParam must be 16 bytes");
static_assert(alignof(UiFloatParam) == 16, "UiFloatParam must be 16-byte aligned");

// ------------------------------------------------------------
// Function: ToRuntimeVA
// Converts an IDA absolute VA into a runtime VA using the game module.
// Params:
// - hGame: game module base
// - absVa: IDA absolute VA
// Returns:
// - runtime VA
// ------------------------------------------------------------

static uintptr_t ToRuntimeVA(HMODULE hGame, uintptr_t absVa)
{
    return reinterpret_cast<uintptr_t>(hGame) + (absVa - IDA_IMAGE_BASE);
}

// ------------------------------------------------------------
// Function: GetVFunc
// Reads a virtual function pointer from an object's vtable by byte offset.
// Params:
// - obj: object instance
// - byteOffset: vtable byte offset such as 0x590
// Returns:
// - typed function pointer or nullptr
// ------------------------------------------------------------

template <typename T>
static T GetVFunc(void* obj, size_t byteOffset)
{
    if (!obj)
        return nullptr;

    auto*** p = reinterpret_cast<void***>(obj);
    if (!p || !*p)
        return nullptr;

    return reinterpret_cast<T>((*p)[byteOffset / sizeof(void*)]);
}

// ------------------------------------------------------------
// Function: GetPopupMode
// Reads popup flags at this+0xA1 and maps them to one of the 3 popup modes.
// Params:
// - thisPtr: popup instance
// Returns:
// - popup mode enum
// ------------------------------------------------------------

static PopupMode GetPopupMode(void* thisPtr)
{
    const uint8_t flags =
        *reinterpret_cast<uint8_t*>(reinterpret_cast<uint8_t*>(thisPtr) + 0xA1);

    if (flags & 0x01)
        return PopupMode::Compact2;

    if (flags & 0x02)
        return PopupMode::Filtered4;

    return PopupMode::Full8;
}

static void* GetUiObject(void* thisPtr)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const uint64_t owner = *reinterpret_cast<uint64_t*>(base + 0x40);
    if (!owner)
        return nullptr;

    return *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(owner) + 0x20);
}

static constexpr uint64_t kExtraRowLayouts[kPhysicalRowCount - kGameRowCount] = { 0x1EF9722A339Full,
                                                                                  0x35CBD98FD133ull };
static constexpr uint64_t kRowModelName = 0xB1B9556CD4A8ull;
static constexpr uint64_t kRowNormalAnim = 0x731EE2FA4A29ull;
static constexpr uint64_t kRowSelectAnim = 0xEB70DFE9D335ull;
static constexpr uint64_t kRowEntryAnim = 0x98AB22DA0790ull;
static constexpr uint64_t kRowNameNode = 0x44DED9C6E075ull;
static constexpr size_t kPopupLayoutRoot = 0x50;

struct ExtraRows
{
    std::array<PopupRowRef, kPhysicalRowCount - kGameRowCount> rows{};
    bool ready = false;
};

static std::unordered_map<void*, ExtraRows> gExtraRows;

template <typename T>
static T GetVFunc(void* obj, size_t byteOffset);

static uint64_t UiLookup(void* uiObj, size_t slot, uint64_t parent, uint64_t name)
{
    using Fn = uint64_t(__fastcall*)(void*, uint64_t, uint64_t);
    Fn fn = GetVFunc<Fn>(uiObj, slot);
    return fn ? fn(uiObj, parent, name) : 0;
}

static bool ResolveExtraRows(void* thisPtr, void* uiObj)
{
    ExtraRows& extra = gExtraRows[thisPtr];
    const bool wasReady = extra.ready;
    extra.ready = false;
    const uint64_t root = *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(thisPtr) + kPopupLayoutRoot);
    if (!uiObj || !root)
        return false;
    std::array<PopupRowRef, kPhysicalRowCount - kGameRowCount> found{};
    for (size_t i = 0; i < found.size(); ++i)
    {
        const uint64_t layout = UiLookup(uiObj, 0x220, root, kExtraRowLayouts[i]);
        if (!layout)
        {
            Log("[LangSelectPopup] extra row %zu not in the layout file - the list keeps 9 rows and pages.\n", i + 10);
            return false;
        }
        PopupRowRef& row = found[i];
        row.enableHandle = UiLookup(uiObj, 0x248, layout, kRowModelName);
        row.normalHandle = UiLookup(uiObj, 0x258, layout, kRowNormalAnim);
        row.selectHandle = UiLookup(uiObj, 0x258, layout, kRowSelectAnim);
        row.entryHandle = UiLookup(uiObj, 0x258, layout, kRowEntryAnim);
        row.layoutHandle = row.enableHandle ? UiLookup(uiObj, 0x290, row.enableHandle, kRowNameNode) : 0;
        if (!row.enableHandle || !row.normalHandle || !row.selectHandle || !row.entryHandle || !row.layoutHandle)
        {
            Log("[LangSelectPopup] extra row %zu is incomplete - the list keeps 9 rows and pages.\n", i + 10);
            return false;
        }
        using PlayFn = void(__fastcall*)(void*, uint64_t, int);
        if (PlayFn play = GetVFunc<PlayFn>(uiObj, 0x680))
            play(uiObj, row.selectHandle, 1);
    }
    extra.rows = found;
    extra.ready = true;
    if (!wasReady)
        Log("[LangSelectPopup] all %d languages fit on one screen (rows 10-11 found in the layout file).\n",
            kPhysicalRowCount);
    return true;
}

static PopupRowRef GetPopupRowRef(void* thisPtr, int rowIndex)
{
    if (rowIndex >= kGameRowCount)
    {
        const auto it = gExtraRows.find(thisPtr);
        if (it == gExtraRows.end() || !it->second.ready || rowIndex >= kPhysicalRowCount)
            return PopupRowRef{};
        return it->second.rows[rowIndex - kGameRowCount];
    }
    auto* rowBase = reinterpret_cast<uint8_t*>(thisPtr) + 0xC0 + (rowIndex * 0x30);

    PopupRowRef row{};
    row.enableHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x00);
    row.normalHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x08);
    row.selectHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x10);
    row.entryHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x18);
    row.layoutHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x20);
    return row;
}

static UiFloatParam MakeUiFloatParam(float value)
{
    UiFloatParam out{};
    out.x = value;
    out.y = 0.0f;
    out.z = 0.0f;
    out.w = 0.0f;
    return out;
}

static void UiCall_2B0_SetRowVisible(void* uiObj, uint64_t handle, int visible)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t, int);
    Fn fn = GetVFunc<Fn>(uiObj, 0x2B0);
    if (fn)
        fn(uiObj, handle, visible);
}

static void UiCall_590_SetLayoutFloat(void* uiObj, uint64_t layoutHandle, uint64_t propHash, float value)
{
    if (!uiObj || !layoutHandle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t, uint64_t, const UiFloatParam*);
    Fn fn = GetVFunc<Fn>(uiObj, 0x590);
    if (!fn)
        return;

    const UiFloatParam temp = MakeUiFloatParam(value);
    fn(uiObj, layoutHandle, propHash, &temp);
}

static void UiCall_6B0(void* uiObj, uint64_t handle)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t);
    Fn fn = GetVFunc<Fn>(uiObj, 0x6B0);
    if (fn)
        fn(uiObj, handle);
}

static void UiCall_678(void* uiObj, uint64_t handle)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t);
    Fn fn = GetVFunc<Fn>(uiObj, 0x678);
    if (fn)
        fn(uiObj, handle);
}

static std::vector<uint32_t> BuildLanguagePool()
{
    std::vector<uint32_t> out;
    out.reserve((sizeof(kBaseFullLangIds) / sizeof(kBaseFullLangIds[0])) + kExtraLangIds.size());

    for (uint32_t id : kBaseFullLangIds)
        out.push_back(id);

    for (uint32_t id : kExtraLangIds)
    {
        if (std::find(out.begin(), out.end(), id) == out.end())
            out.push_back(id);
    }

    return out;
}

static bool IsFakeScrollFullMode(void* thisPtr)
{
    if (!thisPtr)
        return false;

    if (GetPopupMode(thisPtr) != PopupMode::Full8)
        return false;

    const std::vector<uint32_t> pool = BuildLanguagePool();
    return pool.size() > 8;
}

static uint32_t& GetCurrentPageRef(void* thisPtr)
{
    return gCurrentPageByPopup[thisPtr];
}

static std::vector<uint32_t> BuildPageStarts(uint32_t totalLangs)
{
    std::vector<uint32_t> starts;

    if (totalLangs == 0)
        return starts;

    starts.push_back(0);

    if (totalLangs <= 8 || totalLangs <= static_cast<uint32_t>(gRowCapacity))
        return starts;

    uint32_t start = 8;
    starts.push_back(start);

    while ((totalLangs - start) > 8)
    {
        start += 7;
        starts.push_back(start);
    }

    return starts;
}

static uint32_t ClampPageIndex(uint32_t pageIndex, const std::vector<uint32_t>& starts)
{
    if (starts.empty())
        return 0;

    if (pageIndex >= static_cast<uint32_t>(starts.size()))
        return static_cast<uint32_t>(starts.size() - 1);

    return pageIndex;
}

static bool GetLangDisplayPosition(uint32_t langId, float& outX, float& outY)
{
    switch (langId)
    {
    case 0:  outX = 0.0f; outY = 0.125f; return true;
    case 1:  outX = 0.0f; outY = 0.250f; return true;
    case 2:  outX = 0.0f; outY = 0.625f; return true;
    case 3:  outX = 0.0f; outY = 0.750f; return true;
    case 4:  outX = 0.0f; outY = 0.375f; return true;
    case 5:  outX = 0.0f; outY = 0.500f; return true;
    case 6:  outX = 0.0f; outY = 0.875f; return true;
    case 7:  outX = 0.5f; outY = 0.000f; return true;
    case 8:  outX = 0.0f; outY = 0.000f; return true;
    case 9:  outX = 0.5f; outY = 0.125f; return true;
    case 10: outX = 0.5f; outY = 0.250f; return true;
    default:
        break;
    }

    outX = 0.0f;
    outY = 0.0f;
    return false;
}

static bool GetControlDisplayPosition(PageItemKind kind, float& outX, float& outY)
{
    switch (kind)
    {
    case PageItemKind::Prev:
        outX = 0.5f;
        outY = 0.375f;
        return true;

    case PageItemKind::Next:
        outX = 0.5f;
        outY = 0.375f;
        return true;

    default:
        break;
    }

    outX = 0.0f;
    outY = 0.0f;
    return false;
}

static bool GetPageItemDisplayPosition(const PageItem& item, float& outX, float& outY)
{
    if (item.kind == PageItemKind::Language)
        return GetLangDisplayPosition(item.langId, outX, outY);

    return GetControlDisplayPosition(item.kind, outX, outY);
}

static PopupPage BuildPage(uint32_t pageIndex, const std::vector<uint32_t>& pool)
{
    PopupPage page{};

    if (pool.empty())
        return page;

    const std::vector<uint32_t> starts = BuildPageStarts(static_cast<uint32_t>(pool.size()));
    if (starts.empty())
        return page;

    pageIndex = ClampPageIndex(pageIndex, starts);

    const uint32_t start = starts[pageIndex];
    const uint32_t total = static_cast<uint32_t>(pool.size());
    const uint32_t remain = total - start;

    const bool hasPrev = (pageIndex > 0);
    const bool hasNext = (pageIndex + 1 < static_cast<uint32_t>(starts.size()));

    auto pushLanguage = [&](uint32_t langId)
        {
            if (page.visibleCount >= static_cast<uint32_t>(gRowCapacity))
                return;

            page.slots[page.visibleCount].kind = PageItemKind::Language;
            page.slots[page.visibleCount].langId = langId;
            ++page.visibleCount;
        };

    auto pushControl = [&](PageItemKind kind)
        {
            if (page.visibleCount >= static_cast<uint32_t>(gRowCapacity))
                return;

            page.slots[page.visibleCount].kind = kind;
            page.slots[page.visibleCount].langId = kInvalidLangId;
            ++page.visibleCount;
        };

    if (!hasPrev)
    {
        const uint32_t langCount = hasNext ? 8u : ((remain < static_cast<uint32_t>(gRowCapacity)) ? remain : static_cast<uint32_t>(gRowCapacity));

        for (uint32_t i = 0; i < langCount && (start + i) < total; ++i)
            pushLanguage(pool[start + i]);

        if (hasNext)
            pushControl(PageItemKind::Next);
    }
    else
    {
        pushControl(PageItemKind::Prev);

        const uint32_t langCount = hasNext ? 7u : ((remain < 8u) ? remain : 8u);

        for (uint32_t i = 0; i < langCount && (start + i) < total; ++i)
            pushLanguage(pool[start + i]);

        if (hasNext)
            pushControl(PageItemKind::Next);
    }

    return page;
}

static uint32_t FindFirstRealLanguageRow(const PopupPage& page)
{
    for (uint32_t i = 0; i < page.visibleCount; ++i)
    {
        if (page.slots[i].kind == PageItemKind::Language)
            return i;
    }

    return 0;
}

static uint32_t FindLastRealLanguageRow(const PopupPage& page)
{
    if (page.visibleCount == 0)
        return 0;

    for (uint32_t i = page.visibleCount; i-- > 0; )
    {
        if (page.slots[i].kind == PageItemKind::Language)
            return i;
    }

    return 0;
}

static uint32_t ClampCurrentSelection(void* thisPtr, uint32_t visibleCount)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    uint32_t currentIndex = *reinterpret_cast<uint32_t*>(base + 0xA4);

    if (visibleCount == 0)
        currentIndex = 0;
    else if (currentIndex >= visibleCount)
        currentIndex = visibleCount - 1;

    *reinterpret_cast<uint32_t*>(base + 0xA4) = currentIndex;
    return currentIndex;
}

static void SetSelectionIndex(void* thisPtr, uint32_t newIndex)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const uint32_t oldIndex = *reinterpret_cast<uint32_t*>(base + 0xA4);
    *reinterpret_cast<uint32_t*>(base + 0xA8) = oldIndex;
    *reinterpret_cast<uint32_t*>(base + 0xA4) = newIndex;

    auto* listObj = *reinterpret_cast<uint8_t**>(base + 0x48);
    if (listObj)
        *reinterpret_cast<uint32_t*>(listObj + 0x18) = newIndex;
}

static void ClearCommittedEntryHandle(void* thisPtr)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    *reinterpret_cast<uint64_t*>(base + 0x98) = 0;
}

static void SyncListWidgetState(void* thisPtr, uint32_t visibleCount)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    auto* listObj = *reinterpret_cast<uint8_t**>(base + 0x48);
    if (!listObj)
        return;

    *reinterpret_cast<uint32_t*>(listObj + 0x08) |= 0x20;
    *reinterpret_cast<uint32_t*>(listObj + 0x0C) = visibleCount;
    *reinterpret_cast<uint32_t*>(listObj + 0x10) = visibleCount;
    *reinterpret_cast<uint32_t*>(listObj + 0x14) = 0;
    *reinterpret_cast<uint32_t*>(listObj + 0x18) = *reinterpret_cast<uint32_t*>(base + 0xA4);
    *reinterpret_cast<uint32_t*>(listObj + 0x08) |= 0x02;
}

static void ApplyPageItemLayout(void* thisPtr, int physicalRowIndex, const PageItem& item)
{
    void* uiObj = GetUiObject(thisPtr);
    if (!uiObj)
        return;

    float x = 0.0f;
    float y = 0.0f;
    if (!GetPageItemDisplayPosition(item, x, y))
        return;

    const PopupRowRef row = GetPopupRowRef(thisPtr, physicalRowIndex);
    UiCall_590_SetLayoutFloat(uiObj, row.layoutHandle, HASH_TRANSLATE_X, x);
    UiCall_590_SetLayoutFloat(uiObj, row.layoutHandle, HASH_TRANSLATE_Y, y);
}

static PopupPage RenderCurrentPage(void* thisPtr)
{
    PopupPage page{};

    const std::vector<uint32_t> pool = BuildLanguagePool();
    if (pool.empty())
        return page;

    uint32_t& currentPage = GetCurrentPageRef(thisPtr);
    const std::vector<uint32_t> starts = BuildPageStarts(static_cast<uint32_t>(pool.size()));
    currentPage = ClampPageIndex(currentPage, starts);

    page = BuildPage(currentPage, pool);

    void* uiObj = GetUiObject(thisPtr);
    if (!uiObj)
        return page;

    for (int i = 0; i < kPhysicalRowCount; ++i)
    {
        const PopupRowRef row = GetPopupRowRef(thisPtr, i);

        if (i >= static_cast<int>(page.visibleCount) || page.slots[i].kind == PageItemKind::Empty)
        {
            UiCall_2B0_SetRowVisible(uiObj, row.enableHandle, 0);
            continue;
        }

        UiCall_2B0_SetRowVisible(uiObj, row.enableHandle, 1);
        ApplyPageItemLayout(thisPtr, i, page.slots[i]);
    }

    ClampCurrentSelection(thisPtr, page.visibleCount);
    SyncListWidgetState(thisPtr, page.visibleCount);
    return page;
}

static bool ApplyCurrentPageSelectionVisuals(void* thisPtr)
{
    if (!IsFakeScrollFullMode(thisPtr))
        return false;

    const PopupPage page = RenderCurrentPage(thisPtr);

    void* uiObj = GetUiObject(thisPtr);
    if (!uiObj)
        return true;

    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    const uint32_t selectedIndex = ClampCurrentSelection(thisPtr, page.visibleCount);

    for (uint32_t i = 0; i < page.visibleCount; ++i)
    {
        const PopupRowRef row = GetPopupRowRef(thisPtr, static_cast<int>(i));

        if (i == selectedIndex)
        {
            UiCall_6B0(uiObj, row.selectHandle);
            UiCall_678(uiObj, row.normalHandle);

            if (page.slots[i].kind == PageItemKind::Language)
                *reinterpret_cast<uint32_t*>(base + 0xAC) = page.slots[i].langId;
        }
        else
        {
            UiCall_6B0(uiObj, row.normalHandle);
            UiCall_678(uiObj, row.selectHandle);
        }
    }

    SyncListWidgetState(thisPtr, page.visibleCount);
    return true;
}

static void CommitSelectedLanguageRow(void* thisPtr, uint32_t selectedPhysicalIndex)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const PopupRowRef row = GetPopupRowRef(thisPtr, static_cast<int>(selectedPhysicalIndex));
    *reinterpret_cast<uint64_t*>(base + 0x98) = row.entryHandle;

    if (row.entryHandle != 0)
    {
        void* uiObj = GetUiObject(thisPtr);
        UiCall_678(uiObj, row.entryHandle);
    }
}

static bool AutoRetreatFakeScrollOnHighlight(void* thisPtr)
{
    if (!IsFakeScrollFullMode(thisPtr))
        return false;

    const std::vector<uint32_t> pool = BuildLanguagePool();
    if (pool.empty())
        return false;

    const std::vector<uint32_t> starts = BuildPageStarts(static_cast<uint32_t>(pool.size()));
    if (starts.empty())
        return false;

    uint32_t& currentPage = GetCurrentPageRef(thisPtr);
    currentPage = ClampPageIndex(currentPage, starts);

    const PopupPage page = BuildPage(currentPage, pool);
    const uint32_t selectedIndex = ClampCurrentSelection(thisPtr, page.visibleCount);

    if (selectedIndex >= page.visibleCount)
        return false;

    if (page.slots[selectedIndex].kind != PageItemKind::Prev)
        return false;

    if (currentPage == 0)
        return false;

    --currentPage;

    const PopupPage newPage = BuildPage(currentPage, pool);
    const uint32_t targetRow = FindLastRealLanguageRow(newPage);

    SetSelectionIndex(thisPtr, targetRow);
    ClearCommittedEntryHandle(thisPtr);
    RenderCurrentPage(thisPtr);
    ApplyCurrentPageSelectionVisuals(thisPtr);

    Log("[LangSelectPopup] Fake-scroll moved back to page=%u selectRow=%u\n",
        static_cast<unsigned>(currentPage),
        static_cast<unsigned>(targetRow));

    return true;
}

static bool AutoAdvanceFakeScrollOnHighlight(void* thisPtr)
{
    if (!IsFakeScrollFullMode(thisPtr))
        return false;

    const std::vector<uint32_t> pool = BuildLanguagePool();
    if (pool.empty())
        return false;

    const std::vector<uint32_t> starts = BuildPageStarts(static_cast<uint32_t>(pool.size()));
    if (starts.empty())
        return false;

    uint32_t& currentPage = GetCurrentPageRef(thisPtr);
    currentPage = ClampPageIndex(currentPage, starts);

    const PopupPage page = BuildPage(currentPage, pool);
    const uint32_t selectedIndex = ClampCurrentSelection(thisPtr, page.visibleCount);

    if (selectedIndex >= page.visibleCount)
        return false;

    if (page.slots[selectedIndex].kind != PageItemKind::Next)
        return false;

    if ((currentPage + 1) >= static_cast<uint32_t>(starts.size()))
        return false;

    ++currentPage;

    const PopupPage newPage = BuildPage(currentPage, pool);
    const uint32_t targetRow = FindFirstRealLanguageRow(newPage);

    SetSelectionIndex(thisPtr, targetRow);
    ClearCommittedEntryHandle(thisPtr);
    RenderCurrentPage(thisPtr);
    ApplyCurrentPageSelectionVisuals(thisPtr);

    Log("[LangSelectPopup] Fake-scroll advanced to page=%u selectRow=%u\n",
        static_cast<unsigned>(currentPage),
        static_cast<unsigned>(targetRow));

    return true;
}

static bool HandleFakeScrollConfirm(void* thisPtr)
{
    if (!IsFakeScrollFullMode(thisPtr))
        return false;

    const std::vector<uint32_t> pool = BuildLanguagePool();
    if (pool.empty())
        return true;

    const std::vector<uint32_t> starts = BuildPageStarts(static_cast<uint32_t>(pool.size()));
    uint32_t& currentPage = GetCurrentPageRef(thisPtr);
    currentPage = ClampPageIndex(currentPage, starts);

    const PopupPage page = BuildPage(currentPage, pool);
    const uint32_t selectedIndex = ClampCurrentSelection(thisPtr, page.visibleCount);

    if (selectedIndex >= page.visibleCount)
        return true;

    if (page.slots[selectedIndex].kind == PageItemKind::Language)
    {
        CommitSelectedLanguageRow(thisPtr, selectedIndex);
        return true;
    }

    return true;
}

static bool CreateAndEnableHook(void* target, void* detour, void** original, const char* name)
{
    const MH_STATUS createSt = MH_CreateHook(target, detour, original);
    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[%s] MH_CreateHook failed: %d\n", name, static_cast<int>(createSt));
        return false;
    }

    const MH_STATUS enableSt = MH_EnableHook(target);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[%s] MH_EnableHook failed: %d\n", name, static_cast<int>(enableSt));
        return false;
    }

    Log("[%s] Hook enabled.\n", name);
    return true;
}

static void DisableApplyFormVariationRescueHook()
{
    gApplyRescueSessionActive.store(false);
    gApplyRescueTimerStarted.store(false);
    gLastGoodApplyFormVariationThis = nullptr;

    if (!gApplyRescueHookEnabled.load() || !gTargetApplyFormVariation)
        return;

    const MH_STATUS disableSt = MH_DisableHook(gTargetApplyFormVariation);
    if (disableSt != MH_OK && disableSt != MH_ERROR_DISABLED)
    {
        Log("[ApplyRescue_FAKE_SCROLL] MH_DisableHook failed: %d\n", static_cast<int>(disableSt));
        return;
    }

    gApplyRescueHookEnabled.store(false);
    Log("[ApplyRescue_FAKE_SCROLL] Hook disabled after timeout.\n");
}

static DWORD WINAPI ApplyRescueTimeoutThread(LPVOID param)
{
    const uint64_t token = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(param));

    Sleep(kApplyRescueKeepAliveMs);

    const bool sameSession =
        (gApplyRescueSessionToken.load() == token);

    const bool sessionStillActive =
        gApplyRescueSessionActive.load();

    if (sameSession && sessionStillActive)
    {
        Log("[ApplyRescue_FAKE_SCROLL] Timeout expired for session %llu. Detaching rescue hook.\n",
            static_cast<unsigned long long>(token));
        DisableApplyFormVariationRescueHook();
    }

    return 0;
}

static void StartApplyRescueTimeoutThread()
{
    if (gApplyRescueTimerStarted.exchange(true))
        return;

    const uint64_t token = gApplyRescueSessionToken.load();

    HANDLE hThread = CreateThread(
        nullptr,
        0,
        &ApplyRescueTimeoutThread,
        reinterpret_cast<LPVOID>(static_cast<uintptr_t>(token)),
        0,
        nullptr);

    if (hThread)
    {
        CloseHandle(hThread);
        Log("[ApplyRescue_FAKE_SCROLL] First null rescued. Timeout thread started for %u ms. session=%llu\n",
            static_cast<unsigned>(kApplyRescueKeepAliveMs),
            static_cast<unsigned long long>(token));
    }
    else
    {
        gApplyRescueTimerStarted.store(false);
        Log("[ApplyRescue_FAKE_SCROLL] Failed to start timeout thread.\n");
    }
}

static bool PrepareApplyFormVariationRescueHook()
{
    if (gApplyRescueHookCreated.load())
        return true;

    HMODULE hGame = GetModuleHandleW(nullptr);
    if (!hGame)
        return false;

    gTargetApplyFormVariation =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ApplyFormVariation));

    if (!gTargetApplyFormVariation)
    {
        Log("[ApplyRescue_FAKE_SCROLL] Failed to resolve target.\n");
        return false;
    }

    const MH_STATUS createSt =
        MH_CreateHook(
            gTargetApplyFormVariation,
            reinterpret_cast<void*>(&hkApplyFormVariation),
            reinterpret_cast<void**>(&oApplyFormVariation));

    if (createSt != MH_OK && createSt != MH_ERROR_ALREADY_CREATED)
    {
        Log("[ApplyRescue_FAKE_SCROLL] MH_CreateHook failed: %d\n", static_cast<int>(createSt));
        return false;
    }

    gApplyRescueHookCreated.store(true);
    Log("[ApplyRescue_FAKE_SCROLL] Hook prepared at %p\n", gTargetApplyFormVariation);
    return true;
}

static bool EnableApplyFormVariationRescueHook()
{
    if (!PrepareApplyFormVariationRescueHook())
        return false;

    gLastGoodApplyFormVariationThis = nullptr;
    gApplyRescueSessionActive.store(true);
    gApplyRescueTimerStarted.store(false);

    const uint64_t newToken = gApplyRescueSessionToken.fetch_add(1) + 1;

    if (gApplyRescueHookEnabled.load())
    {
        Log("[ApplyRescue_FAKE_SCROLL] Session armed for extended popup. session=%llu\n",
            static_cast<unsigned long long>(newToken));
        return true;
    }

    const MH_STATUS enableSt = MH_EnableHook(gTargetApplyFormVariation);
    if (enableSt != MH_OK && enableSt != MH_ERROR_ENABLED)
    {
        Log("[ApplyRescue_FAKE_SCROLL] MH_EnableHook failed: %d\n", static_cast<int>(enableSt));
        return false;
    }

    gApplyRescueHookEnabled.store(true);
    Log("[ApplyRescue_FAKE_SCROLL] Hook enabled for extended popup. session=%llu\n",
        static_cast<unsigned long long>(newToken));
    return true;
}

static void RemoveApplyFormVariationRescueHookCompletely()
{
    DisableApplyFormVariationRescueHook();

    if (gTargetApplyFormVariation)
    {
        MH_RemoveHook(gTargetApplyFormVariation);
        gTargetApplyFormVariation = nullptr;
    }

    oApplyFormVariation = nullptr;
    gApplyRescueHookCreated.store(false);

    Log("[ApplyRescue_FAKE_SCROLL] Hook fully removed.\n");
}

static bool __fastcall hkApplyFormVariation(
    void* thisPtr,
    void* model,
    void* connectPointFile,
    void* partsBuildDirector,
    void* resourceManager,
    uint32_t* groupValues,
    void* groupDestMethods,
    uint32_t  groupCount,
    bool      doReset,
    bool      resetObjects)
{
    if (!oApplyFormVariation)
        return false;

    if (thisPtr != nullptr)
    {
        gLastGoodApplyFormVariationThis = thisPtr;

        LogDetail("[ApplyRescue_FAKE_SCROLL] normal this=%p model=%p cp=%p pbd=%p rm=%p count=%u reset=%u resetObjs=%u session=%u timerStarted=%u token=%llu\n",
            thisPtr,
            model,
            connectPointFile,
            partsBuildDirector,
            resourceManager,
            static_cast<unsigned>(groupCount),
            static_cast<unsigned>(doReset),
            static_cast<unsigned>(resetObjects),
            static_cast<unsigned>(gApplyRescueSessionActive.load()),
            static_cast<unsigned>(gApplyRescueTimerStarted.load()),
            static_cast<unsigned long long>(gApplyRescueSessionToken.load()));

        return oApplyFormVariation(
            thisPtr,
            model,
            connectPointFile,
            partsBuildDirector,
            resourceManager,
            groupValues,
            groupDestMethods,
            groupCount,
            doReset,
            resetObjects);
    }

    Log("[ApplyRescue_FAKE_SCROLL] NULL this detected. model=%p cp=%p pbd=%p rm=%p count=%u reset=%u resetObjs=%u cached=%p session=%u timerStarted=%u token=%llu\n",
        model,
        connectPointFile,
        partsBuildDirector,
        resourceManager,
        static_cast<unsigned>(groupCount),
        static_cast<unsigned>(doReset),
        static_cast<unsigned>(resetObjects),
        gLastGoodApplyFormVariationThis,
        static_cast<unsigned>(gApplyRescueSessionActive.load()),
        static_cast<unsigned>(gApplyRescueTimerStarted.load()),
        static_cast<unsigned long long>(gApplyRescueSessionToken.load()));

    void* const cachedThis = gLastGoodApplyFormVariationThis;
    if (cachedThis != nullptr)
    {
        StartApplyRescueTimeoutThread();

        Log("[ApplyRescue_FAKE_SCROLL] Forcing cached this=%p\n", cachedThis);

        return oApplyFormVariation(
            cachedThis,
            model,
            connectPointFile,
            partsBuildDirector,
            resourceManager,
            groupValues,
            groupDestMethods,
            groupCount,
            doReset,
            resetObjects);
    }

    Log("[ApplyRescue_FAKE_SCROLL] No cached this available. Returning false.\n");
    return false;
}

static void __fastcall hkSetSelectLangList(void* thisPtr)
{
    if (!oSetSelectLangList)
        return;

    gInOriginalSetSelectLangList = true;
    oSetSelectLangList(thisPtr);
    gInOriginalSetSelectLangList = false;

    void* uiObj = GetUiObject(thisPtr);
    const bool extraRows = ResolveExtraRows(thisPtr, uiObj);
    const bool fullMode = IsFakeScrollFullMode(thisPtr);
    gRowCapacity = (extraRows && fullMode) ? kPhysicalRowCount : kGameRowCount;
    if (extraRows && !fullMode)
    {
        for (int i = kGameRowCount; i < kPhysicalRowCount; ++i)
            UiCall_2B0_SetRowVisible(uiObj, GetPopupRowRef(thisPtr, i).enableHandle, 0);
    }

    if (!fullMode)
        return;

    if (!EnableApplyFormVariationRescueHook())
        Log("[LangSelectPopup] Failed to enable ApplyFormVariation rescue hook.\n");

    GetCurrentPageRef(thisPtr) = 0;
    ClearCommittedEntryHandle(thisPtr);

    const PopupPage page = RenderCurrentPage(thisPtr);
    ApplyCurrentPageSelectionVisuals(thisPtr);

    Log("[LangSelectPopup] Fake-scroll full list initialized. page=0 visible=%u totalLangs=%u\n",
        static_cast<unsigned>(page.visibleCount),
        static_cast<unsigned>(BuildLanguagePool().size()));
}

static void __fastcall hkUpdateLangList(void* thisPtr)
{
    if (!oUpdateLangList)
        return;

    if (gInOriginalSetSelectLangList)
    {
        oUpdateLangList(thisPtr);
        return;
    }

    if (!IsFakeScrollFullMode(thisPtr))
    {
        oUpdateLangList(thisPtr);
        return;
    }

    oUpdateLangList(thisPtr);

    ApplyCurrentPageSelectionVisuals(thisPtr);

    if (AutoRetreatFakeScrollOnHighlight(thisPtr))
        return;

    AutoAdvanceFakeScrollOnHighlight(thisPtr);
}

static void __fastcall hkDecideLangList(void* thisPtr)
{
    if (!oDecideLangList)
        return;

    NoteLanguageApplied();

    if (HandleFakeScrollConfirm(thisPtr))
        return;

    oDecideLangList(thisPtr);
}

static void __fastcall hkUpdateLangPopup(void* thisPtr)
{
    if (!oUpdateLangPopup)
        return;

    oUpdateLangPopup(thisPtr);

    if (IsFakeScrollFullMode(thisPtr))
        ApplyCurrentPageSelectionVisuals(thisPtr);
}

static int __fastcall hkChangeLanguage(void* luaState)
{
    Log("[ChangeLanguage] called\n");
    FlushLog();
    const int result = oChangeLanguage ? oChangeLanguage(luaState) : 0;
    NoteLanguageApplied();
    return result;
}


bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame)
{
    if (!hGame)
        return false;

    gTargetSetSelectLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.SetSelectLangList));
    gTargetUpdateLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UpdateLangList));
    gTargetDecideLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.DecideLangList));
    gTargetUpdateLangPopup = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.UpdateLangPopup));
    gTargetChangeLanguage = reinterpret_cast<void*>(ToRuntimeVA(hGame, gAddr.ChangeLanguage));

    if (!gTargetSetSelectLangList || !gTargetUpdateLangList ||
        !gTargetDecideLangList || !gTargetUpdateLangPopup || !gTargetChangeLanguage)
    {
        Log("[LangSelectPopup] Failed to resolve one or more targets.\n");
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetSetSelectLangList,
        reinterpret_cast<void*>(&hkSetSelectLangList),
        reinterpret_cast<void**>(&oSetSelectLangList),
        "LangSelectPopup::SetSelectLangList"))
    {
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetUpdateLangList,
        reinterpret_cast<void*>(&hkUpdateLangList),
        reinterpret_cast<void**>(&oUpdateLangList),
        "LangSelectPopup::UpdateLangList"))
    {
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetDecideLangList,
        reinterpret_cast<void*>(&hkDecideLangList),
        reinterpret_cast<void**>(&oDecideLangList),
        "LangSelectPopup::DecideLangList"))
    {
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetUpdateLangPopup,
        reinterpret_cast<void*>(&hkUpdateLangPopup),
        reinterpret_cast<void**>(&oUpdateLangPopup),
        "LangSelectPopup::UpdateLangPopup"))
    {
        return false;
    }

    if (!CreateAndEnableHook(
        gTargetChangeLanguage,
        reinterpret_cast<void*>(&hkChangeLanguage),
        reinterpret_cast<void**>(&oChangeLanguage),
        "LangSelectPopup::ChangeLanguage"))
    {
        return false;
    }

    gCurrentPageByPopup.clear();
    gInOriginalSetSelectLangList = false;

    Log("[LangSelectPopup] Fake-scroll rewrite hooks installed.\n");
    return true;
}

void RemoveLangSelectPopupPagedRewriteHooks()
{
    if (gTargetSetSelectLangList)
    {
        MH_DisableHook(gTargetSetSelectLangList);
        MH_RemoveHook(gTargetSetSelectLangList);
        gTargetSetSelectLangList = nullptr;
    }

    if (gTargetUpdateLangList)
    {
        MH_DisableHook(gTargetUpdateLangList);
        MH_RemoveHook(gTargetUpdateLangList);
        gTargetUpdateLangList = nullptr;
    }

    if (gTargetDecideLangList)
    {
        MH_DisableHook(gTargetDecideLangList);
        MH_RemoveHook(gTargetDecideLangList);
        gTargetDecideLangList = nullptr;
    }

    if (gTargetUpdateLangPopup)
    {
        MH_DisableHook(gTargetUpdateLangPopup);
        MH_RemoveHook(gTargetUpdateLangPopup);
        gTargetUpdateLangPopup = nullptr;
    }

    if (gTargetChangeLanguage)
    {
        MH_DisableHook(gTargetChangeLanguage);
        MH_RemoveHook(gTargetChangeLanguage);
        gTargetChangeLanguage = nullptr;
    }

    oSetSelectLangList = nullptr;
    oUpdateLangList = nullptr;
    oDecideLangList = nullptr;
    oUpdateLangPopup = nullptr;
    oChangeLanguage = nullptr;

    gCurrentPageByPopup.clear();
    gInOriginalSetSelectLangList = false;

    RemoveApplyFormVariationRescueHookCompletely();

    Log("[LangSelectPopup] Fake-scroll rewrite hooks removed.\n");
}