// LangSelectPopup_FakeScrollPrevAndNext_WithPopupScopedApplyRescue.cpp
//
// Clean fake-scroll language-popup hook + popup-scoped ApplyFormVariation rescue.
//
// Behavior:
// - Keeps the game's real 9 physical popup rows unchanged
// - Uses fake-scroll paging only in FULL mode when total languages > 8
// - 4-row and 2-row popup modes stay stock
// - Page 1:
//     - up to 8 real languages
//     - row 9 is fake NEXT
// - Page 2+:
//     - row 1 is fake PREV
//     - middle pages: 7 real languages + fake NEXT at row 9
//     - last page: fake PREV + up to 8 real languages
// - Fake NEXT triggers immediately when highlighted
// - Fake PREV triggers immediately when highlighted
// - Fake NEXT semantic position:
//     outX = 0.5f; outY = 0.375f;
// - Fake PREV semantic position:
//     outX = 0.0f; outY = 0.0f;
// - Confirm only commits real language rows
// - When the extended popup appears, ApplyFormVariation rescue is armed
// - First rescued null-this call starts a 10-second keepalive worker thread
// - Repeated null-this ApplyFormVariation calls are rescued during that window
// - After 10 seconds from the first null fix, the rescue hook detaches
//
// Notes:
// - This is still a workaround for the null-this crash path
// - No startup install call for ApplyFormVariation rescue is needed

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

// ------------------------------------------------------------
// Address constants
// ------------------------------------------------------------

static constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
static constexpr uintptr_t ABS_SetSelectLangList = 0x14A4140D0ull;
static constexpr uintptr_t ABS_UpdateLangList = 0x141606250ull;
static constexpr uintptr_t ABS_DecideLangList = 0x14A412670ull;
static constexpr uintptr_t ABS_UpdateLangPopup = 0x141606490ull;
static constexpr uintptr_t ABS_ChangeLanguage = 0x14090F130ull;
static constexpr uintptr_t ABS_ApplyFormVariation = 0x1404E1E60ull;

// Layout property hashes used by the game's +0x590 setter.
static constexpr uint64_t HASH_TRANSLATE_X = 0x1352A707068Bull;
static constexpr uint64_t HASH_TRANSLATE_Y = 0x227F987BF357ull;

// Popup constants.
static constexpr int      kPhysicalRowCount = 9;
static constexpr uint32_t kInvalidLangId = 0xFFFFFFFFu;

// Optional one-shot popup-hook removal after a real language commit.
static constexpr bool kRemovePopupHooksAfterRealSelection = true;

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

// ------------------------------------------------------------
// Hook typedefs
// ------------------------------------------------------------

// Function:
// - Original popup setup function.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
using SetSelectLangList_t = void(__fastcall*)(void* thisPtr);

// Function:
// - Original popup update function.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
using UpdateLangList_t = void(__fastcall*)(void* thisPtr);

// Function:
// - Original popup confirm function.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
using DecideLangList_t = void(__fastcall*)(void* thisPtr);

// Function:
// - Original popup state-machine update function.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
using UpdateLangPopup_t = void(__fastcall*)(void* thisPtr);

// Function:
// - Original committed language change function.
// Params:
// - langId: committed language id
// Returns:
// - none
using ChangeLanguage_t = void(__fastcall*)(uint32_t langId);

// Function:
// - Original ApplyFormVariation function used by the rescue hook.
// Params:
// - standard engine ApplyFormVariation arguments
// Returns:
// - engine result
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

// ------------------------------------------------------------
// Forward declarations
// ------------------------------------------------------------

// Function:
// - Detour for ApplyFormVariation that rescues null-this calls.
// Params:
// - standard ApplyFormVariation args
// Returns:
// - ApplyFormVariation result, or false when rescue cannot be done
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

// Function:
// - Timeout worker that disables the rescue hook after the keepalive window.
// Params:
// - param: session token packed into LPVOID
// Returns:
// - thread exit code
static DWORD WINAPI ApplyRescueTimeoutThread(LPVOID param);

// Function:
// - Starts the one-shot timeout worker after the first rescued null.
// Params:
// - none
// Returns:
// - none
static void StartApplyRescueTimeoutThread();

// ------------------------------------------------------------
// Original trampolines
// ------------------------------------------------------------

static SetSelectLangList_t  oSetSelectLangList = nullptr;
static UpdateLangList_t     oUpdateLangList = nullptr;
static DecideLangList_t     oDecideLangList = nullptr;
static UpdateLangPopup_t    oUpdateLangPopup = nullptr;
static ChangeLanguage_t     oChangeLanguage = nullptr;
static ApplyFormVariation_t oApplyFormVariation = nullptr;

// ------------------------------------------------------------
// Target pointers
// ------------------------------------------------------------

static void* gTargetSetSelectLangList = nullptr;
static void* gTargetUpdateLangList = nullptr;
static void* gTargetDecideLangList = nullptr;
static void* gTargetUpdateLangPopup = nullptr;
static void* gTargetChangeLanguage = nullptr;
static void* gTargetApplyFormVariation = nullptr;

// ------------------------------------------------------------
// Shared state
// ------------------------------------------------------------

static thread_local bool gInOriginalSetSelectLangList = false;
static bool gPopupHooksRemovedAfterSelection = false;

// ------------------------------------------------------------
// Per-popup page state
// ------------------------------------------------------------

// Function:
// - Stores the current logical page index for each popup instance.
// Params:
// - key: popup instance
// Returns:
// - none
static std::unordered_map<void*, uint32_t> gCurrentPageByPopup;

// ------------------------------------------------------------
// ApplyFormVariation rescue state
// ------------------------------------------------------------

// Last non-null FormVariationFile2* seen while rescue is armed.
static thread_local void* gLastGoodApplyFormVariationThis = nullptr;

// Hook lifetime.
static std::atomic_bool gApplyRescueHookCreated{ false };
static std::atomic_bool gApplyRescueHookEnabled{ false };

// Session state:
// - armed when extended popup appears
// - first rescued null starts the worker timer
static std::atomic_bool     gApplyRescueSessionActive{ false };
static std::atomic_bool     gApplyRescueTimerStarted{ false };
static std::atomic_uint64_t gApplyRescueSessionToken{ 0 };

// ------------------------------------------------------------
// Small helper structs
// ------------------------------------------------------------

// Function:
// - References one physical popup row block.
// Params:
// - none
// Returns:
// - none
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

// ------------------------------------------------------------
// Function: GetUiObject
// Returns the same UI object the game uses: *(*(this+0x40)+0x20).
// Params:
// - thisPtr: popup instance
// Returns:
// - UI object pointer or nullptr
// ------------------------------------------------------------

static void* GetUiObject(void* thisPtr)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);

    const uint64_t owner = *reinterpret_cast<uint64_t*>(base + 0x40);
    if (!owner)
        return nullptr;

    return *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(owner) + 0x20);
}

// ------------------------------------------------------------
// Function: GetPopupRowRef
// Returns the handles for one physical popup row block.
// Params:
// - thisPtr: popup instance
// - rowIndex: physical row index 0..8
// Returns:
// - PopupRowRef for that row
// ------------------------------------------------------------

static PopupRowRef GetPopupRowRef(void* thisPtr, int rowIndex)
{
    auto* rowBase = reinterpret_cast<uint8_t*>(thisPtr) + 0xC0 + (rowIndex * 0x30);

    PopupRowRef row{};
    row.enableHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x00);
    row.normalHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x08);
    row.selectHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x10);
    row.entryHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x18);
    row.layoutHandle = *reinterpret_cast<uint64_t*>(rowBase + 0x20);
    return row;
}

// ------------------------------------------------------------
// Function: MakeUiFloatParam
// Builds the aligned temp used by the game's layout float setter.
// Params:
// - value: float value to place into x
// Returns:
// - UiFloatParam temp
// ------------------------------------------------------------

static UiFloatParam MakeUiFloatParam(float value)
{
    UiFloatParam out{};
    out.x = value;
    out.y = 0.0f;
    out.z = 0.0f;
    out.w = 0.0f;
    return out;
}

// ------------------------------------------------------------
// Function: UiCall_2B0_SetRowVisible
// Calls the game's row visibility setter at vtable +0x2B0.
// Params:
// - uiObj: popup UI object
// - handle: row enable handle
// - visible: 0 or 1
// ------------------------------------------------------------

static void UiCall_2B0_SetRowVisible(void* uiObj, uint64_t handle, int visible)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t, int);
    Fn fn = GetVFunc<Fn>(uiObj, 0x2B0);
    if (fn)
        fn(uiObj, handle, visible);
}

// ------------------------------------------------------------
// Function: UiCall_590_SetLayoutFloat
// Calls the game's layout float setter at vtable +0x590.
// Params:
// - uiObj: popup UI object
// - layoutHandle: row layout handle
// - propHash: layout property hash
// - value: float value to set
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: UiCall_6B0
// Calls the game's highlight visual setter at vtable +0x6B0.
// Params:
// - uiObj: popup UI object
// - handle: selected/highlight handle
// ------------------------------------------------------------

static void UiCall_6B0(void* uiObj, uint64_t handle)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t);
    Fn fn = GetVFunc<Fn>(uiObj, 0x6B0);
    if (fn)
        fn(uiObj, handle);
}

// ------------------------------------------------------------
// Function: UiCall_678
// Calls the game's normal/unselected visual setter at vtable +0x678.
// Params:
// - uiObj: popup UI object
// - handle: normal or entry handle
// ------------------------------------------------------------

static void UiCall_678(void* uiObj, uint64_t handle)
{
    if (!uiObj || !handle)
        return;

    using Fn = void(__fastcall*)(void*, uint64_t);
    Fn fn = GetVFunc<Fn>(uiObj, 0x678);
    if (fn)
        fn(uiObj, handle);
}

// ------------------------------------------------------------
// Function: BuildLanguagePool
// Builds the logical full-mode language pool in display order.
// Duplicates are removed while preserving order.
// Params:
// - none
// Returns:
// - logical language pool
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: IsFakeScrollFullMode
// Returns true only when the popup is FULL mode and needs fake-scroll paging.
// Params:
// - thisPtr: popup instance
// Returns:
// - true if custom fake-scroll paging should be used
// ------------------------------------------------------------

static bool IsFakeScrollFullMode(void* thisPtr)
{
    if (!thisPtr)
        return false;

    if (GetPopupMode(thisPtr) != PopupMode::Full8)
        return false;

    const std::vector<uint32_t> pool = BuildLanguagePool();
    return pool.size() > 8;
}

// ------------------------------------------------------------
// Function: GetCurrentPageRef
// Returns the stored logical page index for one popup instance.
// Params:
// - thisPtr: popup instance
// Returns:
// - reference to current page index
// ------------------------------------------------------------

static uint32_t& GetCurrentPageRef(void* thisPtr)
{
    return gCurrentPageByPopup[thisPtr];
}

// ------------------------------------------------------------
// Function: BuildPageStarts
// Builds logical page starts.
// Layout capacity:
// - page 0: 8 real languages if another page exists
// - page 1+: 7 real languages on middle pages, 8 on the last page
// Params:
// - totalLangs: total language count
// Returns:
// - page start offsets
// ------------------------------------------------------------

static std::vector<uint32_t> BuildPageStarts(uint32_t totalLangs)
{
    std::vector<uint32_t> starts;

    if (totalLangs == 0)
        return starts;

    starts.push_back(0);

    if (totalLangs <= 8)
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

// ------------------------------------------------------------
// Function: ClampPageIndex
// Clamps a logical page index to the valid page range.
// Params:
// - pageIndex: requested page index
// - starts: page-start table
// Returns:
// - clamped page index
// ------------------------------------------------------------

static uint32_t ClampPageIndex(uint32_t pageIndex, const std::vector<uint32_t>& starts)
{
    if (starts.empty())
        return 0;

    if (pageIndex >= static_cast<uint32_t>(starts.size()))
        return static_cast<uint32_t>(starts.size() - 1);

    return pageIndex;
}

// ------------------------------------------------------------
// Function: GetLangDisplayPosition
// Returns the semantic display position for a real language id.
// Params:
// - langId: game language id
// - outX: receives X
// - outY: receives Y
// Returns:
// - true if mapped
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: GetControlDisplayPosition
// Returns the display position for one fake control row.
// Params:
// - kind: control type
// - outX: receives X
// - outY: receives Y
// Returns:
// - true if mapped
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: GetPageItemDisplayPosition
// Returns the display position for one page item.
// Params:
// - item: logical page item
// - outX: receives X
// - outY: receives Y
// Returns:
// - true if mapped
// ------------------------------------------------------------

static bool GetPageItemDisplayPosition(const PageItem& item, float& outX, float& outY)
{
    if (item.kind == PageItemKind::Language)
        return GetLangDisplayPosition(item.langId, outX, outY);

    return GetControlDisplayPosition(item.kind, outX, outY);
}

// ------------------------------------------------------------
// Function: BuildPage
// Builds one fake-scroll page.
// Layout:
// - page 0: 8 languages + next if there is another page
// - page 1+: prev first, then real languages, then next if there is another page
// Params:
// - pageIndex: logical page index
// - pool: language pool
// Returns:
// - PopupPage
// ------------------------------------------------------------

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
            if (page.visibleCount >= static_cast<uint32_t>(kPhysicalRowCount))
                return;

            page.slots[page.visibleCount].kind = PageItemKind::Language;
            page.slots[page.visibleCount].langId = langId;
            ++page.visibleCount;
        };

    auto pushControl = [&](PageItemKind kind)
        {
            if (page.visibleCount >= static_cast<uint32_t>(kPhysicalRowCount))
                return;

            page.slots[page.visibleCount].kind = kind;
            page.slots[page.visibleCount].langId = kInvalidLangId;
            ++page.visibleCount;
        };

    if (!hasPrev)
    {
        const uint32_t langCount = hasNext ? 8u : ((remain < 9u) ? remain : 9u);

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

// ------------------------------------------------------------
// Function: FindFirstRealLanguageRow
// Finds the first physical row index that holds a real language.
// Params:
// - page: built popup page
// Returns:
// - physical row index, or 0 if none found
// ------------------------------------------------------------

static uint32_t FindFirstRealLanguageRow(const PopupPage& page)
{
    for (uint32_t i = 0; i < page.visibleCount; ++i)
    {
        if (page.slots[i].kind == PageItemKind::Language)
            return i;
    }

    return 0;
}

// ------------------------------------------------------------
// Function: FindLastRealLanguageRow
// Finds the last physical row index that holds a real language.
// Params:
// - page: built popup page
// Returns:
// - physical row index, or 0 if none found
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ClampCurrentSelection
// Clamps this+0xA4 to the current visible row range.
// Params:
// - thisPtr: popup instance
// - visibleCount: visible row count
// Returns:
// - clamped selected physical index
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: SetSelectionIndex
// Sets current selection index in both popup state and list widget.
// Params:
// - thisPtr: popup instance
// - newIndex: new selected physical row index
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ClearCommittedEntryHandle
// Clears the popup's chosen row entry handle at this+0x98.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
// ------------------------------------------------------------

static void ClearCommittedEntryHandle(void* thisPtr)
{
    auto* base = reinterpret_cast<uint8_t*>(thisPtr);
    *reinterpret_cast<uint64_t*>(base + 0x98) = 0;
}

// ------------------------------------------------------------
// Function: SyncListWidgetState
// Updates the list widget object at this+0x48 with count/index state.
// Params:
// - thisPtr: popup instance
// - visibleCount: visible row count
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ApplyPageItemLayout
// Applies the semantic X/Y layout for one page item into one physical row.
// Params:
// - thisPtr: popup instance
// - physicalRowIndex: physical row slot 0..8
// - item: logical page item shown in that slot
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: RenderCurrentPage
// Renders the current fake-scroll page into the 9 real popup rows.
// Params:
// - thisPtr: popup instance
// Returns:
// - built PopupPage
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ApplyCurrentPageSelectionVisuals
// Updates selection visuals and writes this+0xAC only for real language rows.
// Params:
// - thisPtr: popup instance
// Returns:
// - true if handled by fake-scroll paging
// - false if caller should use stock logic
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: CommitSelectedLanguageRow
// Commits a real language row by writing this+0x98 from the selected
// physical row's entry handle and refreshing that handle once.
// Params:
// - thisPtr: popup instance
// - selectedPhysicalIndex: selected physical row index
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: AutoRetreatFakeScrollOnHighlight
// If fake PREV is highlighted, immediately moves to the previous page.
// Selection lands on the last real language row of that previous page.
// Params:
// - thisPtr: popup instance
// Returns:
// - true if page switched backward
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: AutoAdvanceFakeScrollOnHighlight
// If fake NEXT is highlighted, immediately moves to the next page.
// Selection lands on the first real language row of that next page.
// Params:
// - thisPtr: popup instance
// Returns:
// - true if page switched forward
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: HandleFakeScrollConfirm
// Confirms only real language rows.
// If a fake control is selected, do nothing because page movement already
// happens on highlight.
// Params:
// - thisPtr: popup instance
// Returns:
// - true if handled by fake-scroll paging
// - false if caller should use stock logic
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: IsRealConfiguredLanguageId
// Returns true only for configured language ids in the logical pool.
// Params:
// - langId: language id passed to ChangeLanguage
// Returns:
// - true if it is a real configured language id
// ------------------------------------------------------------

static bool IsRealConfiguredLanguageId(uint32_t langId)
{
    const std::vector<uint32_t> pool = BuildLanguagePool();
    return std::find(pool.begin(), pool.end(), langId) != pool.end();
}

// ------------------------------------------------------------
// Function: CreateAndEnableHook
// Creates and enables one MinHook hook.
// Params:
// - target: target function address
// - detour: detour function
// - original: receives trampoline
// - name: debug label
// Returns:
// - true on success
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: DisableApplyFormVariationRescueHook
// Disables rescue after the timeout worker expires.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: ApplyRescueTimeoutThread
// Waits 10 seconds, then disables the rescue hook only if the same
// popup session is still the active one.
// Params:
// - param: session token packed into LPVOID
// Returns:
// - thread exit code
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: StartApplyRescueTimeoutThread
// Starts the one-shot 10-second timer after the first rescued null.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: PrepareApplyFormVariationRescueHook
// Creates the rescue hook once. Does not enable it yet.
// Params:
// - none
// Returns:
// - true on success
// ------------------------------------------------------------

static bool PrepareApplyFormVariationRescueHook()
{
    if (gApplyRescueHookCreated.load())
        return true;

    HMODULE hGame = GetModuleHandleW(nullptr);
    if (!hGame)
        return false;

    gTargetApplyFormVariation =
        reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_ApplyFormVariation));

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

// ------------------------------------------------------------
// Function: EnableApplyFormVariationRescueHook
// Extended popup appears -> rescue on.
// Params:
// - none
// Returns:
// - true on success
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: RemoveApplyFormVariationRescueHookCompletely
// Fully removes the rescue hook, for manual teardown only.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: hkApplyFormVariation
// Extended popup appears -> armed
// First null fix -> starts real 10-second timeout thread
// More nulls during that window -> rescue
// Timeout thread detaches hook even if no more calls happen
// Params:
// - standard ApplyFormVariation args
// Returns:
// - ApplyFormVariation result, or false if null rescue had no cache
// ------------------------------------------------------------

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

        Log("[ApplyRescue_FAKE_SCROLL] normal this=%p model=%p cp=%p pbd=%p rm=%p count=%u reset=%u resetObjs=%u session=%u timerStarted=%u token=%llu\n",
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

    if (gLastGoodApplyFormVariationThis != nullptr)
    {
        StartApplyRescueTimeoutThread();

        Log("[ApplyRescue_FAKE_SCROLL] Forcing cached this=%p\n", gLastGoodApplyFormVariationThis);

        return oApplyFormVariation(
            gLastGoodApplyFormVariationThis,
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

// ------------------------------------------------------------
// Function: RemovePopupOnlyHooks
// Removes only the popup-related hooks.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

static void RemovePopupOnlyHooks()
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

    oSetSelectLangList = nullptr;
    oUpdateLangList = nullptr;
    oDecideLangList = nullptr;
    oUpdateLangPopup = nullptr;

    gCurrentPageByPopup.clear();
    gInOriginalSetSelectLangList = false;

    Log("[LangSelectPopup] Popup-only hooks removed after real language selection.\n");
}

// ------------------------------------------------------------
// Function: hkSetSelectLangList
// Lets the original build stock state first, then replaces only FULL mode
// with the fake-scroll page model.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
// ------------------------------------------------------------

static void __fastcall hkSetSelectLangList(void* thisPtr)
{
    if (!oSetSelectLangList)
        return;

    gInOriginalSetSelectLangList = true;
    oSetSelectLangList(thisPtr);
    gInOriginalSetSelectLangList = false;

    if (!IsFakeScrollFullMode(thisPtr))
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

// ------------------------------------------------------------
// Function: hkUpdateLangList
// Uses stock logic during original setup.
// In fake-scroll full mode, lets stock process input first, then:
// 1) updates visuals
// 2) checks fake PREV on highlight
// 3) checks fake NEXT on highlight
// Params:
// - thisPtr: popup instance
// Returns:
// - none
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Function: hkDecideLangList
// Confirms only real language rows in fake-scroll full mode.
// Fake control rows do not confirm anything because page movement already
// happens on highlight.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
// ------------------------------------------------------------

static void __fastcall hkDecideLangList(void* thisPtr)
{
    if (!oDecideLangList)
        return;

    if (HandleFakeScrollConfirm(thisPtr))
        return;

    oDecideLangList(thisPtr);
}

// ------------------------------------------------------------
// Function: hkUpdateLangPopup
// Calls the original popup state machine, then reapplies custom visuals
// for fake-scroll full mode.
// Params:
// - thisPtr: popup instance
// Returns:
// - none
// ------------------------------------------------------------

static void __fastcall hkUpdateLangPopup(void* thisPtr)
{
    if (!oUpdateLangPopup)
        return;

    oUpdateLangPopup(thisPtr);

    if (IsFakeScrollFullMode(thisPtr))
        ApplyCurrentPageSelectionVisuals(thisPtr);
}

// ------------------------------------------------------------
// Function: hkChangeLanguage
// Runs when the game actually commits a language change.
// Removes popup hooks before the reload path continues if enabled.
// Params:
// - langId: committed real language id
// Returns:
// - none
// ------------------------------------------------------------

static void __fastcall hkChangeLanguage(uint32_t langId)
{
    Log("[ChangeLanguage] langId=%u\n", langId);

    if (kRemovePopupHooksAfterRealSelection &&
        !gPopupHooksRemovedAfterSelection &&
        IsRealConfiguredLanguageId(langId))
    {
        gPopupHooksRemovedAfterSelection = true;
        RemovePopupOnlyHooks();
    }

    if (oChangeLanguage)
        oChangeLanguage(langId);
}

// ------------------------------------------------------------
// Function: InstallLangSelectPopupPagedRewriteHooks
// Installs the fake-scroll rewrite hooks for the language popup.
// The exported name is kept unchanged so existing dllmain code can stay.
// Params:
// - hGame: game module base
// Returns:
// - true on success
// ------------------------------------------------------------

bool InstallLangSelectPopupPagedRewriteHooks(HMODULE hGame)
{
    if (!hGame)
        return false;

    gTargetSetSelectLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_SetSelectLangList));
    gTargetUpdateLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_UpdateLangList));
    gTargetDecideLangList = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_DecideLangList));
    gTargetUpdateLangPopup = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_UpdateLangPopup));
    gTargetChangeLanguage = reinterpret_cast<void*>(ToRuntimeVA(hGame, ABS_ChangeLanguage));

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
    gPopupHooksRemovedAfterSelection = false;
    gInOriginalSetSelectLangList = false;

    Log("[LangSelectPopup] Fake-scroll rewrite hooks installed.\n");
    return true;
}

// ------------------------------------------------------------
// Function: RemoveLangSelectPopupPagedRewriteHooks
// Removes all popup hooks and fully removes the rescue hook.
// The exported name is kept unchanged so existing dllmain code can stay.
// Params:
// - none
// Returns:
// - none
// ------------------------------------------------------------

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
    gPopupHooksRemovedAfterSelection = false;
    gInOriginalSetSelectLangList = false;

    RemoveApplyFormVariationRescueHookCompletely();

    Log("[LangSelectPopup] Fake-scroll rewrite hooks removed.\n");
}