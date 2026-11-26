#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "MinHook.h"
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

bool RL_LayoutPackSeen();
bool RL_LayoutPackLoad(uint64_t vanillaCode, uint64_t& tick, bool& rightToLeft);

namespace
{
    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr uint32_t TABLE_MAGIC = 0x32544C52;
    constexpr uint32_t TABLE_VERSION = 2;
    constexpr size_t MAX_TABLE_BYTES = 64u * 1024u * 1024u;
    constexpr wchar_t TABLE_FILE[] = L"V_Restored_Languages_Layouts.bin";

    constexpr size_t COMPONENT_NAME = 0x20;
    constexpr size_t COMPONENT_PARENT = 0x38;
    constexpr size_t COMPONENT_TYPE = 0x4A;
    constexpr uint8_t COMPONENT_MODEL = 1;
    constexpr uint8_t COMPONENT_LAYOUT = 2;
    constexpr size_t MODEL_FILE = 0x50;
    constexpr size_t MODEL_ROOT = 0x80;
    constexpr size_t MODEL_NODE_COUNT = 0x90;
    constexpr size_t MODEL_NODES = 0x98;
    constexpr size_t MODEL_ANIMATION_COUNT = 0xA0;
    constexpr size_t MODEL_ANIMATIONS = 0xA8;
    constexpr size_t LAYOUT_NODE = 0x60;
    constexpr size_t LAYOUT_MODEL_COUNT = 0xC0;
    constexpr size_t LAYOUT_MODELS = 0xC8;
    constexpr size_t LAYOUT_CHILD_COUNT = 0xD0;
    constexpr size_t LAYOUT_CHILDREN = 0xD8;
    constexpr size_t ANIMATION_FILE = 0x18;
    constexpr size_t ANIMATION_SHADER_FILE = 0x20;
    constexpr size_t ANIMATION_LAYOUT_DATA = 0x28;
    constexpr size_t FILE_PATH = 0x30;
    constexpr size_t FILE_STATUS = 0x40;
    constexpr size_t FILE_DATA = 0x60;
    constexpr uint8_t FILE_LOADED = 2;
    constexpr size_t RESOURCE_FILE = 0x30;
    constexpr size_t RESOURCE_LAYOUT = 0x58;

    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_ROTATION = 0x30;
    constexpr size_t NODE_SCALE = 0x40;
    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t NODE_TYPE = 0x72;
    constexpr size_t TEXT_FLAGS = 0x90;
    constexpr size_t TEXT_FONT_INFO = 0xA0;
    constexpr size_t TEXT_LINE_ALIGN = 0xD8;
    constexpr size_t TEXT_BLOCK_ALIGN = 0xDA;
    constexpr size_t TEXT_AREA = 0xE0;
    constexpr size_t TEXT_SCALE = 0xF0;
    constexpr size_t MESH_MATERIAL = 0xA8;
    constexpr size_t MESH_PARAMS = 0xC8;
    constexpr size_t MESH_NAMES = 0xD0;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint16_t FLAG_FONT_INFO = 0x200;
    constexpr uint8_t TYPE_MESH = 2;
    constexpr uint8_t TYPE_TEXT = 3;

    constexpr uint32_t UILB_SIGNATURE = 0x424C4955;
    constexpr uint32_t UILB_VERSION = 0x101;
    constexpr size_t UILB_PATH_COUNT = 0x12;
    constexpr size_t UILB_PATHS_REL = 0x28;
    constexpr size_t UILB_BUFFERS = 0x2C;
    constexpr size_t FPK_SIZE = 0x0A;
    constexpr size_t FPK_ENTRY_COUNT = 0x24;
    constexpr size_t FPK_ENTRIES = 0x30;
    constexpr size_t FPK_ENTRY_STRIDE = 48;

    constexpr uint32_t MAX_MODEL_NODES = 400;
    constexpr uint32_t MAX_ANIMATIONS = 64;
    constexpr uint32_t MAX_CHAIN = 12;
    constexpr uint32_t MAX_LAYOUT_ITEMS = 1024;
    constexpr uint32_t MAX_TREE_VISITS = 16384;
    constexpr uint32_t MAX_LAYOUT_PATHS = 512;
    constexpr size_t MAX_TRACKED = 32768;
    constexpr size_t MAX_SHADER_PARAM_SPAN = 0x4000;
    constexpr float TOLERANCE = 1e-4f;

    enum FileKind : uint8_t
    {
        KIND_UIF = 1,
        KIND_UILB = 2,
        KIND_UIA = 3,
    };

    enum NodeKind : uint8_t
    {
        NODE_KIND_TRANSLATE = 1,
        NODE_KIND_SCALE,
        NODE_KIND_ROTATION,
        NODE_KIND_LINE_ALIGN,
        NODE_KIND_BLOCK_ALIGN,
        NODE_KIND_TEXT_AREA,
        NODE_KIND_TEXT_SCALE,
        NODE_KIND_FONT_INFO,
        NODE_KIND_SHADER_PARAM,
    };

    enum PlacementField : uint8_t
    {
        FIELD_TRANSLATE = 1,
        FIELD_SCALE,
        FIELD_ROTATION,
    };

    enum Match : int
    {
        MATCH_NONE = 0,
        MATCH_RTL = 1,
        MATCH_VANILLA = 2,
    };

#pragma pack(push, 1)
    struct TableHeader
    {
        uint32_t magic;
        uint32_t version;
        uint32_t packCount;
        uint32_t fileCount;
        uint32_t siteCount;
        uint32_t nodeCount;
        uint32_t compCount;
        uint32_t locationCount;
    };

    struct PackEntry
    {
        uint64_t code;
        uint32_t vanillaSize;
        uint32_t vanillaCount;
        uint32_t rtlSize;
        uint32_t rtlCount;
    };

    struct FileEntry
    {
        uint64_t path;
        uint32_t size;
        uint32_t root;
        uint32_t packs;
        uint32_t firstSite;
        uint32_t siteCount;
        uint32_t firstNode;
        uint32_t nodeCount;
        uint32_t firstComp;
        uint32_t compCount;
        uint32_t firstLocation;
        uint32_t locationCount;
        uint8_t kind;
        uint8_t prefixLength;
        uint16_t pad;
        uint8_t prefix[32];
    };

    struct Site
    {
        uint32_t offset;
        uint8_t length;
        uint8_t pad[3];
        uint8_t rtl[16];
        uint8_t vanilla[16];
    };

    struct NodeRecord
    {
        uint32_t name;
        uint16_t index;
        uint8_t kind;
        uint8_t pad;
        uint32_t extra;
        float rtl[4];
        float vanilla[4];
    };

    struct CompRecord
    {
        uint32_t name;
        uint8_t type;
        uint8_t field;
        uint16_t pad;
        float rtl[4];
        float vanilla[4];
    };

    struct Location
    {
        uint32_t file;
        uint32_t pack;
        uint32_t vanillaOffset;
        uint32_t vanillaIndex;
        uint32_t rtlOffset;
        uint32_t rtlIndex;
    };
#pragma pack(pop)
    static_assert(sizeof(TableHeader) == 32, "layout table header");
    static_assert(sizeof(PackEntry) == 24, "layout table pack");
    static_assert(sizeof(FileEntry) == 88, "layout table file");
    static_assert(sizeof(Site) == 40, "layout table site");
    static_assert(sizeof(NodeRecord) == 44, "layout table node record");
    static_assert(sizeof(CompRecord) == 40, "layout table placement record");
    static_assert(sizeof(Location) == 24, "layout table location");

    struct Table
    {
        std::vector<uint8_t> blob;
        const PackEntry* packs = nullptr;
        const FileEntry* files = nullptr;
        const Site* sites = nullptr;
        const NodeRecord* nodes = nullptr;
        const CompRecord* comps = nullptr;
        const Location* locations = nullptr;
        uint32_t packCount = 0;
        uint32_t fileCount = 0;
        uint32_t compCount = 0;
        std::unordered_map<uint64_t, std::vector<uint32_t>> byPath;
        std::unordered_map<uint32_t, std::vector<uint32_t>> compsByName;
    };

    constexpr uint8_t SEEN_RTL = 1;
    constexpr uint8_t SEEN_VANILLA = 2;
    constexpr uint8_t SEEN_BOTH = SEEN_RTL | SEEN_VANILLA;

    struct BufferState
    {
        int32_t file;
        uint8_t certain;
        uint8_t seen;
        uint32_t epoch;
    };

    struct BufferInfo
    {
        int file;
        bool mixed;
    };

    struct ModelState
    {
        uintptr_t nodes;
        uint32_t count;
        uint32_t root;
        uint32_t epoch;
    };

    struct ModelView
    {
        uint32_t root;
        uint32_t count;
        uint8_t* const* nodes;
        uint8_t* data;
        uint64_t path;
    };

    struct LoadedFile
    {
        uint8_t* data;
        uint64_t path;
    };

    struct ChainItem
    {
        uint8_t* component;
        uint32_t name;
        uint8_t type;
    };

    using ReadLayout_t = uint64_t(__fastcall*)(void* resource, void* package, void* outLayout, void* animationFiles);
    using GetGraphFile_t = void*(__fastcall*)(void* package, uint64_t path);
    using BindParameter_t = void(__fastcall*)(void* material, uint32_t name, const float* values);

    const uint8_t kReadLayoutPrologue[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
                                            0x57, 0x48, 0x8D, 0xAC, 0x24, 0x38, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC };
    const uint8_t kGetGraphFilePrologue[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE,
                                              0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC9, 0x74, 0x08, 0x48, 0x8B, 0x01, 0xFF };
    const uint8_t kBindParameterPrologue[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
                                               0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x79, 0x10, 0x49 };
    const uint8_t kFpkMagic[] = { 'f', 'o', 'x', 'f', 'p', 'k' };
    const uint8_t kFpkPlatform[] = { 'w', 'i', 'n' };

    std::atomic<const Table*> gTable{ nullptr };
    std::atomic<int> gDirection{ -1 };
    std::atomic<uint32_t> gEpoch{ 0 };
    SRWLOCK gLock = SRWLOCK_INIT;
    std::unordered_map<uintptr_t, BufferState> gBuffers;
    std::unordered_map<uintptr_t, ModelState> gModels;
    std::unordered_map<uintptr_t, uint32_t> gTrees;
    std::unordered_map<uintptr_t, uintptr_t> gLayoutFiles;
    std::unordered_map<uintptr_t, uint64_t> gLayoutPaths;
    ReadLayout_t oReadLayout = nullptr;
    void* gReadLayoutTarget = nullptr;
    GetGraphFile_t gGetGraphFile = nullptr;
    BindParameter_t gBindParameter = nullptr;
    std::atomic<int> gFileLogBudget{ 24 };
    std::atomic<int> gNoteLogBudget{ 12 };
    std::atomic<uint32_t> gPatchedFiles{ 0 };
    std::atomic<uint32_t> gConvertedValues{ 0 };
    std::atomic<uint32_t> gSummaryEpoch{ 0 };
    std::atomic<ULONGLONG> gSummaryDue{ 0 };

    std::wstring TablePath()
    {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(&TablePath), &self))
            return {};
        wchar_t buffer[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(self, buffer, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
            return {};
        std::wstring path(buffer, length);
        const size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
            return TABLE_FILE;
        return path.substr(0, slash + 1) + TABLE_FILE;
    }

    bool ReadWholeFile(const std::wstring& path, std::vector<uint8_t>& out)
    {
        FILE* file = nullptr;
        if (path.empty() || _wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
            return false;
        bool ok = false;
        if (_fseeki64(file, 0, SEEK_END) == 0)
        {
            const long long size = _ftelli64(file);
            if (size >= static_cast<long long>(sizeof(TableHeader)) && size <= static_cast<long long>(MAX_TABLE_BYTES) &&
                _fseeki64(file, 0, SEEK_SET) == 0)
            {
                out.resize(static_cast<size_t>(size));
                ok = std::fread(out.data(), 1, out.size(), file) == out.size();
            }
        }
        std::fclose(file);
        if (!ok)
            out.clear();
        return ok;
    }

    bool InRange(uint32_t first, uint32_t count, uint32_t total)
    {
        return first <= total && count <= total - first;
    }

    bool BuildTable(Table& table)
    {
        const std::vector<uint8_t>& blob = table.blob;
        TableHeader header{};
        std::memcpy(&header, blob.data(), sizeof(header));
        if (header.magic != TABLE_MAGIC || header.version != TABLE_VERSION || header.packCount > 32)
            return false;
        const uint64_t expected = sizeof(TableHeader) + uint64_t(header.packCount) * sizeof(PackEntry) +
                                  uint64_t(header.fileCount) * sizeof(FileEntry) +
                                  uint64_t(header.siteCount) * sizeof(Site) +
                                  uint64_t(header.nodeCount) * sizeof(NodeRecord) +
                                  uint64_t(header.compCount) * sizeof(CompRecord) +
                                  uint64_t(header.locationCount) * sizeof(Location);
        if (expected != blob.size())
            return false;
        const uint8_t* cursor = blob.data() + sizeof(TableHeader);
        table.packs = reinterpret_cast<const PackEntry*>(cursor);
        cursor += size_t(header.packCount) * sizeof(PackEntry);
        table.files = reinterpret_cast<const FileEntry*>(cursor);
        cursor += size_t(header.fileCount) * sizeof(FileEntry);
        table.sites = reinterpret_cast<const Site*>(cursor);
        cursor += size_t(header.siteCount) * sizeof(Site);
        table.nodes = reinterpret_cast<const NodeRecord*>(cursor);
        cursor += size_t(header.nodeCount) * sizeof(NodeRecord);
        table.comps = reinterpret_cast<const CompRecord*>(cursor);
        cursor += size_t(header.compCount) * sizeof(CompRecord);
        table.locations = reinterpret_cast<const Location*>(cursor);
        table.packCount = header.packCount;
        table.fileCount = header.fileCount;
        table.compCount = header.compCount;
        for (uint32_t i = 0; i < header.fileCount; ++i)
        {
            const FileEntry& file = table.files[i];
            if (file.kind < KIND_UIF || file.kind > KIND_UIA || file.prefixLength > sizeof(file.prefix) ||
                file.siteCount == 0 || !InRange(file.firstSite, file.siteCount, header.siteCount) ||
                !InRange(file.firstNode, file.nodeCount, header.nodeCount) ||
                !InRange(file.firstComp, file.compCount, header.compCount) ||
                !InRange(file.firstLocation, file.locationCount, header.locationCount))
                return false;
            for (uint32_t s = 0; s < file.siteCount; ++s)
            {
                const Site& site = table.sites[file.firstSite + s];
                if (site.length == 0 || site.length > sizeof(site.rtl) || site.offset < file.prefixLength ||
                    uint64_t(site.offset) + site.length > file.size)
                    return false;
            }
            for (uint32_t l = 0; l < file.locationCount; ++l)
            {
                const Location& location = table.locations[file.firstLocation + l];
                if (location.file != i || location.pack >= header.packCount)
                    return false;
            }
            table.byPath[file.path].push_back(i);
            for (uint32_t c = 0; c < file.compCount; ++c)
                table.compsByName[table.comps[file.firstComp + c].name].push_back(file.firstComp + c);
        }
        return true;
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

    bool Readable(const uint8_t* address, size_t size)
    {
        if (!address)
            return false;
        const uint8_t* end = address + size;
        while (address < end)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(address, &info, sizeof(info)) != sizeof(info))
                return false;
            if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
                return false;
            address = static_cast<const uint8_t*>(info.BaseAddress) + info.RegionSize;
        }
        return true;
    }

    int MatchFile(const uint8_t* base, const FileEntry& file, const Site* sites)
    {
        __try
        {
            if (std::memcmp(base, file.prefix, file.prefixLength) != 0)
                return MATCH_NONE;
            bool rtl = true;
            bool vanilla = true;
            const Site* site = sites + file.firstSite;
            for (uint32_t i = 0; i < file.siteCount; ++i, ++site)
            {
                const uint8_t* bytes = base + site->offset;
                if (rtl && std::memcmp(bytes, site->rtl, site->length) != 0)
                    rtl = false;
                if (vanilla && std::memcmp(bytes, site->vanilla, site->length) != 0)
                    vanilla = false;
                if (!rtl && !vanilla)
                    return MATCH_NONE;
            }
            return rtl ? MATCH_RTL : MATCH_VANILLA;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return MATCH_NONE;
        }
    }

    bool WriteSites(uint8_t* base, const FileEntry& file, const Site* sites, bool rightToLeft)
    {
        __try
        {
            const Site* site = sites + file.firstSite;
            for (uint32_t i = 0; i < file.siteCount; ++i, ++site)
                std::memcpy(base + site->offset, rightToLeft ? site->rtl : site->vanilla, site->length);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ImageMatches(const uint8_t* base, uint32_t offset, uint32_t index, uint32_t fileSize, uint32_t imageSize,
                      uint32_t entryCount)
    {
        if (index >= entryCount || offset >= imageSize)
            return false;
        const uint8_t* image = base - offset;
        const size_t header = FPK_ENTRIES + FPK_ENTRY_STRIDE * (size_t(index) + 1);
        if (!Readable(image, header))
            return false;
        __try
        {
            if (std::memcmp(image, kFpkMagic, sizeof(kFpkMagic)) != 0 ||
                std::memcmp(image + 7, kFpkPlatform, sizeof(kFpkPlatform)) != 0)
                return false;
            if (*reinterpret_cast<const uint32_t*>(image + FPK_SIZE) != imageSize ||
                *reinterpret_cast<const uint32_t*>(image + FPK_ENTRY_COUNT) != entryCount)
                return false;
            const uint8_t* entry = image + FPK_ENTRIES + FPK_ENTRY_STRIDE * size_t(index);
            return *reinterpret_cast<const uint64_t*>(entry) == offset &&
                   *reinterpret_cast<const uint64_t*>(entry + 8) == fileSize;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool InsidePack(const Table& table, const uint8_t* base, uint32_t fileIndex)
    {
        const FileEntry& file = table.files[fileIndex];
        for (uint32_t i = 0; i < file.locationCount; ++i)
        {
            const Location& location = table.locations[file.firstLocation + i];
            const PackEntry& pack = table.packs[location.pack];
            if (ImageMatches(base, location.vanillaOffset, location.vanillaIndex, file.size, pack.vanillaSize,
                             pack.vanillaCount) ||
                ImageMatches(base, location.rtlOffset, location.rtlIndex, file.size, pack.rtlSize, pack.rtlCount))
                return true;
        }
        return false;
    }

    void NoteFile(const Table& table, uint32_t fileIndex, bool rightToLeft, bool certain)
    {
        gPatchedFiles.fetch_add(1, std::memory_order_relaxed);
        if (gFileLogBudget.load(std::memory_order_relaxed) <= 0 || gFileLogBudget.fetch_sub(1) <= 0)
            return;
        const FileEntry& file = table.files[fileIndex];
        Log("[LayoutDirection]   loaded %s %016llX (root %08X) rewritten to its %s values%s\n",
            file.kind == KIND_UIF ? "model file" : file.kind == KIND_UILB ? "placement file" : "animation file",
            static_cast<unsigned long long>(file.path), file.root, rightToLeft ? "right-to-left" : "original",
            certain ? " (pack confirmed)" : "");
        FlushLog();
    }

    void StoreBuffer(uintptr_t key, const BufferState& state)
    {
        if (gBuffers.size() >= MAX_TRACKED && gBuffers.find(key) == gBuffers.end())
            gBuffers.clear();
        gBuffers[key] = state;
    }

    BufferInfo EnsureBuffer(const Table& table, uint8_t* base, const std::vector<uint32_t>& candidates,
                            bool rightToLeft)
    {
        if (!base || candidates.empty())
            return { -1, false };
        const uint32_t epoch = gEpoch.load(std::memory_order_relaxed);
        const uintptr_t key = reinterpret_cast<uintptr_t>(base);
        int file = -1;
        int state = MATCH_NONE;
        bool certain = false;
        uint8_t seen = 0;
        AcquireSRWLockExclusive(&gLock);
        const auto known = gBuffers.find(key);
        if (known != gBuffers.end())
        {
            const BufferState cached = known->second;
            if (cached.file >= 0)
            {
                state = MatchFile(base, table.files[cached.file], table.sites);
                seen = cached.seen;
                if (state == MATCH_RTL || (state == MATCH_VANILLA && (cached.certain != 0 || !rightToLeft)))
                {
                    file = cached.file;
                    certain = cached.certain != 0;
                }
            }
            else if (cached.epoch == epoch)
            {
                ReleaseSRWLockExclusive(&gLock);
                return { -1, false };
            }
        }
        if (file < 0)
        {
            uint32_t bestSites = 0;
            int vanillaFile = -1;
            int vanillaCertain = -1;
            for (uint32_t candidate : candidates)
            {
                const FileEntry& entry = table.files[candidate];
                const int match = MatchFile(base, entry, table.sites);
                if (match == MATCH_RTL && entry.siteCount > bestSites)
                {
                    bestSites = entry.siteCount;
                    file = static_cast<int>(candidate);
                    state = MATCH_RTL;
                    certain = true;
                }
                else if (match == MATCH_VANILLA)
                {
                    if (vanillaFile < 0)
                        vanillaFile = static_cast<int>(candidate);
                    if (vanillaCertain < 0 && InsidePack(table, base, candidate))
                        vanillaCertain = static_cast<int>(candidate);
                }
            }
            if (file < 0 && vanillaCertain >= 0)
            {
                file = vanillaCertain;
                state = MATCH_VANILLA;
                certain = true;
            }
            else if (file < 0 && vanillaFile >= 0 && !rightToLeft)
            {
                file = vanillaFile;
                state = MATCH_VANILLA;
            }
        }
        if (file < 0)
        {
            StoreBuffer(key, { -1, 0, 0, epoch });
            ReleaseSRWLockExclusive(&gLock);
            return { -1, false };
        }
        const bool wasRightToLeft = state == MATCH_RTL;
        seen |= wasRightToLeft ? SEEN_RTL : SEEN_VANILLA;
        bool written = false;
        if (wasRightToLeft != rightToLeft && (!rightToLeft || certain))
        {
            written = WriteSites(base, table.files[file], table.sites, rightToLeft);
            if (written)
                seen |= rightToLeft ? SEEN_RTL : SEEN_VANILLA;
        }
        StoreBuffer(key, { file, static_cast<uint8_t>(certain ? 1 : 0), seen, epoch });
        ReleaseSRWLockExclusive(&gLock);
        if (written)
            NoteFile(table, static_cast<uint32_t>(file), rightToLeft, certain);
        if (wasRightToLeft != rightToLeft && !written)
            return { rightToLeft ? -1 : file, !rightToLeft };
        return { file, seen == SEEN_BOTH };
    }

    bool ReadModelView(const uint8_t* model, ModelView& view)
    {
        __try
        {
            const uint8_t* root = *reinterpret_cast<const uint8_t* const*>(model + MODEL_ROOT);
            if (!root)
                return false;
            view.root = *reinterpret_cast<const uint32_t*>(root + NODE_NAME);
            view.count = *reinterpret_cast<const uint32_t*>(model + MODEL_NODE_COUNT);
            view.nodes = *reinterpret_cast<uint8_t* const* const*>(model + MODEL_NODES);
            view.data = nullptr;
            view.path = 0;
            const uint8_t* file = *reinterpret_cast<const uint8_t* const*>(model + MODEL_FILE);
            if (file && file[FILE_STATUS] == FILE_LOADED)
            {
                view.data = *reinterpret_cast<uint8_t* const*>(file + FILE_DATA);
                view.path = *reinterpret_cast<const uint64_t*>(file + FILE_PATH);
            }
            return view.nodes && view.count > 0 && view.count <= MAX_MODEL_NODES;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool NearAll(const float* a, const float* b, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            if (!(std::fabs(a[i] - b[i]) <= TOLERANCE))
                return false;
        }
        return true;
    }

    bool SwapFloats(uint8_t* field, const float* from, const float* to, int count)
    {
        if (!NearAll(reinterpret_cast<const float*>(field), from, count))
            return false;
        std::memcpy(field, to, size_t(count) * sizeof(float));
        return true;
    }

    bool SwapByte(uint8_t* field, const float* from, const float* to)
    {
        if (*field != static_cast<uint8_t>(from[0]))
            return false;
        *field = static_cast<uint8_t>(to[0]);
        return true;
    }

    void BindShaderParameter(uint8_t* node, const uint8_t* base, uint32_t offset)
    {
        if (!gBindParameter || !base)
            return;
        void* material = *reinterpret_cast<void**>(node + MESH_MATERIAL);
        const uint8_t* params = *reinterpret_cast<const uint8_t* const*>(node + MESH_PARAMS);
        const uint32_t* names = *reinterpret_cast<const uint32_t* const*>(node + MESH_NAMES);
        const uint8_t* param = base + offset;
        if (!material || !params || !names || param < params || param >= params + MAX_SHADER_PARAM_SPAN)
            return;
        const uint16_t nameIndex = *reinterpret_cast<const uint16_t*>(param + 2);
        if (nameIndex == 0xFFFF)
            return;
        alignas(16) float values[4];
        std::memcpy(values, param + 4, sizeof(values));
        gBindParameter(material, names[nameIndex], values);
    }

    int ConvertNodes(const Table& table, const FileEntry& file, uint8_t* const* nodes, uint32_t count,
                     const uint8_t* base, bool toRightToLeft, bool first)
    {
        int writes = 0;
        __try
        {
            const NodeRecord* record = table.nodes + file.firstNode;
            for (uint32_t i = 0; i < file.nodeCount; ++i, ++record)
            {
                if (record->index >= count)
                    continue;
                uint8_t* node = nodes[record->index];
                if (!node || *reinterpret_cast<const uint32_t*>(node + NODE_NAME) != record->name)
                    continue;
                const float* from = toRightToLeft ? record->vanilla : record->rtl;
                const float* to = toRightToLeft ? record->rtl : record->vanilla;
                const uint8_t type = node[NODE_TYPE];
                bool changed = false;
                bool text = false;
                switch (record->kind)
                {
                case NODE_KIND_TRANSLATE:
                    changed = SwapFloats(node + NODE_TRANSLATION, from, to, 3);
                    break;
                case NODE_KIND_SCALE:
                    changed = SwapFloats(node + NODE_SCALE, from, to, 3);
                    break;
                case NODE_KIND_ROTATION:
                    changed = SwapFloats(node + NODE_ROTATION, from, to, 4);
                    break;
                case NODE_KIND_LINE_ALIGN:
                    text = true;
                    changed = type == TYPE_TEXT && SwapByte(node + TEXT_LINE_ALIGN, from, to);
                    break;
                case NODE_KIND_BLOCK_ALIGN:
                    text = true;
                    changed = type == TYPE_TEXT && SwapByte(node + TEXT_BLOCK_ALIGN, from, to);
                    break;
                case NODE_KIND_TEXT_AREA:
                    text = true;
                    changed = type == TYPE_TEXT && SwapFloats(node + TEXT_AREA, from, to, 4);
                    break;
                case NODE_KIND_TEXT_SCALE:
                    text = true;
                    changed = type == TYPE_TEXT && SwapFloats(node + TEXT_SCALE, from, to, 3);
                    break;
                case NODE_KIND_FONT_INFO:
                    text = true;
                    if (type == TYPE_TEXT && *reinterpret_cast<void* const*>(node + TEXT_FONT_INFO))
                    {
                        uint16_t& flags = *reinterpret_cast<uint16_t*>(node + TEXT_FLAGS);
                        const bool has = (flags & FLAG_FONT_INFO) != 0;
                        const bool want = to[0] != 0.0f;
                        if (has != want)
                        {
                            flags = static_cast<uint16_t>(want ? flags | FLAG_FONT_INFO : flags & ~FLAG_FONT_INFO);
                            changed = true;
                        }
                    }
                    break;
                case NODE_KIND_SHADER_PARAM:
                    if (first && type == TYPE_MESH)
                        BindShaderParameter(node, base, record->extra);
                    break;
                default:
                    break;
                }
                if (changed)
                {
                    if (text)
                        *reinterpret_cast<uint16_t*>(node + TEXT_FLAGS) |= FLAG_REBUILD;
                    ++writes;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return writes;
        }
        return writes;
    }

    uint32_t ReadChain(uint8_t* model, ChainItem* chain)
    {
        uint32_t count = 0;
        __try
        {
            uint8_t* component = model;
            while (component && count < MAX_CHAIN)
            {
                chain[count].component = component;
                chain[count].name = *reinterpret_cast<const uint32_t*>(component + COMPONENT_NAME);
                chain[count].type = component[COMPONENT_TYPE];
                ++count;
                component = *reinterpret_cast<uint8_t* const*>(component + COMPONENT_PARENT);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return count;
    }

    bool ApplyPlacement(const ChainItem& item, const CompRecord& record, bool toRightToLeft)
    {
        __try
        {
            uint8_t* node = nullptr;
            if (item.type == COMPONENT_MODEL)
                node = *reinterpret_cast<uint8_t* const*>(item.component + MODEL_ROOT);
            else if (item.type == COMPONENT_LAYOUT)
                node = item.component + LAYOUT_NODE;
            if (!node)
                return false;
            const float* from = toRightToLeft ? record.vanilla : record.rtl;
            const float* to = toRightToLeft ? record.rtl : record.vanilla;
            switch (record.field)
            {
            case FIELD_TRANSLATE:
                return SwapFloats(node + NODE_TRANSLATION, from, to, 3);
            case FIELD_SCALE:
                return SwapFloats(node + NODE_SCALE, from, to, 3);
            case FIELD_ROTATION:
                return SwapFloats(node + NODE_ROTATION, from, to, 4);
            default:
                return false;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint64_t RecordedLayoutPath(const uint8_t* data)
    {
        uint64_t path = 0;
        AcquireSRWLockShared(&gLock);
        const auto it = gLayoutPaths.find(reinterpret_cast<uintptr_t>(data));
        if (it != gLayoutPaths.end())
            path = it->second;
        ReleaseSRWLockShared(&gLock);
        return path;
    }

    LoadedFile RecordedLayoutFile(const uint8_t* layout)
    {
        uintptr_t data = 0;
        uint64_t path = 0;
        AcquireSRWLockShared(&gLock);
        const auto it = gLayoutFiles.find(reinterpret_cast<uintptr_t>(layout));
        if (it != gLayoutFiles.end())
        {
            data = it->second;
            const auto known = gLayoutPaths.find(data);
            if (known != gLayoutPaths.end())
                path = known->second;
        }
        ReleaseSRWLockShared(&gLock);
        uint8_t* file = reinterpret_cast<uint8_t*>(data);
        if (!file || path == 0 || !Readable(file, UILB_BUFFERS + sizeof(uint32_t)))
            return { nullptr, 0 };
        return { file, path };
    }

    BufferInfo EnsureFile(const Table& table, const LoadedFile& file, bool rightToLeft)
    {
        if (!file.data || file.path == 0)
            return { -1, false };
        const auto candidates = table.byPath.find(file.path);
        if (candidates == table.byPath.end())
            return { -1, false };
        return EnsureBuffer(table, file.data, candidates->second, rightToLeft);
    }

    int ConvertPlacements(const Table& table, uint8_t* component, bool rightToLeft)
    {
        if (table.compCount == 0)
            return 0;
        ChainItem chain[MAX_CHAIN];
        const uint32_t count = ReadChain(component, chain);
        int writes = 0;
        for (uint32_t i = 0; i < count; ++i)
        {
            const ChainItem& item = chain[i];
            const auto named = table.compsByName.find(item.name);
            if (named == table.compsByName.end())
                continue;
            BufferInfo owner{ -1, false };
            if (i + 1 < count && chain[i + 1].type == COMPONENT_LAYOUT)
                owner = EnsureFile(table, RecordedLayoutFile(chain[i + 1].component), rightToLeft);
            if (owner.file >= 0 ? !owner.mixed : rightToLeft)
                continue;
            for (uint32_t index : named->second)
            {
                const CompRecord& record = table.comps[index];
                if (record.type != item.type)
                    continue;
                if (owner.file >= 0)
                {
                    const FileEntry& file = table.files[owner.file];
                    if (index < file.firstComp || index >= file.firstComp + file.compCount)
                        continue;
                }
                if (ApplyPlacement(item, record, rightToLeft))
                    ++writes;
            }
        }
        return writes;
    }

    uint32_t ReadAnimationData(const uint8_t* model, LoadedFile* files, uint8_t** layouts, uint32_t& layoutCount)
    {
        uint32_t fileCount = 0;
        layoutCount = 0;
        __try
        {
            const uint32_t count = *reinterpret_cast<const uint32_t*>(model + MODEL_ANIMATION_COUNT);
            const uint8_t* const* animations = *reinterpret_cast<const uint8_t* const* const*>(model + MODEL_ANIMATIONS);
            if (!animations || count == 0 || count > MAX_ANIMATIONS)
                return 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                const uint8_t* animation = animations[i];
                if (!animation)
                    continue;
                for (int slot = 0; slot < 2; ++slot)
                {
                    const size_t offset = slot == 0 ? ANIMATION_FILE : ANIMATION_SHADER_FILE;
                    const uint8_t* file = *reinterpret_cast<const uint8_t* const*>(animation + offset);
                    if (!file || file[FILE_STATUS] != FILE_LOADED)
                        continue;
                    uint8_t* data = *reinterpret_cast<uint8_t* const*>(file + FILE_DATA);
                    if (data)
                        files[fileCount++] = { data, *reinterpret_cast<const uint64_t*>(file + FILE_PATH) };
                }
                uint8_t* layout = *reinterpret_cast<uint8_t* const*>(animation + ANIMATION_LAYOUT_DATA);
                if (layout)
                    layouts[layoutCount++] = layout;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return fileCount;
    }

    void EnsureAnimations(const Table& table, const uint8_t* model, bool rightToLeft)
    {
        LoadedFile files[MAX_ANIMATIONS * 2];
        uint8_t* layouts[MAX_ANIMATIONS];
        uint32_t layoutCount = 0;
        const uint32_t fileCount = ReadAnimationData(model, files, layouts, layoutCount);
        for (uint32_t i = 0; i < fileCount; ++i)
            EnsureFile(table, files[i], rightToLeft);
        for (uint32_t i = 0; i < layoutCount; ++i)
        {
            const uint64_t path = RecordedLayoutPath(layouts[i]);
            if (path != 0 && Readable(layouts[i], UILB_BUFFERS + sizeof(uint32_t)))
                EnsureFile(table, { layouts[i], path }, rightToLeft);
        }
    }

    bool TouchModel(const uint8_t* model, const ModelView& view, uint32_t epoch)
    {
        const uintptr_t key = reinterpret_cast<uintptr_t>(model);
        const uintptr_t nodes = reinterpret_cast<uintptr_t>(view.nodes);
        AcquireSRWLockExclusive(&gLock);
        if (gModels.size() >= MAX_TRACKED && gModels.find(key) == gModels.end())
            gModels.clear();
        ModelState& state = gModels[key];
        const bool same = state.nodes == nodes && state.count == view.count && state.root == view.root;
        const bool first = !same || state.epoch != epoch;
        state = { nodes, view.count, view.root, epoch };
        ReleaseSRWLockExclusive(&gLock);
        return first;
    }

    bool ProcessModel(const Table& table, uint8_t* model, bool rightToLeft, uint32_t epoch)
    {
        ModelView view{};
        if (!ReadModelView(model, view))
            return false;
        const BufferInfo info = EnsureFile(table, { view.data, view.path }, rightToLeft);
        const bool first = TouchModel(model, view, epoch);
        int writes = 0;
        if (info.file >= 0 && info.mixed && table.files[info.file].nodeCount != 0)
            writes += ConvertNodes(table, table.files[info.file], view.nodes, view.count, view.data, rightToLeft,
                                   first);
        if (first)
        {
            writes += ConvertPlacements(table, model, rightToLeft);
            EnsureAnimations(table, model, rightToLeft);
        }
        if (writes > 0)
            gConvertedValues.fetch_add(static_cast<uint32_t>(writes), std::memory_order_relaxed);
        return first;
    }

    uint32_t ReadLayoutItems(const uint8_t* layout, uint8_t** models, uint32_t& modelCount, uint8_t** children)
    {
        uint32_t childCount = 0;
        modelCount = 0;
        __try
        {
            const uint32_t models32 = *reinterpret_cast<const uint32_t*>(layout + LAYOUT_MODEL_COUNT);
            uint8_t* const* modelArray = *reinterpret_cast<uint8_t* const* const*>(layout + LAYOUT_MODELS);
            if (modelArray && models32 <= MAX_LAYOUT_ITEMS)
            {
                for (uint32_t i = 0; i < models32; ++i)
                {
                    if (modelArray[i])
                        models[modelCount++] = modelArray[i];
                }
            }
            const uint32_t children32 = *reinterpret_cast<const uint32_t*>(layout + LAYOUT_CHILD_COUNT);
            uint8_t* const* childArray = *reinterpret_cast<uint8_t* const* const*>(layout + LAYOUT_CHILDREN);
            if (childArray && children32 <= MAX_LAYOUT_ITEMS)
            {
                for (uint32_t i = 0; i < children32; ++i)
                {
                    if (childArray[i])
                        children[childCount++] = childArray[i];
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return childCount;
    }

    uint8_t* TopComponent(uint8_t* model, bool& layout)
    {
        ChainItem chain[MAX_CHAIN];
        const uint32_t count = ReadChain(model, chain);
        layout = count > 1 && chain[count - 1].type == COMPONENT_LAYOUT;
        return count > 1 ? chain[count - 1].component : nullptr;
    }

    void WalkTree(const Table& table, uint8_t* top, bool rightToLeft, uint32_t epoch)
    {
        std::vector<uint8_t*> pending;
        pending.push_back(top);
        std::vector<uint8_t*> models(MAX_LAYOUT_ITEMS);
        std::vector<uint8_t*> children(MAX_LAYOUT_ITEMS);
        uint32_t visits = 0;
        while (!pending.empty() && visits < MAX_TREE_VISITS)
        {
            uint8_t* layout = pending.back();
            pending.pop_back();
            ++visits;
            uint32_t modelCount = 0;
            const uint32_t childCount = ReadLayoutItems(layout, models.data(), modelCount, children.data());
            const int writes = ConvertPlacements(table, layout, rightToLeft);
            if (writes > 0)
                gConvertedValues.fetch_add(static_cast<uint32_t>(writes), std::memory_order_relaxed);
            for (uint32_t i = 0; i < modelCount; ++i)
                ProcessModel(table, models[i], rightToLeft, epoch);
            for (uint32_t i = 0; i < childCount; ++i)
                pending.push_back(children[i]);
        }
    }

    void ProcessTree(const Table& table, uint8_t* model, bool rightToLeft, uint32_t epoch)
    {
        bool layout = false;
        uint8_t* top = TopComponent(model, layout);
        if (!top || !layout)
            return;
        const uintptr_t key = reinterpret_cast<uintptr_t>(top);
        AcquireSRWLockExclusive(&gLock);
        if (gTrees.size() >= MAX_TRACKED)
            gTrees.clear();
        uint32_t& done = gTrees[key];
        const bool walk = done != epoch;
        done = epoch;
        ReleaseSRWLockExclusive(&gLock);
        if (walk)
            WalkTree(table, top, rightToLeft, epoch);
    }

    uint32_t UpdateDirection(bool rightToLeft)
    {
        const int current = rightToLeft ? 1 : 0;
        int previous = gDirection.load(std::memory_order_relaxed);
        if (previous == current)
            return gEpoch.load(std::memory_order_relaxed);
        if (previous < 0)
        {
            if (RL_LayoutPackSeen())
                gDirection.compare_exchange_strong(previous, current);
            return gEpoch.load(std::memory_order_relaxed);
        }
        if (!gDirection.compare_exchange_strong(previous, current))
            return gEpoch.load(std::memory_order_relaxed);
        const uint32_t epoch = gEpoch.fetch_add(1, std::memory_order_relaxed) + 1;
        gPatchedFiles.store(0, std::memory_order_relaxed);
        gConvertedValues.store(0, std::memory_order_relaxed);
        gSummaryDue.store(GetTickCount64() + 5000, std::memory_order_relaxed);
        gFileLogBudget.store(24, std::memory_order_relaxed);
        Log("[LayoutDirection] the language is now %s while layouts loaded for the other direction are still in "
            "memory - loaded layout files and live screens are converted (switch %u this session).\n",
            rightToLeft ? "right-to-left" : "left-to-right", epoch);
        FlushLog();
        return epoch;
    }

    void LogSummary(uint32_t epoch)
    {
        const ULONGLONG due = gSummaryDue.load(std::memory_order_relaxed);
        if (due == 0 || GetTickCount64() < due)
            return;
        uint32_t logged = gSummaryEpoch.load(std::memory_order_relaxed);
        if (logged == epoch || !gSummaryEpoch.compare_exchange_strong(logged, epoch))
            return;
        gSummaryDue.store(0, std::memory_order_relaxed);
        Log("[LayoutDirection] after switch %u: %u loaded files rewritten, %u live values converted so far.\n", epoch,
            gPatchedFiles.load(std::memory_order_relaxed), gConvertedValues.load(std::memory_order_relaxed));
    }

    uint32_t ReadLayoutPaths(const uint8_t* resource, LoadedFile& own, uint64_t* paths)
    {
        own = { nullptr, 0 };
        __try
        {
            const uint8_t* file = *reinterpret_cast<const uint8_t* const*>(resource + RESOURCE_FILE);
            if (!file || file[FILE_STATUS] != FILE_LOADED)
                return 0;
            uint8_t* bytes = *reinterpret_cast<uint8_t* const*>(file + FILE_DATA);
            if (!bytes || *reinterpret_cast<const uint32_t*>(bytes) != UILB_SIGNATURE ||
                *reinterpret_cast<const uint32_t*>(bytes + 4) != UILB_VERSION)
                return 0;
            own = { bytes, *reinterpret_cast<const uint64_t*>(file + FILE_PATH) };
            const uint32_t count = *reinterpret_cast<const uint16_t*>(bytes + UILB_PATH_COUNT);
            const int32_t buffers = *reinterpret_cast<const int32_t*>(bytes + UILB_BUFFERS);
            const int32_t relative = *reinterpret_cast<const int32_t*>(bytes + UILB_PATHS_REL);
            if (count == 0 || count > MAX_LAYOUT_PATHS || buffers <= 0 || relative < 0)
                return 0;
            std::memcpy(paths, bytes + buffers + relative, size_t(count) * sizeof(uint64_t));
            return count;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    uint8_t* LoadedFileData(void* package, uint64_t path)
    {
        __try
        {
            const uint8_t* file = static_cast<const uint8_t*>(gGetGraphFile(package, path));
            if (!file || file[FILE_STATUS] != FILE_LOADED)
                return nullptr;
            return *reinterpret_cast<uint8_t* const*>(file + FILE_DATA);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    void PrepareLayout(const Table& table, const uint8_t* resource, void* package)
    {
        uint64_t paths[MAX_LAYOUT_PATHS];
        LoadedFile own{ nullptr, 0 };
        const uint32_t count = ReadLayoutPaths(resource, own, paths);
        if (!own.data)
            return;
        const bool rightToLeft = RL_IsRightToLeft();
        EnsureFile(table, own, rightToLeft);
        if (!gGetGraphFile)
            return;
        for (uint32_t i = 0; i < count; ++i)
        {
            if (table.byPath.find(paths[i]) == table.byPath.end())
                continue;
            EnsureFile(table, { LoadedFileData(package, paths[i]), paths[i] }, rightToLeft);
        }
    }

    bool ReadResource(const uint8_t* resource, uintptr_t& layout, uintptr_t& data, uint64_t& path)
    {
        __try
        {
            layout = *reinterpret_cast<const uintptr_t*>(resource + RESOURCE_LAYOUT);
            const uint8_t* file = *reinterpret_cast<const uint8_t* const*>(resource + RESOURCE_FILE);
            if (file && file[FILE_STATUS] == FILE_LOADED)
            {
                data = *reinterpret_cast<const uintptr_t*>(file + FILE_DATA);
                path = *reinterpret_cast<const uint64_t*>(file + FILE_PATH);
            }
            return layout != 0 && data != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void RecordLayout(const uint8_t* resource)
    {
        uintptr_t layout = 0;
        uintptr_t data = 0;
        uint64_t path = 0;
        if (!ReadResource(resource, layout, data, path))
            return;
        AcquireSRWLockExclusive(&gLock);
        if (gLayoutFiles.size() >= MAX_TRACKED && gLayoutFiles.find(layout) == gLayoutFiles.end())
            gLayoutFiles.clear();
        gLayoutFiles[layout] = data;
        if (gLayoutPaths.size() >= MAX_TRACKED && gLayoutPaths.find(data) == gLayoutPaths.end())
            gLayoutPaths.clear();
        gLayoutPaths[data] = path;
        ReleaseSRWLockExclusive(&gLock);
    }

    uint64_t __fastcall hkReadLayout(void* resource, void* package, void* outLayout, void* animationFiles)
    {
        const Table* table = gTable.load(std::memory_order_acquire);
        if (table && resource && gEpoch.load(std::memory_order_relaxed) != 0)
            PrepareLayout(*table, static_cast<const uint8_t*>(resource), package);
        const uint64_t result = oReadLayout(resource, package, outLayout, animationFiles);
        if (table && resource)
            RecordLayout(static_cast<const uint8_t*>(resource));
        return result;
    }

    void* Resolve(HMODULE hGame, uintptr_t address)
    {
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGame) + (address - IDA_IMAGE_BASE));
    }
}

bool InitLayoutDirectionRestore(HMODULE hGame)
{
    if (gTable.load(std::memory_order_acquire))
        return true;
    auto table = std::make_unique<Table>();
    if (!ReadWholeFile(TablePath(), table->blob) || !BuildTable(*table))
    {
        Log("[LayoutDirection] %ls not found or not this version - layouts follow a language switch only when their "
            "pack reloads.\n",
            TABLE_FILE);
        return false;
    }
    const size_t files = table->fileCount;
    const size_t packs = table->packCount;
    gTable.store(table.release(), std::memory_order_release);
    bool hooked = false;
    if (hGame && gAddr.GraphManager_GetGraphFile)
    {
        void* target = Resolve(hGame, gAddr.GraphManager_GetGraphFile);
        if (CodeMatches(target, kGetGraphFilePrologue, sizeof(kGetGraphFilePrologue)))
            gGetGraphFile = reinterpret_cast<GetGraphFile_t>(target);
    }
    if (hGame && gAddr.Material_BindParameter)
    {
        void* target = Resolve(hGame, gAddr.Material_BindParameter);
        if (CodeMatches(target, kBindParameterPrologue, sizeof(kBindParameterPrologue)))
            gBindParameter = reinterpret_cast<BindParameter_t>(target);
    }
    if (hGame && gAddr.GraphResourceLayout_SetupFromRawFile)
    {
        void* target = Resolve(hGame, gAddr.GraphResourceLayout_SetupFromRawFile);
        if (CodeMatches(target, kReadLayoutPrologue, sizeof(kReadLayoutPrologue)) &&
            MH_CreateHook(target, reinterpret_cast<void*>(&hkReadLayout), reinterpret_cast<void**>(&oReadLayout)) ==
                MH_OK)
        {
            if (MH_EnableHook(target) == MH_OK)
            {
                gReadLayoutTarget = target;
                hooked = true;
            }
            else
            {
                MH_RemoveHook(target);
                oReadLayout = nullptr;
            }
        }
    }
    Log("[LayoutDirection] %zu layout files from %zu packs known in both directions - a language switch converts "
        "the ones still loaded (new screens: %s, file lookup: %s, mesh parameters: %s).\n",
        files, packs, hooked ? "prepared before they are built" : "converted when first drawn",
        gGetGraphFile ? "on" : "off", gBindParameter ? "on" : "off");
    return true;
}

void ShutdownLayoutDirectionRestore()
{
    if (gReadLayoutTarget)
    {
        MH_DisableHook(gReadLayoutTarget);
        MH_RemoveHook(gReadLayoutTarget);
        gReadLayoutTarget = nullptr;
    }
}

void RestoreLayoutDirection(uint8_t* model, bool afterMirror)
{
    const Table* table = gTable.load(std::memory_order_acquire);
    if (!model || !table)
        return;
    const bool rightToLeft = RL_IsRightToLeft();
    const uint32_t epoch = UpdateDirection(rightToLeft);
    if (epoch == 0 || rightToLeft == afterMirror)
        return;
    if (ProcessModel(*table, model, rightToLeft, epoch))
        ProcessTree(*table, model, rightToLeft, epoch);
    LogSummary(epoch);
}
