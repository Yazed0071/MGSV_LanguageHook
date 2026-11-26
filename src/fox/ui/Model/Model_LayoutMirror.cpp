#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include "log.h"
#include "AddressSet.h"
#include "LanguageProfile.h"

void* GetModelNodeTextVtable();

namespace
{
    using IsArabLanguage_t = bool(__cdecl*)();
    using GetUix_t = void*(__cdecl*)();
    using SetTranslateX_t = void(__fastcall*)(void* uix, void* node, float x);

    constexpr uintptr_t IDA_IMAGE_BASE = 0x140000000ull;
    constexpr size_t MODEL_ROOT = 0x80;
    constexpr size_t MODEL_NODE_COUNT = 0x90;
    constexpr size_t MODEL_NODES = 0x98;
    constexpr size_t NODE_PARENT = 0x10;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_SIZE = 0x40;
    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t TEXT_FLAGS = 0x90;
    constexpr size_t TEXT_LINE_ALIGN = 0xD8;
    constexpr size_t TEXT_BLOCK_ALIGN = 0xDA;
    constexpr size_t TEXT_AREA_LEFT = 0xE0;
    constexpr size_t TEXT_AREA_WIDTH = 0xE8;
    constexpr size_t TEXT_SCALE = 0xF0;
    constexpr size_t TEXT_WIDTH = 0x17C;
    constexpr uint16_t FLAG_REBUILD = 0x10;
    constexpr uint16_t FLAG_STENCIL = 0x2;
    constexpr size_t VT_SET_TRANSLATE_X = 0x350;
    constexpr uint32_t MAX_MODEL_NODES = 400;
    constexpr size_t MAX_TRACKED_NODES = 8192;
    constexpr float EPSILON = 0.01f;

    enum Policy : uint8_t
    {
        END = 0,
        POINT,
        TEXT_KEEP,
        TEXT_FLIP,
        TEXT_RIGHT,
        MOVE,
        TEXT_MOVE_LEFT,
        TEXT_MOVE_RIGHT,
        MESH_FLIP,
        TEXT_KEEP_RIGHT,
        TAB_SLIDE,
        TEXT_RIGHT_EDGE,
        REFLECT,
    };

    struct NodeRule
    {
        uint32_t name;
        Policy policy;
        float shift;
    };

    struct ModelRule
    {
        uint32_t root;
        int screen;
        bool definesAxis;
        NodeRule nodes[32];
        bool anchorRight;
    };

    enum Screen
    {
        SCREEN_NONE = -1,
        SCREEN_CASSETTE = 0,
        SCREEN_MISSION_LIST,
        SCREEN_SIDE_OPS,
        SCREEN_DISPATCH,
        SCREEN_FULTON,
        SCREEN_SKILL,
        SCREEN_PLAYER,
        SCREEN_HINT,
        SCREEN_TABBAR,
        SCREEN_COUNT,
    };

    const ModelRule kRules[] = {
        { 0x2896156D, SCREEN_CASSETTE, true,
          { { 0x6E0C5B33, POINT }, { 0x642125FD, POINT, 3.3f }, { 0x7C353E65, TEXT_KEEP } } },
        { 0x35E94D81, SCREEN_CASSETTE, false,
          { { 0x6E0C5B33, POINT }, { 0x7C353E65, TEXT_KEEP } } },
        { 0x17CD74F8, SCREEN_CASSETTE, false, { { 0xEF4B69E2, TEXT_FLIP } } },
        { 0x39FB2EA6, SCREEN_CASSETTE, false, { { 0xEF4B69E2, TEXT_FLIP } } },
        { 0x37A75A79, SCREEN_PLAYER, false, { { 0xEF4B69E2, TEXT_FLIP } } },
        { 0xCF57D223, SCREEN_PLAYER, false, { { 0x66813140, TEXT_FLIP } } },
        { 0x21157F4B, SCREEN_NONE, false, { { 0x70526466, TEXT_MOVE_RIGHT, -1.0f } } },
        { 0x4CBE154A, SCREEN_NONE, false, { { 0xEF4B69E2, TEXT_MOVE_RIGHT, 13.0f } } },
        { 0xCCCBCA31, SCREEN_NONE, false, { { 0x58E1D681, MOVE, 14.94f }, { 0xE1D2A307, MOVE, 14.94f } } },
        { 0x29BE63FD, SCREEN_NONE, false, { { 0x1BEFDADE, MOVE, 14.94f }, { 0xE1D2A307, MOVE, 14.94f } } },
        { 0xFDC968E0, SCREEN_NONE, false,
          { { 0xFDC968E0, MOVE, 82.28f }, { 0xA0694252, TEXT_MOVE_RIGHT, 5.4f }, { 0xFE7981FF, MESH_FLIP, 25.0f },
            { 0x019A7E2E, MESH_FLIP, 25.0f }, { 0xC41B4FC8, MESH_FLIP, 25.0f } } },
        { 0xD2E354BE, SCREEN_NONE, false,
          { { 0x5366DEBD, MESH_FLIP, 6.2f }, { 0x66A0AD65, MESH_FLIP, 6.2f }, { 0x5A99F414, MESH_FLIP, 6.2f },
            { 0xB25001E3, MESH_FLIP, 6.2f }, { 0x2348B76B, MESH_FLIP, 6.2f }, { 0x87D0AEAE, MESH_FLIP, 6.2f },
            { 0xA4CD0586, MESH_FLIP, 6.2f } } },
        { 0xA0BD988D, SCREEN_NONE, false,
          { { 0x825D90CB, TEXT_RIGHT_EDGE, 51.6f }, { 0xC6A69892, TEXT_RIGHT_EDGE, 51.6f } } },

        { 0xEAFA0955, SCREEN_MISSION_LIST, true,
          { { 0x1C5BE6CA, POINT }, { 0xDCDD679B, TEXT_KEEP }, { 0x642125FD, POINT }, { 0x6E0C5B33, POINT },
            { 0xD0276D03, POINT }, { 0x9FCDEA8A, TEXT_FLIP }, { 0xE34D3C8E, TEXT_FLIP }, { 0x199F1F93, POINT },
            { 0x6FDFA5CE, TEXT_FLIP } } },
        { 0x71D5AD42, SCREEN_MISSION_LIST, false,
          { { 0xC7B5D45A, TEXT_FLIP }, { 0xBBB03B5A, TEXT_FLIP }, { 0x97D7D9AC, POINT }, { 0xA1C2FE93, POINT },
            { 0xF9184246, POINT }, { 0xA74EFAC7, POINT }, { 0x74B2E9AD, POINT } } },

        { 0xADC6F7BB, SCREEN_SIDE_OPS, true,
          { { 0x693CB4F9, POINT }, { 0x7C353E65, TEXT_KEEP }, { 0x7AE49C0F, POINT }, { 0x892E1722, POINT },
            { 0x4B272D38, TEXT_FLIP }, { 0x6E0C5B33, POINT } } },
        { 0x48BD94DE, SCREEN_SIDE_OPS, false,
          { { 0x86D18FEE, TEXT_FLIP }, { 0x5F24E49A, TEXT_FLIP }, { 0x18E71353, POINT }, { 0xCEC2F72F, TEXT_FLIP },
            { 0xE60A18C3, POINT } } },

        { 0x1E9AA5C9, SCREEN_DISPATCH, false,
          { { 0xC1424902, TEXT_FLIP }, { 0x27F9C795, TEXT_FLIP }, { 0x6DDACB80, TEXT_FLIP }, { 0xFCE5B710, TEXT_FLIP },
            { 0x45B73DB1, POINT } } },
        { 0x4B31D10D, SCREEN_DISPATCH, true,
          { { 0x16EC3B70, TEXT_FLIP }, { 0x6A1DA614, POINT }, { 0x15CA0612, TEXT_FLIP }, { 0x63972DE7, MESH_FLIP, -1.5f },
            { 0x356D571B, TEXT_FLIP, -1.5f }, { 0x6E5608FB, POINT, -1.5f }, { 0x451C8536, POINT, -1.5f }, { 0x201F5CD6, POINT },
            { 0x1C6CDC19, TEXT_KEEP, -3.9f }, { 0x649DAA33, TEXT_KEEP_RIGHT }, { 0x6E0C5B33, POINT }, { 0x30E47AD2, POINT },
            { 0x6835E3D3, POINT }, { 0xB3CC0342, POINT, -9.4f }, { 0xA8138024, POINT } } },

        { 0x546429E3, SCREEN_FULTON, true,
          { { 0xAA981292, TEXT_MOVE_RIGHT, 4.0f }, { 0xF08A4AAC, MOVE, -10.5f }, { 0x9F653494, TEXT_MOVE_LEFT, -2.0f } } },

        { 0x1800103E, SCREEN_SKILL, true,
          { { 0xE1A7F729, POINT }, { 0x20F2AC24, TEXT_FLIP }, { 0x76AE2697, TEXT_MOVE_RIGHT, 1.2471f } } },

        { 0x11724EBD, SCREEN_NONE, false, { { 0xCA453492, MOVE, -57.5f } } },
        { 0xC91E6534, SCREEN_NONE, false, { { 0xCA453492, MOVE, -61.4f } } },
        { 0x3F2BBE0F, SCREEN_NONE, false, { { 0xCA453492, MOVE, -48.4f } } },
        { 0x4F03DCE5, SCREEN_NONE, false, { { 0xCA453492, MOVE, -48.4f } } },
        { 0xB5F951AC, SCREEN_NONE, false,
          { { 0x6390D4BC, MOVE, 63.0f }, { 0xE27ABEB5, MOVE, 63.0f }, { 0x7DD2FB08, MOVE, -49.0f },
            { 0xAD0709BB, MOVE, -52.2f } } },
        { 0xC6D9EE61, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -89.4f }, { 0xE4AFF0EB, MOVE, -89.4f } } },
        { 0x1E4DC78B, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -54.6f }, { 0xE4AFF0EB, MOVE, -54.6f } } },
        { 0x141AC123, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -48.6f }, { 0xE4AFF0EB, MOVE, -48.6f } } },
        { 0x5ECDB1B3, SCREEN_NONE, false, { { 0xCA453492, MOVE, -34.0f } } },
        { 0x77A2D6BE, SCREEN_NONE, false, { { 0x2B0D6B93, TEXT_KEEP_RIGHT } } },
        { 0x5E772A45, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -55.2f }, { 0xE4AFF0EB, MOVE, -55.2f } } },
        { 0xDD1B24FF, SCREEN_NONE, false, { { 0xCA453492, MOVE, -52.0f } } },
        { 0x4A78D6E0, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -101.0f }, { 0xE4AFF0EB, MOVE, -101.0f } } },
        { 0xD099E1E0, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -53.8f }, { 0xE4AFF0EB, MOVE, -53.8f } } },
        { 0x6C754D1D, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -57.2f }, { 0xE4AFF0EB, MOVE, -57.2f } } },
        { 0x0F88AE34, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -46.6f }, { 0xE4AFF0EB, MOVE, -46.6f } } },
        { 0xE0F03997, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -46.6f }, { 0xE4AFF0EB, MOVE, -46.6f } } },
        { 0x14447D7B, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -36.0f }, { 0xE4AFF0EB, MOVE, -36.0f } } },
        { 0x97A397F8, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -38.6f }, { 0xE4AFF0EB, MOVE, -38.6f } } },
        { 0x71DFE42A, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -25.8f }, { 0xE4AFF0EB, MOVE, -25.8f } } },
        { 0xA635BED1, SCREEN_NONE, false, { { 0xF33A2135, TEXT_RIGHT_EDGE, 49.0f } } },
        { 0x27790A65, SCREEN_NONE, false, { { 0x7EA1C479, TEXT_RIGHT_EDGE, 35.0f } } },
        { 0x106AFF21, SCREEN_NONE, false, { { 0x1F65A213, MOVE, 0.0f } } },
        { 0x59F8C705, SCREEN_NONE, false, { { 0x1F65A213, MOVE, 0.0f } } },
        { 0x12E1FFF0, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -43.4f }, { 0xE4AFF0EB, MOVE, -43.4f } } },
        { 0xBCCB6F4C, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -82.4f }, { 0xE4AFF0EB, MOVE, -82.4f } } },
        { 0x1AD1BFCF, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -46.4f }, { 0xE4AFF0EB, MOVE, -46.4f } } },
        { 0x7D028F9D, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -49.2f }, { 0xE4AFF0EB, MOVE, -49.2f } } },
        { 0x30740388, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -49.2f }, { 0xE4AFF0EB, MOVE, -49.2f } } },
        { 0x66C7ABB9, SCREEN_NONE, false, { { 0xE5C886CA, MOVE, -95.4f }, { 0xE4AFF0EB, MOVE, -95.4f } } },

        { 0x570AD870, SCREEN_HINT, false, { { 0x99DD3D2D, TEXT_FLIP } } },
        { 0x9C7232A5, SCREEN_TABBAR, false,
          { { 0x8F6777AD, TAB_SLIDE }, { 0xBF67E927, TAB_SLIDE }, { 0xA2A89162, TAB_SLIDE },
            { 0x5C5B2F53, TAB_SLIDE }, { 0xF7BA5438, TAB_SLIDE }, { 0x15A985A8, TAB_SLIDE },
            { 0x4527E19C, TAB_SLIDE }, { 0x21719E50, TAB_SLIDE }, { 0xBA252032, TAB_SLIDE },
            { 0x46D74CF0, TAB_SLIDE }, { 0xF155F62B, TAB_SLIDE }, { 0xF727B3DE, TAB_SLIDE },
            { 0xC7D39305, TAB_SLIDE }, { 0xD87940F9, TAB_SLIDE }, { 0xAB2CAF9F, TAB_SLIDE },
            { 0x70324E2F, TAB_SLIDE }, { 0xB354A763, TAB_SLIDE }, { 0xAFD1423F, TAB_SLIDE },
            { 0xF448F480, TAB_SLIDE }, { 0xAB17C73B, TAB_SLIDE }, { 0xAA4E7488, TAB_SLIDE },
            { 0xFE00075B, TAB_SLIDE }, { 0x85D8ADD3, POINT }, { 0x8DBD89D2, TEXT_FLIP } } },
        { 0x57C3A5CF, SCREEN_TABBAR, false,
          { { 0x8F6777AD, TAB_SLIDE }, { 0xBF67E927, TAB_SLIDE }, { 0xA2A89162, TAB_SLIDE },
            { 0x5C5B2F53, TAB_SLIDE }, { 0xF7BA5438, TAB_SLIDE }, { 0x15A985A8, TAB_SLIDE },
            { 0x4527E19C, TAB_SLIDE }, { 0x21719E50, TAB_SLIDE }, { 0xBA252032, TAB_SLIDE },
            { 0x46D74CF0, TAB_SLIDE }, { 0xF155F62B, TAB_SLIDE }, { 0xF727B3DE, TAB_SLIDE },
            { 0xC7D39305, TAB_SLIDE }, { 0xD87940F9, TAB_SLIDE }, { 0xAB2CAF9F, TAB_SLIDE },
            { 0x70324E2F, TAB_SLIDE }, { 0xB354A763, TAB_SLIDE }, { 0xAFD1423F, TAB_SLIDE },
            { 0xF448F480, TAB_SLIDE }, { 0xAB17C73B, TAB_SLIDE }, { 0xAA4E7488, TAB_SLIDE },
            { 0xFE00075B, TAB_SLIDE } }, true },

    };

    struct ListFrame
    {
        float paramX;
        float width;
        ULONGLONG tick;
    };

    constexpr uint32_t LIST_WIDTH_NODE = 0x1F65A213;
    constexpr uint32_t kListFrameRoots[] = { 0x11724EBD, 0xC91E6534, 0x3F2BBE0F, 0x4F03DCE5, 0xD099E1E0, 0x106AFF21,
                                             0x59F8C705 };
    constexpr int MAX_LIST_FRAMES = 8;
    constexpr ULONGLONG LIST_FRAME_TTL_MS = 120;
    constexpr ULONGLONG TAB_AXIS_HOLD_MS = 250;
    constexpr ULONGLONG TAB_ROW_IDLE_RESET_MS = 150;
    constexpr float LIST_FRAME_MATCH = 0.5f;
    constexpr uint32_t TAB_KEY_ROOT = 0x6EC66FD5;
    constexpr int MAX_TAB_ROWS = 8;
    constexpr float TAB_ROW_MATCH = 0.05f;
    constexpr float TAB_KEY_OVERHANG = 2.0f;
    constexpr float TAB_KEY_LEAD = 10.0f;
    constexpr float TAB_KEY_WINDOW = 150.0f;
    constexpr float TAB_FIRST_KEY_X = -2.0f;
    constexpr float TAB_ANCHOR_MIN_X = 1.0f;
    constexpr float TAB_MIN_SPAN = 3.0f;
    constexpr float TAB_SPAN_MATCH = 0.05f;
    constexpr int MAX_TAB_SPANS = 8;

    struct TabSpanMemo
    {
        float x;
        float y;
        float span;
        ULONGLONG tick;
    };

    struct TabRow
    {
        const uint8_t* model;
        float y;
        float tabX;
        bool seen;
        float minX;
        float maxX;
        bool haveSpan;
        float span;
        bool haveAxis;
        float axis;
        ULONGLONG tick;
        bool anchorRight;
        ULONGLONG axisTick;
    };

    struct NodeState
    {
        uint32_t name;
        float authoredX;
        float writtenX;
        uint8_t authoredLine;
        uint8_t authoredBlock;
        bool moved;
        bool aligned;
        bool flipped;
        float authoredScaleX;
    };

    struct Geometry
    {
        uint8_t* node;
        const NodeRule* rule;
        bool text;
        float local;
        float world;
        float boxOffset;
        float boxWidth;
        float halfSize;
    };

    IsArabLanguage_t gIsArabLanguage = nullptr;
    GetUix_t gGetUix = nullptr;
    SRWLOCK gLock = SRWLOCK_INIT;
    std::unordered_map<uint8_t*, NodeState> gStates;
    const float kScreenAxis[SCREEN_COUNT] = { 21.6f, 28.33f, 29.8f, 26.5f, 45.1f, 8.8235f, 25.1f, 1.1f, 0.0f };
    float gAxis[SCREEN_COUNT] = {};
    bool gAxisKnown[SCREEN_COUNT] = {};
    std::atomic<int> gLogBudget{ 24 };
    bool gScreenLogged[SCREEN_COUNT] = {};
    bool gWasArabic = false;
    ListFrame gListFrames[MAX_LIST_FRAMES] = {};
    TabRow gTabRows[MAX_TAB_ROWS] = {};
    TabSpanMemo gTabSpans[MAX_TAB_SPANS] = {};
    float gTabSlide = 0.0f;
    std::atomic<int> gTabLogBudget{ 16 };

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

    const ModelRule* FindRule(uint32_t root)
    {
        for (const ModelRule& rule : kRules)
        {
            if (rule.root == root)
                return &rule;
        }
        return nullptr;
    }

    bool ReadRoot(const uint8_t* model, uint32_t& rootName, uint32_t& count, uint8_t* const*& nodes)
    {
        __try
        {
            const uint8_t* root = *reinterpret_cast<const uint8_t* const*>(model + MODEL_ROOT);
            if (!root)
                return false;
            rootName = *reinterpret_cast<const uint32_t*>(root + NODE_NAME);
            count = *reinterpret_cast<const uint32_t*>(model + MODEL_NODE_COUNT);
            nodes = *reinterpret_cast<uint8_t* const* const*>(model + MODEL_NODES);
            return nodes && count > 0 && count <= MAX_MODEL_NODES;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadName(const uint8_t* node, uint32_t& name)
    {
        __try
        {
            name = *reinterpret_cast<const uint32_t*>(node + NODE_NAME);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadGeometry(uint8_t* node, bool text, Geometry& g)
    {
        __try
        {
            g.local = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            float world = 0.0f;
            const uint8_t* walk = *reinterpret_cast<const uint8_t* const*>(node + NODE_PARENT);
            for (int depth = 0; walk && depth < 32; ++depth)
            {
                world += *reinterpret_cast<const float*>(walk + NODE_TRANSLATION);
                walk = *reinterpret_cast<const uint8_t* const*>(walk + NODE_PARENT);
            }
            g.world = world;
            g.boxOffset = 0.0f;
            g.boxWidth = 0.0f;
            g.halfSize = 0.0f;
            if (text)
            {
                const float scale = *reinterpret_cast<const float*>(node + TEXT_SCALE);
                g.boxOffset = scale * *reinterpret_cast<const float*>(node + TEXT_AREA_LEFT);
                g.boxWidth = scale * *reinterpret_cast<const float*>(node + TEXT_AREA_WIDTH);
            }
            else
            {
                g.halfSize = *reinterpret_cast<const float*>(node + NODE_SIZE) * 0.05f;
                if (!(g.halfSize > 0.0f) || g.halfSize > 20.0f)
                    g.halfSize = 0.0f;
            }
            return std::isfinite(g.local) && std::isfinite(g.world) && std::isfinite(g.boxOffset) &&
                   std::isfinite(g.boxWidth);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadAlign(const uint8_t* node, uint8_t& line, uint8_t& block)
    {
        __try
        {
            line = node[TEXT_LINE_ALIGN];
            block = node[TEXT_BLOCK_ALIGN];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void WriteAlign(uint8_t* node, uint8_t line, uint8_t block)
    {
        __try
        {
            if (node[TEXT_LINE_ALIGN] == line && node[TEXT_BLOCK_ALIGN] == block)
                return;
            node[TEXT_LINE_ALIGN] = line;
            node[TEXT_BLOCK_ALIGN] = block;
            *reinterpret_cast<uint16_t*>(node + TEXT_FLAGS) |= FLAG_REBUILD;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void SetLocalX(uint8_t* node, float x)
    {
        if (!gGetUix)
            return;
        __try
        {
            void* uix = gGetUix();
            if (!uix)
                return;
            void** vt = *reinterpret_cast<void***>(uix);
            reinterpret_cast<SetTranslateX_t>(vt[VT_SET_TRANSLATE_X / sizeof(void*)])(uix, node, x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    bool ReadScaleX(const uint8_t* node, float& x)
    {
        __try
        {
            x = *reinterpret_cast<const float*>(node + NODE_SIZE);
            return std::isfinite(x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void WriteScaleX(uint8_t* node, float x)
    {
        __try
        {
            *reinterpret_cast<float*>(node + NODE_SIZE) = x;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    void FlipMesh(uint8_t* node, NodeState& state)
    {
        float current = 0.0f;
        if (!ReadScaleX(node, current) || current == 0.0f)
            return;
        if (current > 0.0f)
            state.authoredScaleX = current;
        if (!(state.authoredScaleX > 0.0f))
            return;
        if (current != -state.authoredScaleX)
            WriteScaleX(node, -state.authoredScaleX);
        state.flipped = true;
    }

    void KeepRightWhenFits(const Geometry& g)
    {
        __try
        {
            const float textWidth = *reinterpret_cast<const float*>(g.node + TEXT_WIDTH);
            const float boxPixels = g.boxWidth * 10.0f;
            if (!(textWidth > 0.0f) || textWidth > boxPixels + 0.5f)
                return;
            const uint8_t block = g.node[TEXT_BLOCK_ALIGN];
            WriteAlign(g.node, 2, block == 3 ? 3 : 2);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    bool IsGameMarquee(const uint8_t* node)
    {
        __try
        {
            return (*reinterpret_cast<const uint16_t*>(node + TEXT_FLAGS) & FLAG_STENCIL) && node[TEXT_LINE_ALIGN] == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    uint8_t Flip(uint8_t align)
    {
        return align == 0 ? 2 : (align == 2 ? 0 : align);
    }

    NodeState& StateFor(uint8_t* node, uint32_t name, float local, uint8_t line, uint8_t block)
    {
        if (gStates.size() > MAX_TRACKED_NODES)
            gStates.clear();
        auto it = gStates.find(node);
        if (it == gStates.end() || it->second.name != name)
        {
            NodeState fresh{ name, local, local, line, block, false, false };
            it = gStates.insert_or_assign(node, fresh).first;
        }
        NodeState& state = it->second;
        if (std::fabs(local - state.writtenX) > EPSILON && std::fabs(local - state.authoredX) > EPSILON)
        {
            state.authoredX = local;
            state.writtenX = local;
            state.moved = false;
        }
        return state;
    }

    int Collect(uint8_t* const* nodes, uint32_t count, const ModelRule& rule, Geometry* out, int capacity)
    {
        void* textVtable = GetModelNodeTextVtable();
        int found = 0;
        for (uint32_t i = 0; i < count && found < capacity; ++i)
        {
            uint8_t* node = nodes[i];
            uint32_t name = 0;
            if (!node || !ReadName(node, name))
                continue;
            for (const NodeRule& nodeRule : rule.nodes)
            {
                if (nodeRule.policy == END)
                    break;
                if (nodeRule.name != name)
                    continue;
                bool text = false;
                __try
                {
                    text = textVtable && *reinterpret_cast<void**>(node) == textVtable;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    break;
                }
                Geometry& g = out[found];
                g.node = node;
                g.rule = &nodeRule;
                g.text = text;
                if (ReadGeometry(node, text, g))
                    ++found;
                break;
            }
        }
        return found;
    }

    bool ReadLocalX(const uint8_t* node, float& x)
    {
        __try
        {
            x = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            return std::isfinite(x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsTextNode(const uint8_t* node, void* textVtable)
    {
        __try
        {
            return textVtable && *reinterpret_cast<void* const*>(node) == textVtable;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void Restore(uint8_t* const* nodes, uint32_t count)
    {
        void* const textVtable = GetModelNodeTextVtable();
        for (uint32_t i = 0; i < count; ++i)
        {
            auto it = gStates.find(nodes[i]);
            if (it == gStates.end())
                continue;
            NodeState& state = it->second;
            uint32_t name = 0;
            if (!ReadName(nodes[i], name) || name != state.name)
            {
                gStates.erase(it);
                continue;
            }
            if (state.moved)
            {
                float local = 0.0f;
                if (ReadLocalX(nodes[i], local) && std::fabs(local - state.writtenX) <= EPSILON)
                    SetLocalX(nodes[i], state.authoredX);
                state.writtenX = state.authoredX;
                state.moved = false;
            }
            if (state.aligned)
            {
                if (IsTextNode(nodes[i], textVtable))
                    WriteAlign(nodes[i], state.authoredLine, state.authoredBlock);
                state.aligned = false;
            }
            if (state.flipped)
            {
                float scale = 0.0f;
                if (state.authoredScaleX > 0.0f && ReadScaleX(nodes[i], scale) && scale == -state.authoredScaleX)
                    WriteScaleX(nodes[i], state.authoredScaleX);
                state.flipped = false;
            }
        }
    }

    bool IsListFrame(uint32_t root)
    {
        for (uint32_t frame : kListFrameRoots)
        {
            if (frame == root)
                return true;
        }
        return false;
    }

    bool ReadParamX(const float* param, float& x)
    {
        if (!param)
            return false;
        __try
        {
            x = param[0];
            return std::isfinite(x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void RegisterListFrame(uint8_t* const* nodes, uint32_t count, const float* param)
    {
        float paramX = 0.0f;
        if (!ReadParamX(param, paramX))
            return;
        for (uint32_t i = 0; i < count; ++i)
        {
            uint32_t name = 0;
            if (!nodes[i] || !ReadName(nodes[i], name) || name != LIST_WIDTH_NODE)
                continue;
            float width = 0.0f;
            __try
            {
                width = *reinterpret_cast<const float*>(nodes[i] + NODE_TRANSLATION);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return;
            }
            if (!(width > 1.0f) || width > 200.0f)
                return;
            const ULONGLONG now = GetTickCount64();
            int slot = -1;
            for (int k = 0; k < MAX_LIST_FRAMES; ++k)
            {
                if (std::fabs(gListFrames[k].paramX - paramX) < 0.01f && gListFrames[k].tick)
                {
                    slot = k;
                    break;
                }
            }
            if (slot < 0)
            {
                ULONGLONG oldest = ~0ull;
                for (int k = 0; k < MAX_LIST_FRAMES; ++k)
                {
                    if (gListFrames[k].tick < oldest)
                    {
                        oldest = gListFrames[k].tick;
                        slot = k;
                    }
                }
            }
            gListFrames[slot] = { paramX, width, now };
            return;
        }
    }

    bool ListAxisFor(const float* param, float& axis)
    {
        float paramX = 0.0f;
        if (!ReadParamX(param, paramX))
            return false;
        const ULONGLONG now = GetTickCount64();
        float best = LIST_FRAME_MATCH;
        bool found = false;
        for (const ListFrame& frame : gListFrames)
        {
            if (!frame.tick || now - frame.tick > LIST_FRAME_TTL_MS)
                continue;
            const float distance = std::fabs(frame.paramX - paramX);
            if (distance < best)
            {
                best = distance;
                axis = frame.paramX + frame.width * 0.5f - paramX;
                found = true;
            }
        }
        return found;
    }

    bool ReadParamXY(const float* param, float& x, float& y)
    {
        if (!param)
            return false;
        __try
        {
            x = param[0];
            y = param[1];
            return std::isfinite(x) && std::isfinite(y);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    TabRow* TabRowForModel(const uint8_t* model)
    {
        TabRow* oldest = &gTabRows[0];
        for (TabRow& row : gTabRows)
        {
            if (row.model == model)
                return &row;
            if (row.tick < oldest->tick)
                oldest = &row;
        }
        *oldest = {};
        oldest->model = model;
        return oldest;
    }

    TabRow* TabRowForKey(float x, float y)
    {
        TabRow* best = nullptr;
        ULONGLONG newest = 0;
        for (TabRow& row : gTabRows)
        {
            if (!row.model || std::fabs(row.y - y) >= TAB_ROW_MATCH)
                continue;
            const float before = row.anchorRight ? TAB_KEY_WINDOW : TAB_KEY_LEAD;
            if (x < row.tabX - before || x > row.tabX + TAB_KEY_WINDOW)
                continue;
            if (row.tick >= newest)
            {
                newest = row.tick;
                best = &row;
            }
        }
        return best;
    }

    void NoteTabKey(const float* param)
    {
        float x = 0.0f, y = 0.0f;
        if (!ReadParamXY(param, x, y))
            return;
        TabRow* row = TabRowForKey(x, y);
        if (!row)
            return;
        if (!row->seen)
        {
            row->minX = x;
            row->maxX = x;
            row->seen = true;
            return;
        }
        row->minX = x < row->minX ? x : row->minX;
        row->maxX = x > row->maxX ? x : row->maxX;
    }

    bool AnchoredRightOfCentre(const float* param)
    {
        float x = 0.0f;
        return ReadParamX(param, x) && x > TAB_ANCHOR_MIN_X;
    }

    void RememberTabSpan(float x, float y, float span)
    {
        TabSpanMemo* slot = &gTabSpans[0];
        for (TabSpanMemo& memo : gTabSpans)
        {
            if (memo.tick && std::fabs(memo.x - x) < TAB_SPAN_MATCH && std::fabs(memo.y - y) < TAB_SPAN_MATCH)
            {
                slot = &memo;
                break;
            }
            if (memo.tick < slot->tick)
                slot = &memo;
        }
        *slot = { x, y, span, GetTickCount64() };
    }

    bool RecallTabSpan(float x, float y, float& span)
    {
        for (const TabSpanMemo& memo : gTabSpans)
        {
            if (memo.tick && std::fabs(memo.x - x) < TAB_SPAN_MATCH && std::fabs(memo.y - y) < TAB_SPAN_MATCH)
            {
                span = memo.span;
                return true;
            }
        }
        return false;
    }

    bool TabLayoutFor(const uint8_t* model, const float* param, bool anchorRight, float& axis, float& slide)
    {
        float x = 0.0f, y = 0.0f;
        if (!ReadParamXY(param, x, y))
            return false;
        const ULONGLONG now = GetTickCount64();
        TabRow* row = TabRowForModel(model);
        if (row->tick && now - row->tick > TAB_ROW_IDLE_RESET_MS)
        {
            if (row->haveAxis && gTabLogBudget.load() > 0 && gTabLogBudget.fetch_sub(1) > 0)
                Log("[LayoutMirror] tab row %p (x %.2f) idle %llu ms - list axis %.2f dropped\n", model, x,
                    now - row->tick, row->axis);
            *row = {};
            row->model = model;
        }
        if (row->seen)
        {
            const float measured = row->maxX - row->minX;
            if (measured > TAB_MIN_SPAN)
            {
                row->span = measured;
                row->haveSpan = true;
                if (anchorRight)
                    RememberTabSpan(x, y, measured);
            }
        }
        row->y = y;
        row->tabX = x;
        row->seen = false;
        row->tick = now;
        row->anchorRight = anchorRight;
        if (anchorRight)
        {
            if (!row->haveSpan)
            {
                float remembered = 0.0f;
                if (!RecallTabSpan(x, y, remembered))
                    return false;
                row->span = remembered;
                row->haveSpan = true;
            }
            axis = 0.0f;
            slide = -TAB_FIRST_KEY_X - row->span;
            return true;
        }
        float listAxis = 0.0f;
        if (ListAxisFor(param, listAxis))
        {
            row->axis = listAxis;
            row->haveAxis = true;
            row->axisTick = now;
        }
        else if (row->haveAxis && now - row->axisTick > TAB_AXIS_HOLD_MS)
        {
            if (gTabLogBudget.load() > 0 && gTabLogBudget.fetch_sub(1) > 0)
                Log("[LayoutMirror] tab row %p (x %.2f) has no list frame for %llu ms - list axis %.2f dropped\n", model,
                    x, now - row->axisTick, row->axis);
            row->haveAxis = false;
        }
        if (!row->haveAxis || !row->haveSpan)
            return false;
        axis = row->axis;
        slide = 2.0f * row->axis + 2.0f * TAB_KEY_OVERHANG - row->span;
        return true;
    }

    void Apply(const ModelRule& rule, uint8_t* const* nodes, uint32_t count, const float* param,
               const uint8_t* model)
    {
        if (rule.screen == SCREEN_TABBAR)
        {
            float axis = 0.0f;
            float slide = 0.0f;
            const bool anchorRight = rule.anchorRight && AnchoredRightOfCentre(param);
            if ((rule.anchorRight && !anchorRight) || !TabLayoutFor(model, param, anchorRight, axis, slide))
            {
                Restore(nodes, count);
                return;
            }
            gAxis[SCREEN_TABBAR] = axis;
            gTabSlide = slide;
        }

        Geometry geo[32];
        const int found = Collect(nodes, count, rule, geo, 32);
        if (found == 0)
            return;

        float authoredWorld[32];
        for (int i = 0; i < found; ++i)
        {
            uint8_t line = 0, block = 0;
            if (geo[i].text)
                ReadAlign(geo[i].node, line, block);
            NodeState& state = StateFor(geo[i].node, geo[i].rule->name, geo[i].local, line, block);
            if (!state.aligned && geo[i].text)
            {
                state.authoredLine = line;
                state.authoredBlock = block;
            }
            authoredWorld[i] = geo[i].world + state.authoredX;
        }

        if (rule.screen >= 0 && rule.definesAxis && !gAxisKnown[rule.screen])
        {
            float lo = 1e9f, hi = -1e9f;
            for (int i = 0; i < found; ++i)
            {
                float left = authoredWorld[i], right = authoredWorld[i];
                if (geo[i].text)
                {
                    left += geo[i].boxOffset;
                    right = left + geo[i].boxWidth;
                }
                else
                {
                    left -= geo[i].halfSize;
                    right += geo[i].halfSize;
                }
                lo = left < lo ? left : lo;
                hi = right > hi ? right : hi;
            }
            if (hi > lo)
            {
                gAxis[rule.screen] = (lo + hi) * 0.5f;
                gAxisKnown[rule.screen] = true;
            }
        }

        const bool needsAxis = rule.screen >= 0;
        if (needsAxis && !gAxisKnown[rule.screen])
            return;
        const float axis = needsAxis ? gAxis[rule.screen] : 0.0f;
        const bool log = needsAxis && !gScreenLogged[rule.screen] && rule.definesAxis && gLogBudget.load() > 0;
        if (log)
        {
            gScreenLogged[rule.screen] = true;
            gLogBudget.fetch_sub(1);
            Log("[LayoutMirror] screen %d (row %08X) mirrored about x=%.2f:\n", rule.screen, rule.root, axis);
        }

        for (int i = 0; i < found; ++i)
        {
            const Geometry& g = geo[i];
            auto it = gStates.find(g.node);
            if (it == gStates.end())
                continue;
            NodeState& state = it->second;

            const Policy policy = g.rule->policy;
            if (g.text && policy == TEXT_KEEP_RIGHT)
                KeepRightWhenFits(g);
            if (g.text && (policy == TEXT_FLIP || policy == TEXT_RIGHT || policy == TEXT_MOVE_LEFT ||
                           policy == TEXT_MOVE_RIGHT))
            {
                uint8_t line = state.authoredLine, block = state.authoredBlock;
                if (policy == TEXT_FLIP)
                {
                    line = Flip(line);
                    block = Flip(block);
                }
                else if (policy == TEXT_RIGHT || policy == TEXT_MOVE_RIGHT)
                {
                    line = 2;
                    if (block == 0)
                        block = 2;
                }
                else
                {
                    line = 0;
                    if (block == 2)
                        block = 0;
                }
                const bool unchanged = line == state.authoredLine && block == state.authoredBlock;
                if (!unchanged && !IsGameMarquee(g.node))
                {
                    WriteAlign(g.node, line, block);
                    state.aligned = true;
                }
            }

            const float world = authoredWorld[i];
            float local = 0.0f;
            if (policy == MESH_FLIP && !g.text)
                FlipMesh(g.node, state);
            const bool flipInPlace = policy == MESH_FLIP && !needsAxis && g.rule->shift != 0.0f;
            if (policy == MOVE || policy == TEXT_MOVE_LEFT || policy == TEXT_MOVE_RIGHT || flipInPlace)
            {
                local = state.authoredX + g.rule->shift;
            }
            else if (policy == REFLECT)
            {
                local = g.rule->shift - state.authoredX;
            }
            else if (policy == TAB_SLIDE)
            {
                local = state.authoredX + gTabSlide;
            }
            else if (policy == TEXT_RIGHT_EDGE)
            {
                if (!g.text)
                    continue;
                local = state.authoredX + (g.rule->shift - (world + g.boxOffset + g.boxWidth));
            }
            else
            {
                if (!needsAxis || policy == TEXT_RIGHT)
                    continue;
                float target = 2.0f * axis - world;
                if (g.text)
                    target -= 2.0f * g.boxOffset + g.boxWidth;
                local = state.authoredX + (target - world) + g.rule->shift;
            }
            if (std::fabs(local - g.local) > EPSILON)
                SetLocalX(g.node, local);
            state.writtenX = local;
            state.moved = true;
            if (log)
                Log("[LayoutMirror]   %08X %s x %.2f (world %.2f, box %.2f+%.2f) -> %.2f\n", g.rule->name,
                    g.text ? "text" : "node", state.authoredX, world, g.boxOffset, g.boxWidth, local);
        }
    }
}

void ApplyArabicLayoutMirror(uint8_t* model, const void* param)
{
    if (!model || !gIsArabLanguage)
        return;
    uint32_t rootName = 0, count = 0;
    uint8_t* const* nodes = nullptr;
    if (!ReadRoot(model, rootName, count, nodes))
        return;
    const float* placement = static_cast<const float*>(param);
    if (rootName == TAB_KEY_ROOT)
    {
        if (IsArabicSafe())
        {
            AcquireSRWLockExclusive(&gLock);
            NoteTabKey(placement);
            ReleaseSRWLockExclusive(&gLock);
        }
        return;
    }
    const ModelRule* rule = FindRule(rootName);
    if (!rule)
        return;
    const bool arabic = IsArabicSafe();
    AcquireSRWLockExclusive(&gLock);
    if (arabic)
    {
        gWasArabic = true;
        if (IsListFrame(rootName))
            RegisterListFrame(nodes, count, placement);
        Apply(*rule, nodes, count, placement, model);
    }
    else if (gWasArabic)
    {
        Restore(nodes, count);
    }
    ReleaseSRWLockExclusive(&gLock);
}

namespace
{
    constexpr uint32_t PF_RATING_PAGE_ROOT = 0xBB6B40EF;
    constexpr uint32_t kPfMirrorRoots[] = { 0x0F877F6C, 0xA7A74EBF, 0xAB01C7BF };
    constexpr float PF_MIRROR_MIN_X = 1.0f;
    constexpr ULONGLONG PF_PAGE_TTL_MS = 250;
    constexpr uint32_t kCornerMirrorRoots[] = { 0x15B9F4F1, 0xF608E74B, 0x925C42C1 };
    constexpr float CORNER_MIRROR_MIN_X = 20.0f;
    constexpr size_t PARAM_FLOATS = 16;
    constexpr size_t PARAM_SCALE_X = 8;
    std::atomic<ULONGLONG> gPfPageTick{ 0 };
    std::atomic<int> gPfLogBudget{ 3 };
    std::atomic<int> gCornerLogBudget{ 6 };

    bool ReadNodeTranslateX(const uint8_t* node, float& x)
    {
        if (!node)
            return false;
        __try
        {
            x = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            return std::isfinite(x);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadParamBlock(const void* param, float* out)
    {
        __try
        {
            std::memcpy(out, param, PARAM_FLOATS * sizeof(float));
            return std::isfinite(out[0]) && std::isfinite(out[PARAM_SCALE_X]);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}

const void* ArabicDrawParam(uint8_t* model, const void* param, float* scratch)
{
    if (!model || !param || !scratch || !gIsArabLanguage || !IsArabicSafe())
        return param;
    uint32_t rootName = 0, count = 0;
    uint8_t* const* nodes = nullptr;
    if (!ReadRoot(model, rootName, count, nodes))
        return param;
    const ULONGLONG now = GetTickCount64();
    if (rootName == PF_RATING_PAGE_ROOT)
        gPfPageTick.store(now);
    for (uint32_t pfRoot : kPfMirrorRoots)
    {
        if (pfRoot != rootName)
            continue;
        if (now - gPfPageTick.load() > PF_PAGE_TTL_MS)
            return param;
        float pfValues[PARAM_FLOATS];
        if (!ReadParamBlock(param, pfValues) || count == 0 || !nodes)
            return param;
        float pfRootX = 0.0f;
        if (!ReadNodeTranslateX(nodes[0], pfRootX))
            return param;
        const float pfEffectiveX = pfValues[0] + pfValues[PARAM_SCALE_X] * pfRootX;
        if (pfEffectiveX <= PF_MIRROR_MIN_X)
            return param;
        std::memcpy(scratch, pfValues, sizeof(pfValues));
        scratch[0] = pfValues[0] - 2.0f * pfEffectiveX;
        if (gPfLogBudget.load() > 0 && gPfLogBudget.fetch_sub(1) > 0)
            Log("[LayoutMirror] PF rating drum %08X at x %.2f (draw %.2f, root node %.2f) mirrored to %.2f\n", rootName,
                pfEffectiveX, pfValues[0], pfRootX, -pfEffectiveX);
        return scratch;
    }
    for (uint32_t cornerRoot : kCornerMirrorRoots)
    {
        if (cornerRoot != rootName)
            continue;
        float cornerValues[PARAM_FLOATS];
        if (!ReadParamBlock(param, cornerValues) || count == 0 || !nodes)
            return param;
        float rootX = 0.0f;
        if (!ReadNodeTranslateX(nodes[0], rootX))
            return param;
        const float effectiveX = cornerValues[0] + cornerValues[PARAM_SCALE_X] * rootX;
        if (effectiveX <= CORNER_MIRROR_MIN_X)
            return param;
        std::memcpy(scratch, cornerValues, sizeof(cornerValues));
        scratch[0] = cornerValues[0] - 2.0f * effectiveX;
        if (gCornerLogBudget.load() > 0 && gCornerLogBudget.fetch_sub(1) > 0)
            Log("[LayoutMirror] corner icon %08X at x %.2f (draw %.2f, root node %.2f) mirrored to %.2f\n", rootName,
                effectiveX, cornerValues[0], rootX, -effectiveX);
        return scratch;
    }
    return param;
}

void InitArabicLayoutMirror(HMODULE hGame)
{
    if (!hGame || !gAddr.IsArabLanguage || !gAddr.GetUixUtilityToFeedQuarkEnvironment)
        return;
    const uintptr_t base = reinterpret_cast<uintptr_t>(hGame);
    gIsArabLanguage = &RL_IsRightToLeft;
    gGetUix = reinterpret_cast<GetUix_t>(base + (gAddr.GetUixUtilityToFeedQuarkEnvironment - IDA_IMAGE_BASE));
    for (int i = 0; i < SCREEN_COUNT; ++i)
    {
        gAxis[i] = kScreenAxis[i];
        gAxisKnown[i] = true;
    }
}

void ShutdownArabicLayoutMirror()
{
    AcquireSRWLockExclusive(&gLock);
    gStates.clear();
    for (int i = 0; i < SCREEN_COUNT; ++i)
    {
        gAxisKnown[i] = false;
        gScreenLogged[i] = false;
    }
    ReleaseSRWLockExclusive(&gLock);
    gIsArabLanguage = nullptr;
    gGetUix = nullptr;
}
