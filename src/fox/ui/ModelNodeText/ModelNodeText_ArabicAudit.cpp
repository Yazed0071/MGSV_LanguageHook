#include "pch.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <share.h>
#include <unordered_map>
#include <unordered_set>
#include "log.h"

bool NodeShowsArabicText(void* node);
bool RL_DiagnosticsEnabled();

namespace
{
    constexpr size_t NODE_FLAGS = 0x08;
    constexpr size_t NODE_PARENT = 0x10;
    constexpr size_t NODE_TRANSLATION = 0x20;
    constexpr size_t NODE_NAME = 0x6C;
    constexpr size_t TEXT_FLAGS = 0x90;
    constexpr size_t TEXT_LINE_ALIGN = 0xD8;
    constexpr size_t TEXT_BLOCK_ALIGN = 0xDA;
    constexpr size_t TEXT_AREA_LEFT = 0xE0;
    constexpr size_t TEXT_AREA_WIDTH = 0xE8;
    constexpr size_t TEXT_SCALE = 0xF0;
    constexpr size_t TEXT_UNITS = 0x138;
    constexpr size_t TEXT_UNIT_COUNT = 0x140;
    constexpr size_t TEXT_WIDTH = 0x17C;
    constexpr size_t UNIT_STRIDE = 0x20;
    constexpr uint16_t FLAG_STENCIL = 0x2;
    constexpr uint8_t ALIGN_LEFT = 0;
    constexpr int MAX_DEPTH = 32;
    constexpr size_t MAX_RECORDED = 6000;
    constexpr size_t MAX_THROTTLED = 20000;
    constexpr ULONGLONG RECHECK_MS = 1000;
    constexpr float OVERFLOW_SLACK = 2.0f;

    struct Sample
    {
        uint32_t root;
        uint32_t parent;
        uint32_t name;
        uint8_t line;
        uint8_t block;
        uint16_t flags;
        float worldX;
        float worldY;
        float localX;
        float box;
        float textWidth;
        float areaLeft;
        char text[96];
    };

    std::mutex gMutex;
    std::unordered_set<uint64_t> gRecorded;
    std::unordered_map<const void*, ULONGLONG> gChecked;
    FILE* gFile = nullptr;
    bool gFileTried = false;

    void OpenFile()
    {
        if (gFileTried)
            return;
        gFileTried = true;
        char path[MAX_PATH];
        if (!GetModuleFileNameA(nullptr, path, MAX_PATH))
            return;
        char* slash = strrchr(path, '\\');
        if (!slash)
            return;
        slash[1] = '\0';
        strcat_s(path, "MGSV_UiAudit.log");
        gFile = _fsopen(path, "a", _SH_DENYWR);
        if (!gFile)
            return;
        SYSTEMTIME t;
        GetLocalTime(&t);
        fprintf(gFile, "# session %04u-%02u-%02u %02u:%02u  root parent node issue line block flags world_x world_y local_x box text_w area_left text\n",
                t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute);
        fflush(gFile);
    }

    bool ReadSample(const uint8_t* node, Sample& s)
    {
        __try
        {
            if (!(*reinterpret_cast<const uint32_t*>(node + NODE_FLAGS) & 1u))
                return false;
            s.name = *reinterpret_cast<const uint32_t*>(node + NODE_NAME);
            s.line = node[TEXT_LINE_ALIGN];
            s.block = node[TEXT_BLOCK_ALIGN];
            s.flags = *reinterpret_cast<const uint16_t*>(node + TEXT_FLAGS);
            s.textWidth = *reinterpret_cast<const float*>(node + TEXT_WIDTH);
            s.areaLeft = *reinterpret_cast<const float*>(node + TEXT_AREA_LEFT);
            s.box = *reinterpret_cast<const float*>(node + TEXT_SCALE) * *reinterpret_cast<const float*>(node + TEXT_AREA_WIDTH) * 10.0f;
            s.localX = *reinterpret_cast<const float*>(node + NODE_TRANSLATION);
            s.worldX = 0.0f;
            s.worldY = 0.0f;
            s.parent = 0;
            s.root = 0;
            const uint8_t* walk = node;
            for (int depth = 0; walk && depth < MAX_DEPTH; ++depth)
            {
                s.worldX += *reinterpret_cast<const float*>(walk + NODE_TRANSLATION);
                s.worldY += *reinterpret_cast<const float*>(walk + NODE_TRANSLATION + 4);
                const uint8_t* up = *reinterpret_cast<uint8_t* const*>(walk + NODE_PARENT);
                if (depth == 0 && up)
                    s.parent = *reinterpret_cast<const uint32_t*>(up + NODE_NAME);
                if (!up)
                    s.root = *reinterpret_cast<const uint32_t*>(walk + NODE_NAME);
                walk = up;
            }
            s.text[0] = '\0';
            const uint8_t* units = *reinterpret_cast<uint8_t* const*>(node + TEXT_UNITS);
            const uint32_t count = *reinterpret_cast<const uint32_t*>(node + TEXT_UNIT_COUNT);
            if (units && count)
            {
                const char* text = *reinterpret_cast<const char* const*>(units);
                if (text)
                {
                    size_t i = 0;
                    for (; i + 1 < sizeof(s.text) && text[i]; ++i)
                        s.text[i] = text[i] == '\n' || text[i] == '\r' || text[i] == '\t' ? ' ' : text[i];
                    s.text[i] = '\0';
                }
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool DueForCheck(const void* node)
    {
        const ULONGLONG now = GetTickCount64();
        if (gChecked.size() > MAX_THROTTLED)
            gChecked.clear();
        auto it = gChecked.find(node);
        if (it != gChecked.end() && now - it->second < RECHECK_MS)
            return false;
        gChecked[node] = now;
        return true;
    }
}

void AuditArabicTextNode(uint8_t* node)
{
    if (!node || !RL_DiagnosticsEnabled())
        return;
    {
        std::lock_guard<std::mutex> lock(gMutex);
        if (gRecorded.size() >= MAX_RECORDED || !DueForCheck(node))
            return;
    }
    Sample s{};
    if (!ReadSample(node, s) || !(s.textWidth > 0.0f) || !NodeShowsArabicText(node))
        return;
    const bool marquee = (s.flags & FLAG_STENCIL) != 0;
    const bool left = s.line == ALIGN_LEFT && !marquee;
    const bool overflow = !marquee && s.box > 0.0f && s.textWidth > s.box + OVERFLOW_SLACK;
    if (!left && !overflow)
        return;
    const char* issue = left && overflow ? "left+overflow" : left ? "left" : "overflow";
    const uint64_t key = (static_cast<uint64_t>(s.root) << 32) | s.name;
    std::lock_guard<std::mutex> lock(gMutex);
    if (!gRecorded.insert(key).second)
        return;
    OpenFile();
    if (!gFile)
        return;
    fprintf(gFile, "%08X %08X %08X %s %u %u %04X %.2f %.2f %.2f %.1f %.1f %.3f [%s]\n", s.root, s.parent, s.name, issue,
            static_cast<unsigned>(s.line), static_cast<unsigned>(s.block), static_cast<unsigned>(s.flags), s.worldX,
            s.worldY, s.localX, s.box, s.textWidth, s.areaLeft, s.text);
    fflush(gFile);
}

void WriteArabicAuditLine(const char* line)
{
    if (!line)
        return;
    std::lock_guard<std::mutex> lock(gMutex);
    OpenFile();
    if (!gFile)
        return;
    fputs(line, gFile);
    fflush(gFile);
}

void CloseArabicTextAudit()
{
    std::lock_guard<std::mutex> lock(gMutex);
    if (gFile)
    {
        fclose(gFile);
        gFile = nullptr;
    }
    gFileTried = false;
    gRecorded.clear();
    gChecked.clear();
}
