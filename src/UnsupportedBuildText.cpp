#include "pch.h"
#include <Windows.h>
#include "log.h"

namespace
{
    struct Notice
    {
        int langId;
        const wchar_t* text;
    };

    const Notice kNotices[] = {
        { 0, L"Restored Languages: this version of the game is not supported.\nUpdate the game through Steam. The game will start without the mod." },
        { 1, L"Restored Languages : cette version du jeu n'est pas prise en charge.\nMettez le jeu \x00E0" L" jour via Steam. Le jeu d\x00E9" L"marrera sans le mod." },
        { 2, L"Restored Languages: questa versione del gioco non \x00E8" L" supportata.\nAggiorna il gioco tramite Steam. Il gioco si avvier\x00E0" L" senza la mod." },
        { 3, L"Restored Languages: Diese Version des Spiels wird nicht unterst\x00FC" L"tzt.\nAktualisiere das Spiel \x00FC" L"ber Steam. Das Spiel startet ohne die Mod." },
        { 4, L"Restored Languages: esta versi\x00F3" L"n del juego no es compatible.\nActualiza el juego a trav\x00E9" L"s de Steam. El juego se iniciar\x00E1" L" sin el mod." },
        { 5, L"Restored Languages: esta vers\x00E3" L"o do jogo n\x00E3" L"o \x00E9" L" compat\x00ED" L"vel.\nAtualize o jogo pela Steam. O jogo ser\x00E1" L" iniciado sem o mod." },
        { 6, L"Restored Languages: \x0647" L"\x0630" L"\x0627" L" \x0627" L"\x0644" L"\x0625" L"\x0635" L"\x062F" L"\x0627" L"\x0631" L" \x0645" L"\x0646" L" \x0627" L"\x0644" L"\x0644" L"\x0639" L"\x0628" L"\x0629" L" \x063A" L"\x064A" L"\x0631" L" \x0645" L"\x062F" L"\x0639" L"\x0648" L"\x0645" L".\n\x062D" L"\x062F" L"\x0651" L"\x062B" L" \x0627" L"\x0644" L"\x0644" L"\x0639" L"\x0628" L"\x0629" L" \x0639" L"\x0628" L"\x0631" L" Steam. \x0633" L"\x062A" L"\x0639" L"\x0645" L"\x0644" L" \x0627" L"\x0644" L"\x0644" L"\x0639" L"\x0628" L"\x0629" L" \x0628" L"\x062F" L"\x0648" L"\x0646" L" \x0627" L"\x0644" L"\x062A" L"\x0639" L"\x062F" L"\x064A" L"\x0644" L"." },
        { 7, L"Restored Languages: \x044D" L"\x0442" L"\x0430" L" \x0432" L"\x0435" L"\x0440" L"\x0441" L"\x0438" L"\x044F" L" \x0438" L"\x0433" L"\x0440" L"\x044B" L" \x043D" L"\x0435" L" \x043F" L"\x043E" L"\x0434" L"\x0434" L"\x0435" L"\x0440" L"\x0436" L"\x0438" L"\x0432" L"\x0430" L"\x0435" L"\x0442" L"\x0441" L"\x044F" L".\n\x041E" L"\x0431" L"\x043D" L"\x043E" L"\x0432" L"\x0438" L"\x0442" L"\x0435" L" \x0438" L"\x0433" L"\x0440" L"\x0443" L" \x0447" L"\x0435" L"\x0440" L"\x0435" L"\x0437" L" Steam. \x0418" L"\x0433" L"\x0440" L"\x0430" L" \x0437" L"\x0430" L"\x043F" L"\x0443" L"\x0441" L"\x0442" L"\x0438" L"\x0442" L"\x0441" L"\x044F" L" \x0431" L"\x0435" L"\x0437" L" \x043C" L"\x043E" L"\x0434" L"\x0430" L"." },
        { 8, L"Restored Languages\xFF1A" L"\x3053" L"\x306E" L"\x30D0" L"\x30FC" L"\x30B8" L"\x30E7" L"\x30F3" L"\x306E" L"\x30B2" L"\x30FC" L"\x30E0" L"\x306B" L"\x306F" L"\x5BFE" L"\x5FDC" L"\x3057" L"\x3066" L"\x3044" L"\x307E" L"\x305B" L"\x3093" L"\x3002" L"\nSteam\x3067" L"\x30B2" L"\x30FC" L"\x30E0" L"\x3092" L"\x66F4" L"\x65B0" L"\x3057" L"\x3066" L"\x304F" L"\x3060" L"\x3055" L"\x3044" L"\x3002" L"\x30B2" L"\x30FC" L"\x30E0" L"\x306F" L"MOD\x306A" L"\x3057" L"\x3067" L"\x8D77" L"\x52D5" L"\x3057" L"\x307E" L"\x3059" L"\x3002" L"" },
        { 9, L"Restored Languages\xFF1A" L"\x4E0D" L"\x652F" L"\x6301" L"\x6B64" L"\x6E38" L"\x620F" L"\x7248" L"\x672C" L"\x3002" L"\n\x8BF7" L"\x901A" L"\x8FC7" L" Steam \x66F4" L"\x65B0" L"\x6E38" L"\x620F" L"\x3002" L"\x6E38" L"\x620F" L"\x5C06" L"\x5728" L"\x4E0D" L"\x52A0" L"\x8F7D" L"\x6B64" L"\x6A21" L"\x7EC4" L"\x7684" L"\x60C5" L"\x51B5" L"\x4E0B" L"\x542F" L"\x52A8" L"\x3002" L"" },
        { 10, L"Restored Languages: \xC774" L" \xAC8C" L"\xC784" L" \xBC84" L"\xC804" L"\xC740" L" \xC9C0" L"\xC6D0" L"\xB418" L"\xC9C0" L" \xC54A" L"\xC2B5" L"\xB2C8" L"\xB2E4" L".\nSteam\xC5D0" L"\xC11C" L" \xAC8C" L"\xC784" L"\xC744" L" \xC5C5" L"\xB370" L"\xC774" L"\xD2B8" L"\xD558" L"\xC138" L"\xC694" L". \xAC8C" L"\xC784" L"\xC740" L" \xBAA8" L"\xB4DC" L" \xC5C6" L"\xC774" L" \xC2E4" L"\xD589" L"\xB429" L"\xB2C8" L"\xB2E4" L"." },
    };
}

const wchar_t* RL_UnsupportedBuildText(int langId)
{
    for (const Notice& n : kNotices)
    {
        if (n.langId == langId)
            return n.text;
    }
    return kNotices[0].text;
}
