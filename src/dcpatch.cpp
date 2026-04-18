#include <windows.h>
/*
 * D.C. Patch DLL (Dynamic Version)
 *
 * Generic patch DLL for Circus-engine visual novels.
 * Addresses are auto-detected via byte pattern scanning.
 * Name / UI translations are loaded from external JSON files.
 * No per-game recompile needed.
 */

#include <commdlg.h>
#include <cstdio>
#include <detours.h>
#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <cctype>

// ============================================================================
// Minimal JSON parser (no external dependencies)
// Supports only the simple formats we need:
//   [{"key": "value", "key2": "value2"}, ...]
// ============================================================================

struct JsonObject {
  std::map<std::string, std::string> fields;
};

// Parse \uXXXX and basic escape sequences out of a JSON string token.
// `p` must point to the character AFTER the opening double-quote.
// Returns the parsed string and advances `p` past the closing double-quote.
static std::string ParseJsonString(const char *&p) {
  std::string result;
  while (*p && *p != '"') {
    if (*p == '\\' && *(p + 1)) {
      p++;
      switch (*p) {
        case '"': result += '"'; break;
        case '\\': result += '\\'; break;
        case '/':  result += '/';  break;
        case 'n':  result += '\n'; break;
        case 'r':  result += '\r'; break;
        case 't':  result += '\t'; break;
        case 'u': {
          // \uXXXX
          char hex[5] = {};
          for (int i = 0; i < 4 && *(p+1); i++) hex[i] = *++p;
          unsigned cp = (unsigned)strtoul(hex, nullptr, 16);
          if (cp < 0x80) {
            result += (char)cp;
          } else if (cp < 0x800) {
            result += (char)(0xC0 | (cp >> 6));
            result += (char)(0x80 | (cp & 0x3F));
          } else {
            result += (char)(0xE0 | (cp >> 12));
            result += (char)(0x80 | ((cp >> 6) & 0x3F));
            result += (char)(0x80 | (cp & 0x3F));
          }
          break;
        }
        default: result += *p; break;
      }
    } else {
      result += *p;
    }
    p++;
  }
  if (*p == '"') p++;
  return result;
}

// Parse an array of JSON objects from a string.
static std::vector<JsonObject> ParseJsonArray(const std::string &src) {
  std::vector<JsonObject> results;
  const char *p = src.c_str();
  // Find opening '['
  while (*p && *p != '[') p++;
  if (!*p) return results;
  p++; // skip '['

  while (*p) {
    // Skip whitespace/commas until '{'
    while (*p && *p != '{' && *p != ']') p++;
    if (*p == ']' || !*p) break;
    p++; // skip '{'

    JsonObject obj;
    while (*p && *p != '}') {
      // Skip whitespace/commas
      while (*p && *p != '"' && *p != '}') p++;
      if (*p != '"') break;
      p++;
      std::string key = ParseJsonString(p);
      // Skip colon
      while (*p && *p != ':') p++;
      if (*p == ':') p++;
      // Skip whitespace
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == '"') {
        p++;
        std::string val = ParseJsonString(p);
        obj.fields[key] = val;
      } else {
        // Skip non-string values
        while (*p && *p != ',' && *p != '}') p++;
      }
    }
    if (*p == '}') p++;
    results.push_back(obj);
  }
  return results;
}

// Read a file to a string. Returns empty string on failure.
static std::string ReadFileToString(const wchar_t *path) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return {};
  DWORD size = GetFileSize(h, NULL);
  if (size == 0 || size == INVALID_FILE_SIZE) { CloseHandle(h); return {}; }
  std::string buf(size, '\0');
  DWORD read = 0;
  ReadFile(h, &buf[0], size, &read, NULL);
  CloseHandle(h);
  buf.resize(read);
  return buf;
}

// Convert a UTF-8 std::string to a std::wstring
static std::wstring Utf8ToWide(const std::string &s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  if (n <= 0) return {};
  std::wstring w(n - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
  return w;
}

// Convert a UTF-8 string to Shift-JIS (codepage 932)
static std::string Utf8ToSjis(const std::string &utf8) {
  std::wstring w = Utf8ToWide(utf8);
  if (w.empty()) return {};
  int n = WideCharToMultiByte(932, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string s(n - 1, '\0');
  WideCharToMultiByte(932, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
  return s;
}

// ============================================================================
// Byte Pattern Scanner
// ============================================================================
// Finds a byte pattern in a memory region.
// `mask` is a C-string same length as `pattern`:
//   'x' = match byte exactly
//   '?' = wildcard (any byte)
// Returns offset from `base` where pattern first matches, or 0 if not found.

static DWORD ScanPattern(const BYTE *base, DWORD size,
                         const BYTE *pattern, const char *mask) {
  size_t patLen = strlen(mask);
  if (patLen == 0 || patLen > size) return 0;
  for (DWORD i = 0; i <= size - (DWORD)patLen; i++) {
    bool match = true;
    for (size_t j = 0; j < patLen; j++) {
      if (mask[j] == 'x' && base[i + j] != pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return 0;
}

// Scan a named PE section for a pattern.
// Returns absolute in-process address, or 0 if not found.
static DWORD ScanSection(const char *sectionName,
                         const BYTE *pattern, const char *mask) {
  HMODULE hExe = GetModuleHandleA(NULL);
  if (!hExe) return 0;
  BYTE *base = (BYTE *)hExe;
  auto *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  auto *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
  auto *sec = IMAGE_FIRST_SECTION(nt);
  int n = nt->FileHeader.NumberOfSections;
  for (int i = 0; i < n; i++) {
    char name[9] = {};
    memcpy(name, sec[i].Name, 8);
    if (_stricmp(name, sectionName) == 0) {
      DWORD off = ScanPattern(base + sec[i].VirtualAddress,
                              sec[i].Misc.VirtualSize, pattern, mask);
      if (off) return (DWORD)base + sec[i].VirtualAddress + off;
    }
  }
  return 0;
}

// Walk backward from `addr` (up to `maxSearchBytes`) looking for an x86
// function prologue: 55 8B EC (push ebp; mov ebp,esp)
// or 53 55 56 / 53 56 57 (push-heavy entry)
// Returns address of the prologue, or 0 if not found.
static DWORD FindFunctionStart(DWORD addr, DWORD maxSearchBytes = 0x1000) {
  const BYTE *p = (const BYTE *)addr;
  for (DWORD i = 0; i < maxSearchBytes && (DWORD)p - i > 0x1000; i++) {
    const BYTE *candidate = p - i;
    // push ebp; mov ebp, esp
    if (candidate[0] == 0x55 && candidate[1] == 0x8B && candidate[2] == 0xEC)
      return (DWORD)candidate;
    // push ebx; push esi; push edi  (common variation)
    if (candidate[0] == 0x53 && candidate[1] == 0x56 && candidate[2] == 0x57)
      return (DWORD)candidate;
    // push esi; push edi
    if (candidate[0] == 0x56 && candidate[1] == 0x57)
      return (DWORD)candidate;
  }
  return 0;
}

// Within the byte range [funcStart, hookSite], scan for a
// `MOV reg, imm32` or `PUSH imm32` that points into the EXE's .data section.
// This is used to find the backlog icon table base address.
static DWORD FindDataPointerInRange(DWORD funcStart, DWORD hookSite) {
  HMODULE hExe = GetModuleHandleA(NULL);
  if (!hExe) return 0;
  BYTE *base = (BYTE *)hExe;
  auto *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  auto *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

  // Get .data section bounds
  DWORD dataVA = 0, dataSize = 0;
  auto *sec = IMAGE_FIRST_SECTION(nt);
  for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    char name[9] = {};
    memcpy(name, sec[i].Name, 8);
    if (_stricmp(name, ".data") == 0) {
      dataVA   = (DWORD)base + sec[i].VirtualAddress;
      dataSize = sec[i].Misc.VirtualSize;
      break;
    }
  }
  if (!dataVA) return 0;

  DWORD lo = dataVA;
  DWORD hi = dataVA + dataSize;

  const BYTE *code = (const BYTE *)funcStart;
  DWORD len = (hookSite > funcStart) ? (hookSite - funcStart) : 0;

  // Walk instructions looking for MOV reg, imm32  (B8-BF xx xx xx xx)
  // or PUSH imm32 (68 xx xx xx xx)
  // that resolve to an address in .data
  for (DWORD i = 0; i < len; i++) {
    DWORD imm = 0;
    bool found = false;
    if ((code[i] >= 0xB8 && code[i] <= 0xBF) && i + 4 < len) {
      memcpy(&imm, &code[i + 1], 4);
      found = true;
      i += 4;
    } else if (code[i] == 0x68 && i + 4 < len) {
      memcpy(&imm, &code[i + 1], 4);
      found = true;
      i += 4;
    } else if (code[i] == 0x8D && i + 5 < len) {
      // LEA reg, [imm32] — ModRM 05 pattern
      if (code[i+1] == 0x05 || (code[i+1] & 0xC7) == 0x05) {
        memcpy(&imm, &code[i + 2], 4);
        found = true;
        i += 5;
      }
    }
    if (found && imm >= lo && imm < hi) {
      return imm; // First .data pointer found
    }
  }
  return 0;
}
// ============================================================================
// Backlog Icon Fix Configuration
// ============================================================================

// ============================================================================
// Name Translation Table (Translated Given Name -> Japanese Given Name)
// ============================================================================
// The game's CheckIcon function looks up Japanese names.
// We map translated names back to Japanese for lookup.
// Loaded at runtime from patch_names.json; DC4 defaults used as fallback.

struct NameMappingEntry {
  std::string translated; // e.g., "Nemu"
  std::string japanese;   // e.g., "音夢" (stored as UTF-8; converted to SJIS on use)
  std::string japaneseSjis; // Shift-JIS version (for direct comparison)
};

// DC4 built-in defaults (UTF-8 source, converted to SJIS at load time)
static const struct { const char *t; const char *j; } k_dc4BuiltinNames[] = {
    {"Nemu",      "\xe9\x9f\xb3\xe5\xa4\xa2"},   // 音夢
    {"Sakura",    "\xe3\x81\x95\xe3\x81\x8f\xe3\x82\x89"},  // さくら
    {"Miharu",    "\xe7\xbe\x8e\xe6\x98\xa5"},   // 美春
    {"Hiyori",    "\xe3\x81\xb2\xe3\x82\x88\xe3\x82\x8a"},  // ひより
    {"Miu",       "\xe6\x9c\xaa\xe7\xbe\xbd"},   // 未羽
    {"Shiina",    "\xe8\xaa\xb9\xe5\x90\x8d"},   // 詩名
    {"Arisu",     "\xe6\x9c\x89\xe9\x87\x8c\xe6\xa0\xb9"},  // 有里栖
    {"Chiyoko",   "\xe3\x81\xa1\xe3\x82\x88\xe5\xad\x90"},  // ちよ子
    {"Nino",      "\xe4\xba\x8c\xe4\xb9\x83"},   // 二乃
    {"Sorane",    "\xe8\xab\xb3\xe5\xad\x90"},   // 諳子
    {"Suginami",  "\xe6\x9d\x89\xe4\xb8\xa6"},   // 杉並
    {"Kanata",    "\xe5\x8f\xb6\xe6\x96\xb9"},   // 叶方
    {"Ichito",    "\xe4\xb8\x80\xe7\x99\xbb"},   // 一登
    {"Gen",       "\xe5\x85\x83"},               // 元
    {"Reiji",     "\xe9\x9b\xb6\xe6\xac\xa1"},   // 零次
    {"Naozumi",   "\xe5\xb0\x9a\xe7\xb4\x94"},   // 尚純
    {"Masayoshi", "\xe6\xad\xa3\xe4\xbd\xb3"},   // 正佳
    {"Izumi",     "\xe6\xb3\x89"},               // 泉
    {"KotoRI",    "KotoRI"},
    {"Alice",     "\xe3\x82\xa2\xe3\x83\xaa\xe3\x82\xb9"},  // アリス
    {"Cheshi",    "\xe3\x81\xa1\xe3\x81\x87\xe3\x81\x97"},  // ちぇし
    {"Towako",    "\xe5\x8d\x81\xe5\x92\x8c\xe5\xad\x90"},  // 十和子
    {"Kasumi",    "\xe5\x8f\xaf\xe7\xb4\x94"},   // 可純
    {"Azusa",     "\xe6\xa2\x93"},               // 梓
    {"Saki",      "\xe7\xb4\x97\xe5\xb8\x8c"},   // 紗希
    {"Lala",      "\xe3\x83\xa9\xe3\x83\xa9"},   // ララ
    {"Lili",      "\xe3\x83\xaa\xe3\x83\xaa"},   // リリ
    {"Lulu",      "\xe3\x83\xab\xe3\x83\xab"},   // ルル
    {"Arisa",     "\xe6\x9c\x89\xe9\x87\x8c\xe5\x92\xb2"},  // 有里咲
    {"Kotori",    "\xe7\x90\xb4\xe9\x87\x8c"},   // 琴里
    {"Mitsumi",   "\xe4\xb8\x89\xe7\xbe\x8e"},   // 三美
    {nullptr,     nullptr}
};

static std::vector<NameMappingEntry> g_nameTable;

// Find Japanese name (SJIS) from translated name
static const char *FindJapaneseName(const char *translatedName) {
  for (const auto &e : g_nameTable) {
    if (e.translated == translatedName)
      return e.japaneseSjis.c_str();
  }
  return nullptr;
}

// Path helpers — set during Init()
static std::wstring g_namesJsonPath;
static std::wstring g_uiJsonPath;
// Legacy fallback paths (without language suffix) for backward compatibility
static std::wstring g_namesJsonFallbackPath;
static std::wstring g_uiJsonFallbackPath;
// Mirrors [Settings] Language at startup:
//   0 = Japanese, 1 = Indonesian, 2 = English
static int g_activeJsonLanguage = 0;

// Convert UTF-16 path to UTF-8 for debug logging
static std::string WideToUtf8(const std::wstring &w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string s(n - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
  return s;
}

// Load name table from language-specific JSON (with legacy fallback).
// JSON format: [{"from": "Nemu", "to": "音夢 (UTF-8)"}, ...]
// Falls back to built-in DC4 names if file is missing or empty.
static void LoadNameTable() {
  g_nameTable.clear();

  bool usedFallbackFile = false;
  std::string src = ReadFileToString(g_namesJsonPath.c_str());
  if (src.empty() && g_namesJsonFallbackPath != g_namesJsonPath) {
    src = ReadFileToString(g_namesJsonFallbackPath.c_str());
    usedFallbackFile = !src.empty();
  }
  if (!src.empty()) {
    auto objs = ParseJsonArray(src);
    for (auto &o : objs) {
      auto itF = o.fields.find("from");
      auto itT = o.fields.find("to");
      if (itF != o.fields.end() && itT != o.fields.end()) {
        NameMappingEntry e;
        e.translated   = itF->second;
        e.japanese     = itT->second; // UTF-8
        e.japaneseSjis = Utf8ToSjis(itT->second);
        if (!e.translated.empty() && !e.japaneseSjis.empty())
          g_nameTable.push_back(std::move(e));
      }
    }
    char msg[128];
    sprintf_s(msg, "DCPatch: Loaded %zu name entries from configured JSON\n",
              g_nameTable.size());
    OutputDebugStringA(msg);
    std::string pathUtf8 = usedFallbackFile ? WideToUtf8(g_namesJsonFallbackPath)
                                            : WideToUtf8(g_namesJsonPath);
    if (!pathUtf8.empty()) {
      std::string pathMsg = "DCPatch: Names JSON path = " + pathUtf8 + "\n";
      OutputDebugStringA(pathMsg.c_str());
    }
    if (!g_nameTable.empty()) return; // success
  }

  // Fallback: built-in DC4 names
  OutputDebugStringA("DCPatch: Using built-in name table\n");
  for (int i = 0; k_dc4BuiltinNames[i].t; i++) {
    NameMappingEntry e;
    e.translated   = k_dc4BuiltinNames[i].t;
    e.japanese     = k_dc4BuiltinNames[i].j; // already UTF-8
    e.japaneseSjis = Utf8ToSjis(e.japanese);
    if (!e.japaneseSjis.empty())
      g_nameTable.push_back(std::move(e));
  }
}

// Write a default names JSON (active language path) populated with built-in entries.
static void WriteDefaultNamesJson() {
  if (GetFileAttributesW(g_namesJsonPath.c_str()) != INVALID_FILE_ATTRIBUTES)
    return; // already exists
  HANDLE h = CreateFileW(g_namesJsonPath.c_str(), GENERIC_WRITE, 0, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  std::string out = "{\n  \"_comment\": \"Character name map: from = translated name, to = original Japanese (UTF-8). Edit for your game.\",\n  \"names\": [\n";
  for (int i = 0; k_dc4BuiltinNames[i].t; i++) {
    out += "    {\"from\": \"";
    out += k_dc4BuiltinNames[i].t;
    out += "\", \"to\": \"";
    out += k_dc4BuiltinNames[i].j; // UTF-8
    out += "\"}";
    if (k_dc4BuiltinNames[i + 1].t) out += ",";
    out += "\n";
  }
  out += "  ]\n}\n";
  DWORD w;
  WriteFile(h, out.c_str(), (DWORD)out.size(), &w, NULL);
  CloseHandle(h);
}

// ============================================================================
// Font Manager
// ============================================================================

class FontManager {
private:
  std::map<int, HFONT> m_dialogueFonts;
  std::map<int, HFONT> m_backlogFonts;
  std::map<int, HFONT> m_backlogNameFonts;
  std::wstring m_dialogueFontName = L"ＭＳ ゴシック";
  std::wstring m_backlogFontName = L"ＭＳ ゴシック";
  std::wstring m_backlogNameFontName = L"ＭＳ ゴシック";
  int m_dialogueFontSizeOverride = -19;
  int m_backlogFontSizeOverride = -19;
  int m_backlogNameFontSizeOverride = -11;
  int m_backlogXOffset = 0;
  int m_backlogLineSpacing = 0;
  int m_backlogYOffset = 12;
  int m_backlogNameXOffset = 13;
  int m_backlogNameYOffset = 0;
  int m_backlogNameSpacing = 0;
  int m_backlogDialogSpacing = 0;
  bool m_advancedSettings = true;
  bool m_enableBacklogAllIcon = true;
  bool m_enableFileRedirection = true;
  bool m_disableBacklogFont = false;
  bool m_disableBacklogSpacing = false;
  bool m_disableBacklogTranslation = false;
  std::wstring m_iniPath;
  int m_language = 0; // 0 = Japanese, 1 = id_Data (Indonesian), 2 = eng_data (English)
  // Game-specific addresses (0 = auto-detect via pattern scan)
  DWORD m_addrBacklogHookRVA  = 0;
  DWORD m_addrBacklogFuncRVA  = 0;
  DWORD m_addrBacklogTableRVA = 0;
  // Backlog table structure (Circus engine standard defaults)
  int m_backlogStride      = 0x544;
  int m_backlogTextOffset  = 0x000;
  int m_backlogNameOffset  = 0x400;
  int m_backlogMaxEntries  = 200;

public:
  void Init() {
    // Determine INI path - stored in main game folder (same dir as DC4.EXE)
    WCHAR modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring exeDir = modulePath;
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
      exeDir = exeDir.substr(0, pos);
    }
    m_iniPath = exeDir + L"\\DCPatch.ini";

    // Create subfolder structure for file redirection
    // id_Data subfolders
    CreateDirectoryW((exeDir + L"\\id_Data").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\id_Data\\MES").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\id_Data\\GRP").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\id_Data\\MOVIE").c_str(), NULL);
    // eng_data subfolders
    CreateDirectoryW((exeDir + L"\\eng_data").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\eng_data\\MES").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\eng_data\\GRP").c_str(), NULL);
    CreateDirectoryW((exeDir + L"\\eng_data\\MOVIE").c_str(), NULL);

    // Check if INI exists, otherwise create it with empty template values.
    if (GetFileAttributesW(m_iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
      HANDLE hFile = CreateFileW(m_iniPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
      if (hFile != INVALID_HANDLE_VALUE) {
        const char* defaultIni = 
            "[Fonts]\r\n"
            "BacklogFont=\r\n"
            "BacklogSize=\r\n"
            "DialogueFont=\r\n"
            "DialogueSize=\r\n"
            "BacklogNameFont=\r\n"
            "BacklogNameSize=\r\n"
            "BacklogXOffset=\r\n"
            "BacklogLineSpacing=\r\n"
            "BacklogYOffset=\r\n"
            "BacklogNameXOffset=\r\n"
            "BacklogNameYOffset=\r\n"
            "BacklogNameSpacing=\r\n"
            "BacklogDialogSpacing=\r\n"
            "AdvancedSettings=\r\n"
            "\r\n"
            "[Settings]\r\n"
            "ShowBacklogIcon=\r\n"
            "EnableFileRedirection=\r\n"
            "Language=\r\n"
            "DisableBacklogFont=\r\n"
            "DisableBacklogSpacing=\r\n"
            "DisableBacklogTranslation=\r\n"
            "\r\n"
            "; ============================================================\r\n"
            "; [Addresses] - game-specific RVA offsets (hex, e.g. 0x5276)\r\n"
            "; Set to 0 (or leave blank) to auto-detect via pattern scan.\r\n"
            "; Use x32dbg to find these if auto-scan fails for your game.\r\n"
            "; ============================================================\r\n"
            "[Addresses]\r\n"
            "; BacklogHookRVA - where xor ebx,ebx; sub eax,1 is in .text\r\n"
            "BacklogHookRVA=\r\n"
            "; BacklogFuncRVA - entry point of the backlog rendering function\r\n"
            "BacklogFuncRVA=\r\n"
            "; BacklogTableRVA - base of the backlog icon table in .data\r\n"
            "BacklogTableRVA=\r\n"
            "; BacklogStride - bytes per backlog entry (default: 0x544)\r\n"
            "BacklogStride=\r\n"
            "; BacklogTextOffset - text field offset within entry (default: 0x0)\r\n"
            "BacklogTextOffset=\r\n"
            "; BacklogNameOffset - name field offset within entry (default: 0x400)\r\n"
            "BacklogNameOffset=\r\n"
            "; BacklogMaxEntries - safety cap on entry count (default: 200)\r\n"
            "BacklogMaxEntries=\r\n";
            
        DWORD bytesWritten;
        WriteFile(hFile, defaultIni, (DWORD)strlen(defaultIni), &bytesWritten, NULL);
        CloseHandle(hFile);
      }
    }

    // Backfill missing keys for existing INI files (e.g. file created first by
    // launcher with only [Launcher] section). This keeps one canonical config
    // file with all runtime-editable options.
    int backfilledCount = 0;
    auto EnsureIniValue = [&](LPCWSTR section, LPCWSTR key, LPCWSTR value) {
      const WCHAR *missingSentinel = L"__MISSING__";
      WCHAR valBuf[256];
      GetPrivateProfileStringW(section, key, missingSentinel, valBuf, 256,
                               m_iniPath.c_str());
      if (wcscmp(valBuf, missingSentinel) == 0) {
        WritePrivateProfileStringW(section, key, value, m_iniPath.c_str());
        backfilledCount++;
      }
    };

    // [Fonts] - keep blank in template; runtime uses internal fallbacks.
    EnsureIniValue(L"Fonts", L"BacklogFont", L"");
    EnsureIniValue(L"Fonts", L"BacklogSize", L"");
    EnsureIniValue(L"Fonts", L"DialogueFont", L"");
    EnsureIniValue(L"Fonts", L"DialogueSize", L"");
    EnsureIniValue(L"Fonts", L"BacklogNameFont", L"");
    EnsureIniValue(L"Fonts", L"BacklogNameSize", L"");
    EnsureIniValue(L"Fonts", L"BacklogXOffset", L"");
    EnsureIniValue(L"Fonts", L"BacklogLineSpacing", L"");
    EnsureIniValue(L"Fonts", L"BacklogYOffset", L"");
    EnsureIniValue(L"Fonts", L"BacklogNameXOffset", L"");
    EnsureIniValue(L"Fonts", L"BacklogNameYOffset", L"");
    EnsureIniValue(L"Fonts", L"BacklogNameSpacing", L"");
    EnsureIniValue(L"Fonts", L"BacklogDialogSpacing", L"");
    EnsureIniValue(L"Fonts", L"AdvancedSettings", L"");

    // [Settings] - keep blank in template; runtime uses internal fallbacks.
    EnsureIniValue(L"Settings", L"ShowBacklogIcon", L"");
    EnsureIniValue(L"Settings", L"EnableFileRedirection", L"");
    EnsureIniValue(L"Settings", L"Language", L"");
    EnsureIniValue(L"Settings", L"DisableBacklogFont", L"");
    EnsureIniValue(L"Settings", L"DisableBacklogSpacing", L"");
    EnsureIniValue(L"Settings", L"DisableBacklogTranslation", L"");

    // [Addresses] - keep blank in template; runtime uses internal fallbacks.
    EnsureIniValue(L"Addresses", L"BacklogHookRVA", L"");
    EnsureIniValue(L"Addresses", L"BacklogFuncRVA", L"");
    EnsureIniValue(L"Addresses", L"BacklogTableRVA", L"");
    EnsureIniValue(L"Addresses", L"BacklogStride", L"");
    EnsureIniValue(L"Addresses", L"BacklogTextOffset", L"");
    EnsureIniValue(L"Addresses", L"BacklogNameOffset", L"");
    EnsureIniValue(L"Addresses", L"BacklogMaxEntries", L"");

    if (backfilledCount > 0) {
      char msg[128];
      sprintf_s(msg, "DCPatch: Backfilled %d missing INI keys\n", backfilledCount);
      OutputDebugStringA(msg);
    }

    // Load custom settings if any
    WCHAR buf[128];
    if (GetPrivateProfileStringW(L"Fonts", L"DialogueFont", L"", buf, 128,
                                 m_iniPath.c_str()) > 0) {
      m_dialogueFontName = buf;
    }
    if (GetPrivateProfileStringW(L"Fonts", L"BacklogFont", L"", buf, 128,
                                 m_iniPath.c_str()) > 0) {
      m_backlogFontName = buf;
    }
    if (GetPrivateProfileStringW(L"Fonts", L"BacklogNameFont", L"", buf, 128,
                                 m_iniPath.c_str()) > 0) {
      m_backlogNameFontName = buf;
    }

    // GetPrivateProfileIntW returns 0 for negative numbers. We need a helper.
    auto ReadInt = [&](LPCWSTR key, int defVal) {
      WCHAR valBuf[64];
      if (GetPrivateProfileStringW(L"Fonts", key, L"", valBuf, 64,
                                   m_iniPath.c_str()) > 0) {
        return _wtoi(valBuf);
      }
      return defVal;
    };

    m_dialogueFontSizeOverride = ReadInt(L"DialogueSize", -19);
    m_backlogFontSizeOverride = ReadInt(L"BacklogSize", -19);
    m_backlogNameFontSizeOverride = ReadInt(L"BacklogNameSize", -11);
    m_backlogXOffset = ReadInt(L"BacklogXOffset", 0);
    m_backlogLineSpacing = ReadInt(L"BacklogLineSpacing", 0);
    m_backlogYOffset = ReadInt(L"BacklogYOffset", 12);
    m_backlogNameXOffset = ReadInt(L"BacklogNameXOffset", 13);
    m_backlogNameYOffset = ReadInt(L"BacklogNameYOffset", 0);
    m_backlogNameSpacing = ReadInt(L"BacklogNameSpacing", 0);
    m_backlogDialogSpacing = ReadInt(L"BacklogDialogSpacing", 0);
    m_advancedSettings = ReadInt(L"AdvancedSettings", 1) != 0;

    auto ReadIntOther = [&](LPCWSTR section, LPCWSTR key, int defVal) {
      WCHAR valBuf[64];
      if (GetPrivateProfileStringW(section, key, L"", valBuf, 64,
                                   m_iniPath.c_str()) > 0) {
        return _wtoi(valBuf);
      }
      return defVal;
    };

    m_enableBacklogAllIcon = ReadIntOther(L"Settings", L"ShowBacklogIcon", 1) != 0;
    
    // Read legacy settings for backwards compatibility
    bool legacyIdEnabled = ReadIntOther(L"Settings", L"EnableFileRedirection", 1) != 0;
    bool legacyEngEnabled = ReadIntOther(L"Settings", L"EnableEngData", 0) != 0;
    
    // Default to Indonesian if legacy EnableFileRedirection was true, but English overrides it.
    int defaultLang = 0;
    if (legacyIdEnabled) defaultLang = 1;
    if (legacyEngEnabled) defaultLang = 2;

    m_language = ReadIntOther(L"Settings", L"Language", defaultLang);
    m_disableBacklogFont = ReadIntOther(L"Settings", L"DisableBacklogFont", 0) != 0;
    m_disableBacklogSpacing = ReadIntOther(L"Settings", L"DisableBacklogSpacing", 0) != 0;
    m_disableBacklogTranslation = ReadIntOther(L"Settings", L"DisableBacklogTranslation", 0) != 0;

    // Read [Addresses] section (hex values like 0x5276)
    auto ReadHex = [&](LPCWSTR section, LPCWSTR key, DWORD defVal) -> DWORD {
      WCHAR valBuf[64];
      if (GetPrivateProfileStringW(section, key, L"", valBuf, 64, m_iniPath.c_str()) > 0) {
        return (DWORD)wcstoul(valBuf, nullptr, 0); // handles 0x prefix
      }
      return defVal;
    };
    m_addrBacklogHookRVA  = ReadHex(L"Addresses", L"BacklogHookRVA",  0);
    m_addrBacklogFuncRVA  = ReadHex(L"Addresses", L"BacklogFuncRVA",  0);
    m_addrBacklogTableRVA = ReadHex(L"Addresses", L"BacklogTableRVA", 0);
    m_backlogStride       = (int)ReadHex(L"Addresses", L"BacklogStride",      0x544);
    m_backlogTextOffset   = (int)ReadHex(L"Addresses", L"BacklogTextOffset",  0x000);
    m_backlogNameOffset   = (int)ReadHex(L"Addresses", L"BacklogNameOffset",  0x400);
    m_backlogMaxEntries   =      ReadIntOther(L"Addresses", L"BacklogMaxEntries", 200);

    // Set JSON file paths (same directory as INI)
    // Language-specific convention:
    //   Indonesian -> patch_names_id.json / patch_ui_id.json
    //   English    -> patch_names_eng.json / patch_ui_eng.json
    // Legacy fallback:
    //   patch_names.json / patch_ui.json
    std::wstring dir = m_iniPath.substr(0, m_iniPath.find_last_of(L"\\/"));
    g_activeJsonLanguage = m_language;

    std::wstring namesFile = L"patch_names";
    std::wstring uiFile    = L"patch_ui";
    if (m_language == 1) {
      namesFile += L"_id";
      uiFile    += L"_id";
    } else if (m_language == 2) {
      namesFile += L"_eng";
      uiFile    += L"_eng";
    }
    namesFile += L".json";
    uiFile    += L".json";

    g_namesJsonPath = dir + L"\\" + namesFile;
    g_uiJsonPath    = dir + L"\\" + uiFile;
    g_namesJsonFallbackPath = dir + L"\\patch_names.json";
    g_uiJsonFallbackPath    = dir + L"\\patch_ui.json";
    if (m_language == 0) {
      // Japanese mode already uses legacy names directly; fallback not needed.
      g_namesJsonFallbackPath = g_namesJsonPath;
      g_uiJsonFallbackPath    = g_uiJsonPath;
    }

    // If no custom dialogue font is set, try fallbacks
    if (m_dialogueFontName == L"ＭＳ ゴシック" || m_dialogueFontName == L"MS Gothic") {
      const wchar_t *candidates[] = {L"ＭＳ ゴシック", L"MS Gothic", L"MS PGothic",
                                     L"Yu Gothic UI", L"Tahoma"};
      for (auto name : candidates) {
        HFONT f = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, SHIFTJIS_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              DEFAULT_QUALITY, DEFAULT_PITCH, name);
        if (f) {
          m_dialogueFontName = name;
          if (m_backlogFontName == L"MS Gothic" || m_backlogFontName == L"ＭＳ ゴシック") { // Sync default if unset
            m_backlogFontName = name;
          }
          if (m_backlogNameFontName == L"MS Gothic" || m_backlogNameFontName == L"ＭＳ ゴシック") { // Sync default if unset
            m_backlogNameFontName = name;
          }
          DeleteObject(f);
          break;
        }
      }
    }
  }

  HFONT GetDialogueFont(int baseSize) {
    int requestedSize =
        m_dialogueFontSizeOverride != 0 ? m_dialogueFontSizeOverride : baseSize;
    if (m_dialogueFonts.count(requestedSize))
      return m_dialogueFonts[requestedSize];

    HFONT f = CreateFontW(requestedSize, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                          SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                          DEFAULT_PITCH, m_dialogueFontName.c_str());
    if (f)
      m_dialogueFonts[requestedSize] = f;
    return f;
  }

  HFONT GetBacklogFont(int baseSize) {
    int requestedSize =
        m_backlogFontSizeOverride != 0 ? m_backlogFontSizeOverride : baseSize;
    if (m_backlogFonts.count(requestedSize))
      return m_backlogFonts[requestedSize];

    HFONT f = CreateFontW(requestedSize, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                          SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                          DEFAULT_PITCH, m_backlogFontName.c_str());
    if (f)
      m_backlogFonts[requestedSize] = f;
    return f;
  }

  HFONT GetBacklogNameFont(int baseSize) {
    int requestedSize = m_backlogNameFontSizeOverride != 0
                            ? m_backlogNameFontSizeOverride
                            : baseSize;
    if (requestedSize == 0)
      requestedSize = baseSize; // Fallback
    if (m_backlogNameFonts.count(requestedSize))
      return m_backlogNameFonts[requestedSize];

    HFONT f = CreateFontW(requestedSize, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                          SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                          DEFAULT_PITCH, m_backlogNameFontName.c_str());
    if (f)
      m_backlogNameFonts[requestedSize] = f;
    return f;
  }

  void SetDialogueFont(const std::wstring &name, int size) {
    m_dialogueFontName = name;
    m_dialogueFontSizeOverride = size;
    for (auto &p : m_dialogueFonts)
      DeleteObject(p.second);
    m_dialogueFonts.clear();

    // Save
    WritePrivateProfileStringW(L"Fonts", L"DialogueFont", name.c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"DialogueSize",
                               std::to_wstring(size).c_str(),
                               m_iniPath.c_str());
  }

  void SetBacklogFont(const std::wstring &name, int size) {
    m_backlogFontName = name;
    m_backlogFontSizeOverride = size;
    for (auto &p : m_backlogFonts)
      DeleteObject(p.second);
    m_backlogFonts.clear();

    // Save
    WritePrivateProfileStringW(L"Fonts", L"BacklogFont", name.c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogSize",
                               std::to_wstring(size).c_str(),
                               m_iniPath.c_str());
  }

  void SetBacklogNameFont(const std::wstring &name, int size) {
    m_backlogNameFontName = name;
    m_backlogNameFontSizeOverride = size;
    for (auto &p : m_backlogNameFonts)
      DeleteObject(p.second);
    m_backlogNameFonts.clear();

    // Save
    WritePrivateProfileStringW(L"Fonts", L"BacklogNameFont", name.c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogNameSize",
                               std::to_wstring(size).c_str(),
                               m_iniPath.c_str());
  }

  void SetBacklogOffsets(int xOffset, int yOffset, int spacing, int nameXOffset,
                         int nameYOffset, int nameSpacing, int dialogSpacing) {
    m_backlogXOffset = xOffset;
    m_backlogYOffset = yOffset;
    m_backlogLineSpacing = spacing;
    m_backlogNameXOffset = nameXOffset;
    m_backlogNameYOffset = nameYOffset;
    m_backlogNameSpacing = nameSpacing;
    m_backlogDialogSpacing = dialogSpacing;
    WritePrivateProfileStringW(L"Fonts", L"BacklogXOffset",
                               std::to_wstring(xOffset).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogYOffset",
                               std::to_wstring(yOffset).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogLineSpacing",
                               std::to_wstring(spacing).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogNameXOffset",
                               std::to_wstring(nameXOffset).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogNameYOffset",
                               std::to_wstring(nameYOffset).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogNameSpacing",
                               std::to_wstring(nameSpacing).c_str(),
                               m_iniPath.c_str());
    WritePrivateProfileStringW(L"Fonts", L"BacklogDialogSpacing",
                               std::to_wstring(dialogSpacing).c_str(),
                               m_iniPath.c_str());
  }

  std::wstring GetDialogueFontName() const { return m_dialogueFontName; }
  std::wstring GetBacklogFontName() const { return m_backlogFontName; }
  std::wstring GetBacklogNameFontName() const { return m_backlogNameFontName; }
  int GetDialogueFontSize() const { return m_dialogueFontSizeOverride; }
  int GetBacklogFontSize() const { return m_backlogFontSizeOverride; }
  int GetBacklogNameFontSize() const { return m_backlogNameFontSizeOverride; }
  int GetBacklogXOffset() const {
    return m_advancedSettings ? m_backlogXOffset : 0;
  }
  int GetBacklogLineSpacing() const {
    return m_advancedSettings ? m_backlogLineSpacing : 0;
  }
  int GetBacklogYOffset() const {
    return m_advancedSettings ? m_backlogYOffset : 12;
  }
  int GetBacklogNameXOffset() const {
    return m_advancedSettings ? m_backlogNameXOffset : 13;
  }
  int GetBacklogNameYOffset() const {
    return m_advancedSettings ? m_backlogNameYOffset : 0;
  }
  int GetBacklogNameSpacing() const {
    return m_advancedSettings ? m_backlogNameSpacing : 0;
  }
  int GetBacklogDialogSpacing() const {
    return m_advancedSettings ? m_backlogDialogSpacing : 0;
  }

  void SetAdvancedSettings(bool advanced) {
    m_advancedSettings = advanced;
    WritePrivateProfileStringW(L"Fonts", L"AdvancedSettings",
                               std::to_wstring(advanced ? 1 : 0).c_str(),
                               m_iniPath.c_str());
  }

  bool GetAdvancedSettings() const { return m_advancedSettings; }
  
  void SetEnableBacklogAllIcon(bool enable) {
    m_enableBacklogAllIcon = enable;
    WritePrivateProfileStringW(L"Settings", L"ShowBacklogIcon",
                               std::to_wstring(enable ? 1 : 0).c_str(),
                               m_iniPath.c_str());
  }

  bool GetEnableBacklogAllIcon() const { return m_enableBacklogAllIcon; }
  
  void SetLanguage(int lang) {
    m_language = lang;
    WritePrivateProfileStringW(L"Settings", L"Language",
                               std::to_wstring(lang).c_str(),
                               m_iniPath.c_str());
  }

  int GetLanguage() const { return m_language; }

  bool GetDisableBacklogFont() const { return m_disableBacklogFont; }
  bool GetDisableBacklogSpacing() const { return m_disableBacklogSpacing; }
  bool GetDisableBacklogTranslation() const { return m_disableBacklogTranslation; }

  // Address getters (0 = auto-detect)
  DWORD GetAddrBacklogHookRVA()  const { return m_addrBacklogHookRVA; }
  DWORD GetAddrBacklogFuncRVA()  const { return m_addrBacklogFuncRVA; }
  DWORD GetAddrBacklogTableRVA() const { return m_addrBacklogTableRVA; }
  // Backlog table structure getters
  int GetBacklogStride()      const { return m_backlogStride; }
  int GetBacklogTextOffset()  const { return m_backlogTextOffset; }
  int GetBacklogNameOffset()  const { return m_backlogNameOffset; }
  int GetBacklogMaxEntries()  const { return m_backlogMaxEntries; }
};

static FontManager g_fontManager;
static HWND g_mainWindow = nullptr;

// ============================================================================
// Backlog Font Handling
// ============================================================================
// DC4's backlog font is large. This section handles font rendering in the
// backlog. Font scaling is currently disabled (100% original size).

static volatile bool g_inBacklogRender = false;

// Backlog font scaling function - returns original size (100%)
static int ScaleBacklogFontSize(int originalSize) {
  if (!g_inBacklogRender)
    return originalSize;
  return originalSize;
}

// ============================================================================
// File Redirection - Load from id_Data / eng_data subfolders by file type
//
// Directory layout:
//   id_Data\MES\     - translated .mes script files (Indonesian)
//   id_Data\GRP\     - translated .grp graphics files
//   id_Data\MOVIE\   - translated movie files (.mpg, .avi, .movie)
//   eng_data\MES\    - English .mes script files
//   eng_data\GRP\    - English .grp graphics files
//   eng_data\MOVIE\  - English movie files
//
// Priority: eng_data (if enabled) > id_Data > original
// ============================================================================

// Get the subfolder name for a given file extension
static const char *GetSubfolderForExt(const char *ext) {
  if (!ext) return nullptr;
  if (_stricmp(ext, ".mes") == 0) return "MES";
  if (_stricmp(ext, ".grp") == 0 || _stricmp(ext, ".crx") == 0 ||
      _stricmp(ext, ".crm") == 0) return "GRP";
  if (_stricmp(ext, ".mpg") == 0 || _stricmp(ext, ".avi") == 0 ||
      _stricmp(ext, ".movie") == 0) return "MOVIE";
  return nullptr;
}

static std::string ReplacePathA(const char *path) {
  if (!path)
    return {};

  std::string_view sv(path);

  // Don't redirect paths that are already inside our data folders
  std::string lowerPath(sv);
  for (auto& c : lowerPath) c = tolower(c);

  if (lowerPath.find("id_data") != std::string_view::npos ||
      lowerPath.find("eng_data") != std::string_view::npos ||
      lowerPath.find("sys_data") != std::string_view::npos) {
    return {};
  }

  // Extract filename (with extension) to determine the routing folder
  size_t sep = sv.find_last_of("\\/");
  std::string_view filename = (sep != std::string_view::npos)
                                  ? sv.substr(sep + 1)
                                  : sv;

  // Extract extension
  size_t dot = filename.find_last_of('.');
  const char *subfolder = nullptr;
  if (dot != std::string_view::npos) {
    std::string ext(filename.substr(dot));
    
    // Ignore graphic/animation files for dynamic redirection.
    // They are hardlink-synced to AdvData at startup, so redirecting them now 
    // causes handle conflicts and engine access violations during animations.
    if (_stricmp(ext.c_str(), ".crx") == 0 || 
        _stricmp(ext.c_str(), ".grp") == 0 || 
        _stricmp(ext.c_str(), ".crm") == 0 ||
        _stricmp(ext.c_str(), ".pck") == 0) {
      return {};
    }
    
    subfolder = GetSubfolderForExt(ext.c_str());
  }

  // 1. Strip 'AdvData\' if it exists to get the clean relative path
  std::string relPath(sv);
  size_t advPos = lowerPath.find("advdata");
  if (advPos != std::string_view::npos) {
    size_t startPos = advPos + 7;
    while (startPos < sv.length() && (sv[startPos] == '\\' || sv[startPos] == '/')) {
      startPos++;
    }
    relPath = std::string(sv.substr(startPos));
  } else if (sv.length() > 2 && sv[1] == ':') {
    // If it's an absolute path entirely outside AdvData, just use the filename to be safe
    relPath = std::string(filename);
  } else {
    // Strip leading .\ or / from flat paths
    size_t startPos = 0;
    while (startPos < sv.length() && (sv[startPos] == '.' || sv[startPos] == '\\' || sv[startPos] == '/')) {
      startPos++;
    }
    relPath = std::string(sv.substr(startPos));
  }

  // 2. Ensure relPath starts with the correct routing subfolder (e.g. "GRP")
  if (subfolder && !relPath.empty()) {
    std::string lowerRel(relPath);
    for (auto& c : lowerRel) c = tolower(c);
    
    std::string lowerSub(subfolder);
    for (auto& c : lowerSub) c = tolower(c);

    bool hasPrefix = false;
    if (lowerRel.length() >= lowerSub.length()) {
      if (lowerRel.substr(0, lowerSub.length()) == lowerSub) {
        if (lowerRel.length() == lowerSub.length() || 
            lowerRel[lowerSub.length()] == '\\' || 
            lowerRel[lowerSub.length()] == '/') {
          hasPrefix = true;
        }
      }
    }

    if (!hasPrefix) {
      relPath = std::string(subfolder) + "\\" + relPath;
    }
  }

  // Replace all forward slashes with backslashes
  for (auto& c : relPath) {
    if (c == '/') c = '\\';
  }

  // 3. Build candidate paths to try, in priority order:
  std::string candidates[6];
  int numCandidates = 0;

  int language = g_fontManager.GetLanguage();
  bool engEnabled = (language == 2);
  bool idEnabled = (language == 1);

  if (engEnabled) {
    if (!relPath.empty()) {
      candidates[numCandidates++] = std::string(".\\eng_data\\") + relPath;
    }
    if (subfolder && sep != std::string_view::npos) {
      candidates[numCandidates++] = std::string(".\\eng_data\\") + std::string(subfolder) + "\\" + std::string(filename);
    }
  }
  
  if (idEnabled) {
    if (!relPath.empty()) {
      candidates[numCandidates++] = std::string(".\\id_Data\\") + relPath;
    }
    if (subfolder && sep != std::string_view::npos) {
      candidates[numCandidates++] = std::string(".\\id_Data\\") + std::string(subfolder) + "\\" + std::string(filename);
    }
  }

  if (idEnabled) {
    if (sep != std::string_view::npos) {
      candidates[numCandidates++] = std::string(".\\id_Data\\") + std::string(filename);
    } else {
      candidates[numCandidates++] = std::string(".\\id_Data\\") + std::string(sv);
    }
  }

  for (int i = 0; i < numCandidates; i++) {
    char dbgCheck[512];
    DWORD attr = GetFileAttributesA(candidates[i].c_str());
    bool exists = (attr != INVALID_FILE_ATTRIBUTES);
    
    if (exists) {
      sprintf_s(dbgCheck, "DCPatch Route Info: File=%s -> Candidate Resolved: %s\n", path, candidates[i].c_str());
      OutputDebugStringA(dbgCheck);
      return candidates[i];
    }
  }
  return {};
}

// ============================================================================
// Backlog Icon Fix - Reverse Name Translation
// ============================================================================
//
// Problem: Translated .mes files in id_Data contain Latin character names
//          (e.g., "Ichito" instead of "一登"). CheckIcon (0x4049D0) finds
//          the icon data correctly (confirmed via x32dbg), but downstream
//          rendering code can't match Latin names to Japanese icon images.
//
// Solution: Hook after the backlog icon table is built (at 0x405276 in the
//           backlog builder function at 0x404EE0). Scan the table entries
//           and replace any translated Latin names with their Japanese
//           equivalents using g_nameTable. This fixes icon lookup while
//           the display name in the backlog text comes from a separate source.
//
// Table layout at 0x4BDA00:
//   Stride: 0x544 bytes per entry
//   [+0x000]: Resource ID (e.g., "dc4_kyo20190214d") — 0x400 bytes max
//   [+0x400]: Field1 — possibly character name
//   [+0x420]: Field2 — possibly another text field
//   [+0x440]: Field3 — possibly another text field
//   Entry count stored at [ebp+0x728] in the builder function

// JmpWrite - Write a JMP instruction at a target address
static bool JmpWrite(DWORD orgAddr, void *targetFunc) {
  BYTE jmp[5];
  jmp[0] = 0xE9; // JMP opcode
  *(DWORD *)(jmp + 1) = (DWORD)targetFunc - orgAddr - 5;

  DWORD oldProtect;
  if (!VirtualProtect((LPVOID)orgAddr, 5, PAGE_EXECUTE_READWRITE,
                      &oldProtect)) {
    return false;
  }

  SIZE_T written;
  // NOTE: Use GetCurrentProcess() — INVALID_HANDLE_VALUE is a Windows-only
  // alias for the current process that is NOT supported on Wine/Proton.
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)orgAddr, jmp, 5, &written);
  VirtualProtect((LPVOID)orgAddr, 5, oldProtect, &oldProtect);
  FlushInstructionCache(GetCurrentProcess(), (LPCVOID)orgAddr, 5);

  return (written == 5);
}

// MemWrite - Write arbitrary bytes at a target address
static bool MemWrite(DWORD addr, const void *data, size_t len) {
  DWORD oldProtect;
  if (!VirtualProtect((LPVOID)addr, len, PAGE_EXECUTE_READWRITE, &oldProtect))
    return false;
  SIZE_T written;
  // NOTE: Use GetCurrentProcess() — INVALID_HANDLE_VALUE is a Windows-only
  // alias for the current process that is NOT supported on Wine/Proton.
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)addr, data, len, &written);
  VirtualProtect((LPVOID)addr, len, oldProtect, &oldProtect);
  FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, len);
  return (written == len);
}

// Convert a UTF-8 string to Shift-JIS (codepage 932)
// Returns the number of bytes written (excluding null terminator), or 0 on
// failure
static int Utf8ToShiftJIS(const char *utf8, char *sjisOut, int sjisMaxLen) {
  // Step 1: UTF-8 → wide char (UTF-16)
  int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
  if (wideLen <= 0)
    return 0;

  wchar_t wideBuf[64];
  if (wideLen > 64)
    return 0;
  MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wideBuf, 64);

  // Step 2: wide char → Shift-JIS (codepage 932)
  int sjisLen = WideCharToMultiByte(932, 0, wideBuf, -1, sjisOut, sjisMaxLen,
                                    nullptr, nullptr);
  if (sjisLen <= 0)
    return 0;

  return sjisLen - 1; // exclude null terminator
}

// Scan the backlog icon table: reverse-translate names AND deduplicate entries.
// Returns the new entry count (may be less than input if duplicates were removed).
static int __cdecl PatchBacklogIconTable(int entryCount) {
  if (entryCount <= 0)
    return entryCount;

  // Safety cap from INI (default 200)
  int maxEntries = g_fontManager.GetBacklogMaxEntries();
  if (entryCount > maxEntries)
    entryCount = maxEntries;

  // Resolve TABLE_BASE dynamically (from INI or auto-scan).
  // Cached globally; set once in ResolveGameAddresses() during InitPatch.
  extern DWORD g_resolvedTableBase;
  const DWORD TABLE_BASE = g_resolvedTableBase;
  if (TABLE_BASE == 0) {
    // Table not yet resolved - skip silently
    return entryCount;
  }
  const int STRIDE     = g_fontManager.GetBacklogStride();     // default 0x544
  const int TEXT_FIELD = g_fontManager.GetBacklogTextOffset(); // default 0x000
  const int NAME_FIELD = g_fontManager.GetBacklogNameOffset(); // default 0x400

  // --- Pass 1: Reverse-translate character names ---
  if (g_fontManager.GetEnableBacklogAllIcon()) {
    for (int i = 0; i < entryCount; i++) {
      BYTE *entry = (BYTE *)(TABLE_BASE + i * STRIDE);
      char *nameField = (char *)(entry + NAME_FIELD);
      if (nameField[0] == 0)
        continue;

      const char *jpName = FindJapaneseName(nameField);
      if (jpName) {
        size_t jpLen = strlen(jpName);
        if (jpLen < 32) {
          memcpy(nameField, jpName, jpLen + 1);
        }
      }
    }
  }

  // --- Pass 2: Remove consecutive duplicate entries ---
  int newCount = entryCount;
  for (int i = 0; i < newCount - 1; i++) {
    char *textA = (char *)(TABLE_BASE + i * STRIDE + TEXT_FIELD);
    char *textB = (char *)(TABLE_BASE + (i + 1) * STRIDE + TEXT_FIELD);

    // Safety: only compare if both strings are non-empty and i+1 is in bounds
    if (i + 1 >= newCount)
      break;

    if (textA[0] != 0 && textB[0] != 0 && strcmp(textA, textB) == 0) {
      for (int j = i + 1; j < newCount - 1; j++) {
        BYTE *dst = (BYTE *)(TABLE_BASE + j * STRIDE);
        BYTE *src = (BYTE *)(TABLE_BASE + (j + 1) * STRIDE);
        memcpy(dst, src, STRIDE);
      }
      memset((BYTE *)(TABLE_BASE + (newCount - 1) * STRIDE), 0, STRIDE);
      newCount--;
      i--;
    }
  }

  return newCount;
}

// Global return address for the naked asm trampoline — set at runtime
// in InstallBacklogIconHook() from the module base.
static DWORD g_backlogReturnAddr = 0;

// Naked asm trampoline: hooks at 0x405276 (after backlog table is built)
// Original bytes at 0x405276: 33 DB 83 E8 01 (xor ebx,ebx; sub eax,1) = 5 bytes
// At this point: eax = entry count from [ebp+0x728]
//
// PatchBacklogIconTable returns the new count (after dedup).
// We write the new count to both EAX and [ebp+0x728] so the rendering
// loop uses the correct number of entries.
__declspec(naked) void HookBacklogTableBuilt() {
  __asm {
    // eax = entry count (from mov eax,[ebp+728] at 0x405270)
        pushad // save all regs (EAX at [esp+28])
        push eax // pass entry count
        call PatchBacklogIconTable // returns new count in eax
        add esp, 4
        mov [esp+28], eax           // overwrite saved EAX with new count
        // Also update [ebp+0x728] — ebp is at [esp+8] in pushad frame
        mov ecx, [esp+8] // ecx = saved EBP (backlog object)
        mov [ecx+0x728], eax // update the entry count in the object
        popad // eax now = new count

        // Execute displaced instructions
        xor ebx, ebx // original: 33 DB
        sub eax, 1 // original: 83 E8 01

    // Jump back — address computed at runtime from module base
        jmp dword ptr [g_backlogReturnAddr]
  }
}

// Install the backlog icon table hook
// Addresses are resolved via auto-scan (pattern matching) with INI fallback.
//
// Pattern scanned in .text:
//   33 DB 83 E8 01  =  xor ebx,ebx; sub eax,1
// This 5-byte sequence immediately follows the backlog table builder loop
// and is the hook insertion point.

// Globally cached resolved addresses
DWORD g_resolvedTableBase   = 0;  // Backlog icon table base (.data)
DWORD g_resolvedHookAddr    = 0;  // Hook insertion point in .text
DWORD g_resolvedFuncAddr    = 0;  // BacklogFunc entry point

static bool InstallBacklogIconHook() {
  DWORD hookAddr = g_resolvedHookAddr;
  if (hookAddr == 0) return false;

  g_backlogReturnAddr = hookAddr + 5;
  return JmpWrite(hookAddr, HookBacklogTableBuilt);
}

// Resolve all game-specific addresses: try INI overrides first, then pattern scan.
// Called once from InitPatch() before any hooks are installed.
static void ResolveGameAddresses() {
  const DWORD moduleBase = (DWORD)GetModuleHandleA(NULL);

  // ---- 1. Hook site: scan .text for 33 DB 83 E8 01 ----
  //         xor ebx,ebx (33 DB)  +  sub eax,1 (83 E8 01)
  //
  // INI override: [Addresses] BacklogHookRVA=0x5276
  DWORD hookRVA = g_fontManager.GetAddrBacklogHookRVA();
  if (hookRVA != 0) {
    g_resolvedHookAddr = moduleBase + hookRVA;
    OutputDebugStringA("DCPatch: BacklogHookAddr from INI\n");
  } else {
    // Auto-scan .text for 33 DB 83 E8 01
    static const BYTE hookPat[] = {0x33, 0xDB, 0x83, 0xE8, 0x01};
    DWORD addr = ScanSection(".text", hookPat, "xxxxx");
    if (addr) {
      g_resolvedHookAddr = addr;
      char msg[128];
      sprintf_s(msg, "DCPatch: BacklogHookAddr auto-scan => 0x%08X (RVA 0x%X)\n",
                addr, addr - moduleBase);
      OutputDebugStringA(msg);
    } else {
      OutputDebugStringA("DCPatch WARNING: BacklogHookAddr pattern not found!\n");
    }
  }

  // ---- 2. BacklogFunc: walk backward from hook site to function prologue ----
  //
  // INI override: [Addresses] BacklogFuncRVA=0x4EE0
  DWORD funcRVA = g_fontManager.GetAddrBacklogFuncRVA();
  if (funcRVA != 0) {
    g_resolvedFuncAddr = moduleBase + funcRVA;
    OutputDebugStringA("DCPatch: BacklogFuncAddr from INI\n");
  } else if (g_resolvedHookAddr != 0) {
    DWORD funcAddr = FindFunctionStart(g_resolvedHookAddr);
    if (funcAddr) {
      g_resolvedFuncAddr = funcAddr;
      char msg[128];
      sprintf_s(msg, "DCPatch: BacklogFuncAddr auto-walk => 0x%08X (RVA 0x%X)\n",
                funcAddr, funcAddr - moduleBase);
      OutputDebugStringA(msg);
    } else {
      OutputDebugStringA("DCPatch WARNING: BacklogFuncAddr prologue not found!\n");
    }
  }

  // ---- 3. Backlog icon table base: scan instructions in [func, hook) range ----
  //
  // INI override: [Addresses] BacklogTableRVA=0xBDA00
  DWORD tableRVA = g_fontManager.GetAddrBacklogTableRVA();
  if (tableRVA != 0) {
    g_resolvedTableBase = moduleBase + tableRVA;
    OutputDebugStringA("DCPatch: BacklogTableBase from INI\n");
  } else if (g_resolvedFuncAddr != 0 && g_resolvedHookAddr != 0) {
    DWORD tableBase = FindDataPointerInRange(g_resolvedFuncAddr, g_resolvedHookAddr);
    if (tableBase) {
      g_resolvedTableBase = tableBase;
      char msg[128];
      sprintf_s(msg, "DCPatch: BacklogTableBase auto-scan => 0x%08X (RVA 0x%X)\n",
                tableBase, tableBase - moduleBase);
      OutputDebugStringA(msg);
    } else {
      OutputDebugStringA("DCPatch WARNING: BacklogTableBase not found in function body!\n");
    }
  }
}

// ============================================================================
// Backlog Render Detection Hook (Detours-based)
// ============================================================================
// The backlog function at 0x404EE0 is called when the user opens the log.
// We use Detours to wrap it: set g_inBacklogRender on entry, call original,
// clear the flag on return. Detours handles prologue displacement
// automatically.

// Function pointer - initialized at runtime in InitPatch() from module base.
// Cannot use compile-time constant because Wine/Proton may relocate the EXE.
static void(__cdecl *Real_BacklogFunc)() = nullptr;

static void __cdecl Hook_BacklogFunc() {
  g_inBacklogRender = true;
  Real_BacklogFunc(); // Detours trampoline handles displaced prologue
  g_inBacklogRender = false;
}

// ============================================================================
// Hooks
// ============================================================================

static decltype(&GetGlyphOutlineA) Real_GetGlyphOutlineA = GetGlyphOutlineA;
static decltype(&CreateFileA) Real_CreateFileA = CreateFileA;
static decltype(&CreateFileW) Real_CreateFileW = CreateFileW;

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

  static thread_local bool s_inCreateFileW = false;
  if (s_inCreateFileW) {
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
  }

  s_inCreateFileW = true;

  int lang = g_fontManager.GetLanguage();
  if (lang == 1 || lang == 2) {
    int len = WideCharToMultiByte(932, 0, lpFileName, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
      std::string pathA(len, '\0');
      WideCharToMultiByte(932, 0, lpFileName, -1, &pathA[0], len, NULL, NULL);
      pathA.resize(len - 1);
      
      std::string newPathA = ReplacePathA(pathA.c_str());
      if (!newPathA.empty()) {
        // Resolve to absolute path
        char absPath[MAX_PATH];
        DWORD absLen = GetFullPathNameA(newPathA.c_str(), MAX_PATH, absPath, NULL);
        const char* finalPathA = (absLen > 0 && absLen < MAX_PATH) ? absPath : newPathA.c_str();

        int wlen = MultiByteToWideChar(932, 0, finalPathA, -1, NULL, 0);
        if (wlen > 0) {
          std::wstring newPathW(wlen, L'\0');
          MultiByteToWideChar(932, 0, finalPathA, -1, &newPathW[0], wlen);
          newPathW.resize(wlen - 1);
          
          char debugStr[512];
          sprintf_s(debugStr, "DCPatch Redirecting W: %s -> %s\n", pathA.c_str(), finalPathA);
          OutputDebugStringA(debugStr);

          HANDLE h = Real_CreateFileW(newPathW.c_str(), dwDesiredAccess, dwShareMode,
                                      lpSecurityAttributes, dwCreationDisposition,
                                      dwFlagsAndAttributes, hTemplateFile);
          s_inCreateFileW = false;
          return h;
        }
      }
    }
  }

  HANDLE h = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                              lpSecurityAttributes, dwCreationDisposition,
                              dwFlagsAndAttributes, hTemplateFile);
  s_inCreateFileW = false;
  return h;
}
static decltype(&CreateWindowExA) Real_CreateWindowExA = CreateWindowExA;
static decltype(&GetTextExtentPoint32A) Real_GetTextExtentPoint32A =
    GetTextExtentPoint32A;
static decltype(&GetTextExtentPoint32W) Real_GetTextExtentPoint32W =
    GetTextExtentPoint32W;
static decltype(&MessageBoxA) Real_MessageBoxA = MessageBoxA;
static decltype(&DialogBoxParamA) Real_DialogBoxParamA = DialogBoxParamA;
static decltype(&AppendMenuA) Real_AppendMenuA = AppendMenuA;
static decltype(&InsertMenuA) Real_InsertMenuA = InsertMenuA;
static decltype(&ModifyMenuA) Real_ModifyMenuA = ModifyMenuA;
static decltype(&GetTextMetricsA) Real_GetTextMetricsA = GetTextMetricsA;
static decltype(&ExtTextOutA) Real_ExtTextOutA = ExtTextOutA;

// ============================================================================
// Japanese Codepage Hooks (Wine/Proton fix)
// ============================================================================
// On Wine/Proton (Android), GetACP() may return the host Linux codepage
// instead of 932 (Shift-JIS), breaking Japanese string handling in the game.
// These hooks are harmless on Windows (LE already set the codepage).
// NOTE: LCID/LangID hooks are intentionally omitted - they break backlog.

typedef UINT(WINAPI *pfnGetACP)(void);
typedef UINT(WINAPI *pfnGetOEMCP)(void);

static pfnGetACP Real_GetACP = GetACP;
static pfnGetOEMCP Real_GetOEMCP = GetOEMCP;

static UINT WINAPI Hook_GetACP() { return 932; }
static UINT WINAPI Hook_GetOEMCP() { return 932; }

// ============================================================================
// Indonesian UI Translation System
// ============================================================================
// Two-pronged approach:
// 1. Hook-based: intercepts MessageBoxA, AppendMenuA etc. for runtime
// translation
// 2. Memory-patch: scans loaded EXE's .rdata/.data and replaces strings
// in-place
//    at startup, catching chapter titles and game-engine-rendered text.
// Indonesian text is pure ASCII which is valid in Shift-JIS codepage.

struct UITranslationEntry {
  std::string japaneseSjis;  // Original SJIS bytes (for comparison & memory patching)
  std::string translated;    // Translated replacement text
  // Keep original SJIS literal for fallback compatibility (pointer stays valid)
  const char *japanese_literal = nullptr; // non-null only for built-in entries
  const char *translated_literal = nullptr;
};

// Master translation table - populated at runtime from patch_ui.json or built-in
static std::vector<UITranslationEntry> g_uiTranslations;

// Built-in DC4 raw SJIS table — stays for fallback (same as original)
struct UITranslation {
  const char *japanese;   // Original SJIS bytes
  const char *indonesian; // Indonesian replacement (ASCII)
};
static const UITranslation k_dc4BuiltinUI[] = {
    // ===================== System UI =====================
    // ◆タイトル名◆
    {"\x81\x9f\x83\x5e\x83\x43\x83\x67\x83\x8b\x96\xbc\x81\x9f",
     "\x81\x9fNama Judul\x81\x9f"},
    // 実行エラー
    {"\x8e\xc0\x8d\x73\x83\x47\x83\x89\x81\x5b", "Terjadi kesalahan eksekusi"},
    // 」を実行できません！
    {"\x81\x76\x82\xf0\x8e\xc0\x8d\x73\x82\xc5\x82\xab\x82\xdc\x82\xb9\x82\xf1"
     "\x81\x49",
     "\x81vtidak dapat dijalankan!"},
    // タイトル名なし
    {"\x83\x5e\x83\x43\x83\x67\x83\x8b\x96\xbc\x82\xc8\x82\xb5",
     "Tanpa nama judul"},
    // 接続に失敗しました。
    {"\x90\xda\x91\xb1\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd"
     "\x81\x42",
     "Koneksi gagal."},
    // ネットに接続しますよろしいですか？
    {"\x83\x6c\x83\x62\x83\x67\x82\xc9\x90\xda\x91\xb1\x82\xb5\x82\xdc\x82\xb7"
     "\x82\xe6\x82\xeb\x82\xb5\x82\xa2\x82\xc5\x82\xb7\x82\xa9\x81\x48",
     "Ingin menyambung ke internet?"},
    // D.C.4 〜ダ・カーポ4〜
    {"\x44\x2e\x43\x2e\x34\x20\x81\x60\x83\x5f\x81\x45\x83\x4a\x81\x5b\x83\x7c"
     "\x34\x81\x60",
     "D.C.4 ~Da Capo 4~"},
    // 空良
    {"\x8b\xf3\x97\xc7", "Sora"},
    // 櫻井
    {"\x9f\x4e\x88\xe4", "Sakurai"},
    // @names.datが読めないか項目数が違います。
    {"\x40\x6e\x61\x6d\x65\x73\x2e\x64\x61\x74\x82\xaa\x93\xc7\x82\xdf\x82\xc8"
     "\x82\xa2\x82\xa9\x8d\x80\x96\xda\x90\x94\x82\xaa\x88\xe1\x82\xa2\x82\xdc"
     "\x82\xb7\x81\x42",
     "@names.dat tidak dapat dibaca atau jumlah item tidak sesuai."},
    // 正しくインストールしてください
    {"\x90\xb3\x82\xb5\x82\xad\x83\x43\x83\x93\x83\x58\x83\x67\x81\x5b\x83\x8b"
     "\x82\xb5\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Silakan instal dengan benar"},
    // 正常に遊ぶためには、正しくインストールしてください
    {"\x90\xb3\x8f\xed\x82\xc9\x97\x56\x82\xd4\x82\xbd\x82\xdf\x82\xc9\x82\xcd"
     "\x81\x41\x90\xb3\x82\xb5\x82\xad\x83\x43\x83\x93\x83\x58\x83\x67\x81\x5b"
     "\x83\x8b\x82\xb5\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Silakan instal dengan benar agar dapat bermain dengan normal"},
    // "%s"を作成してよろしいですか？
    {"\x22\x25\x73\x22\x82\xf0\x8d\xec\x90\xac\x82\xb5\x82\xc4\x82\xe6\x82\xeb"
     "\x82\xb5\x82\xa2\x82\xc5\x82\xb7\x82\xa9\x81\x48",
     "Apakah Anda yakin ingin membuat \"%s\"?"},

    // データVer.%s
    {"\x83\x66\x81\x5b\x83\x5e\x56\x65\x72\x2e\x25\x73", "Versi Data %s"},
    // ログイン情報に空欄があります。
    {"\x83\x8d\x83\x4f\x83\x43\x83\x93\x8f\xee\x95\xf1\x82\xc9\x8b\xf3\x97\x93"
     "\x82\xaa\x82\xa0\x82\xe8\x82\xdc\x82\xb7\x81\x42",
     "Ada kolom informasi login yang kosong."},
    // 最大でインストールを行ってください。
    {"\x8d\xc5\x91\xe5\x82\xc5\x83\x43\x83\x93\x83\x58\x83\x67\x81\x5b\x83\x8b"
     "\x82\xf0\x8d\x73\x82\xc1\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2\x81\x42",
     "Silakan lakukan instalasi maksimal."},
    // 0(ゼロ)とO(オー)、1(イチ)とI(アイ)等もご確認ください。
    {"\x30\x28\x83\x5b\x83\x8d\x29\x82\xc6\x4f\x28\x83\x49\x81\x5b\x29\x81\x41"
     "\x31\x28\x83\x43\x83\x60\x29\x82\xc6\x49\x28\x83\x41\x83\x43\x29\x93\x99"
     "\x82\xe0\x82\xb2\x8a\x6d\x94\x46\x82\xad\x82\xbe\x82\xb3\x82\xa2\x81\x42",
     "Silakan periksa kembali angka 0 (nol) dengan O (huruf O), 1 (satu) "
     "dengan I (huruf I), dll."},
    // 解除キーURLをクリップボードにコピーしますか？
    {"\x89\xf0\x8f\x9c\x83\x4c\x81\x5b\x55\x52\x4c\x82\xf0\x83\x4e\x83\x8a\x83"
     "\x62\x83\x76\x83\x7b\x81\x5b\x83\x68\x82\xc9\x83\x52\x83\x73\x81\x5b\x82"
     "\xb5\x82\xdc\x82\xb7\x82\xa9\x81\x48",
     "Salin URL kunci pembuka ke clipboard?"},
    // ウェブブラウザを起動できませんでした。
    {"\x83\x45\x83\x46\x83\x75\x83\x75\x83\x89\x83\x45\x83\x55\x82\xf0\x8b\x4e"
     "\x93\xae\x82\xc5\x82\xab\x82\xdc\x82\xb9\x82\xf1\x82\xc5\x82\xb5\x82\xbd"
     "\x81\x42",
     "Gagal menjalankan browser web."},
    // に接続します。
    {"\x82\xc9\x90\xda\x91\xb1\x82\xb5\x82\xdc\x82\xb7\x81\x42",
     "Menyambung ke."},
    // 解除しないとディスクレスでプレイできません。
    {"\x89\xf0\x8f\x9c\x82\xb5\x82\xc8\x82\xa2\x82\xc6\x83\x66\x83\x42\x83\x58"
     "\x83\x4e\x83\x8c\x83\x58\x82\xc5\x83\x76\x83\x8c\x83\x43\x82\xc5\x82\xab"
     "\x82\xdc\x82\xb9\x82\xf1\x81\x42",
     "Anda tidak bisa bermain tanpa disk kecuali proteksi dilepaskan."},
    // 解除キーはインターネット経由で入手したものを入れてください。
    {"\x89\xf0\x8f\x9c\x83\x4c\x81\x5b\x82\xcd\x83\x43\x83\x93\x83\x5e\x81\x5b"
     "\x83\x6c\x83\x62\x83\x67\x8c\x6f\x97\x52\x82\xc5\x93\xfc\x8e\xe8\x82\xb5"
     "\x82\xbd\x82\xe0\x82\xcc\x82\xf0\x93\xfc\x82\xea\x82\xc4\x82\xad\x82\xbe"
     "\x82\xb3\x82\xa2\x81\x42",
     "Silakan masukkan kunci pembuka yang diperoleh melalui internet."},
    // 正しく解除しました。
    {"\x90\xb3\x82\xb5\x82\xad\x89\xf0\x8f\x9c\x82\xb5\x82\xdc\x82\xb5\x82\xbd"
     "\x81\x42",
     "Berhasil dilepaskan."},
    // DC4のDVDをセットしてください
    {"\x44\x43\x34\x82\xcc\x44\x56\x44\x82\xf0\x83\x5a\x83\x62\x83\x67\x82\xb5"
     "\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Silakan masukkan DVD DC4"},
    // K.$バージョン情報
    {"\x4b\x2e\x24\x83\x6f\x81\x5b\x83\x57\x83\x87\x83\x93\x8f\xee\x95\xf1",
     "K.$Info Versi"},
    // ウインドウサイズを元に戻す
    {"\x83\x45\x83\x43\x83\x93\x83\x68\x83\x45\x83\x54\x83\x43\x83\x59\x82\xf0"
     "\x8c\xb3\x82\xc9\x96\xdf\x82\xb7",
     "Kembalikan ukuran jendela"},
    // を選択してください
    {"\x82\xf0\x91\x49\x91\xf0\x82\xb5\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Silakan pilih"},
    // ディスクレス化を行いますか？
    {"\x83\x66\x83\x42\x83\x58\x83\x4e\x83\x8c\x83\x58\x89\xbb\x82\xf0\x8d\x73"
     "\x82\xa2\x82\xdc\x82\xb7\x82\xa9\x81\x48",
     "Aktifkan mode tanpa disk?"},
    // 画面解像度/画面色数:%d x
    {"\x89\xe6\x96\xca\x89\xf0\x91\x9c\x93\x78\x2f\x89\xe6\x96\xca\x90\x46\x90"
     "\x94\x3a\x25\x64\x20\x78",
     "Resolusi Layar/Kedalaman Warna:%d x"},
    // を作成しました。
    {"\x82\xf0\x8d\xec\x90\xac\x82\xb5\x82\xdc\x82\xb5\x82\xbd\x81\x42",
     "telah dibuat."},
    // フォルダが選択できませんでした。
    {"\x83\x74\x83\x48\x83\x8b\x83\x5f\x82\xaa\x91\x49\x91\xf0\x82\xc5\x82\xab"
     "\x82\xdc\x82\xb9\x82\xf1\x82\xc5\x82\xb5\x82\xbd\x81\x42",
     "Folder tidak dapat dipilih."},
    // フォルダを選択してください
    {"\x83\x74\x83\x48\x83\x8b\x83\x5f\x82\xf0\x91\x49\x91\xf0\x82\xb5\x82\xc4"
     "\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Silakan pilih folder"},
    // ウインドウサイズを固定する
    {"\x83\x45\x83\x43\x83\x93\x83\x68\x83\x45\x83\x54\x83\x43\x83\x59\x82\xf0"
     "\x8c\xc5\x92\xe8\x82\xb7\x82\xe9",
     "Kunci ukuran jendela"},
    // ウインドウサイズの固定を解除する
    {"\x83\x45\x83\x43\x83\x93\x83\x68\x83\x45\x83\x54\x83\x43\x83\x59\x82\xcc"
     "\x8c\xc5\x92\xe8\x82\xf0\x89\xf0\x8f\x9c\x82\xb7\x82\xe9",
     "Lepas kunci ukuran jendela"},
    // ログアウトしました
    {"\x83\x8d\x83\x4f\x83\x41\x83\x45\x83\x67\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Berhasil logout"},
    // 終了しますか？
    {"\x8f\x49\x97\xb9\x82\xb5\x82\xdc\x82\xb7\x82\xa9\x81\x48",
     "Ingin keluar?"},
    // ログインに失敗しました。
    {"\x83\x8d\x83\x4f\x83\x43\x83\x93\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc"
     "\x82\xb5\x82\xbd\x81\x42",
     "Login gagal."},
    // 通信ができませんでした。
    {"\x92\xca\x90\x4d\x82\xaa\x82\xc5\x82\xab\x82\xdc\x82\xb9\x82\xf1\x82\xc5"
     "\x82\xb5\x82\xbd\x81\x42",
     "Gagal berkomunikasi."},
    // に書き込めません。
    {"\x82\xc9\x8f\x91\x82\xab\x8d\x9e\x82\xdf\x82\xdc\x82\xb9\x82\xf1\x81\x42",
     "Tidak dapat menulis ke."},
    // DC4　インストール
    {"\x44\x43\x34\x81\x40\x83\x43\x83\x93\x83\x58\x83\x67\x81\x5b\x83\x8b",
     "Instalasi DC4"},
    // DirectXはインストールされてます。
    {"\x44\x69\x72\x65\x63\x74\x58\x82\xcd\x83\x43\x83\x93\x83\x58\x83\x67\x81"
     "\x5b\x83\x8b\x82\xb3\x82\xea\x82\xc4\x82\xdc\x82\xb7\x81\x42",
     "DirectX sudah terinstal."},
    // すでにメディアレス化されています。
    {"\x82\xb7\x82\xc5\x82\xc9\x83\x81\x83\x66\x83\x42\x83\x41\x83\x8c\x83\x58"
     "\x89\xbb\x82\xb3\x82\xea\x82\xc4\x82\xa2\x82\xdc\x82\xb7\x81\x42",
     "Sudah dalam mode tanpa media."},
    // すでにディスクレス化されています。
    {"\x82\xb7\x82\xc5\x82\xc9\x83\x66\x83\x42\x83\x58\x83\x4e\x83\x8c\x83\x58"
     "\x89\xbb\x82\xb3\x82\xea\x82\xc4\x82\xa2\x82\xdc\x82\xb7\x81\x42",
     "Sudah dalam mode tanpa disk."},
    // 実行されてますので、ディスクレス認証が起動できません。
    {"\x8e\xc0\x8d\x73\x82\xb3\x82\xea\x82\xc4\x82\xdc\x82\xb7\x82\xcc\x82\xc5"
     "\x81\x41\x83\x66\x83\x42\x83\x58\x83\x4e\x83\x8c\x83\x58\x94\x46\x8f\xd8"
     "\x82\xaa\x8b\x4e\x93\xae\x82\xc5\x82\xab\x82\xdc\x82\xb9\x82\xf1\x81\x42",
     "Karena sedang berjalan, autentikasi tanpa disk tidak dapat dimulai."},
    // }@ＭＳ ゴシック
    {"\x7d\x40\x82\x6c\x82\x72\x20\x83\x53\x83\x56\x83\x62\x83\x4e",
     "}@MS Gothic"},
    // 入力がされてない箇所がありますがよろしいですか？
    {"\x93\xfc\x97\xcd\x82\xaa\x82\xb3\x82\xea\x82\xc4\x82\xc8\x82\xa2\x89\xd3"
     "\x8f\x8a\x82\xaa\x82\xa0\x82\xe8\x82\xdc\x82\xb7\x82\xaa\x82\xe6\x82\xeb"
     "\x82\xb5\x82\xa2\x82\xc5\x82\xb7\x82\xa9\x81\x48",
     "Masih ada bagian yang belum diisi, apakah tidak apa-apa?"},
    // @か.が入力されてないメールアドレスです。
    {"\x40\x82\xa9\x2e\x82\xaa\x93\xfc\x97\xcd\x82\xb3\x82\xea\x82\xc4\x82\xc8"
     "\x82\xa2\x83\x81\x81\x5b\x83\x8b\x83\x41\x83\x68\x83\x8c\x83\x58\x82\xc5"
     "\x82\xb7\x81\x42",
     "Alamat email tidak mengandung @ atau titik (.)."},
    // セーブデータの更新に失敗しました。
    {"\x83\x5a\x81\x5b\x83\x75\x83\x66\x81\x5b\x83\x5e\x82\xcc\x8d\x58\x90\x56"
     "\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd\x81\x42",
     "Gagal memperbarui data save."},
    // セーブデータの取得に失敗しました。
    {"\x83\x5a\x81\x5b\x83\x75\x83\x66\x81\x5b\x83\x5e\x82\xcc\x8e\xe6\x93\xbe"
     "\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd\x81\x42",
     "Gagal mengambil data save."},
    // コマンドセーブの::の数が多い
    {"\x83\x52\x83\x7d\x83\x93\x83\x68\x83\x5a\x81\x5b\x83\x75\x82\xcc\x3a\x3a"
     "\x82\xcc\x90\x94\x82\xaa\x91\xbd\x82\xa2",
     "Terlalu banyak jumlah :: pada command save"},

    // ===================== Chapter/Story Titles =====================
    // 学生特権
    {"\x8a\x77\x90\xb6\x93\xc1\x8c\xa0", "Hak Istimewa Pelajar"},
    // 秘されしモノ
    {"\x94\xe9\x82\xb3\x82\xea\x82\xb5\x83\x82\x83\x6d",
     "Sesuatu yang Tersembunyi"},
    // 願いの軌跡
    {"\x8a\xe8\x82\xa2\x82\xcc\x8b\x4f\x90\xd5", "Jejak Harapan"},
    // 奇跡を願っても
    {"\x8a\xef\x90\xd5\x82\xf0\x8a\xe8\x82\xc1\x82\xc4\x82\xe0",
     "Meski Mengharap Keajaiban"},
    // 今この手の中の幸福
    {"\x8d\xa1\x82\xb1\x82\xcc\x8e\xe8\x82\xcc\x92\x86\x82\xcc\x8d\x4b\x95\x9f",
     "Kebahagiaan di Tangan Ini Sekarang"},
    // 愛という幸福

    {"\x88\xa4\x82\xc6\x82\xa2\x82\xa4\x8d\x4b\x95\x9f", "Cinta Bahagia"},

    // もしこの心届くなら
    {"\x82\xe0\x82\xb5\x82\xb1\x82\xcc\x90\x53\x93\xcd\x82\xad\x82\xc8\x82\xe7",
     "Kebahagiaan yang Disebut Cinta"},
    // 震える心抱いて
    {"\x90\x6b\x82\xa6\x82\xe9\x90\x53\x95\xf8\x82\xa2\x82\xc4",
     "Jika Hati Ini Bisa Sampai Padamu"},
    // 心奏でて
    {"\x90\x53\x91\x74\x82\xc5\x82\xc4", "Memeluk Hati yang Bergetar"},
    // 奮い立つ心
    {"\x95\xb1\x82\xa2\x97\xa7\x82\xc2\x90\x53", "Melodi Hati"},
    // 重ね想う
    {"\x8f\x64\x82\xcb\x91\x7a\x82\xa4", "Semangat yang Membara"},
    // 並んで歩くだけでも
    {"\x95\xc0\x82\xf1\x82\xc5\x95\xe0\x82\xad\x82\xbe\x82\xaf\x82\xc5\x82\xe0",
     "Perasaan yang Bertumpuk"},
    // 抜き足差し足猫の足
    {"\x94\xb2\x82\xab\x91\xab\x8d\xb7\x82\xb5\x91\xab\x94\x4c\x82\xcc\x91\xab",
     "Meski Hanya Berjalan Berdampingan"},
    // こんな上々の休日
    {"\x82\xb1\x82\xf1\x82\xc8\x8f\xe3\x81\x58\x82\xcc\x8b\x78\x93\xfa",
     "Berjinjit Seperti Langkah Kaki Kucing"},
    // 心躍り胸弾む
    {"\x90\x53\x96\xf4\x82\xe8\x8b\xb9\x92\x65\x82\xde",
     "Hari Libur yang Luar Biasa"},
    // 足取り軽く心軽く
    {"\x91\xab\x8e\xe6\x82\xe8\x8c\x79\x82\xad\x90\x53\x8c\x79\x82\xad",
     "Hati Berdebar Penuh Suka Cita"},
    // 静かに冴える夜
    {"\x90\xc3\x82\xa9\x82\xc9\x8d\xe1\x82\xa6\x82\xe9\x96\xe9",
     "Langkah Ringan, Hati Tenang"},
    // まだまだ今日は終わらない
    {"\x82\xdc\x82\xbe\x82\xdc\x82\xbe\x8d\xa1\x93\xfa\x82\xcd\x8f\x49\x82\xed"
     "\x82\xe7\x82\xc8\x82\xa2",
     "Malam yang Hening dan Jernih"},
    // 実家のような心地よさ
    {"\x8e\xc0\x89\xc6\x82\xcc\x82\xe6\x82\xa4\x82\xc8\x90\x53\x92\x6e\x82\xe6"
     "\x82\xb3",
     "Hari Ini Masih Belum Berakhir"},
    // 解き放て青春
    {"\x89\xf0\x82\xab\x95\xfa\x82\xc4\x90\xc2\x8f\x74",
     "Kenyamanan Seperti di Rumah Sendiri"},
    // 学食か購買か弁当か
    {"\x8a\x77\x90\x48\x82\xa9\x8d\x77\x94\x83\x82\xa9\x95\xd9\x93\x96\x82\xa9",
     "Lepaskan Masa Muda"},
    // 未来への資産
    {"\x96\xa2\x97\x88\x82\xd6\x82\xcc\x8e\x91\x8e\x59",
     "Kantin, Koperasi, atau Bekal?"},
    // かったるくない通学路
    {"\x82\xa9\x82\xc1\x82\xbd\x82\xe9\x82\xad\x82\xc8\x82\xa2\x92\xca\x8a\x77"
     "\x98\x48",
     "Aset untuk Masa Depan"},
    // 心躍る幕開け
    {"\x90\x53\x96\xf4\x82\xe9\x96\x8b\x8a\x4a\x82\xaf",
     "Jalan Sekolah yang Tidak Membosankan"},
    // のんびり長閑に
    {"\x82\xcc\x82\xf1\x82\xd1\x82\xe8\x92\xb7\x8a\xd5\x82\xc9",
     "Pembukaan yang Mendebarkan"},
    // 親友≒悪友

    {"\x90\x65\x97\x46\x81\xe0\x88\xab\x97\x46", "Teman Akrab"},

    // ちょこっと自分らしく
    {"\x82\xbf\x82\xe5\x82\xb1\x82\xc1\x82\xc6\x8e\xa9\x95\xaa\x82\xe7\x82\xb5"
     "\x82\xad",
     "Santai dan Tenang"},
    // これでも風紀委員ですから
    {"\x82\xb1\x82\xea\x82\xc5\x82\xe0\x95\x97\x8b\x49\x88\xcf\x88\xf5\x82\xc5"
     "\x82\xb7\x82\xa9\x82\xe7",
     "Sahabat Karib\x81\xe0Teman Nakal"},
    // 少しだけ譲れないもの
    {"\x8f\xad\x82\xb5\x82\xbe\x82\xaf\x8f\xf7\x82\xea\x82\xc8\x82\xa2\x82\xe0"
     "\x82\xcc",
     "Sedikit Menjadi Diriku Sendiri"},
    // 恋愛請負、執行致します
    {"\x97\xf6\x88\xa4\x90\xbf\x95\x89\x81\x41\x8e\xb7\x8d\x73\x92\x76\x82\xb5"
     "\x82\xdc\x82\xb7",
     "Biar Begini, Aku Tetap Anggota Komite Disiplin"},
    // 甘くて美味しいのはいかが？
    {"\x8a\xc3\x82\xad\x82\xc4\x94\xfc\x96\xa1\x82\xb5\x82\xa2\x82\xcc\x82\xcd"
     "\x82\xa2\x82\xa9\x82\xaa\x81\x48",
     "Sesuatu yang Tak Bisa Kukompromikan"},
    // 小悪魔？裏モード？
    {"\x8f\xac\x88\xab\x96\x82\x81\x48\x97\xa0\x83\x82\x81\x5b\x83\x68\x81\x48",
     "Kontraktor Cinta, Akan Segera Bertugas"},
    // 穏やかに舞うサクラのように
    {"\x89\xb8\x82\xe2\x82\xa9\x82\xc9\x95\x91\x82\xa4\x83\x54\x83\x4e\x83\x89"
     "\x82\xcc\x82\xe6\x82\xa4\x82\xc9",
     "Mau Sesuatu yang Manis dan Lezat?"},
    // 穏やかなお日様のように
    {"\x89\xb8\x82\xe2\x82\xa9\x82\xc8\x82\xa8\x93\xfa\x97\x6c\x82\xcc\x82\xe6"
     "\x82\xa4\x82\xc9",
     "Iblis Kecil? Mode Rahasia?"},
    // 風に舞う花のように
    {"\x95\x97\x82\xc9\x95\x91\x82\xa4\x89\xd4\x82\xcc\x82\xe6\x82\xa4\x82\xc9",
     "Bagai Sakura yang Menari dengan Tenang"},
    // いつか見た、懐かしい夢
    {"\x82\xa2\x82\xc2\x82\xa9\x8c\xa9\x82\xbd\x81\x41\x89\xf9\x82\xa9\x82\xb5"
     "\x82\xa2\x96\xb2",
     "Bagai Matahari yang Hangat"},
    // いつか見た夢
    {"\x82\xa2\x82\xc2\x82\xa9\x8c\xa9\x82\xbd\x96\xb2",
     "Bagai Bunga yang Menari Ditiup Angin"},
    // Ｄ．Ｃ．
    {"\x82\x63\x81\x44\x82\x62\x81\x44",
     "Mimpi Nostalgia yang Pernah Kulihat Dulu"},
    // 明日への期待
    {"\x96\xbe\x93\xfa\x82\xd6\x82\xcc\x8a\xfa\x91\xd2",
     "Mimpi yang Pernah Kulihat"},
    // バレンタインな打ち上げ
    {"\x83\x6f\x83\x8c\x83\x93\x83\x5e\x83\x43\x83\x93\x82\xc8\x91\xc5\x82\xbf"
     "\x8f\xe3\x82\xb0",
     "D.C."},
    // 恋のレジェンドバトル
    {"\x97\xf6\x82\xcc\x83\x8c\x83\x57\x83\x46\x83\x93\x83\x68\x83\x6f\x83\x67"
     "\x83\x8b",
     "Harapan untuk Esok Hari"},
    // 恋パの朝
    {"\x97\xf6\x83\x70\x82\xcc\x92\xa9", "Perayaan Valentine"},
    // 明日は恋パ
    {"\x96\xbe\x93\xfa\x82\xcd\x97\xf6\x83\x70",
     "Pertempuran Legendaris Cinta"},
    // ８つ目の大罪
    {"\x82\x57\x82\xc2\x96\xda\x82\xcc\x91\xe5\x8d\xdf",
     "Pagi di Hari Pesta Cinta"},
    // サプライズは秘密
    {"\x83\x54\x83\x76\x83\x89\x83\x43\x83\x59\x82\xcd\x94\xe9\x96\xa7",
     "Besok Adalah Pesta Cinta"},
    // 寝顔はかわいい二乃
    {"\x90\x51\x8a\xe7\x82\xcd\x82\xa9\x82\xed\x82\xa2\x82\xa2\x93\xf1\x94\x54",
     "Dosa Besar Kedelapan"},
    // 準備はあと１日
    {"\x8f\x80\x94\xf5\x82\xcd\x82\xa0\x82\xc6\x82\x50\x93\xfa",
     "Kejutan Itu Rahasia"},
    // 演技でも俺らしく
    {"\x89\x89\x8b\x5a\x82\xc5\x82\xe0\x89\xb4\x82\xe7\x82\xb5\x82\xad",
     "Wajah Tidur Nino yang Imut"},
    // 詩名いじり
    {"\x8e\x8d\x96\xbc\x82\xa2\x82\xb6\x82\xe8",
     "Persiapan Tinggal Satu Hari Lagi"},
    // 至福と無駄遣い
    {"\x8e\x8a\x95\x9f\x82\xc6\x96\xb3\x91\xca\x8c\xad\x82\xa2",
     "Tetap Jadi Diriku Meski Sedang Berakting"},
    // ネゴシエイター二乃
    {"\x83\x6c\x83\x53\x83\x56\x83\x47\x83\x43\x83\x5e\x81\x5b\x93\xf1\x94\x54",
     "Menggoda Shiina"},
    // 大詰めの作業割
    {"\x91\xe5\x8b\x6c\x82\xdf\x82\xcc\x8d\xec\x8b\xc6\x8a\x84",
     "Kebahagiaan dan Pemborosan"},
    // 泉先生の商い講義
    {"\x90\xf2\x90\xe6\x90\xb6\x82\xcc\x8f\xa4\x82\xa2\x8d\x75\x8b\x60",
     "Nino sang Negosiator"},
    // 特命大使ちょこ
    {"\x93\xc1\x96\xbd\x91\xe5\x8e\x67\x82\xbf\x82\xe5\x82\xb1",
     "Pembagian Tugas Tahap Akhir"},
    // 明日からまた忙しく
    {"\x96\xbe\x93\xfa\x82\xa9\x82\xe7\x82\xdc\x82\xbd\x96\x5a\x82\xb5\x82\xad",
     "Kuliah Bisnis dari Ibu Guru Izumi"},
    // 止まった時計
    {"\x8e\x7e\x82\xdc\x82\xc1\x82\xbd\x8e\x9e\x8c\x76",
     "Duta Besar Khusus Choko"},
    // 台本読み練習
    {"\x91\xe4\x96\x7b\x93\xc7\x82\xdd\x97\xfb\x8f\x4b",
     "Mulai Besok Akan Sibuk Lagi"},
    // 杉並と詩名
    {"\x90\x99\x95\xc0\x82\xc6\x8e\x8d\x96\xbc", "Jam yang Terhenti"},
    // うろぼろす
    {"\x82\xa4\x82\xeb\x82\xda\x82\xeb\x82\xb7", "Latihan Membaca Naskah"},
    // ファンタジーな回想
    {"\x83\x74\x83\x40\x83\x93\x83\x5e\x83\x57\x81\x5b\x82\xc8\x89\xf1\x91\x7a",
     "Suginami dan Shiina"},
    // さてもうひと頑張り
    {"\x82\xb3\x82\xc4\x82\xe0\x82\xa4\x82\xd0\x82\xc6\x8a\xe6\x92\xa3\x82\xe8",
     "Ouroboros"},
    // いつもよりは寝過ごして
    {"\x82\xa2\x82\xc2\x82\xe0\x82\xe6\x82\xe8\x82\xcd\x90\x51\x89\xdf\x82\xb2"
     "\x82\xb5\x82\xc4",
     "Kenangan Fantasi"},
    // もう一度見たい
    {"\x82\xe0\x82\xa4\x88\xea\x93\x78\x8c\xa9\x82\xbd\x82\xa2",
     "Baiklah, Mari Berusaha Sedikit Lagi"},
    // 果たしてバグか？
    {"\x89\xca\x82\xbd\x82\xb5\x82\xc4\x83\x6f\x83\x4f\x82\xa9\x81\x48",
     "Tidur Lebih Lama dari Biasanya"},
    // 稀有な体験
    {"\x8b\x48\x97\x4c\x82\xc8\x91\xcc\x8c\xb1",
     "Ingin Melihatnya Sekali Lagi"},
    // 楽しみですね
    {"\x8a\x79\x82\xb5\x82\xdd\x82\xc5\x82\xb7\x82\xcb", "Apakah Ini Bug?"},
    // 新アトラクションのお誘い
    {"\x90\x56\x83\x41\x83\x67\x83\x89\x83\x4e\x83\x56\x83\x87\x83\x93\x82\xcc"
     "\x82\xa8\x97\x55\x82\xa2",
     "Pengalaman yang Langka"},
    // ちぇしの雨宿り
    {"\x82\xbf\x82\xa5\x82\xb5\x82\xcc\x89\x4a\x8f\x68\x82\xe8",
     "Menyenangkan, ya"},
    // 台本のための質問
    {"\x91\xe4\x96\x7b\x82\xcc\x82\xbd\x82\xdf\x82\xcc\x8e\xbf\x96\xe2",
     "Undakan ke Atraksi Baru"},
    // 偶然の同行
    {"\x8b\xf4\x91\x52\x82\xcc\x93\xaf\x8d\x73", "Cheshi Berteduh dari Hujan"},
    // 風紀委員とのネゴ
    {"\x95\x97\x8b\x49\x88\xcf\x88\xf5\x82\xc6\x82\xcc\x83\x6c\x83\x53",
     "Pertanyaan Demi Naskah"},
    // 地味な作業のご褒美
    {"\x92\x6e\x96\xa1\x82\xc8\x8d\xec\x8b\xc6\x82\xcc\x82\xb2\x96\x4a\x94\xfc",
     "Pergi Bersama Secara Kebetulan"},
    // 手が足りなそうなのは
    {"\x8e\xe8\x82\xaa\x91\xab\x82\xe8\x82\xc8\x82\xbb\x82\xa4\x82\xc8\x82\xcc"
     "\x82\xcd",
     "Negosiasi dengan Komite Disiplin"},
    // ご飯を食べて頑張ろう
    {"\x82\xb2\x94\xd1\x82\xf0\x90\x48\x82\xd7\x82\xc4\x8a\xe6\x92\xa3\x82\xeb"
     "\x82\xa4",
     "Hadiah untuk Pekerjaan yang Membosankan"},
    // 心地よい疲労
    {"\x90\x53\x92\x6e\x82\xe6\x82\xa2\x94\xe6\x98\x4a",
     "Kelihatannya Kekurangan Tenaga"},
    // 有能有里栖のお手伝い
    {"\x97\x4c\x94\x5c\x97\x4c\x97\xa2\x90\xb2\x82\xcc\x82\xa8\x8e\xe8\x93\x60"
     "\x82\xa2",
     "Mari Makan dan Berusaha"},
    // 詩名とちよ子の関係
    {"\x8e\x8d\x96\xbc\x82\xc6\x82\xbf\x82\xe6\x8e\x71\x82\xcc\x8a\xd6\x8c\x57",
     "Kelelahan yang Menyenangkan"},
    // 恋愛請負も忘れずに
    {"\x97\xf6\x88\xa4\x90\xbf\x95\x89\x82\xe0\x96\x59\x82\xea\x82\xb8\x82\xc9",
     "Membantu Arisu yang Kompeten"},
    // チラシの手伝い
    {"\x83\x60\x83\x89\x83\x56\x82\xcc\x8e\xe8\x93\x60\x82\xa2",
     "Hubungan Antara Shiina dan Chiyoko"},
    // 遊撃一登の選択
    {"\x97\x56\x8c\x82\x88\xea\x93\x6f\x82\xcc\x91\x49\x91\xf0",
     "Jangan Lupakan Tugas Kontraktor Cinta"},
    // SSR史上最大作戦
    {"\x53\x53\x52\x8e\x6a\x8f\xe3\x8d\xc5\x91\xe5\x8d\xec\x90\xed",
     "Membantu Membagikan Brosur"},
    // 微笑みの爆弾
    {"\x94\xf7\x8f\xce\x82\xdd\x82\xcc\x94\x9a\x92\x65",
     "Pilihan Ichito Sang Pemain Bebas"},
    // どうなることやら
    {"\x82\xc7\x82\xa4\x82\xc8\x82\xe9\x82\xb1\x82\xc6\x82\xe2\x82\xe7",
     "Operasi Terbesar dalam Sejarah SSR"},
    // 言い出しっぺの法則
    {"\x8c\xbe\x82\xa2\x8f\x6f\x82\xb5\x82\xc1\x82\xd8\x82\xcc\x96\x40\x91\xa5",
     "Bom Senyuman"},
    // ちょこっとの期待
    {"\x82\xbf\x82\xe5\x82\xb1\x82\xc1\x82\xc6\x82\xcc\x8a\xfa\x91\xd2",
     "Entah Akan Jadi Bagaimana"},
    // ふとよぎる閃き
    {"\x82\xd3\x82\xc6\x82\xe6\x82\xac\x82\xe9\x91\x4d\x82\xab",
     "Hukum Siapa yang Mengusulkan, Dia yang Melakukan"},
    // 明日も一歩
    {"\x96\xbe\x93\xfa\x82\xe0\x88\xea\x95\xe0", "Sedikit Harapan"},
    // 有里栖の相談
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xcc\x91\x8a\x92\x6b",
     "Kilasan Inspirasi yang Tiba-tiba"},
    // 泉先生の宇宙人講義
    {"\x90\xf2\x90\xe6\x90\xb6\x82\xcc\x89\x46\x92\x88\x90\x6c\x8d\x75\x8b\x60",
     "Melangkah Lagi Besok"},
    // 乙女ゲームな乙女たち
    {"\x89\xb3\x8f\x97\x83\x51\x81\x5b\x83\x80\x82\xc8\x89\xb3\x8f\x97\x82\xbd"
     "\x82\xbf",
     "Konsultasi Arisu"},
    // 変わった猫と
    {"\x95\xcf\x82\xed\x82\xc1\x82\xbd\x94\x4c\x82\xc6",
     "Kuliah Alien dari Ibu Guru Izumi"},
    // 彼女の遠慮
    {"\x94\xde\x8f\x97\x82\xcc\x89\x93\x97\xb6",
     "Para Gadis yang Bagai di Game Otome"},
    // アイドルの苦悩
    {"\x83\x41\x83\x43\x83\x68\x83\x8b\x82\xcc\x8b\xea\x94\x59",
     "Bersama Kucing yang Aneh"},
    // 人気者アリス
    {"\x90\x6c\x8b\x43\x8e\xd2\x83\x41\x83\x8a\x83\x58",
     "Rasa Sungkan Miliknya"},
    // 楽しくなる予感
    {"\x8a\x79\x82\xb5\x82\xad\x82\xc8\x82\xe9\x97\x5c\x8a\xb4",
     "Penderitaan Sang Idola"},
    // SSRバレンタイン対策
    {"\x53\x53\x52\x83\x6f\x83\x8c\x83\x93\x83\x5e\x83\x43\x83\x93\x91\xce\x8d"
     "\xf4",
     "Alice yang Populer"},
    // 転校生
    {"\x93\x5d\x8d\x5a\x90\xb6", "Firasat Bahwa Ini Akan Menjadi Seru"},
    // お馴染みの面々
    {"\x82\xa8\x93\xe9\x90\xf5\x82\xdd\x82\xcc\x96\xca\x81\x58",
     "Persiapan Valentine SSR"},
    // お決まりの朝
    {"\x82\xa8\x8c\x88\x82\xdc\x82\xe8\x82\xcc\x92\xa9", "Murid Pindahan"},
    // これはただの夢？
    {"\x82\xb1\x82\xea\x82\xcd\x82\xbd\x82\xbe\x82\xcc\x96\xb2\x81\x48",
     "Wajah-wajah yang Familiar"},
    // 無限へと漸近する過ち
    {"\x96\xb3\x8c\xc0\x82\xd6\x82\xc6\x91\x51\x8b\xdf\x82\xb7\x82\xe9\x89\xdf"
     "\x82\xbf",
     "Pagi yang Seperti Biasanya"},
    // SSR始動
    {"\x53\x53\x52\x8e\x6e\x93\xae", "Apakah Ini Hanya Mimpi?"},
    // それぞれの感想
    {"\x82\xbb\x82\xea\x82\xbc\x82\xea\x82\xcc\x8a\xb4\x91\x7a",
     "Kesalahan yang Mendekati Tak Terhingga"},
    // 杉並と迷宮
    {"\x90\x99\x95\xc0\x82\xc6\x96\xc0\x8b\x7b", "SSR Dimulai"},
    // 有里栖と自由落下
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xc6\x8e\xa9\x97\x52\x97\x8e\x89\xba",
     "Kesan Masing-masing"},
    // ひよりと耐久勝負
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xc6\x91\xcf\x8b\x76\x8f\x9f\x95\x89",
     "Suginami dan Labirin"},
    // 諳子とお城
    {"\xe6\x7d\x8e\x71\x82\xc6\x82\xa8\x8f\xe9", "Arisu dan Terjun Bebas"},
    // 二乃とショッピング
    {"\x93\xf1\x94\x54\x82\xc6\x83\x56\x83\x87\x83\x62\x83\x73\x83\x93\x83\x4f",
     "Adu Ketahanan dengan Hiyori"},
    // どうしようかな
    {"\x82\xc7\x82\xa4\x82\xb5\x82\xe6\x82\xa4\x82\xa9\x82\xc8",
     "Sorane dan Istana"},
    // いざワンダーランド
    {"\x82\xa2\x82\xb4\x83\x8f\x83\x93\x83\x5f\x81\x5b\x83\x89\x83\x93\x83\x68",
     "Belanja Bersama Nino"},
    // 突然の雷鳴！？
    {"\x93\xcb\x91\x52\x82\xcc\x97\x8b\x96\xc2\x81\x49\x81\x48",
     "Apa yang Harus Kulakukan, ya"},
    // 有里栖からのお誘い
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xa9\x82\xe7\x82\xcc\x82\xa8\x97\x55\x82\xa2",
     "Mari Menuju Wonderland"},
    // ジジイと満月

    {"\x83\x57\x83\x57\x83\x43\x82\xc6\x96\x9e\x8c\x8e", "Kakek Purnama"},

    // 反省会という名の
    {"\x94\xbd\x8f\xc8\x89\xef\x82\xc6\x82\xa2\x82\xa4\x96\xbc\x82\xcc",
     "Guntur Tiba-tiba!?"},
    // 泉先生の雑学講義
    {"\x90\xf2\x90\xe6\x90\xb6\x82\xcc\x8e\x47\x8a\x77\x8d\x75\x8b\x60",
     "Undakan dari Arisu"},
    // らしくないやる気
    {"\x82\xe7\x82\xb5\x82\xad\x82\xc8\x82\xa2\x82\xe2\x82\xe9\x8b\x43",
     "Si Kakek Tua dan Bulan Purnama"},
    // 充実した夕食
    {"\x8f\x5b\x8e\xc0\x82\xb5\x82\xbd\x97\x5b\x90\x48",
     "Sesuatu yang Disebut Sesi Evaluasi"},
    // 役割分担という式
    {"\x96\xf0\x8a\x84\x95\xaa\x92\x53\x82\xc6\x82\xa2\x82\xa4\x8e\xae",
     "Kuliah Pengetahuan Umum dari Ibu Guru Izumi"},
    // 青春の１ページ
    {"\x90\xc2\x8f\x74\x82\xcc\x82\x50\x83\x79\x81\x5b\x83\x57",
     "Motivasi yang Tidak Seperti Biasanya"},
    // 活動開始！
    {"\x8a\x88\x93\xae\x8a\x4a\x8e\x6e\x81\x49", "Makan Malam yang Memuaskan"},
    // 屋上集合
    {"\x89\xae\x8f\xe3\x8f\x57\x8d\x87", "Rumus yang Disebut Pembagian Tugas"},
    // 集まった仲間たち
    {"\x8f\x57\x82\xdc\x82\xc1\x82\xbd\x92\x87\x8a\xd4\x82\xbd\x82\xbf",
     "Satu Halaman Masa Muda"},
    // 二乃の条件

    {"\x93\xf1\x94\x54\x82\xcc\x8f\xf0\x8c\x8f", "Syarat Nino"},

    // 助けてあげたい
    {"\x8f\x95\x82\xaf\x82\xc4\x82\xa0\x82\xb0\x82\xbd\x82\xa2",
     "Mulai Beraksi!"},
    // 楽しいランチタイム
    {"\x8a\x79\x82\xb5\x82\xa2\x83\x89\x83\x93\x83\x60\x83\x5e\x83\x43\x83\x80",
     "Kumpul di Atap"},
    // 月曜の朝も清々しく
    {"\x8c\x8e\x97\x6a\x82\xcc\x92\xa9\x82\xe0\x90\xb4\x81\x58\x82\xb5\x82\xad",
     "Teman-teman yang Berkumpul"},
    // 白河と美嶋
    {"\x94\x92\x89\xcd\x82\xc6\x94\xfc\x93\x88", "Syarat dari Nino"},
    // 杉並から入電！
    {"\x90\x99\x95\xc0\x82\xa9\x82\xe7\x93\xfc\x93\x64\x81\x49",
     "Ingin Menolongnya"},
    // 休日のルーチン
    {"\x8b\x78\x93\xfa\x82\xcc\x83\x8b\x81\x5b\x83\x60\x83\x93",
     "Waktu Makan Siang yang Seru"},
    // WLがオープンしたら？
    {"\x57\x4c\x82\xaa\x83\x49\x81\x5b\x83\x76\x83\x93\x82\xb5\x82\xbd\x82\xe7"
     "\x81\x48",
     "Pagi Hari Senin yang Menyegarkan"},
    // 日常的学園生活
    {"\x93\xfa\x8f\xed\x93\x49\x8a\x77\x89\x80\x90\xb6\x8a\x88",
     "Shirakawa dan Mishima"},
    // いつもの朝
    {"\x82\xa2\x82\xc2\x82\xe0\x82\xcc\x92\xa9",
     "Panggilan Masuk dari Suginami!"},
    // あの人の夢
    {"\x82\xa0\x82\xcc\x90\x6c\x82\xcc\x96\xb2", "Rutinitas Hari Libur"},
    // 我が家の日常
    {"\x89\xe4\x82\xaa\x89\xc6\x82\xcc\x93\xfa\x8f\xed",
     "Bagaimana Jika WL Dibuka?"},
    // 黄昏のうたたね
    {"\x89\xa9\x8d\xa8\x82\xcc\x82\xa4\x82\xbd\x82\xbd\x82\xcb",
     "Kehidupan Sekolah Sehari-hari"},
    // いつかの夢
    {"\x82\xa2\x82\xc2\x82\xa9\x82\xcc\x96\xb2", "Pagi Seperti Biasanya"},
    // 楽しさの拡散
    {"\x8a\x79\x82\xb5\x82\xb3\x82\xcc\x8a\x67\x8e\x55", "Mimpi Orang Itu"},
    // 恋に恋する女の子
    {"\x97\xf6\x82\xc9\x97\xf6\x82\xb7\x82\xe9\x8f\x97\x82\xcc\x8e\x71",
     "Keseharian di Rumah Kami"},
    // 作為的な運命？
    {"\x8d\xec\x88\xd7\x93\x49\x82\xc8\x89\x5e\x96\xbd\x81\x48",
     "Tidur Ayam di Kala Senja"},
    // お部屋デートで
    {"\x82\xa8\x95\x94\x89\xae\x83\x66\x81\x5b\x83\x67\x82\xc5",
     "Mimpi di Suatu Hari"},
    // 一番近くにいたい
    {"\x88\xea\x94\xd4\x8b\xdf\x82\xad\x82\xc9\x82\xa2\x82\xbd\x82\xa2",
     "Penyebaran Kegembiraan"},
    // 自分らしくいられるよう
    {"\x8e\xa9\x95\xaa\x82\xe7\x82\xb5\x82\xad\x82\xa2\x82\xe7\x82\xea\x82\xe9"
     "\x82\xe6\x82\xa4",
     "Cewek yang Sedang Jatuh Cinta pada Cinta"},
    // デートみたいなもの
    {"\x83\x66\x81\x5b\x83\x67\x82\xdd\x82\xbd\x82\xa2\x82\xc8\x82\xe0\x82\xcc",
     "Takdir yang Disengaja?"},
    // 模索するＣＨＯＣＯ
    {"\x96\xcd\x8d\xf5\x82\xb7\x82\xe9\x82\x62\x82\x67\x82\x6e\x82\x62\x82\x6e",
     "Kencan di Dalam Kamar"},
    // 詩名は敏腕マネ？
    {"\x8e\x8d\x96\xbc\x82\xcd\x95\x71\x98\x72\x83\x7d\x83\x6c\x81\x48",
     "Ingin Berada di Tempat Terdekat"},
    // 壁スカート防衛作戦
    {"\x95\xc7\x83\x58\x83\x4a\x81\x5b\x83\x67\x96\x68\x89\x71\x8d\xec\x90\xed",
     "Agar Bisa Menjadi Diriku Sendiri"},
    // とっきー先生の授業
    {"\x82\xc6\x82\xc1\x82\xab\x81\x5b\x90\xe6\x90\xb6\x82\xcc\x8e\xf6\x8b\xc6",
     "Sesuatu yang Mirip Kencan"},
    // 結果ちよ子とふたりで
    {"\x8c\x8b\x89\xca\x82\xbf\x82\xe6\x8e\x71\x82\xc6\x82\xd3\x82\xbd\x82\xe8"
     "\x82\xc5",
     "Choco yang Sedang Mencari Jawaban"},
    // 凹んでいるちよ子
    {"\x89\x9a\x82\xf1\x82\xc5\x82\xa2\x82\xe9\x82\xbf\x82\xe6\x8e\x71",
     "Apakah Shiina Manajer yang Hebat?"},
    // ＣＨＯＣＯの変化
    {"\x82\x62\x82\x67\x82\x6e\x82\x62\x82\x6e\x82\xcc\x95\xcf\x89\xbb",
     "Operasi Pertahanan Rok Dinding"},
    // ＫｏｔｏＲｉさんのお言葉
    {"\x82\x6a\x82\x8f\x82\x94\x82\x8f\x82\x71\x82\x89\x82\xb3\x82\xf1\x82\xcc"
     "\x82\xa8\x8c\xbe\x97\x74",
     "Pelajaran dari Tokki-sensei"},
    // ＫｏｔｏＲＩさんトーク
    {"\x82\x6a\x82\x8f\x82\x94\x82\x8f\x82\x71\x82\x68\x82\xb3\x82\xf1\x83\x67"
     "\x81\x5b\x83\x4e",
     "Akhirnya Berdua dengan Chiyoko"},
    // ＣＨＯＣＯとしての矜持
    {"\x82\x62\x82\x67\x82\x6e\x82\x62\x82\x6e\x82\xc6\x82\xb5\x82\xc4\x82\xcc"
     "\xe1\xe0\x8e\x9d",
     "Chiyoko yang Sedang Murung"},
    // ちょこの呼び出し
    {"\x82\xbf\x82\xe5\x82\xb1\x82\xcc\x8c\xc4\x82\xd1\x8f\x6f\x82\xb5",
     "Perubahan pada CHOCO"},
    // ふたりの距離
    {"\x82\xd3\x82\xbd\x82\xe8\x82\xcc\x8b\x97\x97\xa3",
     "Kata-kata dari Kotori-san"},
    // やり直しと返答と
    {"\x82\xe2\x82\xe8\x92\xbc\x82\xb5\x82\xc6\x95\xd4\x93\x9a\x82\xc6",
     "Obrolan Kotori-san"},
    // もう心配いらない
    {"\x82\xe0\x82\xa4\x90\x53\x94\x7a\x82\xa2\x82\xe7\x82\xc8\x82\xa2",
     "Kebanggaan Sebagai CHOCO"},
    // 新たな形
    {"\x90\x56\x82\xbd\x82\xc8\x8c\x60", "Panggilan dari Choco"},
    // 少し考えさせて
    {"\x8f\xad\x82\xb5\x8d\x6c\x82\xa6\x82\xb3\x82\xb9\x82\xc4",
     "Jarak di Antara Berdua"},
    // つながっている？
    {"\x82\xc2\x82\xc8\x82\xaa\x82\xc1\x82\xc4\x82\xa2\x82\xe9\x81\x48",
     "Mengulang Kembali dan Jawaban"},
    // 高いところを覗く方法
    {"\x8d\x82\x82\xa2\x82\xc6\x82\xb1\x82\xeb\x82\xf0\x94\x60\x82\xad\x95\xfb"
     "\x96\x40",
     "Sudah Tidak Perlu Khawatir Lagi"},
    // 先行するひより
    {"\x90\xe6\x8d\x73\x82\xb7\x82\xe9\x82\xd0\x82\xe6\x82\xe8",
     "Bentuk yang Baru"},
    // 打ち上げと臨時手伝い
    {"\x91\xc5\x82\xbf\x8f\xe3\x82\xb0\x82\xc6\x97\xd5\x8e\x9e\x8e\xe8\x93\x60"
     "\x82\xa2",
     "Biarkan Aku Berpikir Sebentar"},
    // やりがいのある仕事
    {"\x82\xe2\x82\xe8\x82\xaa\x82\xa2\x82\xcc\x82\xa0\x82\xe9\x8e\x64\x8e\x96",
     "Apakah Kita Terhubung?"},
    // バイトヘルプの依頼
    {"\x83\x6f\x83\x43\x83\x67\x83\x77\x83\x8b\x83\x76\x82\xcc\x88\xcb\x97\x8a",
     "Cara Mengintip ke Tempat yang Tinggi"},
    // 依頼募集スレッド
    {"\x88\xcb\x97\x8a\x95\xe5\x8f\x57\x83\x58\x83\x8c\x83\x62\x83\x68",
     "Hiyori yang Pergi Duluan"},
    // ＳＳＲ臨時招集
    {"\x82\x72\x82\x72\x82\x71\x97\xd5\x8e\x9e\x8f\xb5\x8f\x57",
     "Perayaan dan Bantuan Darurat"},
    // 未羽と白河の秘密
    {"\x96\xa2\x89\x48\x82\xc6\x94\x92\x89\xcd\x82\xcc\x94\xe9\x96\xa7",
     "Pekerjaan yang Layak Dilakukan"},
    // 哀しい夢

    {"\x88\xa3\x82\xb5\x82\xa2\x96\xb2", "Mimpi Ibu"},

    // 白河の不調

    {"\x94\x92\x89\xcd\x82\xcc\x95\x73\x92\xb2", "Kondisi Shi"},

    // 保留にさせてください
    {"\x95\xdb\x97\xaf\x82\xc9\x82\xb3\x82\xb9\x82\xc4\x82\xad\x82\xbe\x82\xb3"
     "\x82\xa2",
     "Permintaan Bantuan Kerja Sambilan"},
    // 伝わる気持ち
    {"\x93\x60\x82\xed\x82\xe9\x8b\x43\x8e\x9d\x82\xbf",
     "Utas Lowongan Permintaan"},
    // 朔の夜の別れ
    {"\x8d\xf1\x82\xcc\x96\xe9\x82\xcc\x95\xca\x82\xea",
     "Panggilan Darurat SSR"},
    // 知らないけど知ってる
    {"\x92\x6d\x82\xe7\x82\xc8\x82\xa2\x82\xaf\x82\xc7\x92\x6d\x82\xc1\x82\xc4"
     "\x82\xe9",
     "Rahasia Miu dan Shirakawa"},
    // 手から伝わる温もり
    {"\x8e\xe8\x82\xa9\x82\xe7\x93\x60\x82\xed\x82\xe9\x89\xb7\x82\xe0\x82\xe8",
     "Mimpi yang Sedih"},
    // 何度目かの団欒
    {"\x89\xbd\x93\x78\x96\xda\x82\xa9\x82\xcc\x92\x63\x9f\x52",
     "Kondisi Shirakawa yang Buruk"},
    // 乗り越えなくていい
    {"\x8f\xe6\x82\xe8\x89\x7a\x82\xa6\x82\xc8\x82\xad\x82\xc4\x82\xa2\x82\xa2",
     "Tolong Biarkan Aku Menundanya Dulu"},
    // 為になるダラダラ
    {"\x88\xd7\x82\xc9\x82\xc8\x82\xe9\x83\x5f\x83\x89\x83\x5f\x83\x89",
     "Perasaan yang Tersampaikan"},
    // 未来の奥さん
    {"\x96\xa2\x97\x88\x82\xcc\x89\x9c\x82\xb3\x82\xf1",
     "Perpisahan di Malam Tanpa Bulan"},
    // 別れのリサイタル
    {"\x95\xca\x82\xea\x82\xcc\x83\x8a\x83\x54\x83\x43\x83\x5e\x83\x8b",
     "Aku Tidak Tahu Tapi Aku Tahu"},
    // 青春っぽい時間
    {"\x90\xc2\x8f\x74\x82\xc1\x82\xdb\x82\xa2\x8e\x9e\x8a\xd4",
     "Kehangatan yang Tersalur dari Tangan"},
    // あと2週間の
    {"\x82\xa0\x82\xc6\x32\x8f\x54\x8a\xd4\x82\xcc",
     "Entah Sudah Berapa Kali Berkumpul Bersama"},
    // 満月の夜の邂逅
    {"\x96\x9e\x8c\x8e\x82\xcc\x96\xe9\x82\xcc\xe7\xae\xe7\x90",
     "Kamu Tidak Perlu Melampauinya"},
    // カガミの魔法
    {"\x83\x4a\x83\x4b\x83\x7e\x82\xcc\x96\x82\x96\x40",
     "Bermalas-malasan yang Ada Gunanya"},
    // ちょこからのヒント
    {"\x82\xbf\x82\xe5\x82\xb1\x82\xa9\x82\xe7\x82\xcc\x83\x71\x83\x93\x83\x67",
     "Calon Istri di Masa Depan"},
    // 異世界からの迷い人
    {"\x88\xd9\x90\xa2\x8a\x45\x82\xa9\x82\xe7\x82\xcc\x96\xc0\x82\xa2\x90\x6c",
     "Resital Perpisahan"},
    // 零と無限の交わる世界
    {"\x97\xeb\x82\xc6\x96\xb3\x8c\xc0\x82\xcc\x8c\xf0\x82\xed\x82\xe9\x90\xa2"
     "\x8a\x45",
     "Waktu yang Terasa Seperti Masa Muda"},
    // 月間ヌー春の特別号
    {"\x8c\x8e\x8a\xd4\x83\x6b\x81\x5b\x8f\x74\x82\xcc\x93\xc1\x95\xca\x8d\x86",
     "Tinggal 2 Minggu Lagi"},
    // 夢の中の景色と
    {"\x96\xb2\x82\xcc\x92\x86\x82\xcc\x8c\x69\x90\x46\x82\xc6",
     "Pertemuan di Malam Bulan Purnama"},
    // 詩名のために
    {"\x8e\x8d\x96\xbc\x82\xcc\x82\xbd\x82\xdf\x82\xc9", "Sihir Kagami"},
    // 半分は優しさで
    {"\x94\xbc\x95\xaa\x82\xcd\x97\x44\x82\xb5\x82\xb3\x82\xc5",
     "Petunjuk dari Choco"},
    // これ以上付き合えない
    {"\x82\xb1\x82\xea\x88\xc8\x8f\xe3\x95\x74\x82\xab\x8d\x87\x82\xa6\x82\xc8"
     "\x82\xa2",
     "Seseorang yang Tersesat dari Dunia Lain"},
    // 雷を待ちながら
    {"\x97\x8b\x82\xf0\x91\xd2\x82\xbf\x82\xc8\x82\xaa\x82\xe7",
     "Dunia Tempat Nol dan Tak Terhingga Bertemu"},
    // 隠していたこと
    {"\x89\x42\x82\xb5\x82\xc4\x82\xa2\x82\xbd\x82\xb1\x82\xc6",
     "Majalah Bulanan Nuu Edisi Khusus Musim Semi"},
    // おうちにかえりたい
    {"\x82\xa8\x82\xa4\x82\xbf\x82\xc9\x82\xa9\x82\xa6\x82\xe8\x82\xbd\x82\xa2",
     "Pemandangan di Dalam Mimpi dan..."},
    // 特別な気持ち
    {"\x93\xc1\x95\xca\x82\xc8\x8b\x43\x8e\x9d\x82\xbf", "Demi Shiina"},
    // ラブの匂い？
    {"\x83\x89\x83\x75\x82\xcc\x93\xf5\x82\xa2\x81\x48",
     "Setengahnya Terdiri dari Kebaikan"},
    // まだまだ知らないこと
    {"\x82\xdc\x82\xbe\x82\xdc\x82\xbe\x92\x6d\x82\xe7\x82\xc8\x82\xa2\x82\xb1"
     "\x82\xc6",
     "Aku Tidak Bisa Bersamamu Lebih Lama Lagi"},
    // そんなことでありがとう
    {"\x82\xbb\x82\xf1\x82\xc8\x82\xb1\x82\xc6\x82\xc5\x82\xa0\x82\xe8\x82\xaa"
     "\x82\xc6\x82\xa4",
     "Sambil Menunggu Petir"},
    // とても面倒くさい
    {"\x82\xc6\x82\xc4\x82\xe0\x96\xca\x93\x7c\x82\xad\x82\xb3\x82\xa2",
     "Hal yang Disembunyikan"},
    // 団欒大好き人間
    {"\x92\x63\x9f\x52\x91\xe5\x8d\x44\x82\xab\x90\x6c\x8a\xd4",
     "Aku Ingin Pulang ke Rumah"},
    // 家族でおもてなし
    {"\x89\xc6\x91\xb0\x82\xc5\x82\xa8\x82\xe0\x82\xc4\x82\xc8\x82\xb5",
     "Perasaan yang Spesial"},
    // 杉並の好敵手
    {"\x90\x99\x95\xc0\x82\xcc\x8d\x44\x93\x47\x8e\xe8", "Bau-bau Cinta?"},
    // スパでのお仕事
    {"\x83\x58\x83\x70\x82\xc5\x82\xcc\x82\xa8\x8e\x64\x8e\x96",
     "Hal-hal yang Masih Belum Diketahui"},
    // 偶然のゲット
    {"\x8b\xf4\x91\x52\x82\xcc\x83\x51\x83\x62\x83\x67",
     "Terima Kasih untuk Hal Semacam Itu"},
    // 苦学生？な詩名
    {"\x8b\xea\x8a\x77\x90\xb6\x81\x48\x82\xc8\x8e\x8d\x96\xbc",
     "Sangat Merepotkan"},
    // 見た目で判断しないで
    {"\x8c\xa9\x82\xbd\x96\xda\x82\xc5\x94\xbb\x92\x66\x82\xb5\x82\xc8\x82\xa2"
     "\x82\xc5",
     "Orang yang Sangat Suka Berkumpul Bersama"},
    // 詩名の大好きな人
    {"\x8e\x8d\x96\xbc\x82\xcc\x91\xe5\x8d\x44\x82\xab\x82\xc8\x90\x6c",
     "Jamuan Bersama Keluarga"},
    // 詩名とちょこの出会い
    {"\x8e\x8d\x96\xbc\x82\xc6\x82\xbf\x82\xe5\x82\xb1\x82\xcc\x8f\x6f\x89\xef"
     "\x82\xa2",
     "Rival Suginami"},
    // 懐かしい曲
    {"\x89\xf9\x82\xa9\x82\xb5\x82\xa2\x8b\xc8", "Pekerjaan di Spa"},
    // この先の未来へ
    {"\x82\xb1\x82\xcc\x90\xe6\x82\xcc\x96\xa2\x97\x88\x82\xd6",
     "Berhasil Mendapatkannya Secara Kebetulan"},
    // 特別な瞬間を
    {"\x93\xc1\x95\xca\x82\xc8\x8f\x75\x8a\xd4\x82\xf0",
     "Shiina sang Pelajar yang Susah?"},
    // 付属卒業式
    {"\x95\x74\x91\xae\x91\xb2\x8b\xc6\x8e\xae",
     "Jangan Menilai dari Penampilan"},
    // 明日はいよいよ
    {"\x96\xbe\x93\xfa\x82\xcd\x82\xa2\x82\xe6\x82\xa2\x82\xe6",
     "Orang yang Sangat Dicintai Shiina"},
    // スペシャル放送に向け
    {"\x83\x58\x83\x79\x83\x56\x83\x83\x83\x8b\x95\xfa\x91\x97\x82\xc9\x8c\xfc"
     "\x82\xaf",
     "Pertemuan Shiina dan Choco"},
    // ゲーム実況者ちよ子
    {"\x83\x51\x81\x5b\x83\x80\x8e\xc0\x8b\xb5\x8e\xd2\x82\xbf\x82\xe6\x8e\x71",
     "Lagu yang Membuat Nostalgia"},
    // 曲目決定
    {"\x8b\xc8\x96\xda\x8c\x88\x92\xe8", "Menuju Masa Depan di Depan Sana"},
    // 卒業にはあの曲を
    {"\x91\xb2\x8b\xc6\x82\xc9\x82\xcd\x82\xa0\x82\xcc\x8b\xc8\x82\xf0",
     "Sebuah Momen yang Spesial"},
    // 打ち合わせという名の
    {"\x91\xc5\x82\xbf\x8d\x87\x82\xed\x82\xb9\x82\xc6\x82\xa2\x82\xa4\x96\xbc"
     "\x82\xcc",
     "Upacara Kelulusan Sekolah Afiliasi"},
    // あの日の思い出
    {"\x82\xa0\x82\xcc\x93\xfa\x82\xcc\x8e\x76\x82\xa2\x8f\x6f",
     "Akhirnya Besok Tiba"},
    // 乱れのない心
    {"\x97\x90\x82\xea\x82\xcc\x82\xc8\x82\xa2\x90\x53",
     "Menuju Siaran Spesial"},
    // 踏み出す一歩
    {"\x93\xa5\x82\xdd\x8f\x6f\x82\xb7\x88\xea\x95\xe0",
     "Chiyoko Sang Game Streamer"},
    // 不思議な眼差し
    {"\x95\x73\x8e\x76\x8b\x63\x82\xc8\x8a\xe1\x8d\xb7\x82\xb5",
     "Daftar Lagu Telah Ditentukan"},
    // 追求されたとしても
    {"\x92\xc7\x8b\x81\x82\xb3\x82\xea\x82\xbd\x82\xc6\x82\xb5\x82\xc4\x82\xe0",
     "Gunakan Lagu Itu untuk Kelulusan"},
    // 視線の主は
    {"\x8e\x8b\x90\xfc\x82\xcc\x8e\xe5\x82\xcd", "Sesuatu yang Disebut Rapat"},
    // 美しき旋律
    {"\x94\xfc\x82\xb5\x82\xab\x90\xf9\x97\xa5", "Kenangan di Hari Itu"},
    // 詩名からの提案
    {"\x8e\x8d\x96\xbc\x82\xa9\x82\xe7\x82\xcc\x92\xf1\x88\xc4",
     "Hati yang Tenang"},
    // 止まる指先
    {"\x8e\x7e\x82\xdc\x82\xe9\x8e\x77\x90\xe6", "Melangkahkan Kaki"},
    // 意外な邂逅
    {"\x88\xd3\x8a\x4f\x82\xc8\xe7\xae\xe7\x90", "Tatapan yang Misterius"},
    // 今回の依頼は……
    {"\x8d\xa1\x89\xf1\x82\xcc\x88\xcb\x97\x8a\x82\xcd\x81\x63\x81\x63",
     "Bahkan Jika Dikejar Sekalipun"},
    // 春は節目の季節
    {"\x8f\x74\x82\xcd\x90\xdf\x96\xda\x82\xcc\x8b\x47\x90\xdf",
     "Pemilik Tatapan Itu Adalah..."},
    // 実家へＧＯ！
    {"\x8e\xc0\x89\xc6\x82\xd6\x82\x66\x82\x6e\x81\x49", "Melodi yang Indah"},
    // つけるべきケジメ
    {"\x82\xc2\x82\xaf\x82\xe9\x82\xd7\x82\xab\x83\x50\x83\x57\x83\x81",
     "Usulan dari Shiina"},
    // フラグより見るべきもの
    {"\x83\x74\x83\x89\x83\x4f\x82\xe6\x82\xe8\x8c\xa9\x82\xe9\x82\xd7\x82\xab"
     "\x82\xe0\x82\xcc",
     "Ujung Jari yang Terhenti"},
    // 琴里の後押し
    {"\x8b\xd5\x97\xa2\x82\xcc\x8c\xe3\x89\x9f\x82\xb5",
     "Pertemuan yang Tak Terduga"},
    // 俺にできることを
    {"\x89\xb4\x82\xc9\x82\xc5\x82\xab\x82\xe9\x82\xb1\x82\xc6\x82\xf0",
     "Permintaan Kali Ini Adalah..."},
    // 神様からの贈り物
    {"\x90\x5f\x97\x6c\x82\xa9\x82\xe7\x82\xcc\x91\xa1\x82\xe8\x95\xa8",
     "Musim Semi Adalah Musim Transisi"},
    // ひよりちゃんを助�����て
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xbf\x82\xe1\x82\xf1\x82\xf0\x8f\x95\x82\xaf"
     "\x82\xc4",
     "Pergi ke Rumah Orang Tua!"},
    // 恋愛請負は廃業
    {"\x97\xf6\x88\xa4\x90\xbf\x95\x89\x82\xcd\x94\x70\x8b\xc6",
     "Tanggung Jawab yang Harus Diselesaikan"},
    // ひよりを蝕むもの
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xf0\x90\x49\x82\xde\x82\xe0\x82\xcc",
     "Hal yang Harus Dilihat Selain Flag"},
    // ＳＳＲみんなでフォロー
    {"\x82\x72\x82\x72\x82\x71\x82\xdd\x82\xf1\x82\xc8\x82\xc5\x83\x74\x83\x48"
     "\x83\x8d\x81\x5b",
     "Dukungan dari Kotori"},
    // 先日のことは忘れて
    {"\x90\xe6\x93\xfa\x82\xcc\x82\xb1\x82\xc6\x82\xcd\x96\x59\x82\xea\x82\xc4",
     "Hal yang Bisa Aku Lakukan"},
    // 妖精舞う月夜に
    {"\x97\x64\x90\xb8\x95\x91\x82\xa4\x8c\x8e\x96\xe9\x82\xc9",
     "Hadiah dari Tuhan"},
    // 破られた１００％記録
    {"\x94\x6a\x82\xe7\x82\xea\x82\xbd\x82\x50\x82\x4f\x82\x4f\x81\x93\x8b\x4c"
     "\x98\x5e",
     "Tolong Bantu Hiyori-chan"},
    // ひよりの初恋
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xcc\x8f\x89\x97\xf6",
     "Bisnis Kontraktor Cinta Gulung Tikar"},
    // 私が止めなくちゃ
    {"\x8e\x84\x82\xaa\x8e\x7e\x82\xdf\x82\xc8\x82\xad\x82\xbf\x82\xe1",
     "Sesuatu yang Menggerogoti Hiyori"},
    // 私には止められない
    {"\x8e\x84\x82\xc9\x82\xcd\x8e\x7e\x82\xdf\x82\xe7\x82\xea\x82\xc8\x82\xa2",
     "Semua Anggota SSR Mendukung"},
    // ひよりのため
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xcc\x82\xbd\x82\xdf",
     "Lupakan Kejadian tempo hari"},
    // まだ、でも、もう少し
    {"\x82\xdc\x82\xbe\x81\x41\x82\xc5\x82\xe0\x81\x41\x82\xe0\x82\xa4\x8f\xad"
     "\x82\xb5",
     "Di Malam Berbulan Saat Peri Menari"},
    // キャッチ・ザ・ひより
    {"\x83\x4c\x83\x83\x83\x62\x83\x60\x81\x45\x83\x55\x81\x45\x82\xd0\x82\xe6"
     "\x82\xe8",
     "Rekor 100% yang Terpecahkan"},
    // ひより、手こずる
    {"\x82\xd0\x82\xe6\x82\xe8\x81\x41\x8e\xe8\x82\xb1\x82\xb8\x82\xe9",
     "Cinta Pertama Hiyori"},
    // 相手に寄り添ったこと
    {"\x91\x8a\x8e\xe8\x82\xc9\x8a\xf1\x82\xe8\x93\x59\x82\xc1\x82\xbd\x82\xb1"
     "\x82\xc6",
     "Aku Harus Menghentikannya"},
    // 本校でもムササビ女子
    {"\x96\x7b\x8d\x5a\x82\xc5\x82\xe0\x83\x80\x83\x54\x83\x54\x83\x72\x8f\x97"
     "\x8e\x71",
     "Aku Tidak Bisa Menghentikannya"},
    // 翻弄するひより
    {"\x96\x7c\x98\x4d\x82\xb7\x82\xe9\x82\xd0\x82\xe6\x82\xe8", "Demi Hiyori"},
    // 未羽のアピール・デイ
    {"\x96\xa2\x89\x48\x82\xcc\x83\x41\x83\x73\x81\x5b\x83\x8b\x81\x45\x83\x66"
     "\x83\x43",
     "Masih, Tapi, Sebentar Lagi"},
    // キミがわからない
    {"\x83\x4c\x83\x7e\x82\xaa\x82\xed\x82\xa9\x82\xe7\x82\xc8\x82\xa2",
     "Catch the Hiyori"},
    // 他言無用な出会い
    {"\x91\xbc\x8c\xbe\x96\xb3\x97\x70\x82\xc8\x8f\x6f\x89\xef\x82\xa2",
     "Hiyori Kesulitan"},
    // いざ小旅行へ出発
    {"\x82\xa2\x82\xb4\x8f\xac\x97\xb7\x8d\x73\x82\xd6\x8f\x6f\x94\xad",
     "Tentang Mendampingi Orang Lain"},
    // 友情と恋愛の線引き
    {"\x97\x46\x8f\xee\x82\xc6\x97\xf6\x88\xa4\x82\xcc\x90\xfc\x88\xf8\x82\xab",
     "Bahkan di Sekolah Utama Pun Tetap Cewek Musasabi"},
    // いよいよ明日

    {"\x82\xa2\x82\xe6\x82\xa2\x82\xe6\x96\xbe\x93\xfa", "Besok Saatnya"},

    // ちょっとした優越感
    {"\x82\xbf\x82\xe5\x82\xc1\x82\xc6\x82\xb5\x82\xbd\x97\x44\x89\x7a\x8a\xb4",
     "Hiyori yang Mempermainkan"},
    // ついてくるつもり？
    {"\x82\xc2\x82\xa2\x82\xc4\x82\xad\x82\xe9\x82\xc2\x82\xe0\x82\xe8\x81\x48",
     "Hari Miu Unjuk Gigi"},
    // 決着はプールで！
    {"\x8c\x88\x92\x85\x82\xcd\x83\x76\x81\x5b\x83\x8b\x82\xc5\x81\x49",
     "Aku Tidak Mengertimu"},
    // サプライズな計画
    {"\x83\x54\x83\x76\x83\x89\x83\x43\x83\x59\x82\xc8\x8c\x76\x89\xe6",
     "Pertemuan yang Tak Boleh Dibocorkan"},
    // ひより天啓を得る
    {"\x82\xd0\x82\xe6\x82\xe8\x93\x56\x8c\x5b\x82\xf0\x93\xbe\x82\xe9",
     "Mari Berangkat Menuju Wisata Singkat"},
    // ひよりのいじりポイント
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xcc\x82\xa2\x82\xb6\x82\xe8\x83\x7c\x83\x43"
     "\x83\x93\x83\x67",
     "Batasan Antara Persahabatan dan Cinta"},
    // 一登の心が動く時は？
    {"\x88\xea\x93\x6f\x82\xcc\x90\x53\x82\xaa\x93\xae\x82\xad\x8e\x9e\x82\xcd"
     "\x81\x48",
     "Akhirnya Besok"},
    // オールインワンで勝負
    {"\x83\x49\x81\x5b\x83\x8b\x83\x43\x83\x93\x83\x8f\x83\x93\x82\xc5\x8f\x9f"
     "\x95\x89",
     "Sedikit Rasa Superior"},
    // ひよりからの事情聴取
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xa9\x82\xe7\x82\xcc\x8e\x96\x8f\xee\x92\xae"
     "\x8e\xe6",
     "Mau Ikut Juga?"},
    // 後悔と迷いと
    {"\x8c\xe3\x89\xf7\x82\xc6\x96\xc0\x82\xa2\x82\xc6",
     "Selesaikan Ini di Kolam Renang!"},
    // 突然の延長戦宣言！
    {"\x93\xcb\x91\x52\x82\xcc\x89\x84\x92\xb7\x90\xed\x90\xe9\x8c\xbe\x81\x49",
     "Rencana Kejutan"},
    // 俺の答えは……
    {"\x89\xb4\x82\xcc\x93\x9a\x82\xa6\x82\xcd\x81\x63\x81\x63",
     "Hiyori Mendapatkan Wahyu Ilahi"},
    // 俺はどちらと……
    {"\x89\xb4\x82\xcd\x82\xc7\x82\xbf\x82\xe7\x82\xc6\x81\x63\x81\x63",
     "Titik Kelemahan Hiyori untuk Digoda"},
    // 卒業式のその後に
    {"\x91\xb2\x8b\xc6\x8e\xae\x82\xcc\x82\xbb\x82\xcc\x8c\xe3\x82\xc9",
     "Kapan Hati Ichito Akan Tergerak?"},
    // 第二ボタンと気持ち
    {"\x91\xe6\x93\xf1\x83\x7b\x83\x5e\x83\x93\x82\xc6\x8b\x43\x8e\x9d\x82\xbf",
     "Bertaruh dengan Semuanya"},
    // トキメキデート計画
    {"\x83\x67\x83\x4c\x83\x81\x83\x4c\x83\x66\x81\x5b\x83\x67\x8c\x76\x89\xe6",
     "Interogasi dari Hiyori"},
    // 改めて勝負を
    {"\x89\xfc\x82\xdf\x82\xc4\x8f\x9f\x95\x89\x82\xf0",
     "Penyesalan dan Kebimbangan"},
    // 探偵と風紀委員
    {"\x92\x54\x92\xe3\x82\xc6\x95\x97\x8b\x49\x88\xcf\x88\xf5",
     "Deklarasi Perpanjangan Waktu Tiba-tiba!"},
    // 未羽の相談ごと
    {"\x96\xa2\x89\x48\x82\xcc\x91\x8a\x92\x6b\x82\xb2\x82\xc6",
     "Jawabanku Adalah..."},
    // ひよりとお出かけ
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xc6\x82\xa8\x8f\x6f\x82\xa9\x82\xaf",
     "Aku Akan Bersama yang Mana..."},
    // ひよりの待ち伏せ
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xcc\x91\xd2\x82\xbf\x95\x9a\x82\xb9",
     "Setelah Upacara Kelulusan"},
    // 急ぎ咲かせし恋の花
    {"\x8b\x7d\x82\xac\x8d\xe7\x82\xa9\x82\xb9\x82\xb5\x97\xf6\x82\xcc\x89\xd4",
     "Kancing Kedua dan Perasaan"},
    // ３人寄っての
    {"\x82\x52\x90\x6c\x8a\xf1\x82\xc1\x82\xc4\x82\xcc",
     "Rencana Kencan yang Mendebarkan"},
    // 信頼と真摯

    {"\x90\x4d\x97\x8a\x82\xc6\x90\x5e\x9d\x95", "Kepercayaan"},

    // 昼食を相席して
    {"\x92\x8b\x90\x48\x82\xf0\x91\x8a\x90\xc8\x82\xb5\x82\xc4",
     "Mari Bertanding Sekali Lagi"},
    // ひよりからの依頼
    {"\x82\xd0\x82\xe6\x82\xe8\x82\xa9\x82\xe7\x82\xcc\x88\xcb\x97\x8a",
     "Detektif dan Komite Disiplin"},
    // 我悟りたる
    {"\x89\xe4\x8c\xe5\x82\xe8\x82\xbd\x82\xe9",
     "Hal yang Ingin Dikonsultasikan Miu"},
    // 出合い頭アクシデント
    {"\x8f\x6f\x8d\x87\x82\xa2\x93\xaa\x83\x41\x83\x4e\x83\x56\x83\x66\x83\x93"
     "\x83\x67",
     "Pergi Bersama Hiyori"},
    // 将来に思いを馳せて
    {"\x8f\xab\x97\x88\x82\xc9\x8e\x76\x82\xa2\x82\xf0\x92\x79\x82\xb9\x82\xc4",
     "Hiyori yang Menghadang"},
    // 別の因果の先の世界
    {"\x95\xca\x82\xcc\x88\xf6\x89\xca\x82\xcc\x90\xe6\x82\xcc\x90\xa2\x8a\x45",
     "Bunga Cinta yang Bersemi dengan Cepat"},
    // 逢見諳子という存在
    {"\x88\xa7\x8c\xa9\xe6\x7d\x8e\x71\x82\xc6\x82\xa2\x82\xa4\x91\xb6\x8d\xdd",
     "Tiga Orang Berkumpul"},
    // ごめんね
    {"\x82\xb2\x82\xdf\x82\xf1\x82\xcb", "Kepercayaan dan Ketulusan"},
    // もう一度キスを
    {"\x82\xe0\x82\xa4\x88\xea\x93\x78\x83\x4c\x83\x58\x82\xf0",
     "Duduk Bersama Saat Makan Siang"},
    // しあわせな涙
    {"\x82\xb5\x82\xa0\x82\xed\x82\xb9\x82\xc8\x97\xdc",
     "Permintaan dari Hiyori"},
    // 嫌な予感と看病と
    {"\x8c\x99\x82\xc8\x97\x5c\x8a\xb4\x82\xc6\x8a\xc5\x95\x61\x82\xc6",
     "Aku Telah Mencapai Pencerahan"},
    // かくれんぼの才能
    {"\x82\xa9\x82\xad\x82\xea\x82\xf1\x82\xda\x82\xcc\x8d\xcb\x94\x5c",
     "Kecelakaan Saat Berpapasan"},
    // みんなからの祝福
    {"\x82\xdd\x82\xf1\x82\xc8\x82\xa9\x82\xe7\x82\xcc\x8f\x6a\x95\x9f",
     "Memikirkan Tentang Masa Depan"},
    // いつか見せてもらえたら
    {"\x82\xa2\x82\xc2\x82\xa9\x8c\xa9\x82\xb9\x82\xc4\x82\xe0\x82\xe7\x82\xa6"
     "\x82\xbd\x82\xe7",
     "Dunia di Ujung Kausalitas yang Lain"},
    // ふたりの愛のメモリー
    {"\x82\xd3\x82\xbd\x82\xe8\x82\xcc\x88\xa4\x82\xcc\x83\x81\x83\x82\x83\x8a"
     "\x81\x5b",
     "Eksistensi Bernama Oumi Sorane"},
    // 二乃の疑問
    {"\x93\xf1\x94\x54\x82\xcc\x8b\x5e\x96\xe2", "Maaf, ya"},
    // 弟ではなくて
    {"\x92\xed\x82\xc5\x82\xcd\x82\xc8\x82\xad\x82\xc4",
     "Berikan Aku Ciuman Sekali Lagi"},
    // そら姉の笑顔を
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xcc\x8f\xce\x8a\xe7\x82\xf0",
     "Air Mata Bahagia"},
    // 一登の不調？
    {"\x88\xea\x93\x6f\x82\xcc\x95\x73\x92\xb2\x81\x48",
     "Firasat Buruk dan Merawat Orang Sakit"},
    // ベルガマスクの三番目
    {"\x83\x78\x83\x8b\x83\x4b\x83\x7d\x83\x58\x83\x4e\x82\xcc\x8e\x4f\x94\xd4"
     "\x96\xda",
     "Bakat Bermain Petak Umpet"},
    // 諳子と迷子

    {"\xe6\x7d\x8e\x71\x82\xc6\x96\xc0\x8e\x71", "Akiko Sesat"},

    // バイトのお願い
    {"\x83\x6f\x83\x43\x83\x67\x82\xcc\x82\xa8\x8a\xe8\x82\xa2",
     "Berkat dari Semuanya"},
    // 馴染んだウサ耳
    {"\x93\xe9\x90\xf5\x82\xf1\x82\xbe\x83\x45\x83\x54\x8e\xa8",
     "Jika Suatu Saat Nanti Kamu Bisa Memperlihatkannya Padaku"},
    // ウサミミファンクラブ
    {"\x83\x45\x83\x54\x83\x7e\x83\x7e\x83\x74\x83\x40\x83\x93\x83\x4e\x83\x89"
     "\x83\x75",
     "Memori Cinta Berdua"},
    // 諳子の家族の写真
    {"\xe6\x7d\x8e\x71\x82\xcc\x89\xc6\x91\xb0\x82\xcc\x8e\xca\x90\x5e",
     "Pertanyaan Nino"},
    // 良い旦那さんになれる
    {"\x97\xc7\x82\xa2\x92\x55\x93\xdf\x82\xb3\x82\xf1\x82\xc9\x82\xc8\x82\xea"
     "\x82\xe9",
     "Bukannya Sebagai Adik"},
    // 心強い味方たち
    {"\x90\x53\x8b\xad\x82\xa2\x96\xa1\x95\xfb\x82\xbd\x82\xbf",
     "Senyuman Sora-nee"},
    // 一登好みの味に
    {"\x88\xea\x93\x6f\x8d\x44\x82\xdd\x82\xcc\x96\xa1\x82\xc9",
     "Ichito Sedang Tidak Fit?"},
    // 原因究明の時間に
    {"\x8c\xb4\x88\xf6\x8b\x86\x96\xbe\x82\xcc\x8e\x9e\x8a\xd4\x82\xc9",
     "Yang Ketiga dari Bergamasque"},
    // 流石のSSR
    {"\x97\xac\x90\xce\x82\xcc\x53\x53\x52", "Sorane dan Anak Hilang"},
    // 難なく突破で、いいの？
    {"\x93\xef\x82\xc8\x82\xad\x93\xcb\x94\x6a\x82\xc5\x81\x41\x82\xa2\x82\xa2"
     "\x82\xcc\x81\x48",
     "Permintaan Kerja Sambilan"},
    // 自由な校風だから
    {"\x8e\xa9\x97\x52\x82\xc8\x8d\x5a\x95\x97\x82\xbe\x82\xa9\x82\xe7",
     "Telinga Kelinci yang Sudah Terbiasa"},
    // ジジイに負けたくない
    {"\x83\x57\x83\x57\x83\x43\x82\xc9\x95\x89\x82\xaf\x82\xbd\x82\xad\x82\xc8"
     "\x82\xa2",
     "Fan Club Telinga Kelinci"},
    // わには苦手

    {"\x82\xed\x82\xc9\x82\xcd\x8b\xea\x8e\xe8", "Takut Buaya"},

    // 最後は神頼み
    {"\x8d\xc5\x8c\xe3\x82\xcd\x90\x5f\x97\x8a\x82\xdd",
     "Foto Keluarga Sorane"},
    // 久しぶりの買い物で
    {"\x8b\x76\x82\xb5\x82\xd4\x82\xe8\x82\xcc\x94\x83\x82\xa2\x95\xa8\x82\xc5",
     "Bisa Menjadi Suami yang Baik"},
    // カチューシャ擬態
    {"\x83\x4a\x83\x60\x83\x85\x81\x5b\x83\x56\x83\x83\x8b\x5b\x91\xd4",
     "Teman-teman yang Bisa Diandalkan"},
    // ウサ耳対策会議
    {"\x83\x45\x83\x54\x8e\xa8\x91\xce\x8d\xf4\x89\xef\x8b\x63",
     "Menjadi Rasa Kesukaan Ichito"},
    // 諳子の決意

    {"\xe6\x7d\x8e\x71\x82\xcc\x8c\x88\x88\xd3", "Tekad Akiko"},

    // 誰かの夢とジジイと
    {"\x92\x4e\x82\xa9\x82\xcc\x96\xb2\x82\xc6\x83\x57\x83\x57\x83\x43\x82\xc6",
     "Waktunya Menyelidiki Penyebabnya"},
    // 落ち着いた両親
    {"\x97\x8e\x82\xbf\x92\x85\x82\xa2\x82\xbd\x97\xbc\x90\x65",
     "Seperti yang Diharapkan dari SSR"},
    // 思いがけない異変
    {"\x8e\x76\x82\xa2\x82\xaa\x82\xaf\x82\xc8\x82\xa2\x88\xd9\x95\xcf",
     "Berhasil Melewatinya dengan Mudah, Tidak Apa-apa?"},
    // 二乃が居たらまずい？
    {"\x93\xf1\x94\x54\x82\xaa\x8b\x8f\x82\xbd\x82\xe7\x82\xdc\x82\xb8\x82\xa2"
     "\x81\x48",
     "Karena Budaya Sekolah yang Bebas"},
    // ウサ耳流出阻止
    {"\x83\x45\x83\x54\x8e\xa8\x97\xac\x8f\x6f\x91\x6a\x8e\x7e",
     "Aku Tidak Mau Kalah dari Kakek Tua Itu"},
    // 初恋のお姉さん？
    {"\x8f\x89\x97\xf6\x82\xcc\x82\xa8\x8e\x6f\x82\xb3\x82\xf1\x81\x48",
     "Aku Payah Menghadapi Buaya"},
    // ウサ耳諳子

    {"\x83\x45\x83\x54\x8e\xa8\xe6\x7d\x8e\x71", "Akiko Kelinc"},

    // ヒントは少女漫画に
    {"\x83\x71\x83\x93\x83\x67\x82\xcd\x8f\xad\x8f\x97\x96\x9f\x89\xe6\x82\xc9",
     "Terakhir, Berdoa pada Tuhan"},
    // 千里の道も一歩から
    {"\x90\xe7\x97\xa2\x82\xcc\x93\xb9\x82\xe0\x88\xea\x95\xe0\x82\xa9\x82\xe7",
     "Saat Berbelanja Setelah Sekian Lama"},
    // 現状を打破するには
    {"\x8c\xbb\x8f\xf3\x82\xf0\x91\xc5\x94\x6a\x82\xb7\x82\xe9\x82\xc9\x82\xcd",
     "Kamuflase Bando"},
    // まずは認めてみる
    {"\x82\xdc\x82\xb8\x82\xcd\x94\x46\x82\xdf\x82\xc4\x82\xdd\x82\xe9",
     "Rapat Penanganan Telinga Kelinci"},
    // 諳子のキスで……
    {"\xe6\x7d\x8e\x71\x82\xcc\x83\x4c\x83\x58\x82\xc5\x81\x63\x81\x63",
     "Tekad Sorane"},
    // 未来への誓い
    {"\x96\xa2\x97\x88\x82\xd6\x82\xcc\x90\xbe\x82\xa2",
     "Mimpi Seseorang, Sang Kakek, dan..."},
    // みらいの妹へ
    {"\x82\xdd\x82\xe7\x82\xa2\x82\xcc\x96\x85\x82\xd6",
     "Orang Tua yang Tenang"},
    // 二乃の中の真実
    {"\x93\xf1\x94\x54\x82\xcc\x92\x86\x82\xcc\x90\x5e\x8e\xc0",
     "Kejanggalan yang Tak Terduga"},
    // 全て私のせい

    {"\x91\x53\x82\xc4\x8e\x84\x82\xcc\x82\xb9\x82\xa2", "Salahku Semua"},

    // 三美のお願い
    {"\x8e\x4f\x94\xfc\x82\xcc\x82\xa8\x8a\xe8\x82\xa2",
     "Gawat Kalau Ada Nino di Sini?"},
    // ごめんなさい兄さん
    {"\x82\xb2\x82\xdf\x82\xf1\x82\xc8\x82\xb3\x82\xa2\x8c\x5a\x82\xb3\x82\xf1",
     "Mencegah Kebocoran Foto Telinga Kelinci"},
    // 明日の予定は？
    {"\x96\xbe\x93\xfa\x82\xcc\x97\x5c\x92\xe8\x82\xcd\x81\x48",
     "Kakak Perempuan Cinta Pertama?"},
    // 変えたきっかけ
    {"\x95\xcf\x82\xa6\x82\xbd\x82\xab\x82\xc1\x82\xa9\x82\xaf",
     "Sorane Bertelinga Kelinci"},
    // たとえ恋人じゃなくても
    {"\x82\xbd\x82\xc6\x82\xa6\x97\xf6\x90\x6c\x82\xb6\x82\xe1\x82\xc8\x82\xad"
     "\x82\xc4\x82\xe0",
     "Petunjuknya Ada di Manga Shoujo"},
    // 妹の好物
    {"\x96\x85\x82\xcc\x8d\x44\x95\xa8",
     "Perjalanan Seribu Mil Dimulai dari Satu Langkah"},
    // 懐かしい呼び声
    {"\x89\xf9\x82\xa9\x82\xb5\x82\xa2\x8c\xc4\x82\xd1\x90\xba",
     "Untuk Mendobrak Situasi Saat Ini"},
    // いつもの二乃
    {"\x82\xa2\x82\xc2\x82\xe0\x82\xcc\x93\xf1\x94\x54",
     "Mari Kita Akui Terlebih Dahulu"},
    // 三美のような妹に
    {"\x8e\x4f\x94\xfc\x82\xcc\x82\xe6\x82\xa4\x82\xc8\x96\x85\x82\xc9",
     "Dengan Ciuman dari Sorane..."},
    // 妹を演じる二乃
    {"\x96\x85\x82\xf0\x89\x89\x82\xb6\x82\xe9\x93\xf1\x94\x54",
     "Sumpah untuk Masa Depan"},
    // 普通の妹に
    {"\x95\x81\x92\xca\x82\xcc\x96\x85\x82\xc9",
     "Untuk Adik Perempuan di Masa Depan"},
    // 三美から二乃へ
    {"\x8e\x4f\x94\xfc\x82\xa9\x82\xe7\x93\xf1\x94\x54\x82\xd6",
     "Kebenaran di Dalam Diri Nino"},
    // 近付くあの日
    {"\x8b\xdf\x95\x74\x82\xad\x82\xa0\x82\xcc\x93\xfa", "Ini Semua Salahku"},
    // 調子の悪そうな二乃
    {"\x92\xb2\x8e\x71\x82\xcc\x88\xab\x82\xbb\x82\xa4\x82\xc8\x93\xf1\x94\x54",
     "Permintaan Mitsumi"},
    // 救い上げる声
    {"\x8b\x7e\x82\xa2\x8f\xe3\x82\xb0\x82\xe9\x90\xba",
     "Maafkan Aku, Nii-san"},
    // 二乃のおかげで
    {"\x93\xf1\x94\x54\x82\xcc\x82\xa8\x82\xa9\x82\xb0\x82\xc5",
     "Apa Rencana untuk Besok?"},
    // 水着ハプニング！
    {"\x90\x85\x92\x85\x83\x6e\x83\x76\x83\x6a\x83\x93\x83\x4f\x81\x49",
     "Pemicu Perubahan"},
    // ピアノ部屋と二乃
    {"\x83\x73\x83\x41\x83\x6d\x95\x94\x89\xae\x82\xc6\x93\xf1\x94\x54",
     "Meskipun Bukan Sebagai Kekasih"},
    // 愛ある仕返し
    {"\x88\xa4\x82\xa0\x82\xe9\x8e\x64\x95\xd4\x82\xb5",
     "Makanan Kesukaan Adik Perempuan"},
    // 夢にまで見た姿で
    {"\x96\xb2\x82\xc9\x82\xdc\x82\xc5\x8c\xa9\x82\xbd\x8e\x70\x82\xc5",
     "Suara Panggilan yang Nostalgia"},
    // 夢で見た姿を
    {"\x96\xb2\x82\xc5\x8c\xa9\x82\xbd\x8e\x70\x82\xf0",
     "Nino yang Seperti Biasanya"},
    // メンバーも待っていた
    {"\x83\x81\x83\x93\x83\x6f\x81\x5b\x82\xe0\x91\xd2\x82\xc1\x82\xc4\x82\xa2"
     "\x82\xbd",
     "Menjadi Adik Seperti Mitsumi"},
    // これが惚れた弱み
    {"\x82\xb1\x82\xea\x82\xaa\x8d\x9b\x82\xea\x82\xbd\x8e\xe3\x82\xdd",
     "Nino yang Berperan Sebagai Adik Perempuan"},
    // 待っていたそら姉
    {"\x91\xd2\x82\xc1\x82\xc4\x82\xa2\x82\xbd\x82\xbb\x82\xe7\x8e\x6f",
     "Menjadi Adik Perempuan Biasa"},
    // 家族と娘の恋人として
    {"\x89\xc6\x91\xb0\x82\xc6\x96\xba\x82\xcc\x97\xf6\x90\x6c\x82\xc6\x82\xb5"
     "\x82\xc4",
     "Dari Mitsumi untuk Nino"},
    // 伝えないといけないこと
    {"\x93\x60\x82\xa6\x82\xc8\x82\xa2\x82\xc6\x82\xa2\x82\xaf\x82\xc8\x82\xa2"
     "\x82\xb1\x82\xc6",
     "Hari Itu Semakin Dekat"},
    // １００点の答え
    {"\x82\x50\x82\x4f\x82\x4f\x93\x5f\x82\xcc\x93\x9a\x82\xa6",
     "Nino yang Kelihatannya Tidak Fit"},
    // 妹としての距離感
    {"\x96\x85\x82\xc6\x82\xb5\x82\xc4\x82\xcc\x8b\x97\x97\xa3\x8a\xb4",
     "Suara yang Menyelamatkan"},
    // 衆人環視であーん
    {"\x8f\x4f\x90\x6c\x8a\xc2\x8e\x8b\x82\xc5\x82\xa0\x81\x5b\x82\xf1",
     "Berkat Nino"},
    // 悲しい夢と、重なる今と
    {"\x94\xdf\x82\xb5\x82\xa2\x96\xb2\x82\xc6\x81\x41\x8f\x64\x82\xc8\x82\xe9"
     "\x8d\xa1\x82\xc6",
     "Insiden Baju Renang!"},
    // 気持ちは本物
    {"\x8b\x43\x8e\x9d\x82\xbf\x82\xcd\x96\x7b\x95\xa8",
     "Ruang Piano dan Nino"},
    // 苦手なものコンボ
    {"\x8b\xea\x8e\xe8\x82\xc8\x82\xe0\x82\xcc\x83\x52\x83\x93\x83\x7b",
     "Balas Dendam Penuh Cinta"},
    // 期待と不安せめぎ合う
    {"\x8a\xfa\x91\xd2\x82\xc6\x95\x73\x88\xc0\x82\xb9\x82\xdf\x82\xac\x8d\x87"
     "\x82\xa4",
     "Dalam Wujud yang Bahkan Muncul di Mimpi"},
    // 妹ですから普通です
    {"\x96\x85\x82\xc5\x82\xb7\x82\xa9\x82\xe7\x95\x81\x92\xca\x82\xc5\x82\xb7",
     "Sosok yang Kulihat di Mimpi"},
    // 二乃心は難しい

    {"\x93\xf1\x94\x54\x90\x53\x82\xcd\x93\xef\x82\xb5\x82\xa2",
     "Hati Nino Sulit"},

    // 機嫌を損ねた二乃？
    {"\x8b\x40\x8c\x99\x82\xf0\x91\xb9\x82\xcb\x82\xbd\x93\xf1\x94\x54\x81\x48",
     "Para Anggota Juga Telah Menunggu"},
    // 表面上はいつもの朝
    {"\x95\x5c\x96\xca\x8f\xe3\x82\xcd\x82\xa2\x82\xc2\x82\xe0\x82\xcc\x92\xa9",
     "Inilah Kelemahan Orang yang Sedang Jatuh Cinta"},
    // そら姉はお見通し
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xcd\x82\xa8\x8c\xa9\x92\xca\x82\xb5",
     "Sora-nee Telah Menunggu"},
    // 有里栖のおせっかい
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xcc\x82\xa8\x82\xb9\x82\xc1\x82\xa9\x82\xa2",
     "Sebagai Keluarga dan Kekasih Putrinya"},
    // 友人と気分転換
    {"\x97\x46\x90\x6c\x82\xc6\x8b\x43\x95\xaa\x93\x5d\x8a\xb7",
     "Hal yang Harus Disampaikan"},
    // 二乃を見習って
    {"\x93\xf1\x94\x54\x82\xf0\x8c\xa9\x8f\x4b\x82\xc1\x82\xc4",
     "Jawaban Nilai 100"},
    // 幼き日の二乃と

    {"\x97\x63\x82\xab\x93\xfa\x82\xcc\x93\xf1\x94\x54\x82\xc6",
     "Nino Masa Kecil"},

    // 妹だから
    {"\x96\x85\x82\xbe\x82\xa9\x82\xe7", "Jarak Sebagai Seorang Adik"},
    // バイトを楽しんで
    {"\x83\x6f\x83\x43\x83\x67\x82\xf0\x8a\x79\x82\xb5\x82\xf1\x82\xc5",
     "Menyuapi di Depan Umum"},
    // 二乃とふたりで調査
    {"\x93\xf1\x94\x54\x82\xc6\x82\xd3\x82\xbd\x82\xe8\x82\xc5\x92\xb2\x8d\xb8",
     "Mimpi Buruk yang Bertumpang Tindih dengan Masa Kini"},
    // ３人でバイトのお誘い
    {"\x82\x52\x90\x6c\x82\xc5\x83\x6f\x83\x43\x83\x67\x82\xcc\x82\xa8\x97\x55"
     "\x82\xa2",
     "Perasaan Ini Nyata"},
    // 零次さんの気遣い
    {"\x97\xeb\x8e\x9f\x82\xb3\x82\xf1\x82\xcc\x8b\x43\x8c\xad\x82\xa2",
     "Kombo Hal-hal yang Tidak Disukai"},
    // 二乃の料理チャレンジ
    {"\x93\xf1\x94\x54\x82\xcc\x97\xbf\x97\x9d\x83\x60\x83\x83\x83\x8c\x83\x93"
     "\x83\x57",
     "Antara Harapan dan Kecemasan yang Saling Beradu"},
    // 傍にいれくれる二乃
    {"\x96\x54\x82\xc9\x82\xa2\x82\xea\x82\xad\x82\xea\x82\xe9\x93\xf1\x94\x54",
     "Namanya Juga Adik, Jadi Ini Biasa"},
    // 期待してもいい？
    {"\x8a\xfa\x91\xd2\x82\xb5\x82\xc4\x82\xe0\x82\xa2\x82\xa2\x81\x48",
     "Hati Nino Itu Sulit Dimengerti"},
    // 二乃ちゃんに決めた？
    {"\x93\xf1\x94\x54\x82\xbf\x82\xe1\x82\xf1\x82\xc9\x8c\x88\x82\xdf\x82\xbd"
     "\x81\x48",
     "Apakah Nino Sedang Merajuk?"},
    // そら姉の意見
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xcc\x88\xd3\x8c\xa9",
     "Secara Lahiriah Tetap Pagi Seperti Biasanya"},
    // ぎこちないふたり
    {"\x82\xac\x82\xb1\x82\xbf\x82\xc8\x82\xa2\x82\xd3\x82\xbd\x82\xe8",
     "Sora-nee Sudah Tahu Semuanya"},
    // 二乃のキスで……
    {"\x93\xf1\x94\x54\x82\xcc\x83\x4c\x83\x58\x82\xc5\x81\x63\x81\x63",
     "Campur Tangan Arisu"},
    // 恋人か、家族か
    {"\x97\xf6\x90\x6c\x82\xa9\x81\x41\x89\xc6\x91\xb0\x82\xa9",
     "Mencari Suasana Baru Bersama Teman"},
    // これからもよろしく
    {"\x82\xb1\x82\xea\x82\xa9\x82\xe7\x82\xe0\x82\xe6\x82\xeb\x82\xb5\x82\xad",
     "Belajarlah dari Nino"},
    // 杉並らしい卒業式
    {"\x90\x99\x95\xc0\x82\xe7\x82\xb5\x82\xa2\x91\xb2\x8b\xc6\x8e\xae",
     "Bersama Nino di Masa Kecil"},
    // サプライズも忘れずに
    {"\x83\x54\x83\x76\x83\x89\x83\x43\x83\x59\x82\xe0\x96\x59\x82\xea\x82\xb8"
     "\x82\xc9",
     "Karena Aku Adalah Adikmu"},
    // プレゼントはフリーパス
    {"\x83\x76\x83\x8c\x83\x5b\x83\x93\x83\x67\x82\xcd\x83\x74\x83\x8a\x81\x5b"
     "\x83\x70\x83\x58",
     "Nikmatilah Kerja Sambilanmu"},
    // 何気なく笑える放課後
    {"\x89\xbd\x8b\x43\x82\xc8\x82\xad\x8f\xce\x82\xa6\x82\xe9\x95\xfa\x89\xdb"
     "\x8c\xe3",
     "Menyelidiki Berdua Bersama Nino"},
    // 自然な３人

    {"\x8e\xa9\x91\x52\x82\xc8\x82\x52\x90\x6c", "Alami 3 Org"},

    // 今日は美味しいお弁当
    {"\x8d\xa1\x93\xfa\x82\xcd\x94\xfc\x96\xa1\x82\xb5\x82\xa2\x82\xa8\x95\xd9"
     "\x93\x96",
     "Undakan Kerja Sambilan untuk Bertiga"},
    // しっくりくる３人
    {"\x82\xb5\x82\xc1\x82\xad\x82\xe8\x82\xad\x82\xe9\x82\x52\x90\x6c",
     "Perhatian dari Reiji-san"},
    // そら姉のドッキリ
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xcc\x83\x68\x83\x62\x83\x4c\x83\x8a",
     "Tantangan Memasak Nino"},
    // 二乃の特製お弁当
    {"\x93\xf1\x94\x54\x82\xcc\x93\xc1\x90\xbb\x82\xa8\x95\xd9\x93\x96",
     "Nino yang Selalu Ada di Sampingku"},
    // ご機嫌なそら姉
    {"\x82\xb2\x8b\x40\x8c\x99\x82\xc8\x82\xbb\x82\xe7\x8e\x6f",
     "Boleh Aku Berharap?"},
    // バイト代の使い道
    {"\x83\x6f\x83\x43\x83\x67\x91\xe3\x82\xcc\x8e\x67\x82\xa2\x93\xb9",
     "Sudah Memilih Nino-chan?"},
    // そら姉のコスプレ？
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xcc\x83\x52\x83\x58\x83\x76\x83\x8c\x81\x48",
     "Pendapat Sora-nee"},
    // 両親と帰宅して
    {"\x97\xbc\x90\x65\x82\xc6\x8b\x41\x91\xee\x82\xb5\x82\xc4",
     "Mereka Berdua yang Canggung"},
    // ふたりとの約束
    {"\x82\xd3\x82\xbd\x82\xe8\x82\xc6\x82\xcc\x96\xf1\x91\xa9",
     "Dengan Ciuman dari Nino..."},
    // ふたりにも話をして
    {"\x82\xd3\x82\xbd\x82\xe8\x82\xc9\x82\xe0\x98\x62\x82\xf0\x82\xb5\x82\xc4",
     "Kekasih atau Keluarga?"},
    // バイト代とプレゼント
    {"\x83\x6f\x83\x43\x83\x67\x91\xe3\x82\xc6\x83\x76\x83\x8c\x83\x5b\x83\x93"
     "\x83\x67",
     "Mohon Bantuannya Mulai Sekarang"},
    // そら姉も反対らしい
    {"\x82\xbb\x82\xe7\x8e\x6f\x82\xe0\x94\xbd\x91\xce\x82\xe7\x82\xb5\x82\xa2",
     "Upacara Kelulusan yang Sangat Khas Suginami"},
    // 二乃は反対らしい
    {"\x93\xf1\x94\x54\x82\xcd\x94\xbd\x91\xce\x82\xe7\x82\xb5\x82\xa2",
     "Jangan Lupakan Kejutannya Juga"},
    // もう一度バイトしない？
    {"\x82\xe0\x82\xa4\x88\xea\x93\x78\x83\x6f\x83\x43\x83\x67\x82\xb5\x82\xc8"
     "\x82\xa2\x81\x48",
     "Hadiahnya Adalah Tiket Terusan"},
    // 雨の朝は憂鬱？
    {"\x89\x4a\x82\xcc\x92\xa9\x82\xcd\x97\x4a\x9f\x54\x81\x48",
     "Waktu Pulang Sekolah yang Penuh Tawa Alami"},
    // 買い物と有里栖と
    {"\x94\x83\x82\xa2\x95\xa8\x82\xc6\x97\x4c\x97\xa2\x90\xb2\x82\xc6",
     "Ketiga Orang yang Terlihat Alami"},
    // 久々の親子の団らん
    {"\x8b\x76\x81\x58\x82\xcc\x90\x65\x8e\x71\x82\xcc\x92\x63\x82\xe7\x82\xf1",
     "Hari Ini Bekalnya Enak"},
    // 楽しくも忙しい準備
    {"\x8a\x79\x82\xb5\x82\xad\x82\xe0\x96\x5a\x82\xb5\x82\xa2\x8f\x80\x94\xf5",
     "Ketiga Orang yang Sangat Cocok"},
    // 帰ってくる両親
    {"\x8b\x41\x82\xc1\x82\xc4\x82\xad\x82\xe9\x97\xbc\x90\x65",
     "Prank dari Sora-nee"},
    // 本校に進学したら
    {"\x96\x7b\x8d\x5a\x82\xc9\x90\x69\x8a\x77\x82\xb5\x82\xbd\x82\xe7",
     "Bekal Spesial Buatan Nino"},
    // 友達の進路は？
    {"\x97\x46\x92\x42\x82\xcc\x90\x69\x98\x48\x82\xcd\x81\x48",
     "Sora-nee yang Sedang Senang"},
    // 朝のお約束？
    {"\x92\xa9\x82\xcc\x82\xa8\x96\xf1\x91\xa9\x81\x48",
     "Cara Menggunakan Uang Hasil Kerja Sambilan"},
    // さようなら、ありがとう
    {"\x82\xb3\x82\xe6\x82\xa4\x82\xc8\x82\xe7\x81\x41\x82\xa0\x82\xe8\x82\xaa"
     "\x82\xc6\x82\xa4",
     "Sora-nee Cosplay?"},
    // 世界を変える恋

    {"\x90\xa2\x8a\x45\x82\xf0\x95\xcf\x82\xa6\x82\xe9\x97\xf6",
     "Cinta Ubah Dnia"},

    // 頼もしい仲間たち
    {"\x97\x8a\x82\xe0\x82\xb5\x82\xa2\x92\x87\x8a\xd4\x82\xbd\x82\xbf",
     "Pulang Bersama Orang Tua"},
    // 広がる恋心

    {"\x8d\x4c\x82\xaa\x82\xe9\x97\xf6\x90\x53", "Cinta Mekar"},

    // ふくらむ希望
    {"\x82\xd3\x82\xad\x82\xe7\x82\xde\x8a\xf3\x96\x5d",
     "Janji Bersama Mereka Berdua"},
    // 恋愛強化期間
    {"\x97\xf6\x88\xa4\x8b\xad\x89\xbb\x8a\xfa\x8a\xd4",
     "Berbicaralah Juga pada Mereka Berdua"},
    // 恋のモニタリング
    {"\x97\xf6\x82\xcc\x83\x82\x83\x6a\x83\x5e\x83\x8a\x83\x93\x83\x4f",
     "Gaji Kerja Sambilan dan Hadiah"},
    // 天枷・鷺澤共同作戦
    {"\x93\x56\x9e\x67\x81\x45\x8d\xeb\xe0\x56\x8b\xa4\x93\xaf\x8d\xec\x90\xed",
     "Sepertinya Sora-nee Juga Tidak Setuju"},
    // 恋の拡散大作戦
    {"\x97\xf6\x82\xcc\x8a\x67\x8e\x55\x91\xe5\x8d\xec\x90\xed",
     "Sepertinya Nino Tidak Setuju"},
    // 一筋の希望

    {"\x88\xea\x8b\xd8\x82\xcc\x8a\xf3\x96\x5d", "Sinar Harap"},

    // ただいま、おかえり
    {"\x82\xbd\x82\xbe\x82\xa2\x82\xdc\x81\x41\x82\xa8\x82\xa9\x82\xa6\x82\xe8",
     "Mau Kerja Sambilan Sekali Lagi?"},
    // ありがとう
    {"\x82\xa0\x82\xe8\x82\xaa\x82\xc6\x82\xa4",
     "Apakah Pagi yang Hujan Itu Suram?"},
    // 優しい嘘
    {"\x97\x44\x82\xb5\x82\xa2\x89\x52", "Belanja Bersama Arisu"},
    // マジカルプールデート
    {"\x83\x7d\x83\x57\x83\x4a\x83\x8b\x83\x76\x81\x5b\x83\x8b\x83\x66\x81\x5b"
     "\x83\x67",
     "Kumpul Keluarga yang Sudah Lama Tidak Terjadi"},
    // やり直したらしたいこと
    {"\x82\xe2\x82\xe8\x92\xbc\x82\xb5\x82\xbd\x82\xe7\x82\xb5\x82\xbd\x82\xa2"
     "\x82\xb1\x82\xc6",
     "Persiapan yang Menyenangkan Namun Sibuk"},
    // 常坂元という男
    {"\x8f\xed\x8d\xe2\x8c\xb3\x82\xc6\x82\xa2\x82\xa4\x92\x6a",
     "Orang Tua yang Kembali Pulang"},
    // 世界とふたりと
    {"\x90\xa2\x8a\x45\x82\xc6\x82\xd3\x82\xbd\x82\xe8\x82\xc6",
     "Jika Melanjutkan ke Sekolah Utama"},
    // 使命よりも大切な
    {"\x8e\x67\x96\xbd\x82\xe6\x82\xe8\x82\xe0\x91\xe5\x90\xd8\x82\xc8",
     "Bagaimana dengan Masa Depan Teman-teman?"},
    // Ｄ．Ｃ．の魔法
    {"\x82\x63\x81\x44\x82\x62\x81\x44\x82\xcc\x96\x82\x96\x40",
     "Rutinitas di Pagi Hari?"},
    // 有里咲のプラン
    {"\x97\x4c\x97\xa2\x8d\xe7\x82\xcc\x83\x76\x83\x89\x83\x93",
     "Selamat Tinggal, Terima Kasih"},
    // 俺と有里咲と有里栖と
    {"\x89\xb4\x82\xc6\x97\x4c\x97\xa2\x8d\xe7\x82\xc6\x97\x4c\x97\xa2\x90\xb2"
     "\x82\xc6",
     "Cinta yang Mengubah Dunia"},
    // 無理してそうな有里咲
    {"\x96\xb3\x97\x9d\x82\xb5\x82\xc4\x82\xbb\x82\xa4\x82\xc8\x97\x4c\x97\xa2"
     "\x8d\xe7",
     "Teman-teman yang Bisa Diandalkan"},
    // サクラの国の有里咲
    {"\x83\x54\x83\x4e\x83\x89\x82\xcc\x8d\x91\x82\xcc\x97\x4c\x97\xa2\x8d\xe7",
     "Rasa Cinta yang Menyebar"},
    // 満月と魔法とＶＲと彼女と
    {"\x96\x9e\x8c\x8e\x82\xc6\x96\x82\x96\x40\x82\xc6\x82\x75\x82\x71\x82\xc6"
     "\x94\xde\x8f\x97\x82\xc6",
     "Harapan yang Membuncah"},
    // オカルトな話
    {"\x83\x49\x83\x4a\x83\x8b\x83\x67\x82\xc8\x98\x62",
     "Periode Penguatan Cinta"},
    // 久しぶりのＳＳＲ
    {"\x8b\x76\x82\xb5\x82\xd4\x82\xe8\x82\xcc\x82\x72\x82\x72\x82\x71",
     "Monitoring Cinta"},
    // 確認した日付
    {"\x8a\x6d\x94\x46\x82\xb5\x82\xbd\x93\xfa\x95\x74",
     "Operasi Bersama Amakase dan Sagisawa"},
    // 思いだしてはダメ
    {"\x8e\x76\x82\xa2\x82\xbe\x82\xb5\x82\xc4\x82\xcd\x83\x5f\x83\x81",
     "Operasi Besar Penyebaran Cinta"},
    // ＶＲ使用許可

    {"\x82\x75\x82\x71\x8e\x67\x97\x70\x8b\x96\x89\xc2", "Izin Pakai VR"},

    // ＡＬＩＣＥに会えれば
    {"\x82\x60\x82\x6b\x82\x68\x82\x62\x82\x64\x82\xc9\x89\xef\x82\xa6\x82\xea"
     "\x82\xce",
     "Secercah Harapan"},
    // アリスとＡＬＩＣＥ
    {"\x83\x41\x83\x8a\x83\x58\x82\xc6\x82\x60\x82\x6b\x82\x68\x82\x62\x82\x64",
     "Aku Pulang, Selamat Datang di Rumah"},
    // 遊園地デート再び
    {"\x97\x56\x89\x80\x92\x6e\x83\x66\x81\x5b\x83\x67\x8d\xc4\x82\xd1",
     "Terima Kasih"},
    // 彼女と過ごした日々
    {"\x94\xde\x8f\x97\x82\xc6\x89\xdf\x82\xb2\x82\xb5\x82\xbd\x93\xfa\x81\x58",
     "Kebohongan yang Baik"},
    // 有里栖とメーパン
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xc6\x83\x81\x81\x5b\x83\x70\x83\x93",
     "Kencan Kolam Renang Ajaib"},
    // もう一人の有里栖？
    {"\x82\xe0\x82\xa4\x88\xea\x90\x6c\x82\xcc\x97\x4c\x97\xa2\x90\xb2\x81\x48",
     "Hal yang Ingin Dilakukan Jika Bisa Mengulang Kembali"},
    // SSRのやさしさ
    {"\x53\x53\x52\x82\xcc\x82\xe2\x82\xb3\x82\xb5\x82\xb3",
     "Pria Bernama Tokisaka Gen"},
    // ホクロの位置！？
    {"\x83\x7a\x83\x4e\x83\x8d\x82\xcc\x88\xca\x92\x75\x81\x49\x81\x48",
     "Dunia dan Mereka Berdua"},
    // 個別活動と称して
    {"\x8c\xc2\x95\xca\x8a\x88\x93\xae\x82\xc6\x8f\xcc\x82\xb5\x82\xc4",
     "Lebih Penting Daripada Misi"},
    // いつかの誰かの記憶
    {"\x82\xa2\x82\xc2\x82\xa9\x82\xcc\x92\x4e\x82\xa9\x82\xcc\x8b\x4c\x89\xaf",
     "Sihir D.C."},
    // 神社で不安を和らげて
    {"\x90\x5f\x8e\xd0\x82\xc5\x95\x73\x88\xc0\x82\xf0\x98\x61\x82\xe7\x82\xb0"
     "\x82\xc4",
     "Rencana Arisa"},
    // 明日の約束
    {"\x96\xbe\x93\xfa\x82\xcc\x96\xf1\x91\xa9", "Aku, Arisa, dan Arisu"},
    // 雪とピアノと
    {"\x90\xe1\x82\xc6\x83\x73\x83\x41\x83\x6d\x82\xc6",
     "Arisa yang Kelihatannya Memaksakan Diri"},
    // 自分じゃないみたい
    {"\x8e\xa9\x95\xaa\x82\xb6\x82\xe1\x82\xc8\x82\xa2\x82\xdd\x82\xbd\x82\xa2",
     "Arisa dari Negeri Sakura"},
    // 家族も大事に
    {"\x89\xc6\x91\xb0\x82\xe0\x91\xe5\x8e\x96\x82\xc9",
     "Bulan Purnama, Sihir, VR, dan Dirinya"},
    // ジジイに聞いた雪の話
    {"\x83\x57\x83\x57\x83\x43\x82\xc9\x95\xb7\x82\xa2\x82\xbd\x90\xe1\x82\xcc"
     "\x98\x62",
     "Cerita Okultisme"},
    // アリスの視線
    {"\x83\x41\x83\x8a\x83\x58\x82\xcc\x8e\x8b\x90\xfc",
     "SSR Setelah Sekian Lama"},
    // 他人の夢を見ている感じ
    {"\x91\xbc\x90\x6c\x82\xcc\x96\xb2\x82\xf0\x8c\xa9\x82\xc4\x82\xa2\x82\xe9"
     "\x8a\xb4\x82\xb6",
     "Tanggal yang Telah Dikonfirmasi"},
    // 有里栖と同じ夢を再び
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xc6\x93\xaf\x82\xb6\x96\xb2\x82\xf0\x8d\xc4"
     "\x82\xd1",
     "Jangan Mengingatnya"},
    // ここ一年の話

    {"\x82\xb1\x82\xb1\x88\xea\x94\x4e\x82\xcc\x98\x62", "Cerita Setahun"},

    // 有里栖の食レポブログ
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xcc\x90\x48\x83\x8c\x83\x7c\x83\x75\x83\x8d"
     "\x83\x4f",
     "Izin Penggunaan VR"},
    // 二重人格なのかな？
    {"\x93\xf1\x8f\x64\x90\x6c\x8a\x69\x82\xc8\x82\xcc\x82\xa9\x82\xc8\x81\x48",
     "Jika Bisa Bertemu ALICE"},
    // 曖昧な記憶

    {"\x9e\x42\x96\x86\x82\xc8\x8b\x4c\x89\xaf", "Memori Kabur"},

    // 夢の中の少年と少女
    {"\x96\xb2\x82\xcc\x92\x86\x82\xcc\x8f\xad\x94\x4e\x82\xc6\x8f\xad\x8f\x97",
     "Alice dan ALICE"},
    // ひとり水鏡湖へ

    {"\x82\xd0\x82\xc6\x82\xe8\x90\x85\x8b\xbe\x8c\xce\x82\xd6",
     "Ke Danau Suikyo"},

    // 似ている景色
    {"\x8e\x97\x82\xc4\x82\xa2\x82\xe9\x8c\x69\x90\x46",
     "Kencan di Taman Hiburan Sekali Lagi"},
    // 有里栖と巡る島
    {"\x97\x4c\x97\xa2\x90\xb2\x82\xc6\x8f\x84\x82\xe9\x93\x87",
     "Hari-hari yang Dihabiskan Bersamanya"},
    // 初めて会った場所は？
    {"\x8f\x89\x82\xdf\x82\xc4\x89\xef\x82\xc1\x82\xbd\x8f\xea\x8f\x8a\x82\xcd"
     "\x81\x48",
     "Arisu dan Maipan"},
    // 思い出探しをしよう
    {"\x8e\x76\x82\xa2\x8f\x6f\x92\x54\x82\xb5\x82\xf0\x82\xb5\x82\xe6\x82\xa4",
     "Arisu yang Satunya Lagi?"},
    // 病み上がりの有里栖
    {"\x95\x61\x82\xdd\x8f\xe3\x82\xaa\x82\xe8\x82\xcc\x97\x4c\x97\xa2\x90\xb2",
     "Kebaikan SSR"},
    // メイドさんの対応
    {"\x83\x81\x83\x43\x83\x68\x82\xb3\x82\xf1\x82\xcc\x91\xce\x89\x9e",
     "Posisi Tahi Lalat!?"},
    // 欠席の彼女
    {"\x8c\x87\x90\xc8\x82\xcc\x94\xde\x8f\x97",
     "Dengan Alasan Kegiatan Individu"},
    // 気になった別れ際
    {"\x8b\x43\x82\xc9\x82\xc8\x82\xc1\x82\xbd\x95\xca\x82\xea\x8d\xdb",
     "Ingatan Seseorang di Suatu Waktu"},
    // 季節外れの雪
    {"\x8b\x47\x90\xdf\x8a\x4f\x82\xea\x82\xcc\x90\xe1",
     "Meredakan Kecemasan di Kuil"},
    // 鏡の中の涙？
    {"\x8b\xbe\x82\xcc\x92\x86\x82\xcc\x97\xdc\x81\x48",
     "Janji untuk Esok Hari"},
    // 懐かしい記憶
    {"\x89\xf9\x82\xa9\x82\xb5\x82\xa2\x8b\x4c\x89\xaf", "Salju dan Piano"},
    // 巨神を駆逐する
    {"\x8b\x90\x90\x5f\x82\xf0\x8b\xec\x92\x80\x82\xb7\x82\xe9",
     "Seperti Bukan Diriku Sendiri"},
    // 差し入れは二乃の弁当
    {"\x8d\xb7\x82\xb5\x93\xfc\x82\xea\x82\xcd\x93\xf1\x94\x54\x82\xcc\x95\xd9"
     "\x93\x96",
     "Jagalah Juga Keluargamu"},
    // エンタメのお仕事
    {"\x83\x47\x83\x93\x83\x5e\x83\x81\x82\xcc\x82\xa8\x8e\x64\x8e\x96",
     "Cerita Tentang Salju yang Kudengar dari Si Kakek"},
    // 数学はマストです
    {"\x90\x94\x8a\x77\x82\xcd\x83\x7d\x83\x58\x83\x67\x82\xc5\x82\xb7",
     "Tatapan Alice"},
    // 親子三人で

    {"\x90\x65\x8e\x71\x8e\x4f\x90\x6c\x82\xc5", "Bertiga Fam"},

    // 鷺澤会長と娘
    {"\x8d\xeb\xe0\x56\x89\xef\x92\xb7\x82\xc6\x96\xba",
     "Rasanya Seperti Melihat Mimpi Orang Lain"},
    // いざ初バイトへ
    {"\x82\xa2\x82\xb4\x8f\x89\x83\x6f\x83\x43\x83\x67\x82\xd6",
     "Melihat Mimpi yang Sama dengan Arisu Sekali Lagi"},
    // 揺れる裾に釘付け
    {"\x97\x68\x82\xea\x82\xe9\x90\x9e\x82\xc9\x93\x42\x95\x74\x82\xaf",
     "Cerita Tentang Setahun Terakhir Ini"},
    // バイトどうしよ
    {"\x83\x6f\x83\x43\x83\x67\x82\xc7\x82\xa4\x82\xb5\x82\xe6",
     "Blog Ulasan Makanan Arisu"},
    // 一登さんご指名です
    {"\x88\xea\x93\x6f\x82\xb3\x82\xf1\x82\xb2\x8e\x77\x96\xbc\x82\xc5\x82\xb7",
     "Apakah Ini Kepribadian Ganda?"},
    // 雨は嫌いじゃないけど
    {"\x89\x4a\x82\xcd\x8c\x99\x82\xa2\x82\xb6\x82\xe1\x82\xc8\x82\xa2\x82\xaf"
     "\x82\xc7",
     "Ingatan yang Samar"},
    // 名探偵の名推理
    {"\x96\xbc\x92\x54\x92\xe3\x82\xcc\x96\xbc\x90\x84\x97\x9d",
     "Anak Laki-laki dan Perempuan di Dalam Mimpi"},
    // いろいろな親子関係
    {"\x82\xa2\x82\xeb\x82\xa2\x82\xeb\x82\xc8\x90\x65\x8e\x71\x8a\xd6\x8c\x57",
     "Pergi Sendirian ke Danau Mizukagami"},
    // 両親の帰宅予告
    {"\x97\xbc\x90\x65\x82\xcc\x8b\x41\x91\xee\x97\x5c\x8d\x90",
     "Pemandangan yang Mirip"},
    // 将来は財閥を？
    {"\x8f\xab\x97\x88\x82\xcd\x8d\xe0\x94\xb4\x82\xf0\x81\x48",
     "Menjelajahi Pulau Bersama Arisu"},
    // 泉先生へのオススメ
    {"\x90\xf2\x90\xe6\x90\xb6\x82\xd6\x82\xcc\x83\x49\x83\x58\x83\x58\x83\x81",
     "Di Mana Tempat Pertama Kali Kita Bertemu?"},
    // なんだか普段と違う朝
    {"\x82\xc8\x82\xf1\x82\xbe\x82\xa9\x95\x81\x92\x69\x82\xc6\x88\xe1\x82\xa4"
     "\x92\xa9",
     "Mari Mencari Kenangan"},
    // 知らない呼び方
    {"\x92\x6d\x82\xe7\x82\xc8\x82\xa2\x8c\xc4\x82\xd1\x95\xfb",
     "Arisu yang Baru Sembuh dari Sakit"},
    // データが違います。正しくインストールしてください。
    {"\x83\x66\x81\x5b\x83\x5e\x82\xaa\x88\xe1\x82\xa2\x82\xdc\x82\xb7\x81\x42"
     "\x90\xb3\x82\xb5\x82\xad\x83\x43\x83\x93\x83\x58\x83\x67\x81\x5b\x83\x8b"
     "\x82\xb5\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2\x81\x42",
     "Pelayanan dari Pelayan"},
    // MESファイルを更新してください
    {"\x4d\x45\x53\x83\x74\x83\x40\x83\x43\x83\x8b\x82\xf0\x8d\x58\x90\x56\x82"
     "\xb5\x82\xc4\x82\xad\x82\xbe\x82\xb3\x82\xa2",
     "Dirinya yang Tidak Hadir"},
    // MESファイルバッファがとれません
    {"\x4d\x45\x53\x83\x74\x83\x40\x83\x43\x83\x8b\x83\x6f\x83\x62\x83\x74\x83"
     "\x40\x82\xaa\x82\xc6\x82\xea\x82\xdc\x82\xb9\x82\xf1",
     "Momen Perpisahan yang Mengganjal di Hati"},
    // ラベルが見つかりません
    {"\x83\x89\x83\x78\x83\x8b\x82\xaa\x8c\xa9\x82\xc2\x82\xa9\x82\xe8\x82\xdc"
     "\x82\xb9\x82\xf1",
     "Salju yang Turun di Luar Musimnya"},
    // インデックス数 flaied
    {"\x83\x43\x83\x93\x83\x66\x83\x62\x83\x4e\x83\x58\x90\x94\x20\x66\x6c\x61"
     "\x69\x65\x64",
     "Air Mata di Dalam Cermin?"},
    // Direct3Dの初期化に失敗しました
    {"\x44\x69\x72\x65\x63\x74\x33\x44\x82\xcc\x8f\x89\x8a\xfa\x89\xbb\x82\xc9"
     "\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Kenangan yang Nostalgia"},
    // セカンダリバッファの作成に失敗しました
    {"\x83\x5a\x83\x4a\x83\x93\x83\x5f\x83\x8a\x83\x6f\x83\x62\x83\x74\x83\x40"
     "\x82\xcc\x8d\xec\x90\xac\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5"
     "\x82\xbd",
     "Membasmi Raksasa"},
    // dataチャンクが存在しません
    {"\x64\x61\x74\x61\x83\x60\x83\x83\x83\x93\x83\x4e\x82\xaa\x91\xb6\x8d\xdd"
     "\x82\xb5\x82\xdc\x82\xb9\x82\xf1",
     "Makan Malamnya Adalah Bekal dari Nino"},
    // WAVEFORMATEXE情報の取得に失敗しました
    {"\x57\x41\x56\x45\x46\x4f\x52\x4d\x41\x54\x45\x58\x45\x8f\xee\x95\xf1\x82"
     "\xcc\x8e\xe6\x93\xbe\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82"
     "\xbd",
     "Pekerjaan di Bidang Hiburan"},
    // fmtチャンクが存在しません
    {"\x66\x6d\x74\x83\x60\x83\x83\x83\x93\x83\x4e\x82\xaa\x91\xb6\x8d\xdd\x82"
     "\xb5\x82\xdc\x82\xb9\x82\xf1",
     "Matematika Itu Wajib"},
    // ではありません
    {"\x82\xc5\x82\xcd\x82\xa0\x82\xe8\x82\xdc\x82\xb9\x82\xf1",
     "Bertiga Sebagai Orang Tua dan Anak"},
    // FONT:テキストテクスチャロック失敗
    {"\x46\x4f\x4e\x54\x3a\x83\x65\x83\x4c\x83\x58\x83\x67\x83\x65\x83\x4e\x83"
     "\x58\x83\x60\x83\x83\x83\x8d\x83\x62\x83\x4e\x8e\xb8\x94\x73",
     "Ketua Sagisawa dan Putrinya"},
    // HTTPまたはHTTPSでもないです
    {"\x48\x54\x54\x50\x82\xdc\x82\xbd\x82\xcd\x48\x54\x54\x50\x53\x82\xc5\x82"
     "\xe0\x82\xc8\x82\xa2\x82\xc5\x82\xb7",
     "Mari Menuju Kerja Sambilan Pertama"},
    // HTTPファイル読み込みに失敗しました
    {"\x48\x54\x54\x50\x83\x74\x83\x40\x83\x43\x83\x8b\x93\xc7\x82\xdd\x8d\x9e"
     "\x82\xdd\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Terpaku pada Ujung Baju yang Goyang"},
    // ステータスコードが成功でないです
    {"\x83\x58\x83\x65\x81\x5b\x83\x5e\x83\x58\x83\x52\x81\x5b\x83\x68\x82\xaa"
     "\x90\xac\x8c\xf7\x82\xc5\x82\xc8\x82\xa2\x82\xc5\x82\xb7",
     "Bagaimana dengan Kerja Sambilan, ya"},
    // ステータスコードの取得に失敗しました
    {"\x83\x58\x83\x65\x81\x5b\x83\x5e\x83\x58\x83\x52\x81\x5b\x83\x68\x82\xcc"
     "\x8e\xe6\x93\xbe\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Ada Permintaan Khusus untuk Ichito-san"},
    // HTTP要求送信に失敗しました
    {"\x48\x54\x54\x50\x97\x76\x8b\x81\x91\x97\x90\x4d\x82\xc9\x8e\xb8\x94\x73"
     "\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Aku Tidak Benci Hujan, Tapi..."},
    // HTTPリクエストに失敗しました
    {"\x48\x54\x54\x50\x83\x8a\x83\x4e\x83\x47\x83\x58\x83\x67\x82\xc9\x8e\xb8"
     "\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Deduksi Hebat dari Detektif Ternama"},
    // HTTP接続に失敗しました
    {"\x48\x54\x54\x50\x90\xda\x91\xb1\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc"
     "\x82\xb5\x82\xbd",
     "Berbagai Macam Hubungan Orang Tua dan Anak"},
    // WinInetの初期化に失敗しました
    {"\x57\x69\x6e\x49\x6e\x65\x74\x82\xcc\x8f\x89\x8a\xfa\x89\xbb\x82\xc9\x8e"
     "\xb8\x94\x73\x82\xb5\x82\xdc\x82\xb5\x82\xbd",
     "Pemberitahuan Kepulangan Orang Tua"},
    // URL解析に失敗しました
    {"\x55\x52\x4c\x89\xf0\x90\xcd\x82\xc9\x8e\xb8\x94\x73\x82\xb5\x82\xdc\x82"
     "\xb5\x82\xbd",
     "Apa Nanti Akan Mengurus Konglomerat?"},
    // URLが不正です
    {"\x55\x52\x4c\x82\xaa\x95\x73\x90\xb3\x82\xc5\x82\xb7",
     "Rekomendasi untuk Ibu Guru Izumi"},
    // コメントの文字数が多い
    {"\x83\x52\x83\x81\x83\x93\x83\x67\x82\xcc\x95\xb6\x8e\x9a\x90\x94\x82\xaa"
     "\x91\xbd\x82\xa2",
     "Pagi yang Entah Mengapa Terasa Berbeda dari Biasanya"},

    {nullptr, nullptr} // End marker
};

// Load UI translation table from language-specific JSON (with legacy fallback).
// JSON format: [{"japanese": "...", "translated": "..."}]
// The "japanese" field is UTF-8 text (will be converted to SJIS);
// Falls back to built-in DC4 data if file is missing.
static void LoadUiTranslations() {
  g_uiTranslations.clear();

  bool usedFallbackFile = false;
  std::string src = ReadFileToString(g_uiJsonPath.c_str());
  if (src.empty() && g_uiJsonFallbackPath != g_uiJsonPath) {
    src = ReadFileToString(g_uiJsonFallbackPath.c_str());
    usedFallbackFile = !src.empty();
  }
  if (!src.empty()) {
    auto objs = ParseJsonArray(src);
    for (auto &o : objs) {
      auto itJ = o.fields.find("japanese");
      auto itT = o.fields.find("translated");
      if (itJ != o.fields.end() && itT != o.fields.end()) {
        UITranslationEntry e;
        e.japaneseSjis = Utf8ToSjis(itJ->second);
        e.translated   = itT->second;
        if (!e.japaneseSjis.empty() && !e.translated.empty())
          g_uiTranslations.push_back(std::move(e));
      }
    }
    char msg[128];
    sprintf_s(msg, "DCPatch: Loaded %zu UI translations from configured JSON\n",
              g_uiTranslations.size());
    OutputDebugStringA(msg);
    std::string pathUtf8 = usedFallbackFile ? WideToUtf8(g_uiJsonFallbackPath)
                                            : WideToUtf8(g_uiJsonPath);
    if (!pathUtf8.empty()) {
      std::string pathMsg = "DCPatch: UI JSON path = " + pathUtf8 + "\n";
      OutputDebugStringA(pathMsg.c_str());
    }
    if (!g_uiTranslations.empty()) return;
  }

  // Fallback: built-in DC4 Indonesian UI table only for Indonesian mode.
  // For English mode, we intentionally avoid Indonesian hardcoded fallback.
  if (g_activeJsonLanguage == 1) {
    OutputDebugStringA("DCPatch: Using built-in UI translation table (Indonesian fallback)\n");
    for (int i = 0; k_dc4BuiltinUI[i].japanese; i++) {
      UITranslationEntry e;
      e.japanese_literal    = k_dc4BuiltinUI[i].japanese;
      e.translated_literal  = k_dc4BuiltinUI[i].indonesian;
      e.japaneseSjis        = k_dc4BuiltinUI[i].japanese;
      e.translated          = k_dc4BuiltinUI[i].indonesian;
      g_uiTranslations.push_back(std::move(e));
    }
  } else {
    OutputDebugStringA("DCPatch: No UI JSON loaded; built-in UI fallback disabled for this language\n");
  }
}

// Write a default UI JSON at the active language path.
// Indonesian mode writes built-in entries; other modes write a template file.
static void WriteDefaultUiJson() {
  if (GetFileAttributesW(g_uiJsonPath.c_str()) != INVALID_FILE_ATTRIBUTES)
    return;
  HANDLE h = CreateFileW(g_uiJsonPath.c_str(), GENERIC_WRITE, 0, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  // Write UTF-8 BOM so Notepad etc. shows the content correctly
  const char bom[] = "\xEF\xBB\xBF";
  DWORD w;
  WriteFile(h, bom, 3, &w, NULL);

  std::string out;
  if (g_activeJsonLanguage == 1) {
    out = "[\n  {\"_comment\": \"UI string map for DC4 Indonesian mode. japanese = original Japanese text (UTF-8), translated = replacement.\"},\n";
    for (int i = 0; k_dc4BuiltinUI[i].japanese; i++) {
      // Convert SJIS to UTF-8 for readability
      std::string sjis = k_dc4BuiltinUI[i].japanese;
      std::wstring wide;
      int wn = MultiByteToWideChar(932, 0, sjis.c_str(), -1, nullptr, 0);
      if (wn > 0) {
        wide.resize(wn - 1);
        MultiByteToWideChar(932, 0, sjis.c_str(), -1, &wide[0], wn);
      }
      std::string jpUtf8;
      if (!wide.empty()) {
        int un = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (un > 0) {
          jpUtf8.resize(un - 1);
          WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &jpUtf8[0], un, nullptr, nullptr);
        }
      }
      // Escape quotes in japanese string for JSON safety
      std::string jpEscaped, trEscaped;
      for (char c : jpUtf8)  { if (c == '"') jpEscaped += '\\'; jpEscaped += c; }
      for (char c : std::string(k_dc4BuiltinUI[i].indonesian)) { if (c == '"') trEscaped += '\\'; trEscaped += c; }
      out += "  {\"japanese\": \"";
      out += jpEscaped;
      out += "\", \"translated\": \"";
      out += trEscaped;
      out += "\"}";
      if (k_dc4BuiltinUI[i + 1].japanese) out += ",";
      out += "\n";
    }
    out += "]\n";
  } else if (g_activeJsonLanguage == 2) {
    out =
        "[\n"
        "  {\"_comment\": \"UI string map for English mode. Add entries as {\\\"japanese\\\":\\\"...\\\",\\\"translated\\\":\\\"...\\\"}.\"},\n"
        "  {\"japanese\": \"\", \"translated\": \"\"}\n"
        "]\n";
  } else {
    out =
        "[\n"
        "  {\"_comment\": \"UI string map. Add entries as {\\\"japanese\\\":\\\"...\\\",\\\"translated\\\":\\\"...\\\"}.\"},\n"
        "  {\"japanese\": \"\", \"translated\": \"\"}\n"
        "]\n";
  }
  WriteFile(h, out.c_str(), (DWORD)out.size(), &w, NULL);
  CloseHandle(h);
}
// Translate a SJIS string if it matches a known entry (exact match)
static const char *TranslateUI(const char *sjisText) {
  if (!sjisText)
    return nullptr;
  if (g_fontManager.GetLanguage() == 0)
    return nullptr;
  for (const auto &e : g_uiTranslations) {
    if (e.japaneseSjis == sjisText)
      return e.translated.c_str();
  }
  return nullptr;
}

// Check if a string contains a SJIS substring and return the translation
static const char *TranslateUIPartial(const char *sjisText) {
  if (!sjisText)
    return nullptr;
  if (g_fontManager.GetLanguage() == 0)
    return nullptr;
  for (const auto &e : g_uiTranslations) {
    if (strstr(sjisText, e.japaneseSjis.c_str()) != nullptr)
      return e.translated.c_str();
  }
  return nullptr;
}

// ============================================================================
// Memory String Patcher - patches strings directly in the loaded EXE image
// ============================================================================
// Scans .rdata and .data sections and replaces Japanese strings with
// Indonesian translations in-place. Only patches where the translation
// fits within the original string's byte space.

static void PatchStringsInMemory() {
  if (g_fontManager.GetLanguage() == 0)
    return;

  HMODULE hExe = GetModuleHandleA(NULL);
  if (!hExe)
    return;

  BYTE *base = (BYTE *)hExe;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return;

  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  int numSections = nt->FileHeader.NumberOfSections;

  // Make all target sections writable first
  DWORD oldProtects[32] = {};
  for (int s = 0; s < numSections && s < 32; s++) {
    char secName[9] = {};
    memcpy(secName, sec[s].Name, 8);
    if (strcmp(secName, ".rdata") != 0 && strcmp(secName, ".data") != 0 &&
        strcmp(secName, ".text") != 0)
      continue;
    BYTE *secStart = base + sec[s].VirtualAddress;
    DWORD secSize = sec[s].Misc.VirtualSize;
    VirtualProtect(secStart, secSize, PAGE_READWRITE, &oldProtects[s]);
  }

  for (const auto &entry : g_uiTranslations) {
    const char *jp = entry.japaneseSjis.c_str();
    const char *id = entry.translated.c_str();
    int jpLen = (int)entry.japaneseSjis.size();
    int idLen = (int)entry.translated.size();

    if (idLen <= jpLen) {
      // === PASS 1: In-place replacement (translation fits) ===
      for (int s = 0; s < numSections; s++) {
        char secName[9] = {};
        memcpy(secName, sec[s].Name, 8);
        if (strcmp(secName, ".rdata") != 0 && strcmp(secName, ".data") != 0)
          continue;

        BYTE *secStart = base + sec[s].VirtualAddress;
        DWORD secSize = sec[s].Misc.VirtualSize;

        for (DWORD offset = 0; offset + jpLen <= secSize; offset++) {
          if (memcmp(secStart + offset, jp, jpLen) == 0) {
            if (secStart[offset + jpLen] != 0)
              continue;
            memcpy(secStart + offset, id, idLen);
            memset(secStart + offset + idLen, 0, jpLen - idLen + 1);
          }
        }
      }
    } else {
      // === PASS 2: Pointer redirection (translation too long) ===
      // 1. Find address of the SJIS string in the EXE's data sections
      BYTE *strAddr = nullptr;
      for (int s = 0; s < numSections && !strAddr; s++) {
        char secName[9] = {};
        memcpy(secName, sec[s].Name, 8);
        if (strcmp(secName, ".rdata") != 0 && strcmp(secName, ".data") != 0)
          continue;

        BYTE *secStart = base + sec[s].VirtualAddress;
        DWORD secSize = sec[s].Misc.VirtualSize;

        for (DWORD offset = 0; offset + jpLen <= secSize; offset++) {
          if (memcmp(secStart + offset, jp, jpLen) == 0) {
            if (secStart[offset + jpLen] != 0)
              continue;
            strAddr = secStart + offset;
            break;
          }
        }
      }

      if (!strAddr)
        continue;

      // 2. Allocate persistent memory for the longer Indonesian string
      char *newStr = (char *)VirtualAlloc(
          NULL, idLen + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      if (!newStr)
        continue;
      memcpy(newStr, id, idLen + 1);

      // 3. Scan ALL sections for pointers (4-byte values) to the original
      // string
      //    and redirect them to our new string
      DWORD oldAddr = (DWORD)(uintptr_t)strAddr;
      DWORD newAddr = (DWORD)(uintptr_t)newStr;

      for (int s = 0; s < numSections; s++) {
        char secName[9] = {};
        memcpy(secName, sec[s].Name, 8);
        // Scan .rdata, .data, and .text for pointer references
        if (strcmp(secName, ".rdata") != 0 && strcmp(secName, ".data") != 0 &&
            strcmp(secName, ".text") != 0)
          continue;

        BYTE *secStart = base + sec[s].VirtualAddress;
        DWORD secSize = sec[s].Misc.VirtualSize;

        // Scan for 4-byte pointer values matching the original string address
        for (DWORD offset = 0; offset + 4 <= secSize; offset++) {
          DWORD val;
          memcpy(&val, secStart + offset, 4);
          if (val == oldAddr) {
            memcpy(secStart + offset, &newAddr, 4);
          }
        }
      }
    }
  }

  // Restore original protections
  for (int s = 0; s < numSections && s < 32; s++) {
    if (oldProtects[s] == 0)
      continue;
    char secName[9] = {};
    memcpy(secName, sec[s].Name, 8);
    if (strcmp(secName, ".rdata") != 0 && strcmp(secName, ".data") != 0 &&
        strcmp(secName, ".text") != 0)
      continue;
    BYTE *secStart = base + sec[s].VirtualAddress;
    DWORD secSize = sec[s].Misc.VirtualSize;
    VirtualProtect(secStart, secSize, oldProtects[s], &oldProtects[s]);
  }
}

// Hook GetTextMetricsA to reduce line height in backlog
// This is the KEY hook for line spacing - the game uses tmHeight for line
// spacing
static BOOL WINAPI Hook_GetTextMetricsA(HDC hdc, LPTEXTMETRICA lptm) {
  BOOL res = Real_GetTextMetricsA(hdc, lptm);
  if (res && g_inBacklogRender) {
    int spacing = g_fontManager.GetBacklogLineSpacing();
    lptm->tmHeight += spacing;
    lptm->tmAscent += spacing;
  }
  return res;
}

// Translate full-width punctuation, letters, and numbers into their 1-byte ASCII equivalents
static const char* FilterSjisString(LPCSTR lpString, UINT* c_inout, bool performTranslation = true) {
  if (!lpString || *c_inout == 0)
    return lpString;

  static thread_local char s_buffer[1024]; // Safe upper bound for text out calls
  UINT len = *c_inout;
  if (len >= sizeof(s_buffer)) {
    len = sizeof(s_buffer) - 1; // Truncate safely
  }

  bool modified = false;
  UINT outLen = 0;
  for (UINT i = 0; i < len; i++) {
    unsigned char ch1 = (unsigned char)lpString[i];
    
    // Check for double-byte Shift-JIS characters
    if ((ch1 >= 0x81 && ch1 <= 0x9F) || (ch1 >= 0xE0 && ch1 <= 0xFC)) {
      if (i + 1 < len) {
        unsigned char ch2 = (unsigned char)lpString[i + 1];
        char replacement = 0;
        
        if (performTranslation) {
          if (ch1 == 0x81) {
            switch (ch2) {
              case 0x40: replacement = ' '; break; // Full space
            case 0x41: replacement = ','; break; // 、
            case 0x42: replacement = '.'; break; // 。
            case 0x43: replacement = ','; break; // ，
            case 0x44: replacement = '.'; break; // ．
            case 0x45: replacement = ' '; break; // ・
            case 0x46: replacement = ':'; break; // ：
            case 0x47: replacement = ';'; break; // ；
            case 0x48: replacement = '?'; break; // ？
            case 0x49: replacement = '!'; break; // ！
            case 0x5B: replacement = '-'; break; // ー
            case 0x5C: replacement = '-'; break; // ―
            case 0x5D: replacement = '-'; break; // ‐
            case 0x5E: replacement = '/'; break; // ／
            case 0x5F: replacement = '\\'; break;// ＼
            case 0x60: replacement = '~'; break; // ～
            case 0x61: replacement = '|'; break; // ∥
            case 0x62: replacement = '|'; break; // ｜
            case 0x65: replacement = '\''; break;// ‘
            case 0x66: replacement = '\''; break;// ’
            case 0x67: replacement = '\"'; break;// “
            case 0x68: replacement = '\"'; break;// ”
            case 0x69: replacement = '('; break; // （
            case 0x6A: replacement = ')'; break; // ）
            case 0x6D: replacement = '['; break; // ［
            case 0x6E: replacement = ']'; break; // ］
            case 0x6F: replacement = '{'; break; // ｛
            case 0x70: replacement = '}'; break; // ｝
            case 0x7B: replacement = '+'; break; // ＋
            case 0x7C: replacement = '-'; break; // －
            case 0x81: replacement = '='; break; // ＝
            case 0x83: replacement = '<'; break; // ＜
            case 0x84: replacement = '>'; break; // ＞
            case 0x93: replacement = '%'; break; // ％
            case 0x94: replacement = '#'; break; // ＃
            case 0x95: replacement = '&'; break; // ＆
            case 0x96: replacement = '*'; break; // ＊
            case 0x97: replacement = '@'; break; // ＠
          }
        } else if (ch1 == 0x82) {
          if (ch2 >= 0x4F && ch2 <= 0x58) { // ０-９
            replacement = '0' + (ch2 - 0x4F);
          } else if (ch2 >= 0x60 && ch2 <= 0x79) { // Ａ-Ｚ
            replacement = 'A' + (ch2 - 0x60);
          } else if (ch2 >= 0x81 && ch2 <= 0x9A) { // ａ-ｚ
            replacement = 'a' + (ch2 - 0x81);
          }
        }
        }
        
        if (replacement != 0) {
          s_buffer[outLen++] = replacement;
          modified = true;
          i++; // Skip the second byte
          continue;
        }
        
        // No translation found, copy the full 2-byte char as-is
        s_buffer[outLen++] = lpString[i];
        s_buffer[outLen++] = lpString[i + 1];
        i++;
      } else {
        // Truncated multi-byte
        s_buffer[outLen++] = lpString[i];
      }
      continue;
    }
    
    // Single byte checks
    if (ch1 == 0xA5) { // Katakana middle dot (our custom space placeholder)
      s_buffer[outLen++] = 0x20;  // Replace with ASCII space
      modified = true;
    } else {
      s_buffer[outLen++] = lpString[i];
    }
  }

  if (modified) {
    s_buffer[outLen] = '\0';
    *c_inout = outLen;
    return s_buffer;
  }
  return lpString; // Return original if no changes needed
}

static bool IsUiElement(LPCSTR str, UINT c) {
  if (!str || c == 0)
    return false;

  // Ensure null termination for safe strstr scanning if it's not already null-terminated
  static thread_local char s_ui_buffer[1024];
  UINT len = (c >= sizeof(s_ui_buffer)) ? sizeof(s_ui_buffer) - 1 : c;
  memcpy(s_ui_buffer, str, len);
  s_ui_buffer[len] = '\0';

  const char *ui_elements[] = {"Scene Jump",
                               "Putar Suara",
                               "Kembali",
                               "Aktifkan Thumbnail",
                               "シーンジャンプ",
                               "音声再生",
                               "戻る",
                               "サムネイル有効",
                               "LOG",
                               "Log",
                               "log"};
  for (const auto &elem : ui_elements) {
    if (strstr(s_ui_buffer, elem) != nullptr) {
      return true;
    }
  }
  return false;
}

// Hook ExtTextOutA - UI Text Rendering (e.g. Character Names in Backlog)
static BOOL WINAPI Hook_ExtTextOutA(HDC hdc, int x, int y, UINT options,
                                    const RECT *lprect, LPCSTR lpString, UINT c,
                                    const INT *lpDx) {

  UINT originalC = c;
  int actualLen = lstrlenA(lpString);
  if (c > 0 && actualLen > c && actualLen < c + 150) {
    c = actualLen;
  }

  UINT renderLen = c;
  bool performTranslation = !(g_inBacklogRender && g_fontManager.GetDisableBacklogTranslation());
  LPCSTR renderStr = FilterSjisString(lpString, &renderLen, performTranslation);

  static thread_local HDC s_lastHdc_ExtTextOut = NULL;
  static thread_local HFONT s_lastBgFont_ExtTextOut = NULL;
  static thread_local int s_lastTmHeight_ExtTextOut = 0;
  
  HFONT currFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
  if (hdc != s_lastHdc_ExtTextOut || currFont != s_lastBgFont_ExtTextOut || s_lastHdc_ExtTextOut == NULL) {
    TEXTMETRICA tm;
    Real_GetTextMetricsA(hdc, &tm);
    s_lastTmHeight_ExtTextOut = tm.tmHeight;
    s_lastHdc_ExtTextOut = hdc;
    s_lastBgFont_ExtTextOut = currFont;
  }

  bool isName = !IsUiElement(renderStr, renderLen);
  if (g_inBacklogRender && !IsUiElement(lpString, c)) {
    isName = (s_lastTmHeight_ExtTextOut <= 18);
  }

  int nameSpacing = isName ? g_fontManager.GetBacklogNameSpacing() : 0;
  
  if (g_inBacklogRender && g_fontManager.GetDisableBacklogSpacing()) {
    nameSpacing = 0; // Skip character spacing
  }

  HFONT customFont = NULL;
  HFONT oldFont = NULL;

  bool hasCustomFont = false;
  if (isName) {
    hasCustomFont = ((g_fontManager.GetBacklogNameFontSize() != 0) ||
                     (g_fontManager.GetBacklogNameFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogNameFontName() != L"ＭＳ ゴシック") ||
                     (nameSpacing != 0));
  } else if (g_inBacklogRender) {
    hasCustomFont = ((g_fontManager.GetBacklogFontSize() != 0) ||
                     (g_fontManager.GetBacklogFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogFontName() != L"ＭＳ ゴシック"));
  }

  if (g_inBacklogRender && g_fontManager.GetDisableBacklogFont()) {
    hasCustomFont = false;
  }

  if (hasCustomFont) {
    if (isName) {
      customFont = g_fontManager.GetBacklogNameFont(s_lastTmHeight_ExtTextOut);
    } else {
      customFont = g_fontManager.GetBacklogFont(s_lastTmHeight_ExtTextOut);
    }
    oldFont = (HFONT)SelectObject(hdc, customFont);
  }

  int renderY = y;
  if (!g_fontManager.GetDisableBacklogSpacing()) {
    if (hasCustomFont) {
      if (isName) {
        renderY += g_fontManager.GetBacklogNameYOffset();
      }
    }
  }

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, nameSpacing);
  }

  if (g_inBacklogRender && !isName) {
    // Enable opaque background for Dialog Text to fill the spaced gaps
    SetBkMode(hdc, OPAQUE);
    // Dark transparent-like blue matching the BKLOGCHIP theme (RGB(0, 140,
    // 255))
    SetBkColor(hdc, RGB(0, 140, 255));
  } else {
    // Names and normal text remain transparent
    SetBkMode(hdc, TRANSPARENT);
  }

  BOOL result = Real_ExtTextOutA(hdc, x, renderY, options, lprect, renderStr,
                                 renderLen, lpDx);

  SetBkMode(hdc, TRANSPARENT);

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, 0); // Restore
  }

  if (oldFont) {
    SelectObject(hdc, oldFont);
  }

  return result;
}

static BOOL WINAPI Hook_GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c,
                                              LPSIZE lpSize) {
  int actualLen = lstrlenA(lpString);
  if (c > 0 && actualLen > c && actualLen < c + 150)
    c = actualLen;
  
  UINT filteredLen = c;
  bool performTranslation = !(g_inBacklogRender && g_fontManager.GetDisableBacklogTranslation());
  lpString = FilterSjisString(lpString, &filteredLen, performTranslation);
  c = filteredLen;

  static thread_local HDC s_lastHdc_GetTextExtent = NULL;
  static thread_local HFONT s_lastBgFont_GetTextExtent = NULL;
  static thread_local int s_lastTmHeight_GetTextExtent = 0;
  
  HFONT currFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
  if (hdc != s_lastHdc_GetTextExtent || currFont != s_lastBgFont_GetTextExtent || s_lastHdc_GetTextExtent == NULL) {
    TEXTMETRICA tm;
    Real_GetTextMetricsA(hdc, &tm);
    s_lastTmHeight_GetTextExtent = tm.tmHeight;
    s_lastHdc_GetTextExtent = hdc;
    s_lastBgFont_GetTextExtent = currFont;
  }

  bool isName = false;
  if (g_inBacklogRender && !IsUiElement(lpString, c)) {
    isName = (s_lastTmHeight_GetTextExtent <= 18);
  }

  int nameSpacing = isName ? g_fontManager.GetBacklogNameSpacing() : 0;
  if (g_inBacklogRender && g_fontManager.GetDisableBacklogSpacing()) {
    nameSpacing = 0;
  }

  HFONT customFont = NULL;
  HFONT oldFont = NULL;

  bool hasCustomFont = false;
  if (isName) {
    hasCustomFont = ((g_fontManager.GetBacklogNameFontSize() != 0) ||
                     (g_fontManager.GetBacklogNameFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogNameFontName() != L"ＭＳ ゴシック") ||
                     (nameSpacing != 0));
  } else if (g_inBacklogRender) {
    hasCustomFont = ((g_fontManager.GetBacklogFontSize() != 0) ||
                     (g_fontManager.GetBacklogFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogFontName() != L"ＭＳ ゴシック"));
  }

  if (g_inBacklogRender && g_fontManager.GetDisableBacklogFont()) {
    hasCustomFont = false;
  }

  if (hasCustomFont) {
    if (isName) {
      customFont = g_fontManager.GetBacklogNameFont(s_lastTmHeight_GetTextExtent);
    } else {
      customFont = g_fontManager.GetBacklogFont(s_lastTmHeight_GetTextExtent);
    }
    oldFont = (HFONT)SelectObject(hdc, customFont);
  }

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, nameSpacing);
  }

  BOOL result = Real_GetTextExtentPoint32A(hdc, lpString, c, lpSize);

  if (!g_fontManager.GetDisableBacklogSpacing()) {
    if (result && g_inBacklogRender && !isName) {
      lpSize->cy += g_fontManager.GetBacklogLineSpacing();
    }
  }

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, 0);
  }
  if (oldFont) {
    SelectObject(hdc, oldFont);
  }

  return result;
}

static BOOL WINAPI Hook_GetTextExtentPoint32W(HDC hdc, LPCWSTR lpString, int c,
                                              LPSIZE lpSize) {
  BOOL result = Real_GetTextExtentPoint32W(hdc, lpString, c, lpSize);
  return result;
}

// GetTextExtentExPoint Hooks
static decltype(&GetTextExtentExPointA) Real_GetTextExtentExPointA =
    GetTextExtentExPointA;
static decltype(&GetTextExtentExPointW) Real_GetTextExtentExPointW =
    GetTextExtentExPointW;

static BOOL WINAPI Hook_GetTextExtentExPointA(HDC hdc, LPCSTR lpszString,
                                              int cchString, int nMaxExtent,
                                              LPINT lpnFit, LPINT lpnDx,
                                              LPSIZE lpSize) {
  int actualLen = lstrlenA(lpszString);
  if (cchString > 0 && actualLen > cchString && actualLen < cchString + 150)
    cchString = actualLen;
  
  UINT filteredLen = cchString;
  bool performTranslation = !(g_inBacklogRender && g_fontManager.GetDisableBacklogTranslation());
  lpszString = FilterSjisString(lpszString, &filteredLen, performTranslation);
  cchString = filteredLen;

  static thread_local HDC s_lastHdc_GetTextExtentEx = NULL;
  static thread_local HFONT s_lastBgFont_GetTextExtentEx = NULL;
  static thread_local int s_lastTmHeight_GetTextExtentEx = 0;
  
  HFONT currFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
  if (hdc != s_lastHdc_GetTextExtentEx || currFont != s_lastBgFont_GetTextExtentEx || s_lastHdc_GetTextExtentEx == NULL) {
    TEXTMETRICA tm;
    Real_GetTextMetricsA(hdc, &tm);
    s_lastTmHeight_GetTextExtentEx = tm.tmHeight;
    s_lastHdc_GetTextExtentEx = hdc;
    s_lastBgFont_GetTextExtentEx = currFont;
  }

  bool isName = false;
  if (g_inBacklogRender && !IsUiElement(lpszString, cchString)) {
    isName = (s_lastTmHeight_GetTextExtentEx <= 18);
  }

  int nameSpacing = isName ? g_fontManager.GetBacklogNameSpacing() : 0;
  if (g_inBacklogRender && g_fontManager.GetDisableBacklogSpacing()) {
    nameSpacing = 0;
  }

  HFONT customFont = NULL;
  HFONT oldFont = NULL;

  bool hasCustomFont = false;
  if (isName) {
    hasCustomFont = ((g_fontManager.GetBacklogNameFontSize() != 0) ||
                     (g_fontManager.GetBacklogNameFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogNameFontName() != L"ＭＳ ゴシック") ||
                     (nameSpacing != 0));
  } else if (g_inBacklogRender) {
    hasCustomFont = ((g_fontManager.GetBacklogFontSize() != 0) ||
                     (g_fontManager.GetBacklogFontName() != L"MS Gothic" && 
                      g_fontManager.GetBacklogFontName() != L"ＭＳ ゴシック"));
  }

  if (g_inBacklogRender && g_fontManager.GetDisableBacklogFont()) {
    hasCustomFont = false;
  }

  if (hasCustomFont) {
    if (isName) {
      customFont = g_fontManager.GetBacklogNameFont(s_lastTmHeight_GetTextExtentEx);
    } else {
      customFont = g_fontManager.GetBacklogFont(s_lastTmHeight_GetTextExtentEx);
    }
    oldFont = (HFONT)SelectObject(hdc, customFont);
  }

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, nameSpacing);
  }

  BOOL result = Real_GetTextExtentExPointA(hdc, lpszString, cchString,
                                           nMaxExtent, lpnFit, lpnDx, lpSize);

  if (!g_fontManager.GetDisableBacklogSpacing()) {
    if (result && g_inBacklogRender && !isName && lpSize != NULL) {
      lpSize->cy += g_fontManager.GetBacklogLineSpacing();
    }
  }

  if (nameSpacing != 0) {
    SetTextCharacterExtra(hdc, 0);
  }
  if (oldFont) {
    SelectObject(hdc, oldFont);
  }
  return result;
}

static BOOL WINAPI Hook_GetTextExtentExPointW(HDC hdc, LPCWSTR lpszString,
                                              int cchString, int nMaxExtent,
                                              LPINT lpnFit, LPINT lpnDx,
                                              LPSIZE lpSize) {
  BOOL result = Real_GetTextExtentExPointW(hdc, lpszString, cchString,
                                           nMaxExtent, lpnFit, lpnDx, lpSize);
  return result;
}

// GetCharWidth32 Hooks
static decltype(&GetCharWidth32A) Real_GetCharWidth32A = GetCharWidth32A;
static decltype(&GetCharWidth32W) Real_GetCharWidth32W = GetCharWidth32W;

static BOOL WINAPI Hook_GetCharWidth32A(HDC hdc, UINT iFirst, UINT iLast,
                                        LPINT lpBuffer) {
  BOOL res = Real_GetCharWidth32A(hdc, iFirst, iLast, lpBuffer);
  return res;
}

static BOOL WINAPI Hook_GetCharWidth32W(HDC hdc, UINT iFirst, UINT iLast,
                                        LPINT lpBuffer) {
  BOOL res = Real_GetCharWidth32W(hdc, iFirst, iLast, lpBuffer);
  return res;
}

static DWORD WINAPI Hook_GetGlyphOutlineA(HDC hdc, UINT uChar, UINT fuFormat,
                                           LPGLYPHMETRICS lpgm, DWORD cjBuffer,
                                           LPVOID pvBuffer, const MAT2 *lpmat2) {
  if (uChar == 0xA5) {
    uChar = 0x20;
  }

  DWORD r = GDI_ERROR;

  static thread_local HDC s_lastHdc_GlyphOutline = NULL;
  static thread_local HFONT s_lastBgFont_GlyphOutline = NULL;
  static thread_local int s_lastTmHeight_GlyphOutline = 0;

  HFONT currFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
  if (hdc != s_lastHdc_GlyphOutline || currFont != s_lastBgFont_GlyphOutline || s_lastHdc_GlyphOutline == NULL) {
    TEXTMETRICA tm;
    if (Real_GetTextMetricsA(hdc, &tm)) {
      s_lastTmHeight_GlyphOutline = tm.tmHeight;
    } else {
      s_lastTmHeight_GlyphOutline = 0; // Fallback
    }
    s_lastHdc_GlyphOutline = hdc;
    s_lastBgFont_GlyphOutline = currFont;
  }

  bool isName = false;
  
  if (g_inBacklogRender && s_lastTmHeight_GlyphOutline > 0 && !g_fontManager.GetDisableBacklogFont()) {
    int fontSize = ScaleBacklogFontSize(s_lastTmHeight_GlyphOutline);
    isName = (s_lastTmHeight_GlyphOutline <= 18);
    
    HFONT f = NULL;
    if (isName) {
      f = g_fontManager.GetBacklogNameFont(fontSize);
    } else {
      f = g_fontManager.GetBacklogFont(fontSize);
    }

    if (f) {
      SelectObject(hdc, f); // Permanently mutate HDC for this loop
      r = Real_GetGlyphOutlineA(hdc, uChar, fuFormat, lpgm, cjBuffer, pvBuffer,
                                lpmat2);
    }
  }

  if (r == GDI_ERROR) {
    r = Real_GetGlyphOutlineA(hdc, uChar, fuFormat, lpgm, cjBuffer, pvBuffer,
                              lpmat2);
  }

  // WINE/PROTON SAFETY: If GetGlyphOutlineA still returns GDI_ERROR (e.g.,
  // because the font doesn't support the requested glyph, or Wine's GDI
  // implementation is incomplete), return a fallback glyph instead.
  // The game uses the return value as a buffer size and EDI as a destination
  // pointer. Returning GDI_ERROR (0xFFFFFFFF) causes the game to attempt
  // a write to address 0xFFFFFFFF → ACCESS_VIOLATION at 0x0045AE8C.
  // Returning 0 with an empty lpgm causes malloc(0) and deref of NULL -> ACCESS_VIOLATION at 0x0045AF4E.
  if (r == GDI_ERROR) {
    r = Real_GetGlyphOutlineA(hdc, '?', fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
    if (r == GDI_ERROR) {
      r = Real_GetGlyphOutlineA(hdc, ' ', fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
      if (r == GDI_ERROR) {
        if (lpgm) {
          memset(lpgm, 0, sizeof(GLYPHMETRICS));
          lpgm->gmCellIncX = s_lastTmHeight_GlyphOutline > 0 ? (s_lastTmHeight_GlyphOutline / 2) : 10;
        }
        return 0;
      }
    }
  }

  if (r != GDI_ERROR && lpgm && g_inBacklogRender && !g_fontManager.GetDisableBacklogSpacing()) {
    if (!isName) {
      lpgm->gmptGlyphOrigin.x += g_fontManager.GetBacklogXOffset();
      lpgm->gmptGlyphOrigin.y += g_fontManager.GetBacklogYOffset();


      lpgm->gmCellIncX += g_fontManager.GetBacklogDialogSpacing();
    } else {
      lpgm->gmptGlyphOrigin.x += g_fontManager.GetBacklogNameXOffset();
    }
  }

  return r;
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

  static thread_local bool s_inCreateFile = false;
  if (s_inCreateFile) {
    return Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
  }

  s_inCreateFile = true;

  int lang = g_fontManager.GetLanguage();
  if (lang == 1 || lang == 2) {
    std::string newPath = ReplacePathA(lpFileName);
    if (!newPath.empty()) {
      // Resolve to absolute path to avoid CWD-dependent resolution issues
      char absPath[MAX_PATH];
      DWORD absLen = GetFullPathNameA(newPath.c_str(), MAX_PATH, absPath, NULL);
      const char* finalPath = (absLen > 0 && absLen < MAX_PATH) ? absPath : newPath.c_str();

      HANDLE h = Real_CreateFileA(finalPath, dwDesiredAccess, dwShareMode,
                                  lpSecurityAttributes, dwCreationDisposition,
                                  dwFlagsAndAttributes, hTemplateFile);
      s_inCreateFile = false;
      return h;
    }
  }

  HANDLE h = Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                              lpSecurityAttributes, dwCreationDisposition,
                              dwFlagsAndAttributes, hTemplateFile);
  s_inCreateFile = false;
  return h;
}

// DVD check patch removed — handle via x32dbg if needed.
// (Users are expected to patch the EXE manually for their specific game.)


static int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,
                                   UINT uType) {
  // Translate Japanese text to Indonesian
  const char *translatedText = TranslateUI(lpText);
  const char *translatedCaption = TranslateUI(lpCaption);
  if (!translatedText)
    translatedText = TranslateUIPartial(lpText);
  if (!translatedCaption)
    translatedCaption = TranslateUIPartial(lpCaption);

  return Real_MessageBoxA(hWnd, translatedText ? translatedText : lpText,
                          translatedCaption ? translatedCaption : lpCaption,
                          uType);
}

// Menu hooks - translate Japanese menu item text to Indonesian
static BOOL WINAPI Hook_AppendMenuA(HMENU hMenu, UINT uFlags,
                                    UINT_PTR uIDNewItem, LPCSTR lpNewItem) {
  if (lpNewItem && !(uFlags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR))) {
    const char *translated = TranslateUI(lpNewItem);
    if (!translated)
      translated = TranslateUIPartial(lpNewItem);
    if (translated)
      return Real_AppendMenuA(hMenu, uFlags, uIDNewItem, translated);
  }
  return Real_AppendMenuA(hMenu, uFlags, uIDNewItem, lpNewItem);
}

static BOOL WINAPI Hook_InsertMenuA(HMENU hMenu, UINT uPosition, UINT uFlags,
                                    UINT_PTR uIDNewItem, LPCSTR lpNewItem) {
  if (lpNewItem && !(uFlags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR))) {
    const char *translated = TranslateUI(lpNewItem);
    if (!translated)
      translated = TranslateUIPartial(lpNewItem);
    if (translated)
      return Real_InsertMenuA(hMenu, uPosition, uFlags, uIDNewItem, translated);
  }
  return Real_InsertMenuA(hMenu, uPosition, uFlags, uIDNewItem, lpNewItem);
}

static BOOL WINAPI Hook_ModifyMenuA(HMENU hMenu, UINT uPosition, UINT uFlags,
                                    UINT_PTR uIDNewItem, LPCSTR lpNewItem) {
  if (lpNewItem && !(uFlags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR))) {
    const char *translated = TranslateUI(lpNewItem);
    if (!translated)
      translated = TranslateUIPartial(lpNewItem);
    if (translated)
      return Real_ModifyMenuA(hMenu, uPosition, uFlags, uIDNewItem, translated);
  }
  return Real_ModifyMenuA(hMenu, uPosition, uFlags, uIDNewItem, lpNewItem);
}

// ============================================================================
// KEY (Serial Key) Verification Bypass - Skip startup dialogs
// ============================================================================
static int g_dialogSkipCount = 0;

static INT_PTR WINAPI Hook_DialogBoxParamA(HINSTANCE hInstance,
                                           LPCSTR lpTemplateName,
                                           HWND hWndParent,
                                           DLGPROC lpDialogFunc,
                                           LPARAM dwInitParam) {
  return Real_DialogBoxParamA(hInstance, lpTemplateName, hWndParent,
                              lpDialogFunc, dwInitParam);
}

// ============================================================================
// Settings Dialog
// ============================================================================

#define IDC_CHECK_BACKLOG_ICONS 1001
#define IDC_CHECK_FILE_REDIRECT 1002
#define IDC_BTN_CHANGE_DIALOGUE_FONT 1003
#define IDC_BTN_CHANGE_BACKLOG_FONT 1006
#define IDC_LBL_SPACING 1007
#define IDC_EDIT_SPACING 1008
#define IDC_LBL_XOFFSET 1009
#define IDC_EDIT_XOFFSET 1010
#define IDC_LBL_YOFFSET 1011
#define IDC_EDIT_YOFFSET 1012
#define IDC_BTN_CHANGE_BACKLOG_NAME_FONT 1013
#define IDC_LBL_NAME_XOFFSET 1020
#define IDC_EDIT_NAME_XOFFSET 1021
#define IDC_LBL_NAME_YOFFSET 1018
#define IDC_EDIT_NAME_YOFFSET 1019
#define IDC_LBL_NAME_SPACING 1014
#define IDC_EDIT_NAME_SPACING 1015
#define IDC_LBL_DIALOG_SPACING 1016
#define IDC_EDIT_DIALOG_SPACING 1017
#define IDC_CHK_ADVANCED 1022
#define IDC_BTN_OK 1004
#define IDC_BTN_CANCEL 1005
#define IDC_BTN_ABOUT 1023
#define IDC_BTN_ADVANCED 1024
#define IDC_COMBO_LANGUAGE 1026

static INT_PTR CALLBACK AdvancedSettingsDialogProc(HWND hwndDlg, UINT uMsg,
                                                   WPARAM wParam, LPARAM lParam);
static void ShowAdvancedSettingsDialog(HWND parent);

static INT_PTR CALLBACK SettingsDialogProc(HWND hwndDlg, UINT uMsg,
                                           WPARAM wParam, LPARAM lParam) {
  switch (uMsg) {
  case WM_INITDIALOG: {
    // Center the dialog on the parent window
    RECT rcParent, rcDlg;
    GetWindowRect(g_mainWindow, &rcParent);
    GetWindowRect(hwndDlg, &rcDlg);
    int x = rcParent.left +
            (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2;
    int y = rcParent.top +
            (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2;
    SetWindowPos(hwndDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // Populate ComboBox
    HWND hCombo = GetDlgItem(hwndDlg, IDC_COMBO_LANGUAGE);
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"Japanese (Original)");
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"Indonesian / Bahasa Indonesia (id_Data)");
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"English (eng_data)");
    
    // Set selection
    SendMessageW(hCombo, CB_SETCURSEL, g_fontManager.GetLanguage(), 0);

    return TRUE;
  }

  case WM_COMMAND: {
    if (LOWORD(wParam) == IDC_BTN_ADVANCED) {
      ShowAdvancedSettingsDialog(hwndDlg);
      return TRUE;
    }

    switch (LOWORD(wParam)) {
    case IDC_BTN_CHANGE_DIALOGUE_FONT: {
      // Show font chooser dialog
      LOGFONTW lf = {};
      CHOOSEFONTW cf = {};
      cf.lStructSize = sizeof(cf);
      cf.hwndOwner = hwndDlg;
      cf.lpLogFont = &lf;
      cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT;
      wcscpy_s(lf.lfFaceName, g_fontManager.GetDialogueFontName().c_str());
      lf.lfHeight = g_fontManager.GetDialogueFontSize();

      if (ChooseFontW(&cf)) {
        int height = lf.lfHeight;
        g_fontManager.SetDialogueFont(lf.lfFaceName, height);
        MessageBoxW(hwndDlg, L"Dialogue font updated!", L"D.C. Patch",
                    MB_OK | MB_ICONINFORMATION);
      }
      return TRUE;
    }

    case IDC_BTN_CHANGE_BACKLOG_FONT: {
      // Show font chooser dialog
      LOGFONTW lf = {};
      CHOOSEFONTW cf = {};
      cf.lStructSize = sizeof(cf);
      cf.hwndOwner = hwndDlg;
      cf.lpLogFont = &lf;
      cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT;
      wcscpy_s(lf.lfFaceName, g_fontManager.GetBacklogFontName().c_str());
      lf.lfHeight = g_fontManager.GetBacklogFontSize();

      if (ChooseFontW(&cf)) {
        int height = lf.lfHeight;
        g_fontManager.SetBacklogFont(lf.lfFaceName, height);
        MessageBoxW(hwndDlg, L"Backlog font updated!", L"D.C. Patch",
                    MB_OK | MB_ICONINFORMATION);
      }
      return TRUE;
    }

    case IDC_BTN_CHANGE_BACKLOG_NAME_FONT: {
      // Show font chooser dialog
      LOGFONTW lf = {};
      CHOOSEFONTW cf = {};
      cf.lStructSize = sizeof(cf);
      cf.hwndOwner = hwndDlg;
      cf.lpLogFont = &lf;
      cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT;
      wcscpy_s(lf.lfFaceName, g_fontManager.GetBacklogNameFontName().c_str());
      lf.lfHeight = g_fontManager.GetBacklogNameFontSize();

      if (ChooseFontW(&cf)) {
        int height = lf.lfHeight;
        g_fontManager.SetBacklogNameFont(lf.lfFaceName, height);
        MessageBoxW(hwndDlg, L"Backlog Character Name font updated!",
                    L"D.C. Patch", MB_OK | MB_ICONINFORMATION);
      }
      return TRUE;
    }

    case IDC_BTN_OK: {
      // Save language settings
      HWND hCombo = GetDlgItem(hwndDlg, IDC_COMBO_LANGUAGE);
      int selectedLang = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
      if (selectedLang == CB_ERR) selectedLang = 0;

      bool anyChanged = (selectedLang != g_fontManager.GetLanguage());

      if (anyChanged) {
        g_fontManager.SetLanguage(selectedLang);
        MessageBoxW(hwndDlg,
                    L"\u26a0\ufe0f File redirection setting changed.\n\n"
                    L"Return to title screen or restart the game\n"
                    L"for this to take full effect.",
                    L"D.C. Patch", MB_OK | MB_ICONWARNING);
      }

      EndDialog(hwndDlg, IDOK);
      return TRUE;
    }

    case IDC_BTN_ABOUT:
      MessageBoxW(
          hwndDlg,
          L"This patch has been made by:\nSakura Symphony Re;Translation",
          L"About DC4 Patch", MB_OK | MB_ICONINFORMATION);
      return TRUE;

    case IDC_BTN_CANCEL:
      EndDialog(hwndDlg, IDCANCEL);
      return TRUE;
    }
    break;
  }

  case WM_CLOSE:
    EndDialog(hwndDlg, IDCANCEL);
    return TRUE;
  }
  return FALSE;
}

// In-memory DIALOG resource construction
static void ShowSettingsDialog() {
  if (!g_mainWindow)
    return;

  // Allocate a buffer for the DLGTEMPLATE and controls
  const int bufSize = 4096;
  BYTE *buffer = new BYTE[bufSize];
  memset(buffer, 0, bufSize);

  WORD *pw = (WORD *)buffer;

  // Dialog Header
  DLGTEMPLATE *pDlg = (DLGTEMPLATE *)pw;
  pDlg->style = WS_POPUP | WS_BORDER | WS_SYSMENU | WS_CAPTION | DS_MODALFRAME |
                DS_CENTER | DS_SETFONT;
  pDlg->dwExtendedStyle = 0;
  pDlg->cdit = 11; // 2 Warning Labels, 2 Checkboxes, 3 Font Buttons, 1 Adv Button, OK, Cancel, About
  pDlg->x = 0;
  pDlg->y = 0;
  pDlg->cx = 250;
  pDlg->cy = 200;

  pw = (WORD *)(pDlg + 1);
  *pw++ = 0; // Menu
  *pw++ = 0; // Class
  // Title: null-terminated Unicode string
  const WCHAR *dlgTitle = L"D.C. Patch Settings";
  wcscpy((WCHAR *)pw, dlgTitle);
  pw += wcslen(dlgTitle) + 1;
  // Font (because DS_SETFONT): point size + font name
  *pw++ = 9; // point size
  const WCHAR *fontName = L"Segoe UI";
  wcscpy((WCHAR *)pw, fontName);
  pw += wcslen(fontName) + 1;

  // Helper: align pointer to DWORD boundary (required before each
  // DLGITEMTEMPLATE)
  auto AlignDword = [](WORD *&p) {
    while ((ULONG_PTR)p & 3)
      p++;
  };

  // Control: Warning Label English
  AlignDword(pw);
  DLGITEMTEMPLATE *pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 10;
  pItem->cx = 230;
  pItem->cy = 10;
  pItem->id = -1;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0082; // Static class
  const WCHAR *textWarnEn = L"Warning: Wrong setting could lead to crashing.";
  wcscpy((WCHAR *)pw, textWarnEn);
  pw += wcslen(textWarnEn) + 1;
  *pw++ = 0;

  // Control: Warning Label Indonesian
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 20;
  pItem->cx = 230;
  pItem->cy = 10;
  pItem->id = -1;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0082; // Static class
  const WCHAR *textWarnId = L"Peringatan: Pengaturan yang salah dapat menyebabkan crash.";
  wcscpy((WCHAR *)pw, textWarnId);
  pw += wcslen(textWarnId) + 1;
  *pw++ = 0;

  // Control 1: Language Label
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 35;
  pItem->cx = 230;
  pItem->cy = 10;
  pItem->id = -1;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0082; // Static class
  const WCHAR *text2 = L"Game Text Language / Bahasa / \x8A00\x8A9E:";
  wcscpy((WCHAR *)pw, text2);
  pw += wcslen(text2) + 1;
  *pw++ = 0;

  // Control 1.5: Language ComboBox
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 48;
  pItem->cx = 200;
  pItem->cy = 100; // Dropdown height
  pItem->id = IDC_COMBO_LANGUAGE;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0085; // ComboBox class
  *pw++ = 0; // Empty title
  *pw++ = 0; // No creation data

  // Control 3: Change Dialogue Font Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 72;
  pItem->cx = 200;
  pItem->cy = 18;
  pItem->id = IDC_BTN_CHANGE_DIALOGUE_FONT;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text3 = L"Change Dialogue Font...";
  wcscpy((WCHAR *)pw, text3);
  pw += wcslen(text3) + 1;
  *pw++ = 0;

  // Control 3.5: Change Backlog Font Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 92;
  pItem->cx = 200;
  pItem->cy = 18;
  pItem->id = IDC_BTN_CHANGE_BACKLOG_FONT;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text35 = L"Change Backlog Font...";
  wcscpy((WCHAR *)pw, text35);
  pw += wcslen(text35) + 1;
  *pw++ = 0;

  // Control 3.75: Change Backlog Name Font Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 112;
  pItem->cx = 200;
  pItem->cy = 18;
  pItem->id = IDC_BTN_CHANGE_BACKLOG_NAME_FONT;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text375 = L"Change Backlog Name Font...";
  wcscpy((WCHAR *)pw, text375);
  pw += wcslen(text375) + 1;
  *pw++ = 0;

  // Control: Advanced Settings Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
  pItem->dwExtendedStyle = 0;
  pItem->x = 10;
  pItem->y = 132;
  pItem->cx = 200;
  pItem->cy = 18;
  pItem->id = IDC_BTN_ADVANCED;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080; // Button class
  const WCHAR *textAdv = L"Advanced Backlog Spacing...";
  wcscpy((WCHAR *)pw, textAdv);
  pw += wcslen(textAdv) + 1;
  *pw++ = 0;

  // Control 4: OK Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP;
  pItem->dwExtendedStyle = 0;
  pItem->x = 50;
  pItem->y = 162;
  pItem->cx = 50;
  pItem->cy = 18;
  pItem->id = IDC_BTN_OK;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text4 = L"OK";
  wcscpy((WCHAR *)pw, text4);
  pw += wcslen(text4) + 1;
  *pw++ = 0;

  // Control 5: Cancel Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
  pItem->dwExtendedStyle = 0;
  pItem->x = 110;
  pItem->y = 162;
  pItem->cx = 50;
  pItem->cy = 18;
  pItem->id = IDC_BTN_CANCEL;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text5 = L"Cancel";
  wcscpy((WCHAR *)pw, text5);
  pw += wcslen(text5) + 1;
  *pw++ = 0;

  // Control 6: About Button
  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
  pItem->dwExtendedStyle = 0;
  pItem->x = 170;
  pItem->y = 162;
  pItem->cx = 50;
  pItem->cy = 18;
  pItem->id = IDC_BTN_ABOUT;
  pw = (WORD *)(pItem + 1);
  *pw++ = 0xFFFF;
  *pw++ = 0x0080;
  const WCHAR *text6 = L"About";
  wcscpy((WCHAR *)pw, text6);
  pw += wcslen(text6) + 1;
  *pw++ = 0;

  // Show dialog
  DialogBoxIndirectW(GetModuleHandleA(NULL), (DLGTEMPLATE *)buffer,
                     g_mainWindow, SettingsDialogProc);
}

static INT_PTR CALLBACK AdvancedSettingsDialogProc(HWND hwndDlg, UINT uMsg,
                                                   WPARAM wParam, LPARAM lParam) {
  switch (uMsg) {
  case WM_INITDIALOG: {
    RECT rcParent, rcDlg;
    GetWindowRect(GetParent(hwndDlg), &rcParent);
    GetWindowRect(hwndDlg, &rcDlg);
    int x = rcParent.left + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2;
    int y = rcParent.top + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2;
    SetWindowPos(hwndDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    SetDlgItemInt(hwndDlg, IDC_EDIT_SPACING, g_fontManager.GetBacklogLineSpacing(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_XOFFSET, g_fontManager.GetBacklogXOffset(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_YOFFSET, g_fontManager.GetBacklogYOffset(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_NAME_XOFFSET, g_fontManager.GetBacklogNameXOffset(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_NAME_YOFFSET, g_fontManager.GetBacklogNameYOffset(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_NAME_SPACING, g_fontManager.GetBacklogNameSpacing(), TRUE);
    SetDlgItemInt(hwndDlg, IDC_EDIT_DIALOG_SPACING, g_fontManager.GetBacklogDialogSpacing(), TRUE);
    return TRUE;
  }

  case WM_COMMAND: {
    if (LOWORD(wParam) == IDC_BTN_OK) {
      int spacing = GetDlgItemInt(hwndDlg, IDC_EDIT_SPACING, NULL, TRUE);
      int xOffset = GetDlgItemInt(hwndDlg, IDC_EDIT_XOFFSET, NULL, TRUE);
      int yOffset = GetDlgItemInt(hwndDlg, IDC_EDIT_YOFFSET, NULL, TRUE);
      int nameXOffset = GetDlgItemInt(hwndDlg, IDC_EDIT_NAME_XOFFSET, NULL, TRUE);
      int nameYOffset = GetDlgItemInt(hwndDlg, IDC_EDIT_NAME_YOFFSET, NULL, TRUE);
      int nameSpacing = GetDlgItemInt(hwndDlg, IDC_EDIT_NAME_SPACING, NULL, TRUE);
      int dialogSpacing = GetDlgItemInt(hwndDlg, IDC_EDIT_DIALOG_SPACING, NULL, TRUE);

      g_fontManager.SetBacklogOffsets(xOffset, yOffset, spacing, nameXOffset,
                                      nameYOffset, nameSpacing, dialogSpacing);
      g_fontManager.SetAdvancedSettings(true); // Implicitly enabled when used
      EndDialog(hwndDlg, IDOK);
      return TRUE;
    } else if (LOWORD(wParam) == IDC_BTN_CANCEL) {
      EndDialog(hwndDlg, IDCANCEL);
      return TRUE;
    }
    break;
  }

  case WM_CLOSE:
    EndDialog(hwndDlg, IDCANCEL);
    return TRUE;
  }
  return FALSE;
}

static void ShowAdvancedSettingsDialog(HWND parent) {
  const int bufSize = 4096;
  BYTE *buffer = new BYTE[bufSize];
  memset(buffer, 0, bufSize);
  WORD *pw = (WORD *)buffer;

  DLGTEMPLATE *pDlg = (DLGTEMPLATE *)pw;
  pDlg->style = WS_POPUP | WS_BORDER | WS_SYSMENU | WS_CAPTION | DS_MODALFRAME | DS_CENTER | DS_SETFONT;
  pDlg->cdit = 16; // 7 labels, 7 edits, 2 buttons
  pDlg->cx = 200;
  pDlg->cy = 200;

  pw = (WORD *)(pDlg + 1);
  *pw++ = 0; *pw++ = 0;
  wcscpy((WCHAR *)pw, L"Advanced Backlog Settings");
  pw += wcslen((WCHAR *)pw) + 1;
  *pw++ = 9;
  wcscpy((WCHAR *)pw, L"Segoe UI");
  pw += wcslen((WCHAR *)pw) + 1;

  auto AlignDword = [](WORD *&p) { while ((ULONG_PTR)p & 3) p++; };
  auto AddLabelAndEdit = [&](int idLbl, int idEdit, const WCHAR* labelText, int yPos) {
    AlignDword(pw);
    DLGITEMTEMPLATE *pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    pItem->x = 10; pItem->y = yPos + 2; pItem->cx = 100; pItem->cy = 14; pItem->id = idLbl;
    pw = (WORD *)(pItem + 1); *pw++ = 0xFFFF; *pw++ = 0x0082;
    wcscpy((WCHAR *)pw, labelText); pw += wcslen(labelText) + 1; *pw++ = 0;

    AlignDword(pw);
    pItem = (DLGITEMTEMPLATE *)pw;
    pItem->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL;
    pItem->dwExtendedStyle = WS_EX_CLIENTEDGE;
    pItem->x = 115; pItem->y = yPos; pItem->cx = 40; pItem->cy = 14; pItem->id = idEdit;
    pw = (WORD *)(pItem + 1); *pw++ = 0xFFFF; *pw++ = 0x0081;
    wcscpy((WCHAR *)pw, L""); pw += wcslen(L"") + 1; *pw++ = 0;
  };

  AddLabelAndEdit(IDC_LBL_SPACING, IDC_EDIT_SPACING, L"Line Spacing:", 10);
  AddLabelAndEdit(IDC_LBL_XOFFSET, IDC_EDIT_XOFFSET, L"X Offset:", 30);
  AddLabelAndEdit(IDC_LBL_YOFFSET, IDC_EDIT_YOFFSET, L"Y Offset:", 50);
  AddLabelAndEdit(IDC_LBL_NAME_XOFFSET, IDC_EDIT_NAME_XOFFSET, L"Name X Offset:", 70);
  AddLabelAndEdit(IDC_LBL_NAME_YOFFSET, IDC_EDIT_NAME_YOFFSET, L"Name Y Offset:", 90);
  AddLabelAndEdit(IDC_LBL_NAME_SPACING, IDC_EDIT_NAME_SPACING, L"Name Ext Spacing:", 110);
  AddLabelAndEdit(IDC_LBL_DIALOG_SPACING, IDC_EDIT_DIALOG_SPACING, L"Base Ext Spacing:", 130);

  AlignDword(pw);
  DLGITEMTEMPLATE *pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP;
  pItem->x = 30; pItem->y = 160; pItem->cx = 50; pItem->cy = 16; pItem->id = IDC_BTN_OK;
  pw = (WORD *)(pItem + 1); *pw++ = 0xFFFF; *pw++ = 0x0080;
  wcscpy((WCHAR *)pw, L"OK"); pw += wcslen(L"OK") + 1; *pw++ = 0;

  AlignDword(pw);
  pItem = (DLGITEMTEMPLATE *)pw;
  pItem->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
  pItem->x = 100; pItem->y = 160; pItem->cx = 50; pItem->cy = 16; pItem->id = IDC_BTN_CANCEL;
  pw = (WORD *)(pItem + 1); *pw++ = 0xFFFF; *pw++ = 0x0080;
  wcscpy((WCHAR *)pw, L"Cancel"); pw += wcslen(L"Cancel") + 1; *pw++ = 0;

  DialogBoxIndirectW(GetModuleHandleA(NULL), (DLGTEMPLATE *)buffer, parent, AdvancedSettingsDialogProc);
  delete[] buffer;
}

// Window procedure hook to add menu item and keyboard shortcut
static LRESULT CALLBACK MenuWndProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                                    LPARAM lParam);
static WNDPROC g_OrigWndProc = nullptr;

static HWND WINAPI Hook_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName,
                                        LPCSTR lpWindowName, DWORD dwStyle,
                                        int X, int Y, int nWidth, int nHeight,
                                        HWND hWndParent, HMENU hMenu,
                                        HINSTANCE hInstance, LPVOID lpParam) {

  HWND hWnd = Real_CreateWindowExA(dwExStyle, lpClassName, lpWindowName,
                                   dwStyle, X, Y, nWidth, nHeight, hWndParent,
                                   hMenu, hInstance, lpParam);

  // Check if this is the main game window (has a title and is a top-level
  // window)
  if (hWnd && lpWindowName && hWndParent == NULL && g_mainWindow == nullptr) {
    g_mainWindow = hWnd;

    // Add patch options to system menu
    HMENU hSysMenu = GetSystemMenu(hWnd, FALSE);
    if (hSysMenu) {
      AppendMenuW(hSysMenu, MF_SEPARATOR, 0, nullptr);
      AppendMenuW(hSysMenu, MF_STRING, 0x1919999,
                  L"D.C. Patch Settings... (F11)");
    }

    // Subclass the window to handle our menu command
    g_OrigWndProc =
        (WNDPROC)SetWindowLongPtrA(hWnd, GWLP_WNDPROC, (LONG_PTR)MenuWndProc);
  }

  return hWnd;
}

static LRESULT CALLBACK MenuWndProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                                    LPARAM lParam) {
  // Handle F11 key press
  if (uMsg == WM_KEYDOWN && wParam == VK_F11) {
    ShowSettingsDialog();
    return 0;
  }

  if (uMsg == WM_SYSCOMMAND) {
    if (wParam == 0x1919999) {
      // Show settings dialog
      ShowSettingsDialog();
      return 0;
    }

    // Legacy individual handlers (kept for backwards compatibility)
    if (wParam == 0x114514) {
      // Show font chooser dialog directly
      LOGFONTW lf = {};
      CHOOSEFONTW cf = {};
      cf.lStructSize = sizeof(cf);
      cf.hwndOwner = hWnd;
      cf.lpLogFont = &lf;
      cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT;
      wcscpy_s(lf.lfFaceName, g_fontManager.GetDialogueFontName().c_str());
      lf.lfHeight = g_fontManager.GetDialogueFontSize();

      if (ChooseFontW(&cf)) {
        int height = lf.lfHeight;
        g_fontManager.SetDialogueFont(lf.lfFaceName, height);
        MessageBoxW(hWnd, L"Font updated!", L"D.C. Patch",
                    MB_OK | MB_ICONINFORMATION);
      }
      return 0;
    }

    if (wParam == 0x1919810) {
      // Toggle backlog show all icons
      HMENU hSysMenu = GetSystemMenu(hWnd, FALSE);
      if (hSysMenu) {
        MENUITEMINFOW mii = {};
        mii.cbSize = sizeof(MENUITEMINFOW);
        mii.fMask = MIIM_STATE;
        GetMenuItemInfoW(hSysMenu, 0x1919810, FALSE, &mii);

        // Toggle the state
        bool isEnabled = !(mii.fState & MF_CHECKED);
        g_fontManager.SetEnableBacklogAllIcon(isEnabled);

        ModifyMenuW(hSysMenu, 0x1919810,
                    isEnabled ? MF_CHECKED : MF_UNCHECKED,
                    0x1919810, L"Backlog Show All Icons");
      }
      return 0;
    }

    if (wParam == 0x1919811) {
      // Toggle file redirection
      HMENU hSysMenu = GetSystemMenu(hWnd, FALSE);
      if (hSysMenu) {
        MENUITEMINFOW mii = {};
        mii.cbSize = sizeof(MENUITEMINFOW);
        mii.fMask = MIIM_STATE;
        GetMenuItemInfoW(hSysMenu, 0x1919811, FALSE, &mii);

        bool isEnabled = !(mii.fState & MF_CHECKED);
        g_fontManager.SetLanguage(isEnabled ? 1 : 0);

        ModifyMenuW(hSysMenu, 0x1919811,
                    isEnabled ? MF_CHECKED : MF_UNCHECKED,
                    0x1919811, L"Enable id_Data File Redirection");

        MessageBoxW(
            hWnd,
            isEnabled
                ? L"File redirection ENABLED.\nTranslated files from "
                  L"id_Data\\ "
                  L"will be used.\n\n⚠️ RESTART REQUIRED:\nReturn to title "
                  L"screen or restart the game for this to take full "
                  L"effect.\n(Already-loaded files are cached in memory.)"
                : L"File redirection DISABLED.\nOriginal files from "
                  L"AdvData\\ "
                  L"will be used.\n\n⚠️ RESTART REQUIRED:\nReturn to title "
                  L"screen or restart the game for this to take full "
                  L"effect.\n(Already-loaded files are cached in memory.)",
            L"D.C. Patch", MB_OK | MB_ICONWARNING);
      }
      return 0;
    }
  }
  return CallWindowProcA(g_OrigWndProc, hWnd, uMsg, wParam, lParam);
}

// ============================================================================
// IAT (Import Address Table) Patching
// Safer than Detours for system APIs - patches the game's import table
// directly
// ============================================================================
static bool PatchIAT(HMODULE hModule, const char *dllName, PROC oldFunc,
                     PROC newFunc) {
  BYTE *base = (BYTE *)hModule;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return false;

  IMAGE_IMPORT_DESCRIPTOR *imp =
      (IMAGE_IMPORT_DESCRIPTOR
           *)(base +
              nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                  .VirtualAddress);

  for (; imp->Name; imp++) {
    const char *name = (const char *)(base + imp->Name);
    if (_stricmp(name, dllName) != 0)
      continue;

    IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
    for (; thunk->u1.Function; thunk++) {
      PROC *funcPtr = (PROC *)&thunk->u1.Function;
      if (*funcPtr == oldFunc) {
        DWORD oldProtect;
        VirtualProtect(funcPtr, sizeof(PROC), PAGE_READWRITE, &oldProtect);
        *funcPtr = newFunc;
        VirtualProtect(funcPtr, sizeof(PROC), oldProtect, &oldProtect);
        return true;
      }
    }
  }
  return false;
}

// ============================================================================
// Crash Handler (Vectored Exception Handler)
// ============================================================================
// In addition to logging, this handler RECOVERS from specific known crashes
// that occur only under Wine/Proton on Android (GameHub).
//
// Known crash: The game's internal memcpy at 0x45AE8C (file offset 0x5A28C)
//   Instruction: mov byte ptr [edi], al   (opcode: 88 07)
//   Cause: Game's sprite buffer allocation returns -1 (FFFFFFFF) under Wine,
//          and the unrolled memcpy tries to write to that address.
//   Fix: Zero ECX (loop counter) to stop the copy, skip past the faulting
//        instruction, and let the game continue.
static LONG WINAPI CrashLogger(EXCEPTION_POINTERS *ep) {
  DWORD code = ep->ExceptionRecord->ExceptionCode;

  // --- Recovery: game engine memcpy with invalid destination pointer ---
  if (code == EXCEPTION_ACCESS_VIOLATION) {
    DWORD eip = ep->ContextRecord->Eip;
    DWORD faultAddr = (DWORD)ep->ExceptionRecord->ExceptionInformation[1];
    DWORD isWrite = (DWORD)ep->ExceptionRecord->ExceptionInformation[0];

    // Check if this is the known memcpy crash pattern:
    //   - Write access violation
    //   - Destination (EDI) is 0xFFFFFFFF (failed allocation)
    //   - The instruction at EIP is "mov [edi], al" (88 07)
    if (isWrite && faultAddr == 0xFFFFFFFF &&
        ep->ContextRecord->Edi == 0xFFFFFFFF) {
      __try {
        BYTE *pCode = (BYTE *)eip;
        if (pCode[0] == 0x88 && pCode[1] == 0x07) {
          // Recovery: skip the faulting instruction and stop the copy loop
          ep->ContextRecord->Ecx = 0;   // ECX = remaining bytes → 0
          ep->ContextRecord->Eip += 2;  // Skip "mov [edi], al" (2 bytes)
          return EXCEPTION_CONTINUE_EXECUTION;
        }
      }
      __except(EXCEPTION_EXECUTE_HANDLER) {
        // EIP is not readable — fall through to logging
      }
    }
  }

  // --- Logging for unhandled crashes ---
  if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_STACK_OVERFLOW ||
      code == EXCEPTION_ILLEGAL_INSTRUCTION ||
      code == EXCEPTION_PRIV_INSTRUCTION) {
    FILE *f = fopen("dc4_crash.log", "a");
    if (f) {
      fprintf(f, "CRASH: code=0x%08X EIP=0x%08X", code, ep->ContextRecord->Eip);
      if (code == EXCEPTION_ACCESS_VIOLATION)
        fprintf(f, " addr=0x%08X (%s)",
                (DWORD)ep->ExceptionRecord->ExceptionInformation[1],
                ep->ExceptionRecord->ExceptionInformation[0] ? "write"
                                                             : "read");
      fprintf(f, "\n  EAX=%08X EBX=%08X ECX=%08X EDX=%08X\n",
              ep->ContextRecord->Eax, ep->ContextRecord->Ebx,
              ep->ContextRecord->Ecx, ep->ContextRecord->Edx);
      fprintf(f, "  ESP=%08X EBP=%08X ESI=%08X EDI=%08X\n",
              ep->ContextRecord->Esp, ep->ContextRecord->Ebp,
              ep->ContextRecord->Esi, ep->ContextRecord->Edi);
      fclose(f);
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// id_Data -> AdvData Hardlink Sync
// ============================================================================
// The CIRCUS engine's internal CRX image loader bypasses Win32 CreateFileA for
// some rendering codepaths (e.g. Scenario Mode navigation). To ensure translated
// graphics always load, we create hardlinks (or copies) from id_Data into the
// AdvData directories at startup, making files appear where the engine expects.

static void EnsureDirectoryExists(const char* path) {
  char tmp[MAX_PATH];
  strcpy_s(tmp, path);
  for (char* p = tmp; *p; p++) {
    if (*p == '\\' || *p == '/') {
      char saved = *p;
      *p = '\0';
      CreateDirectoryA(tmp, NULL);
      *p = saved;
    }
  }
  CreateDirectoryA(tmp, NULL);
}

static int SyncDirectoryRecursive(const char* srcDir, const char* srcRoot,
                                   const char* dstRoot, const char* cacheRoot,
                                   FILE* manifest) {
  int count = 0;
  char searchPath[MAX_PATH];
  sprintf_s(searchPath, "%s\\*", srcDir);

  WIN32_FIND_DATAA fd;
  HANDLE hFind = FindFirstFileA(searchPath, &fd);
  if (hFind == INVALID_HANDLE_VALUE) return 0;

  size_t srcRootLen = strlen(srcRoot);

  do {
    if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
    
    // CRITICAL: Ignore cache and manifest files to prevent infinite loop of copying backups!
    if (_stricmp(fd.cFileName, ".original_cache") == 0 ||
        _stricmp(fd.cFileName, ".sync_manifest") == 0) {
      continue;
    }

    char fullSrc[MAX_PATH];
    sprintf_s(fullSrc, "%s\\%s", srcDir, fd.cFileName);

    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      count += SyncDirectoryRecursive(fullSrc, srcRoot, dstRoot, cacheRoot, manifest);
    } else {
      // Only sync graphic/animation files
      const char* ext = strrchr(fd.cFileName, '.');
      if (!ext) continue;
      if (_stricmp(ext, ".crx") != 0 && _stricmp(ext, ".grp") != 0 &&
          _stricmp(ext, ".crm") != 0 && _stricmp(ext, ".pck") != 0) continue;

      // Build destination path: dstRoot + relative path after srcRoot
      const char* relPath = fullSrc + srcRootLen;
      char fullDst[MAX_PATH];
      sprintf_s(fullDst, "%s%s", dstRoot, relPath);

      // Ensure target directory exists
      char dstDir[MAX_PATH];
      strcpy_s(dstDir, fullDst);
      char* lastSep = strrchr(dstDir, '\\');
      if (lastSep) {
        *lastSep = '\0';
        EnsureDirectoryExists(dstDir);
      }

      // Back up the original AdvData file to cache before overwriting
      DWORD dstAttr = GetFileAttributesA(fullDst);
      if (dstAttr != INVALID_FILE_ATTRIBUTES) {
        char cachePath[MAX_PATH];
        sprintf_s(cachePath, "%s%s", cacheRoot, relPath);

        // Ensure cache directory exists
        char cacheDir[MAX_PATH];
        strcpy_s(cacheDir, cachePath);
        char* cacheSep = strrchr(cacheDir, '\\');
        if (cacheSep) {
          *cacheSep = '\0';
          EnsureDirectoryExists(cacheDir);
        }

        // Only back up if cache doesn't already have this file
        DWORD cacheAttr = GetFileAttributesA(cachePath);
        if (cacheAttr == INVALID_FILE_ATTRIBUTES) {
          MoveFileA(fullDst, cachePath);
        } else {
          DeleteFileA(fullDst);
        }
      }

      // Create hardlink (fall back to copy)
      if (CreateHardLinkA(fullDst, fullSrc, NULL) ||
          CopyFileA(fullSrc, fullDst, FALSE)) {
        count++;
        // Write to manifest
        if (manifest) {
          fprintf(manifest, "%s\n", fullDst);
        }
      }
    }
  } while (FindNextFileA(hFind, &fd));

  FindClose(hFind);
  return count;
}

static void SyncGraphicsFromDir(const char* srcRelDir, const char* manifestFile, const char* cacheRelDir) {
  char srcAbs[MAX_PATH], dstAbs[MAX_PATH], cacheAbs[MAX_PATH];
  GetFullPathNameA(srcRelDir, MAX_PATH, srcAbs, NULL);
  GetFullPathNameA(".\\AdvData", MAX_PATH, dstAbs, NULL);
  GetFullPathNameA(cacheRelDir, MAX_PATH, cacheAbs, NULL);

  DWORD attr = GetFileAttributesA(srcAbs);
  if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return;

  FILE* manifest = fopen(manifestFile, "w");
  int count = SyncDirectoryRecursive(srcAbs, srcAbs, dstAbs, cacheAbs, manifest);
  if (manifest) fclose(manifest);

  char msg[256];
  sprintf_s(msg, "DCPatch: Synced %d graphic files from %s to AdvData\n", count, srcRelDir);
  OutputDebugStringA(msg);
}

static void CleanupSyncedFrom(const char* manifestFile, const char* cacheRelDir) {
  FILE* manifest = fopen(manifestFile, "r");
  if (!manifest) return;

  char cacheAbs[MAX_PATH], dstAbs[MAX_PATH];
  GetFullPathNameA(cacheRelDir, MAX_PATH, cacheAbs, NULL);
  GetFullPathNameA(".\\AdvData", MAX_PATH, dstAbs, NULL);

  size_t dstRootLen = strlen(dstAbs);

  int count = 0;
  char line[MAX_PATH];
  while (fgets(line, MAX_PATH, manifest)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
      line[--len] = '\0';
    if (len == 0) continue;

    DeleteFileA(line);

    if (len > dstRootLen) {
      const char* relPath = line + dstRootLen;
      char cachePath[MAX_PATH];
      sprintf_s(cachePath, "%s%s", cacheAbs, relPath);

      DWORD cacheAttr = GetFileAttributesA(cachePath);
      if (cacheAttr != INVALID_FILE_ATTRIBUTES) {
        MoveFileA(cachePath, line);
      }
    }
    count++;
  }
  fclose(manifest);
  DeleteFileA(manifestFile);

  char msg[256];
  sprintf_s(msg, "DCPatch: Cleaned up %d synced files, restored originals from cache\n", count);
  OutputDebugStringA(msg);
}

// ============================================================================
// Initialization
// ============================================================================

static void InitPatch() {
  // Install crash logger first so we can diagnose any crashes
  AddVectoredExceptionHandler(1, CrashLogger);

  // Load INI settings and set JSON file paths
  g_fontManager.Init();

  // ---- Load / generate external JSON tables ----
  // Write defaults if missing, then load (may load new game's JSON instead)
  WriteDefaultNamesJson();
  WriteDefaultUiJson();
  LoadNameTable();
  LoadUiTranslations();

  // ---- Auto-detect game addresses ----
  // Must run BEFORE any Detours/JmpWrite hooks that use g_resolved* globals
  ResolveGameAddresses();

  // Read language setting
  int lang = g_fontManager.GetLanguage();

  // Handle id_Data (Indonesian) sync/cleanup
  if (lang == 1) {
    SyncGraphicsFromDir(".\\id_Data", ".\\id_Data\\.sync_manifest", ".\\id_Data\\.original_cache");
  } else {
    CleanupSyncedFrom(".\\id_Data\\.sync_manifest", ".\\id_Data\\.original_cache");
  }

  // Handle eng_data (English) sync/cleanup
  if (lang == 2) {
    SyncGraphicsFromDir(".\\eng_data", ".\\eng_data\\.sync_manifest", ".\\eng_data\\.original_cache");
  } else {
    CleanupSyncedFrom(".\\eng_data\\.sync_manifest", ".\\eng_data\\.original_cache");
  }

  // Patch Japanese strings in the EXE image with loaded translations
  PatchStringsInMemory();

  // Set Japanese codepage (Shift-JIS) as early as possible.
  // This fixes encoding on Wine/Proton where GetACP() returns the wrong
  // value. LCID/LangID hooks are intentionally NOT included - they crash the
  // backlog.
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(&(PVOID &)Real_GetACP, Hook_GetACP);
  DetourAttach(&(PVOID &)Real_GetOEMCP, Hook_GetOEMCP);
  DetourTransactionCommit();

  // BacklogFunc hook: ONLY attach if address was explicitly set in DCPatch.ini
  // [Addresses] BacklogFuncRVA=0xXXXX.
  // Auto-scan results are logged for reference but NOT used to attach hooks,
  // because a wrong address from scan will crash the game immediately.
  if (g_fontManager.GetAddrBacklogFuncRVA() != 0 && g_resolvedFuncAddr != 0) {
    Real_BacklogFunc = (void(__cdecl *)())g_resolvedFuncAddr;
    char msg[128];
    sprintf_s(msg, "DCPatch: BacklogFunc hook ENABLED at 0x%08X (from INI)\n", g_resolvedFuncAddr);
    OutputDebugStringA(msg);
  } else if (g_resolvedFuncAddr != 0) {
    // Auto-scan found something but we don't trust it — log for user reference
    char msg[192];
    sprintf_s(msg, "DCPatch INFO: Auto-scan found BacklogFunc at 0x%08X (RVA 0x%X).\n"
                   "  To enable backlog font hook, add to DCPatch.ini:\n"
                   "  [Addresses]\n  BacklogFuncRVA=0x%X\n",
              g_resolvedFuncAddr,
              g_resolvedFuncAddr - (DWORD)GetModuleHandleA(NULL),
              g_resolvedFuncAddr - (DWORD)GetModuleHandleA(NULL));
    OutputDebugStringA(msg);
  } else {
    OutputDebugStringA("DCPatch: BacklogFunc not found. Backlog font hook disabled.\n");
  }

  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(&(PVOID &)Real_GetGlyphOutlineA, Hook_GetGlyphOutlineA);
  DetourAttach(&(PVOID &)Real_CreateFileA, Hook_CreateFileA);
  DetourAttach(&(PVOID &)Real_CreateFileW, Hook_CreateFileW);
  DetourAttach(&(PVOID &)Real_CreateWindowExA, Hook_CreateWindowExA);
  DetourAttach(&(PVOID &)Real_GetTextExtentPoint32A,
               Hook_GetTextExtentPoint32A);
  DetourAttach(&(PVOID &)Real_GetTextExtentPoint32W,
               Hook_GetTextExtentPoint32W);
  DetourAttach(&(PVOID &)Real_GetTextExtentExPointA,
               Hook_GetTextExtentExPointA);
  DetourAttach(&(PVOID &)Real_GetTextExtentExPointW,
               Hook_GetTextExtentExPointW);
  DetourAttach(&(PVOID &)Real_GetCharWidth32A, Hook_GetCharWidth32A);
  DetourAttach(&(PVOID &)Real_GetCharWidth32W, Hook_GetCharWidth32W);
  // UI translation hooks
  DetourAttach(&(PVOID &)Real_MessageBoxA, Hook_MessageBoxA);
  DetourAttach(&(PVOID &)Real_DialogBoxParamA, Hook_DialogBoxParamA);
  DetourAttach(&(PVOID &)Real_AppendMenuA, Hook_AppendMenuA);
  DetourAttach(&(PVOID &)Real_InsertMenuA, Hook_InsertMenuA);
  DetourAttach(&(PVOID &)Real_ModifyMenuA, Hook_ModifyMenuA);
  // Backlog font hook - only if BacklogFunc was resolved
  if (Real_BacklogFunc != nullptr) {
    DetourAttach(&(PVOID &)Real_BacklogFunc, Hook_BacklogFunc);
  }
  // Backlog line spacing and text position
  DetourAttach(&(PVOID &)Real_GetTextMetricsA, Hook_GetTextMetricsA);
  DetourAttach(&(PVOID &)Real_ExtTextOutA, Hook_ExtTextOutA);

  DetourTransactionCommit();

  // Backlog icon hook: ONLY install if BacklogHookRVA is explicitly set in
  // DCPatch.ini [Addresses]. Auto-scan addresses are not trusted for JmpWrite.
  if (g_fontManager.GetEnableBacklogAllIcon() &&
      g_fontManager.GetAddrBacklogHookRVA() != 0) {
    bool hookOk = InstallBacklogIconHook();
    if (!hookOk) {
      OutputDebugStringA("DCPatch WARNING: InstallBacklogIconHook() failed!\n");
      FILE *f = fopen("dc_crash.log", "a");
      if (f) { fprintf(f, "WARNING: InstallBacklogIconHook failed\n"); fclose(f); }
    }
  } else if (g_fontManager.GetEnableBacklogAllIcon() &&
             g_resolvedHookAddr != 0) {
    // Auto-scan found something — tell user the RVA to confirm in INI
    char msg[256];
    DWORD rva = g_resolvedHookAddr - (DWORD)GetModuleHandleA(NULL);
    sprintf_s(msg, "DCPatch INFO: Auto-scan found BacklogHookAddr at RVA 0x%X.\n"
                   "  To enable backlog icon hook, add to DCPatch.ini:\n"
                   "  [Addresses]\n  BacklogHookRVA=0x%X\n", rva, rva);
    OutputDebugStringA(msg);
  }
}

static void CleanupPatch() {
  // Note: JmpWrite hook at CheckIcon else branch does not need cleanup
  // (game is exiting anyway, and restoring displaced bytes is complex)

  // Detach codepage hooks
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach(&(PVOID &)Real_GetACP, Hook_GetACP);
  DetourDetach(&(PVOID &)Real_GetOEMCP, Hook_GetOEMCP);
  DetourTransactionCommit();

  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach(&(PVOID &)Real_GetGlyphOutlineA, Hook_GetGlyphOutlineA);
  DetourDetach(&(PVOID &)Real_CreateFileA, Hook_CreateFileA);
  DetourDetach(&(PVOID &)Real_CreateFileW, Hook_CreateFileW);
  DetourDetach(&(PVOID &)Real_CreateWindowExA, Hook_CreateWindowExA);
  DetourDetach(&(PVOID &)Real_GetTextExtentPoint32A,
               Hook_GetTextExtentPoint32A);
  DetourDetach(&(PVOID &)Real_GetTextExtentPoint32W,
               Hook_GetTextExtentPoint32W);
  DetourDetach(&(PVOID &)Real_GetTextExtentExPointA,
               Hook_GetTextExtentExPointA);
  DetourDetach(&(PVOID &)Real_GetTextExtentExPointW,
               Hook_GetTextExtentExPointW);
  DetourDetach(&(PVOID &)Real_GetCharWidth32A, Hook_GetCharWidth32A);
  DetourDetach(&(PVOID &)Real_GetCharWidth32W, Hook_GetCharWidth32W);
  DetourDetach(&(PVOID &)Real_MessageBoxA, Hook_MessageBoxA);
  DetourDetach(&(PVOID &)Real_DialogBoxParamA, Hook_DialogBoxParamA);
  DetourDetach(&(PVOID &)Real_AppendMenuA, Hook_AppendMenuA);
  DetourDetach(&(PVOID &)Real_InsertMenuA, Hook_InsertMenuA);
  DetourDetach(&(PVOID &)Real_ModifyMenuA, Hook_ModifyMenuA);
  if (Real_BacklogFunc != nullptr) {
    DetourDetach(&(PVOID &)Real_BacklogFunc, Hook_BacklogFunc);
  }
  DetourDetach(&(PVOID &)Real_GetTextMetricsA, Hook_GetTextMetricsA);
  DetourDetach(&(PVOID &)Real_ExtTextOutA, Hook_ExtTextOutA);
  // NOTE: Hook_TitleLookup removed — see InitPatch for explanation.

  DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    InitPatch();
  } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    CleanupPatch();
  }
  return TRUE;
}
