/*
 * D.C. Patch Launcher
 *
 * Launches DC4.EXE with Japanese locale and injects DC4Patch.dll.
 *
 * On Wine/Proton: Sets Japanese locale in registry + LC_ALL=ja_JP.UTF-8.
 * On Windows:     Uses Locale Emulator (LoaderDll.dll), with silent fallback.
 *
 * Distribution: Only DC4Launcher.exe + DC4Patch.dll needed.
 */

#define WIN32_LEAN_AND_MEAN
#include "resource.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>


// ============================================================================
// Wine/Proton detection
// ============================================================================
typedef const char *(CDECL *pfnWineGetVersion)(void);

static bool IsRunningUnderWine() {
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll)
    return false;
  pfnWineGetVersion pWineGetVersion =
      (pfnWineGetVersion)GetProcAddress(hNtdll, "wine_get_version");
  return (pWineGetVersion != NULL);
}

// ============================================================================
// Locale Emulator structures (from LEProc/LoaderWrapper.cs)
// ============================================================================

#pragma pack(push, 1)

struct TIME_FIELDS {
  USHORT Year;
  USHORT Month;
  USHORT Day;
  USHORT Hour;
  USHORT Minute;
  USHORT Second;
  USHORT Milliseconds;
  USHORT Weekday;
};

struct RTL_TIME_ZONE_INFORMATION {
  LONG Bias;
  WCHAR StandardName[32];
  TIME_FIELDS StandardDate;
  LONG StandardBias;
  WCHAR DaylightName[32];
  TIME_FIELDS DaylightDate;
  LONG DaylightBias;
};

struct LEB {
  DWORD AnsiCodePage;
  DWORD OemCodePage;
  DWORD LocaleID;
  DWORD DefaultCharset;
  DWORD HookUILanguageAPI;
  BYTE DefaultFaceName[64];
  RTL_TIME_ZONE_INFORMATION Timezone;
};

#pragma pack(pop)

typedef DWORD(WINAPI *pfnLeCreateProcess)(
    void *leb, LPCWSTR applicationName, LPCWSTR commandLine,
    LPCWSTR currentDirectory, DWORD creationFlags, LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation, LPVOID processAttributes,
    LPVOID threadAttributes, LPVOID environment, LPVOID token);

// ============================================================================
// Extract embedded resource to file
// ============================================================================
static bool ExtractResource(HMODULE hModule, LPCSTR resourceName,
                            const char *outputPath) {
  HRSRC hRes = FindResourceA(hModule, resourceName, RT_RCDATA);
  if (!hRes)
    return false;
  HGLOBAL hData = LoadResource(hModule, hRes);
  if (!hData)
    return false;
  DWORD size = SizeofResource(hModule, hRes);
  void *data = LockResource(hData);
  if (!data || size == 0)
    return false;
  HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return false;
  DWORD written;
  BOOL ok = WriteFile(hFile, data, size, &written, NULL);
  CloseHandle(hFile);
  return ok && (written == size);
}

// ============================================================================
// Inject DLL into a running process
// ============================================================================
static bool InjectDLL(HANDLE hProcess, const char *dllPath) {
  SIZE_T pathLen = strlen(dllPath) + 1;
  LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remotePath) {
    MessageBoxA(NULL, "Failed to allocate memory in target process",
                "Injection Error", MB_ICONERROR);
    return false;
  }
  if (!WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL)) {
    MessageBoxA(NULL, "Failed to write to target process memory",
                "Injection Error", MB_ICONERROR);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    return false;
  }
  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
  if (!pLoadLibraryA) {
    MessageBoxA(NULL, "Failed to get LoadLibraryA address", "Injection Error",
                MB_ICONERROR);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    return false;
  }
  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                      remotePath, 0, NULL);
  if (!hThread) {
    char msg[256];
    sprintf_s(msg, "Failed to create remote thread. Error: %lu",
              GetLastError());
    MessageBoxA(NULL, msg, "Injection Error", MB_ICONERROR);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    return false;
  }
  WaitForSingleObject(hThread, 5000);
  CloseHandle(hThread);
  VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
  return true;
}

// ============================================================================
// Set Japanese locale in registry (Wine/Proton path)
// Wine reads HKCU\Control Panel\International to determine ANSI codepage.
// Setting these before launch makes DC4.EXE see Japanese locale (CP932).
// ============================================================================
static void SetJapaneseLocaleRegistry() {
  HKEY hKey;
  if (RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\International", 0,
                      NULL, 0, KEY_SET_VALUE, NULL, &hKey,
                      NULL) == ERROR_SUCCESS) {
    RegSetValueExA(hKey, "ACP", 0, REG_SZ, (const BYTE *)"932", 4);
    RegSetValueExA(hKey, "OEMCP", 0, REG_SZ, (const BYTE *)"932", 4);
    RegSetValueExA(hKey, "MACCP", 0, REG_SZ, (const BYTE *)"10001", 6);
    RegSetValueExA(hKey, "Locale", 0, REG_SZ, (const BYTE *)"00000411", 9);
    RegSetValueExA(hKey, "LocaleName", 0, REG_SZ, (const BYTE *)"ja-JP", 6);
    RegCloseKey(hKey);
  }
  if (RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Nls\\CodePage", 0,
                      NULL, 0, KEY_SET_VALUE, NULL, &hKey,
                      NULL) == ERROR_SUCCESS) {
    RegSetValueExA(hKey, "ACP", 0, REG_SZ, (const BYTE *)"932", 4);
    RegSetValueExA(hKey, "OEMCP", 0, REG_SZ, (const BYTE *)"932", 4);
    RegCloseKey(hKey);
  }
}

// ============================================================================
// Create process with Japanese locale via environment (Wine/Proton path)
// ============================================================================
static bool CreateProcessWithLC_ALL(const char *exePath, const char *currentDir,
                                    DWORD extraFlags, PROCESS_INFORMATION *pi) {
  // Write Japanese locale to Wine registry before spawning the process
  SetJapaneseLocaleRegistry();

  LPCH envBlock = GetEnvironmentStringsA();
  if (!envBlock)
    return false;

  SIZE_T envSize = 0;
  {
    const char *p = envBlock;
    while (*p) {
      SIZE_T len = strlen(p) + 1;
      envSize += len;
      p += len;
    }
    envSize++;
  }

  const char *lcAll = "LC_ALL=ja_JP.UTF-8";
  const char *lang = "LANG=ja_JP.UTF-8";
  const char *wineDllOverrides = "WINEDLLOVERRIDES=mfplat=n,b;mfplay=n,b;mfreadwrite=n,b;mfmediaengine=n,b;mfsrcsnk=n,b;msmpeg2vdec=n,b;winegstreamer=";
  const char *wineESync = "WINEESYNC=0";
  const char *wineDebug = "WINEDEBUG=-all,err-all,fixme-all";

  SIZE_T lcAllLen = strlen(lcAll) + 1;
  SIZE_T langLen = strlen(lang) + 1;
  SIZE_T overrideLen = strlen(wineDllOverrides) + 1;
  SIZE_T esyncLen = strlen(wineESync) + 1;
  SIZE_T debugLen = strlen(wineDebug) + 1;

  char *newEnv = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   envSize + lcAllLen + langLen + overrideLen + esyncLen + debugLen + 64);
  if (!newEnv) {
    FreeEnvironmentStringsA(envBlock);
    return false;
  }

  char *dst = newEnv;
  const char *src = envBlock;
  while (*src) {
    SIZE_T varLen = strlen(src) + 1;
    if (_strnicmp(src, "LC_ALL=", 7) != 0 && _strnicmp(src, "LANG=", 5) != 0 &&
        _strnicmp(src, "WINEDLLOVERRIDES=", 17) != 0 && _strnicmp(src, "WINEESYNC=", 10) != 0 &&
        _strnicmp(src, "WINEDEBUG=", 10) != 0) {
      memcpy(dst, src, varLen);
      dst += varLen;
    }
    src += varLen;
  }
  memcpy(dst, lcAll, lcAllLen);
  dst += lcAllLen;
  memcpy(dst, lang, langLen);
  dst += langLen;
  memcpy(dst, wineDllOverrides, overrideLen);
  dst += overrideLen;
  memcpy(dst, wineESync, esyncLen);
  dst += esyncLen;
  memcpy(dst, wineDebug, debugLen);
  dst += debugLen;
  *dst = '\0';

  FreeEnvironmentStringsA(envBlock);

  STARTUPINFOA siA = {sizeof(siA)};
  *pi = {};
  BOOL ok = CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                           CREATE_SUSPENDED | extraFlags, newEnv, currentDir,
                           &siA, pi);

  HeapFree(GetProcessHeap(), 0, newEnv);
  return ok ? true : false;
}

// ============================================================================
// Launch with Locale Emulator (Windows path)
// ============================================================================
static bool LaunchWithLocaleEmulator(HINSTANCE hInstance, const char *exePath,
                                     const char *currentDir,
                                     PROCESS_INFORMATION *pi) {
  char loaderDllPath[MAX_PATH];
  char localeEmuPath[MAX_PATH];
  sprintf_s(loaderDllPath, "%s\\LoaderDll.dll", currentDir);
  sprintf_s(localeEmuPath, "%s\\LocaleEmulator.dll", currentDir);

  if (GetFileAttributesA(loaderDllPath) == INVALID_FILE_ATTRIBUTES)
    if (!ExtractResource(hInstance, MAKEINTRESOURCEA(IDR_LOADERDLL),
                         loaderDllPath))
      return false;

  if (GetFileAttributesA(localeEmuPath) == INVALID_FILE_ATTRIBUTES)
    if (!ExtractResource(hInstance, MAKEINTRESOURCEA(IDR_LOCALEEMU),
                         localeEmuPath))
      return false;

  HMODULE hLoaderDll = LoadLibraryA(loaderDllPath);
  if (!hLoaderDll)
    return false;

  pfnLeCreateProcess pLeCreateProcess =
      (pfnLeCreateProcess)GetProcAddress(hLoaderDll, "LeCreateProcess");
  if (!pLeCreateProcess) {
    FreeLibrary(hLoaderDll);
    return false;
  }

  LEB leb = {};
  leb.AnsiCodePage = 932;
  leb.OemCodePage = 932;
  leb.LocaleID = 0x0411;
  leb.DefaultCharset = 128; // SHIFTJIS_CHARSET
  leb.HookUILanguageAPI = 0;
  memset(&leb.Timezone, 0, sizeof(leb.Timezone));
  leb.Timezone.Bias = -540;
  wcscpy_s(leb.Timezone.StandardName, 32, L"Tokyo Standard Time");
  wcscpy_s(leb.Timezone.DaylightName, 32, L"Tokyo Standard Time");

  wchar_t wExePath[MAX_PATH], wCurrentDir[MAX_PATH], wCommandLine[MAX_PATH * 2];
  MultiByteToWideChar(CP_ACP, 0, exePath, -1, wExePath, MAX_PATH);
  MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, MAX_PATH);
  swprintf_s(wCommandLine, L"\"%s\"", wExePath);

  STARTUPINFOW si = {sizeof(si)};
  *pi = {};
  BYTE lebBuffer[sizeof(LEB) + 4] = {};
  memcpy(lebBuffer, &leb, sizeof(LEB));

  DWORD ret = pLeCreateProcess(lebBuffer, wExePath, wCommandLine, wCurrentDir,
                               0x00000004, &si, pi, NULL, NULL, NULL, NULL);

  FreeLibrary(hLoaderDll);
  return (ret == 0);
}

// ============================================================================
// Read target EXE name from DC4Patch.ini [Launcher] section.
// Falls back to scanning for .exe in current dir, then "DC4.EXE".
// ============================================================================
static void GetTargetExePath(const char *currentDir, char *exePathOut,
                             size_t exePathLen, char *dllPathOut,
                             size_t dllPathLen) {
  // Build INI path
  char iniPath[MAX_PATH];
  sprintf_s(iniPath, "%s\\DCPatch.ini", currentDir);

  // Try reading [Launcher] TargetExe from INI
  char targetExe[MAX_PATH] = {};
  GetPrivateProfileStringA("Launcher", "TargetExe", "", targetExe,
                           MAX_PATH, iniPath);

  if (targetExe[0] != '\0') {
    // Use value from INI directly
    if (strchr(targetExe, '\\') || strchr(targetExe, '/')) {
      // Absolute or relative path given
      sprintf_s(exePathOut, exePathLen, "%s", targetExe);
    } else {
      sprintf_s(exePathOut, exePathLen, "%s\\%s", currentDir, targetExe);
    }
  } else {
    // Auto-detect: scan current dir for *.exe, skip known launcher/helper names
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    sprintf_s(pattern, "%s\\*.exe", currentDir);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    bool found = false;
    if (hFind != INVALID_HANDLE_VALUE) {
      do {
        const char *name = fd.cFileName;
        // Skip known non-game EXEs
        if (_stricmp(name, "DC4Launcher.exe") == 0) continue;
        if (_stricmp(name, "DC4PHLauncher.exe") == 0) continue;
        if (_strnicmp(name, "Directx", 7) == 0) continue;
        if (_stricmp(name, "unins000.exe") == 0) continue;
        if (_stricmp(name, "dstart.exe") == 0) continue;
        if (strstr(name, "setup") != nullptr) continue;
        if (strstr(name, "Setup") != nullptr) continue;
        if (strstr(name, "_dstart") != nullptr) continue;
        // Pick the first remaining EXE
        sprintf_s(exePathOut, exePathLen, "%s\\%s", currentDir, name);
        // Write it to INI so user knows which was chosen
        WritePrivateProfileStringA("Launcher", "TargetExe", name, iniPath);
        found = true;
        break;
      } while (FindNextFileA(hFind, &fd));
      FindClose(hFind);
    }
    if (!found) {
      // Last resort fallback
      sprintf_s(exePathOut, exePathLen, "%s\\DC4.EXE", currentDir);
    }
  }

  // DLL path is always DC4Patch.dll next to the launcher
  sprintf_s(dllPathOut, dllPathLen, "%s\\DCPatch.dll", currentDir);
}

// ============================================================================
// Write the [Launcher] section to INI if it doesn't have one yet
// ============================================================================
static void EnsureLauncherIniSection(const char *iniPath) {
  char buf[MAX_PATH] = {};
  GetPrivateProfileStringA("Launcher", "TargetExe", "__MISSING__", buf,
                           MAX_PATH, iniPath);
  if (strcmp(buf, "__MISSING__") == 0) {
    // Section/key missing — write a comment block
    // GetPrivateProfileString can't write comments, so we append manually
    HANDLE h = CreateFileA(iniPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
      // Seek to end and append
      SetFilePointer(h, 0, NULL, FILE_END);
      const char *section =
          "\r\n[Launcher]\r\n"
          "; Name of the game EXE to launch (just filename, e.g. DC3DD.exe)\r\n"
          "; Leave blank to auto-detect (first .exe in the game folder)\r\n"
          "TargetExe=\r\n";
      DWORD w;
      WriteFile(h, section, (DWORD)strlen(section), &w, NULL);
      CloseHandle(h);
    }
  }
}

// ============================================================================
// Main
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  char currentDir[MAX_PATH];
  // Use the directory of the launcher EXE itself, not the working directory
  GetModuleFileNameA(NULL, currentDir, MAX_PATH);
  char *lastSlash = strrchr(currentDir, '\\');
  if (lastSlash) *lastSlash = '\0';

  char iniPath[MAX_PATH];
  sprintf_s(iniPath, "%s\\DC4Patch.ini", currentDir);

  // Add [Launcher] section to INI if not present
  EnsureLauncherIniSection(iniPath);

  char exePath[MAX_PATH];
  char dllPath[MAX_PATH];
  GetTargetExePath(currentDir, exePath, MAX_PATH, dllPath, MAX_PATH);

  // Validate EXE
  if (GetFileAttributesA(exePath) == INVALID_FILE_ATTRIBUTES) {
    char msg[512];
    sprintf_s(msg,
              "Game EXE not found:\n%s\n\n"
              "Please set TargetExe= in DC4Patch.ini [Launcher] section.",
              exePath);
    MessageBoxA(NULL, msg, "DC4 Patch Launcher", MB_ICONERROR);
    return 1;
  }

  // Validate DLL
  if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
    char msg[512];
    sprintf_s(msg, "DC4Patch.dll not found:\n%s\n\nPlace DC4Patch.dll in the game folder.", dllPath);
    MessageBoxA(NULL, msg, "DC4 Patch Launcher", MB_ICONERROR);
    return 1;
  }

  PROCESS_INFORMATION pi = {};
  bool isWine = IsRunningUnderWine();

  if (isWine) {
    // Wine/Proton: LE kernel hooks unavailable — use registry + LC_ALL
    if (!CreateProcessWithLC_ALL(exePath, currentDir, 0, &pi)) {
      char msg[256];
      sprintf_s(msg, "Failed to start game under Wine. Error: %lu",
                GetLastError());
      MessageBoxA(NULL, msg, "Patch Launcher", MB_ICONERROR);
      return 1;
    }
  } else {
    // Windows: try Locale Emulator, then silent plain fallback
    if (!LaunchWithLocaleEmulator(hInstance, exePath, currentDir, &pi)) {
      STARTUPINFOA siA = {sizeof(siA)};
      pi = {};
      if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                          NULL, currentDir, &siA, &pi)) {
        char msg[256];
        sprintf_s(msg, "Failed to start game. Error: %lu", GetLastError());
        MessageBoxA(NULL, msg, "Patch Launcher", MB_ICONERROR);
        return 1;
      }
    }
  }

  bool injected = InjectDLL(pi.hProcess, dllPath);
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  if (!injected) {
    MessageBoxA(NULL,
                "DLL injection failed, but game is running without the patch.",
                "Patch Launcher", MB_ICONWARNING);
    return 1;
  }
  return 0;
}
