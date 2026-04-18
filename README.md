# DCPatch
Circus-engine patch used for DC4.

This folder intentionally ships with:
- empty `DCPatch.ini` values
- empty `patch_names*.json` and `patch_ui*.json` templates

## Features

- `DCLauncher.exe` launches the game and injects `DCPatch.dll`
- Japanese locale handling:
  - Windows: Locale Emulator API path (embedded resources)
- Hooked text rendering and font override for dialogue/backlog
- JSON-based name mapping and UI/scenario-title translation
- Language-specific JSON support:
  - Indonesian: `_id`
  - English: `_eng`
  - legacy fallback: unsuffixed `.json`
- Backlog icon fix and backlog font hook with configurable RVAs
- File routing and graphics sync:
  - `id_Data` for Indonesian
  - `eng_data` for English
  - `.sync_manifest` + `.original_cache` used for restore/cleanup

## Repository Layout

```text
github_clean/
  CMakeLists.txt
  DCPatch.ini
  patch_names.json
  patch_names_id.json
  patch_names_eng.json
  patch_ui.json
  patch_ui_id.json
  patch_ui_eng.json
  src/
    dcpatch.cpp
    launcher.cpp
    launcher.rc
    resource.h
    ...
  Detours/
    src/
    LICENSE
  LoaderDll.dll
  LocaleEmulator.dll
  icon.ico
```

## Build (x86 only)

Requirements:
- Visual Studio C++ toolchain (x86 tools)
- CMake 3.15+

Build commands (Developer Command Prompt for VS, x86):

```bat
cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Outputs:
- `build\DCPatch.dll`
- `build\DCLauncher.exe`

Notes:
- `CMakeLists.txt` is configured for 32-bit only. x64 build is blocked.
- `LoaderDll.dll` and `LocaleEmulator.dll` are embedded into `DCLauncher.exe` by `src/launcher.rc`.

## Third-Party Licenses

Third-party notice and provenance:
- `THIRD_PARTY_NOTICES.md`

License-related files:
- `Detours/LICENSE`
- `LICENSES/Detours-MIT.txt`
- `LICENSES/Locale-Emulator-LICENSE-NOTES.txt`
- `LICENSES/LGPL-3.0-link.txt`
- `LICENSES/GPL-3.0-link.txt`

## Credits

- CircusEnginePatchs by `cokkeijigen`:
  - https://github.com/cokkeijigen/CircusEnginePatchs/tree/master

## Install / Run

1. Copy to the game folder:
   - `DCLauncher.exe`
   - `DCPatch.dll`
   - `DCPatch.ini`
   - language JSON files you plan to use
2. Set `[Launcher] TargetExe` in `DCPatch.ini` (for example `DC4.EXE`).
3. Run `DCLauncher.exe`.

If `TargetExe` is blank, launcher auto-detects the first suitable `.exe` and writes it back to INI.

## DC4 Recommended Settings (Copy-Paste)

`DCPatch.ini` in this repo is intentionally empty as a template.  
For DC4, you can start with this full baseline:

```ini
[Fonts]
BacklogFont=MS Gothic
BacklogSize=-19
DialogueFont=MS Gothic
DialogueSize=-19
BacklogNameFont=MS Gothic
BacklogNameSize=-11
BacklogXOffset=0
BacklogLineSpacing=0
BacklogYOffset=12
BacklogNameXOffset=13
BacklogNameYOffset=0
BacklogNameSpacing=0
BacklogDialogSpacing=0
AdvancedSettings=1

[Settings]
ShowBacklogIcon=1
EnableFileRedirection=1
Language=1
DisableBacklogFont=0
DisableBacklogSpacing=0
DisableBacklogTranslation=0

[Addresses]
BacklogHookRVA=0x5276
BacklogFuncRVA=0x4EE0
BacklogTableRVA=0xBDA00
BacklogStride=0x544
BacklogTextOffset=0x0
BacklogNameOffset=0x400
BacklogMaxEntries=200

[Launcher]
TargetExe=DC4.EXE
```

Quick language switch:
- Indonesian: `Language=1` (uses `patch_names_id.json` + `patch_ui_id.json`)
- English: `Language=2` (uses `patch_names_eng.json` + `patch_ui_eng.json`)
- Japanese/original mode: `Language=0` (uses unsuffixed JSON files)

## DCPatch.ini Reference

The `Default` column below means internal runtime fallback when a key is blank.

### `[Fonts]`

| Key | Default | Description |
| --- | --- | --- |
| `BacklogFont` | `MS Gothic` | Backlog dialogue font face |
| `BacklogSize` | `-19` | Backlog dialogue font size |
| `DialogueFont` | `MS Gothic` | Main dialogue font face |
| `DialogueSize` | `-19` | Main dialogue font size |
| `BacklogNameFont` | `MS Gothic` | Backlog speaker-name font face |
| `BacklogNameSize` | `-11` | Backlog speaker-name font size |
| `BacklogXOffset` | `0` | Backlog glyph X offset |
| `BacklogLineSpacing` | `0` | Extra backlog line spacing |
| `BacklogYOffset` | `12` | Backlog glyph Y offset |
| `BacklogNameXOffset` | `13` | Speaker-name X offset |
| `BacklogNameYOffset` | `0` | Speaker-name Y offset |
| `BacklogNameSpacing` | `0` | Extra spacing for speaker names |
| `BacklogDialogSpacing` | `0` | Extra spacing for backlog dialogue glyphs |
| `AdvancedSettings` | `1` | Enables advanced backlog spacing UI |

### `[Settings]`

| Key | Default | Description |
| --- | --- | --- |
| `ShowBacklogIcon` | `1` | Enable backlog icon patch path |
| `EnableFileRedirection` | `1` | Legacy compatibility flag (used for default language fallback) |
| `Language` | `1` | `0=Japanese`, `1=Indonesian`, `2=English` |
| `DisableBacklogFont` | `0` | Disable backlog font override |
| `DisableBacklogSpacing` | `0` | Disable backlog spacing adjustments |
| `DisableBacklogTranslation` | `0` | Disable UI translation while backlog renders |

### `[Addresses]`

| Key | Default | Description |
| --- | --- | --- |
| `BacklogHookRVA` | `0` | RVA for backlog icon JmpWrite hook site |
| `BacklogFuncRVA` | `0` | RVA of backlog render function for Detours attach |
| `BacklogTableRVA` | `0` | RVA of backlog icon table base |
| `BacklogStride` | `0x544` | Bytes per backlog table entry |
| `BacklogTextOffset` | `0x0` | Text field offset inside entry |
| `BacklogNameOffset` | `0x400` | Name field offset inside entry |
| `BacklogMaxEntries` | `200` | Safety cap for patched entries |

### `[Launcher]`

| Key | Default | Description |
| --- | --- | --- |
| `TargetExe` | empty | Game executable filename/path |

## Language and JSON File Selection

| `Language` | Primary files | Fallback files |
| --- | --- | --- |
| `0` (Japanese) | `patch_names.json`, `patch_ui.json` | none |
| `1` (Indonesian) | `patch_names_id.json`, `patch_ui_id.json` | `patch_names.json`, `patch_ui.json` |
| `2` (English) | `patch_names_eng.json`, `patch_ui_eng.json` | `patch_names.json`, `patch_ui.json` |

JSON loading behavior:
- If selected file is missing/empty, fallback file is tried (for language `1/2`).
- Name table falls back to built-in DC4 mappings when no JSON entries are loaded.
- UI table built-in fallback is only used in Indonesian mode.

## JSON Schema

`patch_names*.json`:

```json
[
  { "from": "Nemu", "to": "音夢" },
  { "from": "Sakura", "to": "さくら" }
]
```

`patch_ui*.json`:

```json
[
  { "japanese": "セーブ", "translated": "Save" },
  { "japanese": "ロード", "translated": "Load" }
]
```

Notes:
- Save files as UTF-8.
- `japanese` should be original Japanese text.
- The parser reads arrays of objects and uses string fields only.

## DC4 Address Example (Version Specific)

For the tested DC4 build, typical values were:

```ini
[Addresses]
BacklogHookRVA=0x5276
BacklogFuncRVA=0x4EE0
BacklogTableRVA=0xBDA00
BacklogStride=0x544
BacklogTextOffset=0x0
BacklogNameOffset=0x400
BacklogMaxEntries=200
```

Important:
- These RVAs are executable-version dependent.
- Backlog hooks are intentionally guarded: non-zero INI values are required before hook attach/patch.

## Tutorial: Finding `[Addresses]` for Your Build

Use this when your executable is a different build and backlog hooks are not active.

Important behavior from the code:
- Auto-scan resolves candidate addresses and logs them.
- Auto-scan does **not** auto-enable risky hooks.
- Hooks are only activated when specific INI keys are explicitly non-zero.

Feature-to-key mapping:
- Backlog font/render hook:
  - must set `BacklogFuncRVA` (non-zero)
- Backlog icon table patch hook:
  - must set `ShowBacklogIcon=1`
  - must set `BacklogHookRVA` (non-zero)
  - `BacklogTableRVA` is recommended if table auto-scan fails

Notes:
- Empty values are allowed in INI; runtime falls back internally.
- Hex values like `0x5276` are supported (`wcstoul(..., base 0)`), decimal also works.

### Method A (Best): Two-Pass Auto-Scan Workflow

Pass 1 (discover):
1. In `[Addresses]`, leave `BacklogHookRVA`, `BacklogFuncRVA`, `BacklogTableRVA` blank (or `0`).
2. Ensure `ShowBacklogIcon=1` in `[Settings]` if you want icon hook data.
3. Launch through `DCLauncher.exe`.
4. Capture debug logs using DebugView/x64dbg output window.
5. Record these log lines:
   - `DCPatch: BacklogHookAddr auto-scan => ... (RVA 0x...)`
   - `DCPatch: BacklogFuncAddr auto-walk => ... (RVA 0x...)`
   - `DCPatch: BacklogTableBase auto-scan => ... (RVA 0x...)`
   - `DCPatch INFO: Auto-scan found BacklogFunc ... BacklogFuncRVA=0x...`
   - `DCPatch INFO: Auto-scan found BacklogHookAddr ... BacklogHookRVA=0x...`

Pass 2 (activate):
1. Copy found RVAs into `[Addresses]`.
2. Relaunch game.
3. Confirm activation logs:
   - `DCPatch: BacklogFunc hook ENABLED at ... (from INI)`
   - No `InstallBacklogIconHook failed` warning.
4. If you see table warnings (`BacklogTableBase not found`), set `BacklogTableRVA` explicitly from your scan/debugger.

Typical DC4 result:

```ini
[Addresses]
BacklogHookRVA=0x5276
BacklogFuncRVA=0x4EE0
BacklogTableRVA=0xBDA00
BacklogStride=0x544
BacklogTextOffset=0x0
BacklogNameOffset=0x400
BacklogMaxEntries=200
```

### Method B (Manual Fallback): x32dbg / IDA

Use this if Method A cannot resolve stable values.

1. Open EXE in x32dbg and note module base.
2. In `.text`, search for pattern `33 DB 83 E8 01` (`xor ebx,ebx; sub eax,1`).
3. Compute:
   - `BacklogHookRVA = HookAddress - ModuleBase`
4. From that location, walk backward to function prologue (`55 8B EC`) to get:
   - `BacklogFuncRVA = FuncStart - ModuleBase`
5. In the same function body, identify backlog table pointer in `.data`:
   - `BacklogTableRVA = TableBase - ModuleBase`
6. Keep structure fields at defaults unless your build proves otherwise:
   - `BacklogStride=0x544`
   - `BacklogTextOffset=0x0`
   - `BacklogNameOffset=0x400`
   - `BacklogMaxEntries=200`

Safety checklist:
- Set one address at a time and retest.
- Keep crash logs (`dc4_crash.log` / `dc_crash.log`) for bad RVA diagnosis.
- If only font hook is needed, set only `BacklogFuncRVA` first.
- If only icon hook is needed, set `ShowBacklogIcon=1` + `BacklogHookRVA` first.

## Troubleshooting

- If launcher says game EXE not found: set `[Launcher] TargetExe`.
- If translations do not apply: check `Language` and matching JSON filename suffix.
- If backlog icon/font hooks do not run: confirm `[Addresses]` RVAs for your exact executable.
- Crash logs can appear as `dc4_crash.log` or `dc_crash.log`.
- Runtime diagnostics are also emitted through `OutputDebugString` (view with DebugView/x64dbg).
