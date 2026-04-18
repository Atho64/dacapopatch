# Third-Party Notices

This project includes third-party components. This file documents what is bundled, where it came from, and license pointers.

## 1) Microsoft Detours

- Component path:
  - `Detours/src/*`
  - `Detours/LICENSE`
- Upstream:
  - https://github.com/microsoft/Detours
- License:
  - MIT (copied in `Detours/LICENSE`)
  - Mirror copy in `LICENSES/Detours-MIT.txt`

## 2) Locale Emulator runtime DLLs

- Bundled files:
  - `LoaderDll.dll`
  - `LocaleEmulator.dll`
- Used by:
  - `src/launcher.cpp`
  - Embedded via `src/launcher.rc`
- Upstream projects:
  - https://github.com/xupefei/Locale-Emulator
  - https://github.com/xupefei/Locale-Emulator-Core
- Upstream license statements:
  - Locale-Emulator repository lists LGPL-3.0/GPL-3.0 for project licensing context.
  - Locale-Emulator-Core README states `Loader`, `LoaderDll`, and `LocaleEmulator` sources are LGPL-3.0.
- Local license pointers:
  - `LICENSES/Locale-Emulator-LICENSE-NOTES.txt`
  - `LICENSES/LGPL-3.0-link.txt`
  - `LICENSES/GPL-3.0-link.txt`

### Binary fingerprints (SHA-256)

- `LocaleEmulator.dll`
  - `C79C175FDAD174AA46A72197D148316299A56F950AAAB1B84930D09EE1084A88`
- `LoaderDll.dll`
  - `82FAE0F44F4CA0C9C37907DF74CEF2415EEB5FAE1CF8D4F36F34FFCAF7E3CC0C`

### Signature metadata

- Both bundled DLLs are currently unsigned in this package.
- Keep hashes above if you want provenance tracking in release notes.
