@echo off
echo ==========================================
echo Building D.C. Patch (Launcher + DLL)
echo ==========================================

call "E:\VS\dotnet\VC\Auxiliary\Build\vcvars32.bat"

if exist build rmdir /s /q build
mkdir build
cd build

echo [1/2] Configuring CMake...
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo [ERROR] CMake failed.
    pause
    exit /b %errorlevel%
)

echo [2/2] Compiling...
nmake
if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed.
    pause
    exit /b %errorlevel%
)

echo.
echo ==========================================
echo [SUCCESS] Build completed!
echo ==========================================
echo.
echo Output files:
echo   - build\DCLauncher.exe
echo   - build\DCPatch.dll
echo.
echo Installation:
echo   1. Copy BOTH files to the DC4 game folder
echo   2. Run DC4Launcher.exe instead of DC4.EXE
echo.
pause
