/*
 * DC4 Patch - dsound.dll Proxy using Linker Forwarding
 * 
 * This version uses #pragma comment(linker) to forward exports
 * directly to the system DLL, avoiding wrapper function issues.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// Forward all dsound exports to the system DLL
// Format: /export:ExportName=ModuleName.ExportName
#pragma comment(linker, "/export:DirectSoundCreate=dsound_original.DirectSoundCreate")
#pragma comment(linker, "/export:DirectSoundEnumerateA=dsound_original.DirectSoundEnumerateA")
#pragma comment(linker, "/export:DirectSoundEnumerateW=dsound_original.DirectSoundEnumerateW")
#pragma comment(linker, "/export:DllCanUnloadNow=dsound_original.DllCanUnloadNow")
#pragma comment(linker, "/export:DllGetClassObject=dsound_original.DllGetClassObject")
#pragma comment(linker, "/export:DirectSoundCaptureCreate=dsound_original.DirectSoundCaptureCreate")
#pragma comment(linker, "/export:DirectSoundCaptureEnumerateA=dsound_original.DirectSoundCaptureEnumerateA")
#pragma comment(linker, "/export:DirectSoundCaptureEnumerateW=dsound_original.DirectSoundCaptureEnumerateW")
#pragma comment(linker, "/export:DirectSoundCreate8=dsound_original.DirectSoundCreate8")
#pragma comment(linker, "/export:DirectSoundCaptureCreate8=dsound_original.DirectSoundCaptureCreate8")
#pragma comment(linker, "/export:DirectSoundFullDuplexCreate=dsound_original.DirectSoundFullDuplexCreate")
#pragma comment(linker, "/export:GetDeviceID=dsound_original.GetDeviceID")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        ::DisableThreadLibraryCalls(hModule);
        ::MessageBoxA(NULL, "dsound.dll proxy loaded!\n\nUsing linker forwarding method.", "DC4 Patch", MB_OK);
    }
    return TRUE;
}
