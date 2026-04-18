/*
 * DC4 Patch - d3dx9_43.dll Proxy
 * 
 * This proxies d3dx9_43.dll (DirectX redistributable, not protected by KnownDLLs)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HMODULE hOriginal = nullptr;

// Load original d3dx9_43.dll from System32
static void LoadOriginal() {
    if (hOriginal) return;
    
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\d3dx9_43.dll");
    hOriginal = LoadLibraryA(path);
    
    if (!hOriginal) {
        MessageBoxA(NULL, "Failed to load d3dx9_43.dll from System32!", "Error", MB_ICONERROR);
    }
}

// Generic forwarder - gets the real function and calls it
// This is called by the naked stubs below
static void* GetOriginalProc(const char* name) {
    LoadOriginal();
    if (!hOriginal) return nullptr;
    return GetProcAddress(hOriginal, name);
}

// D3DX9 has MANY exports, but games typically only use a few
// We'll export the most common ones and add more if needed

extern "C" {
    // Naked functions preserve the exact calling convention
    // They just jump to the real function
    
    #define PROXY_FUNC(name) \
        __declspec(naked) void __stdcall name() { \
            __asm { push #name } \
            __asm { call GetOriginalProc } \
            __asm { jmp eax } \
        }
    
    // Actually, naked + inline asm is tricky. Let's use a simpler approach.
    // We'll just forward using function pointers loaded at startup.
}

// Store function pointers
static FARPROC pD3DXCreateSprite = nullptr;
static FARPROC pD3DXCreateFontA = nullptr;
static FARPROC pD3DXCreateFontW = nullptr;
static FARPROC pD3DXCreateTextureFromFileA = nullptr;
static FARPROC pD3DXCreateTextureFromFileW = nullptr;
static FARPROC pD3DXLoadSurfaceFromFileA = nullptr;
static FARPROC pD3DXCompileShader = nullptr;
static FARPROC pD3DXCreateEffect = nullptr;
static FARPROC pD3DXMatrixMultiply = nullptr;
static FARPROC pD3DXVec3TransformCoord = nullptr;

#define LOAD_PROC(name) p##name = GetProcAddress(hOriginal, #name)

static void LoadAllProcs() {
    LoadOriginal();
    if (!hOriginal) return;
    
    // Load common D3DX9 functions - add more as needed
    LOAD_PROC(D3DXCreateSprite);
    LOAD_PROC(D3DXCreateFontA); 
    LOAD_PROC(D3DXCreateFontW);
    LOAD_PROC(D3DXCreateTextureFromFileA);
    LOAD_PROC(D3DXCreateTextureFromFileW);
    LOAD_PROC(D3DXLoadSurfaceFromFileA);
    LOAD_PROC(D3DXCompileShader);
    LOAD_PROC(D3DXCreateEffect);
    LOAD_PROC(D3DXMatrixMultiply);
    LOAD_PROC(D3DXVec3TransformCoord);
}

// Export wrappers - use __declspec(naked) for zero-overhead forwarding
extern "C" {
    __declspec(naked) void D3DXCreateSprite() { __asm { jmp [pD3DXCreateSprite] } }
    __declspec(naked) void D3DXCreateFontA() { __asm { jmp [pD3DXCreateFontA] } }
    __declspec(naked) void D3DXCreateFontW() { __asm { jmp [pD3DXCreateFontW] } }
    __declspec(naked) void D3DXCreateTextureFromFileA() { __asm { jmp [pD3DXCreateTextureFromFileA] } }
    __declspec(naked) void D3DXCreateTextureFromFileW() { __asm { jmp [pD3DXCreateTextureFromFileW] } }
    __declspec(naked) void D3DXLoadSurfaceFromFileA() { __asm { jmp [pD3DXLoadSurfaceFromFileA] } }
    __declspec(naked) void D3DXCompileShader() { __asm { jmp [pD3DXCompileShader] } }
    __declspec(naked) void D3DXCreateEffect() { __asm { jmp [pD3DXCreateEffect] } }
    __declspec(naked) void D3DXMatrixMultiply() { __asm { jmp [pD3DXMatrixMultiply] } }
    __declspec(naked) void D3DXVec3TransformCoord() { __asm { jmp [pD3DXVec3TransformCoord] } }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        LoadAllProcs();
        MessageBoxA(NULL, "d3dx9_43.dll proxy loaded!", "DC4 Patch", MB_OK);
    }
    return TRUE;
}
