// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <iostream>
#include <vector>
#include <d3d11.h>

HMODULE myhModule;

DWORD __stdcall ejectThread(LPVOID lpParameter) {
    Sleep(100);
    FreeLibraryAndExitThread(myhModule, 0);
}
// func prototype for hooking function inside steamoverlay
HRESULT(__fastcall* hookingFunc)(uint64_t pToHook, uint64_t pDest, uint64_t pReturnFuncAddress, int a4) = nullptr;

// steam present function prototype to return original function
typedef HRESULT(__fastcall* tPresentFunc)(IDXGISwapChain*, UINT, UINT);
tPresentFunc pPresentFuncOriginal = nullptr;

HRESULT __fastcall PresentHook(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
    std::cout << "Present Hooked" << std::endl;
}


DWORD_PTR getAddressFromSignature(std::vector<int> signature, DWORD_PTR startaddress = 0, DWORD_PTR endaddress = 0) {

    std::cout << "Scanning..." << std::endl;
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    if (startaddress == 0) {
        startaddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
    }
    if (endaddress == 0) {
        endaddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);
    }

    MEMORY_BASIC_INFORMATION mbi{ 0 };
    DWORD protectflags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

    for (DWORD_PTR i = startaddress; i < endaddress - signature.size(); i++) {
        if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi))) {
            if (mbi.Protect & protectflags || !(mbi.State & MEM_COMMIT)) {
                i += mbi.RegionSize;
                continue; // if bad address then don't read from it
            }
            for (DWORD_PTR k = (DWORD_PTR)mbi.BaseAddress; k < (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize - signature.size(); k++) {
                for (size_t j = 0; j < signature.size(); j++) {
                    if (signature.at(j) != -1 && signature.at(j) != *(BYTE*)(k + j))
                        break;
                    if (j + 1 == signature.size())
                        return k;
                }
            }
            i = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
    }
    return NULL;
}

DWORD_PTR aobInjectionNopFromSignature(std::vector<int> signature, DWORD_PTR startaddress = 0, DWORD_PTR endaddress = 0) {
    std::cout << "Injecting" << std::endl;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    if (startaddress == 0) {
        startaddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
    }
    if (endaddress == 0) {
        endaddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);
    }

    MEMORY_BASIC_INFORMATION mbi{ 0 };
    DWORD protectflags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

    for (DWORD_PTR i = startaddress; i < endaddress - signature.size(); i++) {
        if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi))) {
            if (mbi.Protect & protectflags || !(mbi.State & MEM_COMMIT)) {
                i += mbi.RegionSize;
                continue; // if bad address then don't read from it
            }
            for (DWORD_PTR k = (DWORD_PTR)mbi.BaseAddress; k < (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize - signature.size(); k++) {
                for (size_t j = 0; j < signature.size(); j++) {
                    if (signature.at(j) != -1 && signature.at(j) != *(BYTE*)(k + j))
                        break;
                    if (j + 1 == signature.size()) {
                        // Found the pattern, now replace with NOPs
                        std::cout << "Pattern found at: " << std::hex << k << std::endl;

                        // Change memory protection to allow writing
                        DWORD oldProtect;
                        if (VirtualProtect((LPVOID)k, signature.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            for (size_t n = 0; n < signature.size(); n++) {
                                *(BYTE*)(k + n) = 0x90; // NOP instruction
                            }
                            // Restore old protection
                            VirtualProtect((LPVOID)k, signature.size(), oldProtect, &oldProtect);
                        }
                        else {
                            std::cerr << "Failed to change memory protection." << std::endl;
                        }
                        return k; // Return the address where the pattern was found
                    }
                }
            }
            i = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
    }
    return NULL; // Pattern not found
}

void HookPresent()
{
    std::vector<int> sigPresent = { /* NEEEEEED signature pattern for IDXGISwapChain::Present */ };
    DWORD_PTR presentAddress = getAddressFromSignature(sigPresent);

    if (presentAddress) {
        // Hook the Present function
        pPresentFuncOriginal = (tPresentFunc)presentAddress;
        hookingFunc(presentAddress, (uint64_t)PresentHook, (uint64_t)pPresentFuncOriginal, 0);
        std::cout << "Present function hooked successfully" << std::endl;
    }
    else {
        std::cerr << "Failed to find the Present function signature" << std::endl;
    }
}

DWORD WINAPI menu() {
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    HookPresent();

    std::cout << "Press 0 to Exit | Press 1 for Infinity Ammo" << std::endl;
    while (1) {
        Sleep(100);
        if (GetAsyncKeyState(VK_NUMPAD0))
            break; // exit

        if (GetAsyncKeyState(VK_NUMPAD1)) {
            std::vector<int> sigAmmoSub = { 0x2B, 0x81, -1, -1, -1, -1, 0x33, 0xED }; // 2b 81 ? ? ? ? 33 ed
            DWORD_PTR Entry = aobInjectionNopFromSignature(sigAmmoSub);

            if (Entry == NULL) {
                std::cout << "Couldnt find the pattern" << std::endl;
            }

        }
    }

    fclose(fp);
    FreeConsole();
    CreateThread(0, 0, ejectThread, 0, 0, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myhModule = hModule;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)menu, NULL, 0, NULL);

        
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
