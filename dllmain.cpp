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

typedef HRESULT(__stdcall* PresentOriginal)(IDXGISwapChain* swap_chain, UINT SyncInterval, UINT Flags);
PresentOriginal present_original = nullptr;

HRESULT __stdcall present_hook(IDXGISwapChain* swap_chain, UINT SyncInterval, UINT Flags)
{
    return present_original(swap_chain, SyncInterval, Flags);
}

void HookPresent()
{
    std::vector<int> sigPresent = { 0x48, 0x89, 0x5C, 0x24, -1, 0x48, 0x89, 0x6C, 0x24, -1, 0x48, 0x89, 0x74, 0x24, -1, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, -1, 0x41, 0x8B, 0xE8 }; // 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 41 8B E8
    DWORD_PTR presentAddress = getAddressFromSignature(sigPresent);
    std::vector<int> sigCreateHook = { 0x48, 0x89, 0x5C, 0x24, -1, 0x57, 0x48, 0x83, 0xEC, -1, 0x33, 0xC0, 0x48, 0x89, 0x44, 0x24 }; // 48 89 5C 24 ? 57 48 83 EC ? 33 C0 48 89 44 24
    DWORD_PTR createhookAddress = getAddressFromSignature(sigCreateHook);

    __int64(__fastcall * CreateHook)(unsigned __int64 pFuncAddress, __int64 pDetourFuncAddress, unsigned __int64* pOriginalFuncAddressOut, int a4);

    CreateHook = (decltype(CreateHook))createhookAddress;
    CreateHook(presentAddress, (__int64)&present_hook, (unsigned __int64*)&present_original, 1);

    if (present_original != nullptr)
    {
        std::cout << "Present function hooked successfully!" << std::endl;
    }
    else {
        std::cout << "Failed to hook Present function." << std::endl;
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
