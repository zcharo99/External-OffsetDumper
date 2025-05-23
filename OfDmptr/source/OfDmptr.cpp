#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <format>
#include <string>
#include <thread>
#include <cmath>
#include <Psapi.h>
#include "main.hpp"
#include <cmath>
#include <cstdint>  
#include <thread>
#include "Security/xorstr.hpp"

using namespace Offsets;

/*
Hey!
This is a simple offset dumper for roblox made by Volxphy.
I hope you enjoy it!

Credits: Volxphy (you wont even mention me)
Special Thanks to Forlorn (yea you are the best) for giving me this awesome idea and showing me how it works!

AT LEAST FUCKING STAR MY REPO!
*/

/*

ill do a simple explaining for you :)
*/

// im getting UserId and PlaceId from Latest Roblox LOGS so that it works on everyone's run
auto userid_str = cUserId(); 
int32_t myUserId = std::stoull(userid_str, nullptr, 0);
uintptr_t displayableUserId = std::stoull(userid_str, nullptr, 0);
auto id_str = cPlaceId();
uintptr_t id = std::stoull(id_str, nullptr, 0);


// this is the main function where everything starts
int main() {

HWND hwnd = FindWindowA(nullptr, xorstr_("Roblox"));
DWORD procId = 0;
if (hwnd) {
    GetWindowThreadProcessId(hwnd, &procId);
    Globals::state.windowHandle = hwnd;
    Globals::state.processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
}

    if (!Globals::state.windowHandle) {
        std::cerr << xorstr_("[-] Failed to find Roblox") << std::endl;
        std::cin.get();
        return 1;
    }
    uintptr_t base = 0;
    DWORD size = 0;
    HMODULE hModule = nullptr;
    MODULEINFO moduleInfo = {};


    std::cout << xorstr_("[*] Game started in PlaceId: ") << id << std::endl;
    std::cout << xorstr_("[*] Game started with UserId: ") << displayableUserId << std::endl;

	// here you are just getting the base address of the roblox proc
    if (EnumProcessModules(Globals::state.windowHandle, &hModule, sizeof(hModule), &size)) {
        if (GetModuleInformation(Globals::state.windowHandle, hModule, &moduleInfo, sizeof(moduleInfo))) {
            base = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            std::cout << xorstr_("[*] BaseAddress: 0x") << std::hex << base << std::dec << std::endl;
        }
        else {  
            // fails anyways doesnt matter 
        }
    }
    else {
    }

    // Getting DataModel through logs
    uintptr_t datamodel = Tasks::GetDataModel();

    if (!datamodel) {
        std::cerr << xorstr_("[-] Failed to locate DataModel") << std::endl;
        return 1;
    }
    // im thinking about why i didnt use spdlog atp maybe ill change that later
    std::cout << xorstr_("[*] DataModel located at: 0x") << std::hex << std::uppercase << datamodel << std::dec << std::endl;
   


	// you can get the Name Offset by searching for "Ugc" on the Datamodel
    while (true)
    {
        uintptr_t ptr = read<uintptr_t>(datamodel + Offsets::offsets.name);
        std::string instancename = readstring(ptr);

        if (instancename == xorstr_("Ugc"))
        {
            printf(xorstr_("[+] Name: %#llx\n"), Offsets::offsets.name);
            break;
        }

        Offsets::offsets.name += 1;
    }
    

	// thats also an easy offset, just search for "PlaceId", wich is defined earlier from logs on the datamodel
    while (true)
    {
        uintptr_t placeid = read<uintptr_t>(datamodel + Offsets::offsets.placeid);

        if (placeid == id)
        {
            printf(xorstr_("[+] PlaceId: 0x%X\n"), Offsets::offsets.placeid);
            printf(xorstr_("[+] GameId: 0x%X\n"), Offsets::offsets.placeid);
            break;
        }

        Offsets::offsets.placeid += 1;
    }
    uintptr_t workspaceptr; // --> thats just an initialValue

    // here is where it gets interesting
    while (true)
    {
		workspaceptr = read<uintptr_t>(datamodel + Offsets::offsets.workspace); // we are getting the Workspace Pointer by reading the datamodel + offset wich is 0x0 at this point
		uintptr_t workspacename = read<uintptr_t>(workspaceptr + Offsets::offsets.name); // Here we are getting the name of the workspace by USING the offset "Name" wich we were getting earlier.
        std::string name = readstring(workspacename);

        if (name == xorstr_("Workspace"))
        {
            printf(xorstr_("[+] Workspace: %#llx\n"), Offsets::offsets.workspace);
            break;
        }

        Offsets::offsets.workspace += 1;
    }

	// because we setip the Workspace pointer we can easily get the parent offset by just searching for Ugc (remember? logical that its the Parent)
    while (true)
    {
        uintptr_t parent_ptr = read<uintptr_t>(workspaceptr + Offsets::offsets.parent);
        uintptr_t name_ptr = read<uintptr_t>(parent_ptr + Offsets::offsets.name);
        std::string name = readstring(name_ptr);

        if (name == xorstr_("Ugc"))
        {
            printf(xorstr_("[+] Parent: %#llx\n"), Offsets::offsets.parent);
            break;
        }

        Offsets::offsets.parent += 1;
    }

    // getting classdescriptor is more advanced
    while (true)
    {
        uintptr_t class_descriptor_ptr = read<uintptr_t>(datamodel + offsets.classdescriptor); // --> init pointer (just datamodel + 0x0)
		uintptr_t classname_ptr = read<uintptr_t>(class_descriptor_ptr + 0x8); // --> this is the offset for class name (*name is always 0x8)
        std::string classname = readstring(classname_ptr);

        if (classname == xorstr_("DataModel"))
        {
            printf(xorstr_("[+] ClassDescriptor: %#llx\n"), offsets.classdescriptor);
            break;
        }

        offsets.classdescriptor += 1;
    }
    uintptr_t playersaddress;
    while (true)
    {
        uintptr_t start = read<uintptr_t>(datamodel + offsets.children);
        uintptr_t instances = read<uintptr_t>(start);
        bool found = false;

        for (int i = 0; i < 30; i++)
        {
            uintptr_t instance = read<uintptr_t>(instances + i * 0x10);
            uintptr_t name_ptr = read<uintptr_t>(instance + offsets.name);
            std::string name = readstring(name_ptr);

            if (name == xorstr_("Players"))
            {
                printf(xorstr_("[+] Children: %#llx\n"), offsets.children);
                found = true;
                playersaddress = instance;
                break;
            }
        }

        if (found)
            break;

        offsets.children += 1;
    }
    uintptr_t possibleEnd = 0;
    for (int off = 0x8; off < 0x50; off += 8) {
        uintptr_t val = read<uintptr_t>(datamodel + offsets.children + off);
        if ((val - offsets.childrenend) % 0x10 == 0 && val > offsets.childrenend) {
            possibleEnd = val;
            printf(xorstr_("[+] ChildrenEnd: 0x%X\n"), off);
            break;
        }
    }


    while (true)
    {
        int64_t loaded = read<int64_t>(datamodel + offsets.loaded);

        if (loaded == 31)
        {
            printf(xorstr_("[+] Gameloaded: %#llx\n"), offsets.loaded);
            break;
        }

        offsets.loaded += 1;
    }
    uintptr_t cameraptr;

    while (true) {
        cameraptr = read<uintptr_t>(workspaceptr + offsets.camera);
        uintptr_t cameraname = read<uintptr_t>(cameraptr + offsets.name);
        std::string name = readstring(cameraname);

        if (name == xorstr_("Camera"))
        {
            printf(xorstr_("[+] Camera: %#llx\n"), offsets.camera);
            break;
        }
        offsets.camera += 1;

    }
    uintptr_t localPlayerPtr = 0;
    while (true) {
        localPlayerPtr = read<uintptr_t>(playersaddress + offsets.localplayer);
        if (localPlayerPtr) {
            // verify its fr the players children
            uintptr_t childrenStart = read<uintptr_t>(playersaddress + offsets.children);
            uintptr_t instances = read<uintptr_t>(childrenStart);
            for (int i = 0; i < 30; i++) {
                uintptr_t inst = read<uintptr_t>(instances + i * 0x10);
                if (inst == localPlayerPtr) {
                    printf(xorstr_("[+] LocalPlayer: 0x%X\n"), offsets.localplayer);
                    goto GOT_LOCAL;
                }
            }
        }
        offsets.localplayer++;
    }
GOT_LOCAL:;
    uintptr_t characterPtr = 0;
    uintptr_t namePtr = read<uintptr_t>(localPlayerPtr + offsets.name);
    std::string myName = readstring(namePtr);
    while (true) {
        characterPtr = read<uintptr_t>(localPlayerPtr + offsets.character);
        if (characterPtr) {
            uintptr_t cnamePtr = read<uintptr_t>(characterPtr + offsets.name);
            if (readstring(cnamePtr) == myName) {
                break;
            }
        }
        offsets.character++;
    }

    uintptr_t humanoidPtr = 0;
    while (true) {
        humanoidPtr = read<uintptr_t>(characterPtr + offsets.humanoid);
        if (humanoidPtr) {
            uintptr_t cdPtr = read<uintptr_t>(humanoidPtr + offsets.classdescriptor);
            uintptr_t cnPtr = read<uintptr_t>(cdPtr + 0x8);
            if (readstring(cnPtr) == xorstr_("Humanoid")) {
                //printf("[*] Humanoidpntr: 0x%x\n", offsets.humanoid);
                break;
            }
        }
        offsets.humanoid++;
    }
    while (true) {
        float jp = read<float>(humanoidPtr + offsets.JumpPower);
        if (fabs(jp - 50.0f) < 0.001f) {
            printf(xorstr_("[+] JumpPower: 0x%X\n"), offsets.JumpPower);
            break;
        }
        offsets.JumpPower += sizeof(float);
    }

    int foundWalkSpeeds = 0;
    const float epsilon = 0.001f;
    uintptr_t searchOffset = 0x0;
    while (searchOffset < 0x1000 && foundWalkSpeeds < 2) {
        float ws = read<float>(humanoidPtr + searchOffset);
        if (fabs(ws - 16.0f) < epsilon) {
            if (foundWalkSpeeds == 0) {
                offsets.walkspeedA = searchOffset;
                printf(xorstr_("[+] WalkspeedA: 0x%X\n"), offsets.walkspeedA);
            }
            else if (foundWalkSpeeds == 1) {
                offsets.walkspeedB = searchOffset;
                printf(xorstr_("[+] WalkspeedB: 0x%X\n"), offsets.walkspeedB);
            }
            foundWalkSpeeds++;
        }
        searchOffset += sizeof(float);
    }

    int foundGravities = 0;
    const float defaultGravity = 196.2f;

    uintptr_t dummydif = 0x0; 

    while (offsets.gravitys < 0x1000 && foundGravities < 2) {
        float g = read<float>(workspaceptr + offsets.gravity);

        if (fabs(g - defaultGravity) < epsilon) {
            printf(xorstr_("[+] Gravity: 0x%X\n"), offsets.gravity);
            foundGravities++;

            if (foundGravities == 1) {
                dummydif = offsets.gravitys;
                break;
            }
        }

        offsets.gravity += sizeof(float) * 2;
    }



    const float defaultHealth = 100.0f;
    std::vector<uint32_t> healthCandidates;
    bool found = false;
    while (offsets.health < 0x1000 && !found) {
        float h = read<float>(humanoidPtr + offsets.health);
        if (std::fabs(h - defaultHealth) < epsilon) {
            offsets.health = offsets.health;
            found = true;
        }
        offsets.health += sizeof(float);
    }
    if (found) {
        float val = read<float>(humanoidPtr + offsets.health);
        printf(xorstr_("[+] Health: 0x%X\n"), offsets.health);
    }


    const float defaultFov = 70.0f * (3.1415926f / 180.0f);
    while (true) {
        float f = read<float>(cameraptr + offsets.fov);
        if (fabs(f - defaultFov) < epsilon) {
            printf(xorstr_("[+] FOV: 0x%X\n"), offsets.fov);
            break;
        }
        offsets.fov += sizeof(float);
    }

    while (true) {
        int32_t val = read<int32_t>(localPlayerPtr + offsets.userid);
        if (val == myUserId) {
            printf(xorstr_("[+] UserId: 0x%X\n"), offsets.userid + 0x10); // apparentely its + 0x10 but im not sure :shrug:
            break;
        }
        offsets.userid += sizeof(int32_t);
    } // BROKEN


    Tasks::saveOffsetsToFile();
    system("pause");
    return 0;
}
