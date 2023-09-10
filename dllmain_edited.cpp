#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <iostream>
#include <MinHook.h>
#include <INIReader.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>

#if _WIN64 
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif


//Globals
HINSTANCE DllHandle;

//U can Edit this
bool InjectAtStart = true; //To inject script at start
bool Dump = false; //To dump loaded scripts (bytecodes). Use ljd to decode them.
std::string path = "D:\\"; //path of dumped scripts
bool showConsole = true;
int scriptInjectionCounter = 127;
std::string scriptExecutePath = ".\\";
std::string scriptName = "Script.out";
int executeScriptKey = 0x72;
int exitConsoleKey = 0x73;
std::string executeScriptKeyValue = "VK_F3";
std::string exitConsoleKeyValue = "VK_F4";

//Don't Edit this
typedef void* lua_State;
bool InjectTemp = false;
int countLoadbuffer = 0;
static int fileCount;

//Get Address functions
BYTE* FindPatternPointerAddress(DWORD pid, const void* data, size_t len)
{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION info;
        std::vector<char> chunk;
        BYTE* p = 0;
        while (p < si.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
            {
                p = (BYTE*)info.BaseAddress;
                chunk.resize(info.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
                {
                    for (size_t i = 0; i < (bytesRead - len); ++i)
                    {
                        if (memcmp(data, &chunk[i], len) == 0 && (void*)(p + i) != (void*)data)
                        {
                            return (BYTE*)p + i;
                        }
                    }
                }
                p += info.RegionSize;
            }
        }
        CloseHandle(process);
    }
    return 0;
}

uintptr_t GetCalledFunctionOfPointer(void* address) {
    // Address of the function whose CALL instruction you want to obtain
    void (*functionPtr)() = reinterpret_cast<void (*)()>(address); // Replace this with your function pointer address

    // Convert the function pointer to a pointer to an array of bytes
    unsigned char* bytePtr = reinterpret_cast<unsigned char*>(functionPtr);

    // The CALL instruction on x86-64 is encoded as: E8 xx xx xx xx (E8 followed by a 32-bit offset)
    // The CALL instruction on x86 is encoded as: E8 xx xx xx xx (E8 followed by a 32-bit offset)
    // Make sure the architecture corresponds to your system.

    unsigned char callOpCode = 0xE8; // CALL opcode on x86-64 and x86
    uintptr_t mask = 0xFFFFFFFF;
    uintptr_t callTargetOffset = *reinterpret_cast<uintptr_t*>(bytePtr + 1); // 32-bit offset after the opcode
    uintptr_t callTargetAddress = (reinterpret_cast<uintptr_t>(bytePtr) + 5 + callTargetOffset) & mask;

    return callTargetAddress;
}

//Hex Paterns
const BYTE loadbufferPatern[] = { 0xE8, 0x6F, 0x38, 0xFD, 0xFF }; //Hex patern to find loadbuffer pointer address
const BYTE pcallPatern[] = { 0xE8, 0x3B, 0xA3, 0xFB, 0xFF }; //Hex patern to find pcall pointer address

// Get addresses of luaL_loadbuffer and luaL_pcall functions
uintptr_t luaL_loadbufferAddress = GetCalledFunctionOfPointer(FindPatternPointerAddress(GetCurrentProcessId(), loadbufferPatern, sizeof(loadbufferPatern)));
uintptr_t luaL_pcallAddress = GetCalledFunctionOfPointer(FindPatternPointerAddress(GetCurrentProcessId(), pcallPatern, sizeof(pcallPatern)));

// Hooks
typedef int (*luaL_pcall)(lua_State* L, int nargs, int nresults, int errfunc);
luaL_pcall luaL_pcall_after = reinterpret_cast<luaL_pcall>(luaL_pcallAddress);

typedef int(*luaL_loadbuffer)(lua_State* L, const char* buff, size_t sz, const char* name);
luaL_loadbuffer luaL_loadbuffer_before = nullptr;
luaL_loadbuffer luaL_loadbuffer_after = reinterpret_cast<luaL_loadbuffer>(luaL_loadbufferAddress);

int __cdecl luaL_loadbuffer_hook(lua_State* L, const char* buff, size_t sz, const char* description) {
    if (Dump) {
        std::ofstream outfile(path + std::to_string(fileCount) + ".luac", std::ofstream::binary);
        outfile.write(buff, sz);
        outfile.close();
        fileCount = fileCount + 1;
    }

    if (InjectAtStart && countLoadbuffer == scriptInjectionCounter || InjectTemp) { // countLoadbuffer only useful for Elsrift
        if (InjectTemp) { InjectTemp = !InjectTemp; }
        // if (InjectAtStart) { InjectAtStart = !InjectAtStart; }
        std::ifstream infile(scriptExecutePath + scriptName, std::ofstream::binary); // Load LuaJit bytecode from Script.out (in the same directory as x2.exe)
        infile.seekg(0, infile.end);
        size_t size = infile.tellg();
        infile.seekg(0);
        char* buffer = new char[size];
        infile.read(buffer, size);
        luaL_loadbuffer_before(L, buffer, size, description) || luaL_pcall_after(L, 0, 0, 0); // LuaJit bytecode injection
    }

    if (showConsole) {
        std::cout << "Count : " << countLoadbuffer << "\n";
        std::cout << "Lua State : " << L << "\n";
    }
    countLoadbuffer = countLoadbuffer + 1;
    return luaL_loadbuffer_before(L, buff, sz, description);
}

void CleanupAndExit() {
    // Disable the hook on the luaL_loadbuffer function
    MH_DisableHook(reinterpret_cast<void**>(luaL_loadbuffer_after));

    // Uninitialize MinHook
    MH_Uninitialize();

    // Close the console if it was opened
    FreeConsole();
}

DWORD WINAPI EjectThread(LPVOID lpParameter) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    FreeLibraryAndExitThread(DllHandle, 0);
    return 0; // Ensure to return a DWORD value (0 in this case) as expected by the thread entry function
}

void shutdown(FILE* fp, std::string reason) {
    MH_Uninitialize();

    if (showConsole) {
        std::cout << reason << std::endl;
    }

    //std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    if (fp != nullptr) {
        fclose(fp);
    }
}

void readConfig() {
    // Path of ini file.
    INIReader reader("C:\\Temp\\config.ini");
    std::string dllConfigKey = "DllConfig";
    std::string keyboardKey = "Keyboard";

    if (reader.ParseError() == 0) {
        InjectAtStart = reader.GetBoolean(dllConfigKey, "InjectAtStart", true); //To inject script at start
        Dump = reader.GetBoolean(dllConfigKey, "Dump", false); //To dump loaded scripts (bytecodes). Use ljd to decode them.
        path = reader.Get(dllConfigKey, "dunpPath", "D:\\"); //Path of dumped scripts

        showConsole = reader.GetBoolean(dllConfigKey, "showConsole", true);

        scriptInjectionCounter = reader.GetInteger(dllConfigKey, "scriptInjectionCounter", -1);
        scriptExecutePath = reader.Get(dllConfigKey, "scriptExecutePath", ".\\");
        scriptName = reader.Get(dllConfigKey, "scriptName", "Script.out");

        executeScriptKeyValue = reader.Get(dllConfigKey, "executeScriptKey", "VK_F3");
        executeScriptKey = reader.GetInteger(keyboardKey, executeScriptKeyValue, 0x72);
        
        exitConsoleKeyValue = reader.Get(dllConfigKey, "exitConsoleKey", "VK_F4");
        exitConsoleKey = reader.GetInteger(keyboardKey, exitConsoleKeyValue, 0x73);
    }
}

DWORD WINAPI Menue(HINSTANCE hModule) {
    readConfig();
    if (showConsole) {
        AllocConsole();
    }
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout); //sets cout to be used with newly created console


    if (MH_Initialize() != MH_OK || MH_CreateHook(reinterpret_cast<void**>(luaL_loadbuffer_after), &luaL_loadbuffer_hook, reinterpret_cast<void**>(&luaL_loadbuffer_before)) != MH_OK) {
        shutdown(fp, "Minhook initialization or CreateHook failed!");
        return 0;
    }

    if (showConsole) {
        std::cout << "[" << exitConsoleKeyValue << "] Quit" << std::endl;
        std::cout << "[" << executeScriptKeyValue << "] Load " << scriptName << " manually" << std::endl;
        std::cout << "luaL_loadbuffer Address : " << std::hex << luaL_loadbufferAddress << std::endl;
        std::cout << "luaL_pcall Address : " << std::hex << luaL_pcallAddress << std::endl;

        std::cout << "\nHookedFunction enabled" << std::endl;
    }
    if (MH_EnableHook(reinterpret_cast<void**>(luaL_loadbuffer_after)) != MH_OK) {
        shutdown(fp, "luaL_loadbuffer_after: EnableHook failed!");
        return 0;
    }

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        if (GetAsyncKeyState(exitConsoleKey) & 0x8000) {
            if (showConsole) {
                std::cout << "[" << exitConsoleKeyValue << "] Pressed" << std::endl;
                std::cout << "HookedFunction disabled" << std::endl;
            }
            CleanupAndExit();
            break;
        }

        if (GetAsyncKeyState(executeScriptKey) & 0x8000 && !InjectTemp) {
            if (showConsole) {
                std::cout << "[" << executeScriptKeyValue << "] Pressed" << std::endl;
            }
            InjectTemp = !InjectTemp; // To load Script
        }
    }

    shutdown(fp, "Bye");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DllHandle = hModule;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Menue, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        EjectThread(nullptr);
        break;
    }
    return TRUE;
}
