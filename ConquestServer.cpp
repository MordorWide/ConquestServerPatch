#include <windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <tlhelp32.h>


bool WriteMemory(HANDLE process, LPVOID address, const std::vector<BYTE>& sequence) {
    SIZE_T writtenBytes;
    if (WriteProcessMemory(process, address, sequence.data(), sequence.size(), &writtenBytes) &&
        writtenBytes == sequence.size()) {
        std::cout << "Memory patched successfully at address: " << address << "\n";
        return true;
    }
    else {
        std::cerr << "Failed to write memory.\n";
        return false;
    }
}

bool ReadMemory(HANDLE process, LPVOID address, std::vector<BYTE>& buffer) {
    SIZE_T bytesRead;
    if (ReadProcessMemory(process, address, buffer.data(), buffer.size(), &bytesRead) &&
        bytesRead == buffer.size()) {
        return true;
    }
    else {
        std::cerr << "Failed to read memory.\n";
        return false;
    }
}

// Function to get the handle of a process by its name
HANDLE GetProcessHandleByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error code: " << GetLastError() << "\n";
        return NULL;
    }

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                CloseHandle(hSnapshot);
                return hProcess;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    //std::cerr << "Process not found: " << std::wstring(processName.begin(), processName.end()) << "\n";
    return NULL;
}

bool WriteProtectedMemory(HANDLE hProcess, LPVOID address, std::vector<BYTE>& buffer) {
    DWORD oldProtect;

    // Change memory protection to writable
    if (!VirtualProtectEx(hProcess, address, buffer.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Now, write to the memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, address, buffer.data(), buffer.size(), &bytesWritten)) {
        std::cerr << "Failed to write to process memory. Error: " << GetLastError() << std::endl;
        // Restore original protection before returning
        VirtualProtectEx(hProcess, address, buffer.size(), oldProtect, &oldProtect);
        return false;
    }

    // Restore original memory protection
    if (!VirtualProtectEx(hProcess, address, buffer.size(), oldProtect, &oldProtect)) {
        std::cerr << "Failed to restore memory protection. Error: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    // The address and value to monitor and replace
    const DWORD PATCH_SSLCHECK_ADDRESS = 0x006091B9; // Target address (SSL check)
    const std::vector<BYTE> PATCH_SSLCHECK_PATTERN = { 0x81, 0xe1, 0xee, 0x0f, 0x00, 0x00, 0x83, 0xc1, 0x15, 0x8b, 0xc1 };
    const std::vector<BYTE> PATCH_SSLCHECK_BYPASS_PATTERN = { 0x81, 0xe1, 0xee, 0x0f, 0x00, 0x00, 0xb8, 0x15, 0x00, 0x00, 0x00 };

    // Step 1: Build the command line for OriginalConquestServer.exe
    // Construct the arguments string
    std::wstring targetProgram = L"OriginalConquestServer.exe";
    std::wstring arguments;
    for (int i = 1; i < argc; ++i) {
        arguments += argv[i];
        arguments += L" ";
    }

    // Step 1: Launch OriginalConquestServer.exe with ShellExecute
    HINSTANCE hInstance = ShellExecute(
        NULL,
        L"open",             // Operation to perform
        targetProgram.c_str(), // Path to the target program
        arguments.c_str(),     // Arguments to pass
        NULL,                  // Default working directory
        SW_SHOWNORMAL          // Show the program normally
    );

    if ((INT_PTR)hInstance <= 32) {
        std::cerr << "Failed to launch OriginalConquestServer.exe. Error code: " << GetLastError() << "\n";
        return 1;
    }

    std::wcout << L"OriginalConquestServer.exe launched successfully." << "\n";

    // Step 2: Get the process handle to OriginalConquestServer.exe
    HANDLE hProcess = GetProcessHandleByName(L"OriginalConquestServer.exe");
    if (!hProcess) {
        std::cerr << "Could not find OriginalConquestServer.exe process.\n";
        return 1;
    }

    // Step 3: Scan and patch memory for the SSL check
    std::vector<BYTE> buffer(PATCH_SSLCHECK_PATTERN.size());
    while (true) {
        // Read the memory at the target address
        if (ReadMemory(hProcess, (LPVOID)PATCH_SSLCHECK_ADDRESS, buffer)) {
            //std::cout << "Read sequence at address " << std::hex << PATCH_SSLCHECK_ADDRESS << ": ";
            //for (BYTE byte : buffer) {
            //     std::cout << "0x" << std::hex << (int)byte << " ";
            //}
            //std::cout << "\n";

            // Check if the target sequence is found
            if (buffer == PATCH_SSLCHECK_PATTERN) {
                std::cout << "Target sequence found. Patching...\n";
                if (WriteMemory(hProcess, (LPVOID)PATCH_SSLCHECK_ADDRESS, PATCH_SSLCHECK_BYPASS_PATTERN)) {
                    std::cout << "Patched SSL check bypass successfully.\n";
                    break;
                }
                else {
                    std::cout << "Failed to patch SSL check bypass. Exiting...\n";
                    TerminateProcess(hProcess, -1);
                    return -1;
                }
            }
        }
        // We nearly do busy waiting... Just suspend shortly...
        Sleep(1);
    }

    // Step 4: Patch the remaining stuff in data
    std::cout << "Patch the remaining data locations...\n";

    // Patch EANation Endpoint 1 - Patch 'fesl.ea.com\x00' (6665736c2e65612e636f6d00) -> 'mordorwi.de\x00' (6d6f72646f7277692e646500)
    const DWORD PATCH_EANATION_ENDPOINT_1_ADDRESS = 0x009A19008;
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_1_PATTERN = { 0x66, 0x65, 0x73, 0x6c, 0x2e, 0x65, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x00 };
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_1_REPLACEMENT = { 0x6d, 0x6f, 0x72, 0x64, 0x6f, 0x72, 0x77, 0x69, 0x2e, 0x64, 0x65, 0x00 };
    std::cout << "Trying to patch EANation Endpoint 1...\n";
    while (!WriteProtectedMemory(hProcess, (LPVOID)PATCH_EANATION_ENDPOINT_1_ADDRESS, PATCH_EANATION_ENDPOINT_1_REPLACEMENT)) {
        Sleep(1);
    }
    std::cout << "Patched EANation Endpoint 1 successfully.\n";

    // Patch EANation Endpoint 2 - Patch '.fesl\x00' (2e6665736c00) -> '.mord\x00' (2e6d6f726400)
    const DWORD PATCH_EANATION_ENDPOINT_2_ADDRESS = 0x009A1B84;
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_2_PATTERN = { 0x2e, 0x66, 0x65, 0x73, 0x6c, 0x00 };
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_2_REPLACEMENT = { 0x2e, 0x6d, 0x6f, 0x72, 0x64, 0x00 };
    std::cout << "Trying to patch EANation Endpoint 2...\n";
    while (!WriteProtectedMemory(hProcess, (LPVOID)PATCH_EANATION_ENDPOINT_2_ADDRESS, PATCH_EANATION_ENDPOINT_2_REPLACEMENT)) {
        Sleep(1);
    }
    std::cout << "Patched EANation Endpoint 2 successfully.\n";

    // Patch EANation Endpoint 3 - Patch '.ea.com\x00' (2e65612e636f6d00) to 'ordorwi.de\x00' intro(6f7277692e646500)
    const DWORD PATCH_EANATION_ENDPOINT_3_ADDRESS = 0x009A1B7C;
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_3_PATTERN = { 0x2e, 0x65, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x00 };
    std::vector<BYTE> PATCH_EANATION_ENDPOINT_3_REPLACEMENT = { 0x6f, 0x72, 0x77, 0x69, 0x2e, 0x64, 0x65, 0x00 };
    std::cout << "Trying to patch EANation Endpoint 3...\n";
    while (!WriteProtectedMemory(hProcess, (LPVOID)PATCH_EANATION_ENDPOINT_3_ADDRESS, PATCH_EANATION_ENDPOINT_3_REPLACEMENT)) {
        Sleep(1);
    }
    std::cout << "Patched EANation Endpoint 3 successfully.\n";

    // Step 5: Clean up
    CloseHandle(hProcess);

    // Report shortly...
    std::cout << "Successfully patched the values! Exiting in 5 seconds...\n";
    Sleep(5000);
    return 0;
}
