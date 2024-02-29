#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h> 
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string> 
#include <vector>
bool InjectDllIntoProcess(DWORD processId, const char* dllPath) {
	// Open the target process
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (processHandle == NULL) {
		std::cerr << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
		return false;
	}

	// Allocate memory for the DLL path in the target process
	LPVOID dllPathAddress = VirtualAllocEx(processHandle, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dllPathAddress == NULL) {
		std::cerr << "Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
		CloseHandle(processHandle);
		return false;
	}

	// Write the DLL path to the allocated memory in the target process
	if (!WriteProcessMemory(processHandle, dllPathAddress, dllPath, strlen(dllPath) + 1, NULL)) {
		std::cerr << "Failed to write the DLL path to the target process. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(processHandle);
		return false;
	}

	// Get the address of the LoadLibraryA function in the kernel32 module
	LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (loadLibraryAddress == NULL) {
		std::cerr << "Failed to get the address of LoadLibraryA. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(processHandle);
		return false;
	}

	// Create a remote thread in the target process to load the DLL
	HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddress, 0, NULL);
	if (remoteThread == NULL) {
		std::cerr << "Failed to create a remote thread in the target process. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(processHandle);
		return false;
	}

	// Wait for the remote thread to finish
	WaitForSingleObject(remoteThread, INFINITE);

	// Clean up
	CloseHandle(remoteThread);
	VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
	CloseHandle(processHandle);

	

	return true;
}

// Function to be injected
DWORD WINAPI InjectedFunction(LPVOID lpParam) {
	MessageBoxA(NULL, "Hello from injected function!", "Injected", MB_OK);
	return 0;
}
DWORD GetPID(const wchar_t* AppName) { // Change parameter to wchar_t* for string
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (Process32First(hSnap, &pe)) {
		do {
			if (!wcscmp(pe.szExeFile, AppName)) { // Compare wide character strings
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &pe));
	}
	CloseHandle(hSnap);
	return pid; // Return the PID
}
std::string getDllPathInSameFolderAsExe(const std::string& dllName) {
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH); // Get the path of the executable file
	std::string exeDirectory = exePath;
	size_t lastBackslashIndex = exeDirectory.find_last_of("\\");
	exeDirectory = exeDirectory.substr(0, lastBackslashIndex + 1); // Extract directory portion

	std::string dllPath = exeDirectory + dllName; // Append DLL file name to directory path

	// Check if the DLL file exists in the directory
	DWORD attributes = GetFileAttributesA(dllPath.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		return dllPath;
	}
	else {
		return ""; // Return empty string if DLL is not found
	}
}


// Your existing code here...
std::vector<DWORD> GetAllProcessPids(const wchar_t* processName) {
	std::vector<DWORD> pids;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);
		if (Process32First(hSnapshot, &pe32)) {
			do {
				if (wcscmp(pe32.szExeFile, processName) == 0) {
					pids.push_back(pe32.th32ProcessID);
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	return pids;
}

// Your existing code here...

int main(int argc, char* argv[]) {
	std::string dllName = "Injected.dll"; // Change this to your DLL file name
	std::string dllPath = getDllPathInSameFolderAsExe(dllName);
	if (dllPath.empty()) {
		std::cerr << "DLL not found in the same folder as the executable." << std::endl;
		return 1;
	}

	if (argc > 1) { // If command-line arguments are provided
		std::vector<DWORD> pids;
		for (int i = 1; i < argc; ++i) {
			DWORD pid = std::atoi(argv[i]); // Convert argument to DWORD (PID)
			if (pid != 0) {
				pids.push_back(pid);
			}
		}

		if (!pids.empty()) { // If valid PIDs were provided
			for (DWORD pid : pids) {
				if (InjectDllIntoProcess(pid, dllPath.c_str())) {
					std::cout << "DLL injected successfully into process with PID: " << pid << std::endl;
				}
				else {
					std::cerr << "Failed to inject DLL into process with PID: " << pid << std::endl;
				}
			}
		}
		else {
			std::cerr << "No valid process IDs provided." << std::endl;
		}
	}
	else { // If no command-line arguments are provided, inject into all instances of Notepad
		std::vector<DWORD> notepadPids = GetAllProcessPids(L"notepad.exe");
		if (notepadPids.empty()) {
			std::cerr << "No instances of Notepad found." << std::endl;
		}
		else {
			for (DWORD pid : notepadPids) {
				if (InjectDllIntoProcess(pid, dllPath.c_str())) {
					std::cout << "DLL injected successfully into Notepad with PID: " << pid << std::endl;
				}
				else {
					std::cerr << "Failed to inject DLL into Notepad with PID: " << pid << std::endl;
				}
			}
		}
	}

	std::cout << "Press any key to exit" << std::endl;
	getchar();

	return 0;
}
