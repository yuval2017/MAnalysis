#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h> 
#include <stdlib.h>
#include <string.h>
#include <iostream>


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

int main() {


	// Step 1: Find the Process ID (PID) of the target .exe
	unsigned char code[] = "\xb8\x0a\x00\x00\x00\xc3";
	const wchar_t* testApp= L"ConsoleApplication1.exe";
	const wchar_t* notePad = L"notepad.exe";
	const wchar_t* chrome = L"chrome.exe";
	DWORD pid = GetPID(notePad);
	if (pid == 0) {
		printf("Target process not found!\n");
		return 1;
	}
	const char *dllPath = "C:\\Users\\ISE\\Desktop\\Ass2\\Injected\\Debug\\Injected.dll";
	const char *dllPath2 = "C:\\Users\\ISE\\Desktop\\Ass2\\Injected\\x64\\Debug\\Injected.dll";
	const char *dllPath3 = "C:\\Users\\ISE\\source\\repos\\ChromeDll\\x64\\Debug\\ChromeDll.dll";


	if (InjectDllIntoProcess(pid, dllPath2)) {
		std::cout << "DLL injected successfully!" << std::endl;
	}
	std::cout << "Press any key to exit" << std::endl;
	getchar();
	
	return 0;
}
