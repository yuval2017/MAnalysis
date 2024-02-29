

#include "utils.h"

DWORD GetPID(const WCHAR* AppName) { // Change parameter to wchar_t* for string
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (Process32First(hSnap, &pe)) {
		do {
			//std::wcout << pe.szExeFile << std::endl;
			if (!wcscmp(pe.szExeFile, AppName)) { // Compare wide character strings
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &pe));
	}
	CloseHandle(hSnap);
	return pid; // Return the PID
}

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
	LPCSTR moduleName = "kernel32.dll";
	LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA(moduleName), "LoadLibraryA");

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
