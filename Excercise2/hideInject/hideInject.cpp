// hideInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h> 
#include <stdlib.h>
#include <string.h>
#include "tchar.h"
#include <fstream>
#include <string>
#include <Shlwapi.h>
// Link against Shlwapi.lib
#pragma comment(lib, "Shlwapi.lib")

HANDLE GetRemoteDllHandle(DWORD targetPID, const WCHAR *fullDllPath)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return NULL; // Error: Unable to create snapshot
	}

	HANDLE hInjectedDll = NULL;
	MODULEENTRY32W me32;
	me32.dwSize = sizeof(MODULEENTRY32W);

	if (!Module32FirstW(hSnapshot, &me32))
	{
		CloseHandle(hSnapshot);
		return NULL; // Error: Unable to retrieve first module
	}

	do
	{
		if (_wcsicmp(fullDllPath, me32.szExePath) == 0)
		{
			hInjectedDll = me32.hModule;
			break;
		}
	} while (Module32NextW(hSnapshot, &me32));

	CloseHandle(hSnapshot);
	return hInjectedDll;
}

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

#include <windows.h>

BOOL RemoveDll(HANDLE hProcess, const WCHAR *fullDllPath)
{
	// Get handle to Kernel32.dll
	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if (!hKernel32)
	{
		// Error: Unable to get handle to Kernel32.dll
		return FALSE;
	}

	// Get address of FreeLibrary function
	FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");
	if (!pFreeLibrary)
	{
		// Error: FreeLibrary function not found
		return FALSE;
	}

	// Get handle of the injected DLL
	HANDLE hInjectedDll = GetRemoteDllHandle(GetProcessId(hProcess), fullDllPath);
	if (!hInjectedDll)
	{
		// Error: DLL not found in the target process
		wprintf(L"The DLL '%s' wasn't found in the target process.\n", fullDllPath);
		return FALSE;
	}

	// Create a remote thread to call FreeLibrary in the target process
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hInjectedDll, 0, NULL);

	if (!hThread)
	{
		// Error: Unable to create remote thread
		return FALSE;
	}

	// Wait for the thread to finish executing
	WaitForSingleObject(hThread, INFINITE);

	// Clean up the thread handle
	CloseHandle(hThread);

	// Return success
	return TRUE;
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

int main() {
	const wchar_t* taskmgrName = L"Taskmgr.exe";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPID(taskmgrName));
	std::string dllName = "APIHooking.dll"; // Change this to your DLL file name
	std::string dllPath = getDllPathInSameFolderAsExe(dllName);
	if (!dllPath.empty()) {
		std::cout << "DLL is in the same folder as the executable. Path: " << dllPath << std::endl;
	}
	else {
		std::cout << "DLL is not in the same folder as the executable." << std::endl;
	}

	if (!PathFileExistsW(std::wstring(dllPath.begin(), dllPath.end()).c_str())) {
		printf("The specified DLL path does not exist.\n");
		return EXIT_FAILURE;
	}
	if (!RemoveDll(hProcess, std::wstring(dllPath.begin(), dllPath.end()).c_str())) {
		std::cerr << "Failed to Remove DLL." << std::endl;
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}
	std::cout << "FreeLibrary is successed." << std::endl;
	
	std::cout << "Press any key to exit" << std::endl;
	getchar();
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
