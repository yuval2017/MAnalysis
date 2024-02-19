#include "pch.h"
#include <string> 
#include <windows.h>
#include <tchar.h>

// Callback function used with EnumWindows to enumerate top-level windows
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	// Buffers to store window title
	TCHAR buff[255];

	// Variables to store process ID
	DWORD pId;
	int currentPid = GetCurrentProcessId(); // Get the process ID of the current process
	if (!IsWindowVisible(hWnd)) {
		return TRUE;
	}
	// Get the process ID associated with the window
	DWORD dwThreadID = GetWindowThreadProcessId(hWnd, &pId);
	// Check if the window belongs to the current process
	if (currentPid && pId != currentPid) {
		return TRUE;
	}
	// Get the window title
	if (!GetWindowText(hWnd, buff, 254) > 0) {
		OutputDebugString(_T("Failed to get window title"));
	}
	OutputDebugString(_T("Extract the window title"));
	OutputDebugString(buff); // Output the window title to the debugger
	if (!SetWindowText(hWnd, _T("This NOTEPAD was HACKED by Yuval"))) {
		OutputDebugString(_T("Failed to set window title"));
	}
	OutputDebugString(_T("Changed the window title"));


	//Stop to check.
	return FALSE;
}

// Entry point function for the DLL
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	// Output a debug message indicating the DLL is loaded
	OutputDebugString(_T("Loaded"));

	// Handle different reasons for calling the DLLMain function
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Output a debug message indicating DLL_PROCESS_ATTACH
		OutputDebugString(_T("Attached dll"));
		// Enumerate all top-level windows and call EnumWindowsProc for each window
		EnumWindows((WNDENUMPROC)EnumWindowsProc, 0);
		break;
	case DLL_THREAD_ATTACH:
		// No action needed for DLL_THREAD_ATTACH
		break;
	case DLL_THREAD_DETACH:
		// No action needed for DLL_THREAD_DETACH
		break;
	case DLL_PROCESS_DETACH:
		// No action needed for DLL_PROCESS_DETACH
		break;
	}
	return TRUE; // Return TRUE to indicate successful execution
}
