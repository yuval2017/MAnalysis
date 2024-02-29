// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string> 
#include <winternl.h>
#include <tchar.h>
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	DWORD processId;
	GetWindowThreadProcessId(hWnd, &processId);
	// Check if the window belongs to the target process
	if (processId == GetCurrentProcessId()) {

		// Set the window text to the injected process name
		SetWindowText(hWnd, L"This NOTEPAD was HACKED by Yuval!" );
		return FALSE; // Stop enumeration
	}

	return TRUE; // Continue enumeration
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		EnumWindows(EnumWindowsProc, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

