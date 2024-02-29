#include "utils.h"


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



int main() {

	// Write function pointer to shared memory
	//WriteFunctionPointerToSharedMemory(DisplayMessageBox);

	// Wait for input before exiting
	//std::cout << "Press Enter to exit...";
	//std::cin.get();

	//return 0;

	// Step 1: Find the Process ID (PID) of the target .exe
	unsigned char code[] = "\xb8\x0a\x00\x00\x00\xc3";
	const wchar_t* testApp = L"ConsoleApplication1.exe";
	const wchar_t* notePad = L"notepad.exe";
	const wchar_t* chrome = L"chrome.exe";
	const wchar_t* FireFox = L"firefox.exe";
	const wchar_t* taskmgrName = L"Taskmgr.exe"; // Corrected process name for Task Manager
	const wchar_t* procexp64 = L"procexp64.exe";
	const wchar_t* procmon = L"Procmon.exe";
	const wchar_t* cmd = L"cmd.exe";

	const char *dllPath = "C:\\Users\\ISE\\Desktop\\Ass2\\Injected\\Debug\\Injected.dll";
	const char *dllPath2 = "C:\\Users\\ISE\\Desktop\\Ass2\\Injected\\x64\\Debug\\Injected.dll";
	const char *dllPath3 = "Z:\\MalwareAnalysis\\ChromeDll\\x64\\Debug\\ChromeDll.dll";


	DWORD pid = GetPID(procexp64);
	if (pid == 0) {
		printf("Target process not found!\n");
		return 1;
	}


	
	if (InjectDllIntoProcess(pid, dllPath3)) {
		std::cout << "DLL injected successfully!" << std::endl;
	}
	else {
		std::cout << "DLL injected Fail!" << std::endl;
	}
	std::cout << "Press any key to exit" << std::endl;
	getchar();

	return 0;
}