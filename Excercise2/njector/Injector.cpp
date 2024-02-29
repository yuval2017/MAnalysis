#include "utils.h"
#include <Shlwapi.h>
// Link against Shlwapi.lib
#pragma comment(lib, "Shlwapi.lib")

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
	// Write function pointer to shared memory
	//WriteFunctionPointerToSharedMemory(DisplayMessageBox);

	// Wait for input before exiting
	//std::cout << "Press Enter to exit...";
	//std::cin.get();


	const wchar_t* taskmgrName = L"Taskmgr.exe";

	std::string dllName = "APIHooking.dll"; // Change this to your DLL file name
	std::string dllPath = getDllPathInSameFolderAsExe(dllName);
	if (!dllPath.empty()) {
		std::cout << "DLL is in the same folder as the executable. Path: " << dllPath << std::endl;
	}
	else {
		std::cout << "DLL is not in the same folder as the executable." << std::endl;
		return 0;
	}

	if (!PathFileExistsW(std::wstring(dllPath.begin(), dllPath.end()).c_str())) {
		printf("The specified DLL path does not exist.\n");
		return EXIT_FAILURE;
	}

	DWORD pid = GetPID(taskmgrName);
	if (pid == 0) {
		printf("Target process not found!\n");
		return 1;
	}



	if (InjectDllIntoProcess(pid, dllPath.c_str())) {
		std::cout << "DLL injected successfully!" << std::endl;
	}
	else {
		std::cout << "DLL injected Fail!" << std::endl;
	}
	std::cout << "Press any key to exit" << std::endl;
	getchar();

	return 0;
}