// hideInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

// Function pointer type for the function to be executed
typedef void(*MessageFunctionPtr)(LPCTSTR);

// Function to retrieve the function pointer from shared memory and execute it
void ExecuteFunctionFromSharedMemory() {
	// Open handle to shared memory
	HANDLE hSharedMemory = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, L"MySharedMemory");

	if (hSharedMemory != NULL) {
		// Map view of shared memory
		MessageFunctionPtr* pFunctionPtr = (MessageFunctionPtr*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(MessageFunctionPtr));

		if (pFunctionPtr != NULL) {
			// Execute the function
			(*pFunctionPtr)(L"Hello from HIDinjector!");

			// Unmap view of shared memory
			UnmapViewOfFile(pFunctionPtr);
		}
		else {
			// Handle error: unable to map view of shared memory
			std::cerr << "Error: Unable to map view of shared memory" << std::endl;
		}

		// Close handle to shared memory
		CloseHandle(hSharedMemory);
	}
	else {
		// Handle error: unable to open handle to shared memory
		std::cerr << "Error: Unable to open handle to shared memory" << std::endl;
	}
}

int main() {
	// Retrieve function pointer from shared memory and execute it
	ExecuteFunctionFromSharedMemory();

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
