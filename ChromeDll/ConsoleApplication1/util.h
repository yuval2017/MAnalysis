#pragma once
#include <iostream>
#include <stdio.h>
#include <windows.h>
class utils
{
public:
	bool InjectDllIntoProcess(DWORD processId, const char* dllPath);
};

