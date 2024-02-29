#pragma once
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h> 
#include <stdlib.h>
#include <string.h>
#include "tchar.h"
#include <fstream>
#include <string>
bool InjectDllIntoProcess(DWORD processId, const char* dllPath);
DWORD GetPID(const WCHAR* AppName);


