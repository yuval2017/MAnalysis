#pragma once
#include "pch.h"
#include <fstream>
#include <string>

class Logger {
public:
	Logger(const std::wstring& filename);
	~Logger();
	void write(const std::wstring& data);
	bool writeStr(const std::string &message); // New function declaration
	bool writeWchar(const WCHAR* unicodeString);

private:
	std::wofstream logfile;
};
