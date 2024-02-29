#include "pch.h"
#include "Logger.h"
#include <codecvt>
Logger::Logger(const std::wstring& filename) {
	// If the filename does not end with ".txt", append "output.txt"
	if (filename.substr(filename.length() - 4) != L".txt") {
		this->logfile.open(filename + L"output.txt", std::ios::app);
	}
	else {
		this->logfile.open(filename, std::ios::app);
	}

	// Create the file if it does not exist
	if (!this->logfile.is_open()) {
		this->logfile.open(filename, std::ios::out);
	}
}

Logger::~Logger() {
	if (this->logfile.is_open()) {
		this->logfile.close();
	}
}

void Logger::write(const std::wstring& data) {
	if (this->logfile.is_open()) {
		this->logfile << data << std::endl;
	}
}
bool Logger::writeStr(const std::string& message) {
	if (logfile.is_open()) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wideMessage = converter.from_bytes(message);

		logfile << wideMessage << std::endl;
		return true;
	}
	return false;
}
// Function to convert a UNICODE string to std::string
bool Logger::writeWchar(const WCHAR* unicodeString) {
	std::wstring wstringResult(unicodeString);
	write(wstringResult);
	return TRUE;
}
