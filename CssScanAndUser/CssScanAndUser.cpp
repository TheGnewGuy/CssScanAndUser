// CssScanAndUser.cpp : main project file.

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include "accctrl.h"
#include "aclapi.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <fstream>
using std::ios;
using std::ifstream;

#include <exception>
using std::exception;

#pragma comment(lib, "advapi32.lib")

using namespace System;

void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	//MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
	//_tprintf(TEXT("Error: %llu\n"), lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

bool equalFiles(ifstream& in1, ifstream& in2)
{
	ifstream::pos_type size1, size2;

	size1 = in1.seekg(0, ifstream::end).tellg();
	in1.seekg(0, ifstream::beg);

	size2 = in2.seekg(0, ifstream::end).tellg();
	in2.seekg(0, ifstream::beg);

	if (size1 != size2)
		return false;

	static const size_t BLOCKSIZE = 4096;
	size_t remaining = int(size1);

	while (remaining)
	{
		char buffer1[BLOCKSIZE], buffer2[BLOCKSIZE];
		size_t size = min(BLOCKSIZE, remaining);

		in1.read(buffer1, size);
		in2.read(buffer2, size);

		if (0 != memcmp(buffer1, buffer2, size))
			return false;

		remaining -= size;
	}

	return true;
}

int GetOwner(const std::string& data)
{
	DWORD dwRtnCode = 0;
	PSID pSidOwner = NULL;
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 0, dwDomainName = 0;
	SID_NAME_USE eUse = SidTypeUnknown;
	HANDLE hFile;
	PSECURITY_DESCRIPTOR pSD = NULL;

	std::wstring stemp = std::wstring(data.begin(), data.end());
	LPCWSTR sw = stemp.c_str();
	
	// Get the handle of the file object.
	hFile = CreateFile(
		//TEXT("S:\\Projects\\Backyboycs\\"),  This does not work as a folder
		//TEXT("C:\\temp\\myfile.txt"), 
		//TEXT("S:\\Projects\\Ambrose\\css.gm86"), 
		//TEXT("S:\\Projects\\N Files\\C.gm86"),
		sw,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	// Check GetLastError for CreateFile error code.
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		_tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
		return -1;
	}

	// Get the owner SID of the file.
	dwRtnCode = GetSecurityInfo(
		hFile,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		&pSidOwner,
		NULL,
		NULL,
		NULL,
		&pSD);

	// Check GetLastError for GetSecurityInfo error condition.
	if (dwRtnCode != ERROR_SUCCESS) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		_tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
		return -1;
	}

	// First call to LookupAccountSid to get the buffer sizes.
	bRtnBool = LookupAccountSid(
		NULL,           // local computer
		pSidOwner,
		AcctName,
		(LPDWORD)&dwAcctName,
		DomainName,
		(LPDWORD)&dwDomainName,
		&eUse);

	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)GlobalAlloc(
		GMEM_FIXED,
		dwAcctName);

	// Check GetLastError for GlobalAlloc error condition.
	if (AcctName == NULL) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		_tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
		return -1;
	}

	DomainName = (LPTSTR)GlobalAlloc(
		GMEM_FIXED,
		dwDomainName);

	// Check GetLastError for GlobalAlloc error condition.
	if (DomainName == NULL) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		_tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
		return -1;

	}

	// Second call to LookupAccountSid to get the account name.
	bRtnBool = LookupAccountSid(
		NULL,                   // name of local or remote computer
		pSidOwner,              // security identifier
		AcctName,               // account name buffer
		(LPDWORD)&dwAcctName,   // size of account name buffer 
		DomainName,             // domain name
		(LPDWORD)&dwDomainName, // size of domain name buffer
		&eUse);                 // SID type

								// Check GetLastError for LookupAccountSid error condition.
	if (bRtnBool == FALSE) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();

		if (dwErrorCode == ERROR_NONE_MAPPED)
			_tprintf(TEXT
			("Account owner not found for specified SID.\n"));
		else
			_tprintf(TEXT("Error in LookupAccountSid.\n"));
		return -1;

	}
	else if (bRtnBool == TRUE) {

		// Print the account name.
		std::wstring w_s = AcctName;
		std::string s_temp(w_s.begin(), w_s.end());
		const wchar_t* szName = w_s.c_str();
		_tprintf(TEXT("Account owner = %ws\n"), szName);
	}
	return 0;
}

__int64 GetFileSize(const wchar_t* name)
{
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesEx(name, GetFileExInfoStandard, &fad))
		return -1; // error condition, could call GetLastError to find out more
	LARGE_INTEGER size;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}

void FindAllFiles(const std::string& folderName)
{
	WIN32_FIND_DATA FileData;
	ULONGLONG FileSize;
	std::wstring w_szDir;
	std::wstring szNewPath;
	HANDLE FirstFile;
	std::string folder;
	std::string newfolder;
	int len = 0;

	len = MultiByteToWideChar(CP_ACP, 0, folderName.c_str(), folderName.length(), NULL, 0);
	if (len > 0)
	{
		w_szDir.resize(len);
		MultiByteToWideChar(CP_ACP, 0, folderName.c_str(), folderName.length(), &w_szDir[0], len);
	}
	w_szDir = w_szDir + TEXT("\\*.*");

	folder = folderName + "\\*";
	std::wstring stemp = std::wstring(folder.begin(), folder.end());
	LPCWSTR result = stemp.c_str();

	FirstFile = FindFirstFile(result, &FileData);

	if (FirstFile != INVALID_HANDLE_VALUE)
	{
		do {
			if (strcmp((char *)FileData.cFileName, ".") != 0 && strcmp((char *)FileData.cFileName, "..") != 0)
			{
				//If this is a directory, then create a new string
				if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					len = MultiByteToWideChar(CP_ACP, 0, folderName.c_str(), folderName.length(), NULL, 0);
					szNewPath.resize(len);
					MultiByteToWideChar(CP_ACP, 0, folderName.c_str(), folderName.length(), &szNewPath[0], len);
					szNewPath = szNewPath + TEXT("\\");

					// Build string with new path and pass to routine
					szNewPath = szNewPath + FileData.cFileName;
					std::string s( szNewPath.begin(), szNewPath.end() );
					FindAllFiles(s);
				}
				else
				{
					FileSize = FileData.nFileSizeHigh;
					FileSize <<= sizeof(FileData.nFileSizeHigh) * 8;
					FileSize |= FileData.nFileSizeLow;

					//If the filesize matches the size of counter strike, then display it.
					if (FileSize == 104706493)
					{
						std::wstring w_temp(folderName.begin(), folderName.end());
						const wchar_t* szName = w_temp.c_str();
						_tprintf(TEXT("The file found is: %ws\\%ws, Filesize is: %llu\n"),
							szName, FileData.cFileName, FileSize);

						std::wstring tmpbuff = FileData.cFileName;
						std::string stemp(tmpbuff.begin(), tmpbuff.end());
						std::string s (folderName + "\\" + stemp);

						try {
							// Test file that is Counter Strike
							ifstream in1("C:\\Users\\john.gnew\\Downloads\\css.gmdi", ios::binary);
							ifstream in2(s, ios::binary);

							if (equalFiles(in1, in2)) {
								cout << "Files are equal: This is a copy of Counter Strike!" << endl;
								//exit(0);
							}
							else
							{
								cout << "Files are not equal" << endl;
								//exit(1);
							}

						}
						catch (const exception& ex) {
							cerr << ex.what() << endl;
							exit(-2);
						}

						GetOwner(s);
					}
				}
			}
		} while (FindNextFile(FirstFile, &FileData));
	}
	else
	{
		printf("INVALID_HANDLE_VALUE\n");
	}
}


int main(array<System::String ^> ^args)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	ULONGLONG FileSize;
	LPCTSTR   lpFileName;
	std::string folderName;

	lpFileName = L"C:\\Users\\john.gnew\\Downloads\\css.gmdi"; //file size is 104706493 or 102,253

	//hFind = FindFirstFile(lpFileName, &FindFileData);
	//if (hFind == INVALID_HANDLE_VALUE)
	//{
	//	printf("File not found (%d)\n", GetLastError());
	//	return -1;
	//}
	//else
	//{
	//	FileSize = FindFileData.nFileSizeHigh;
	//	FileSize <<= sizeof(FindFileData.nFileSizeHigh) * 8;
	//	FileSize |= FindFileData.nFileSizeLow;
	//	_tprintf(TEXT("file size is %llu\n"), FileSize);
	//	FindClose(hFind);
	//}

	//FileSize = GetFileSize(lpFileName);
	//_tprintf(TEXT("file size is %llu\n"), FileSize);

	//lpFileName = L"C:\\Users\\john.gnew\\Downloads\\*.*";

	hFind = FindFirstFile(lpFileName, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			FileSize = FindFileData.nFileSizeHigh;
			FileSize <<= sizeof(FindFileData.nFileSizeHigh) * 8;
			FileSize |= FindFileData.nFileSizeLow;
			if (FileSize == 104706493)
				_tprintf(TEXT("The test Counter Strike file is: %ws, Filesize is: %llu\n"),
					FindFileData.cFileName, FileSize);
		} while (FindNextFile(hFind, &FindFileData));
		FindClose(hFind);
	}

	//folderName = "C:\\Users\\john.gnew\\Downloads";
	folderName = "S:\\Projects";
	//folderName = "S:\\Templates";
	//folderName = "S:\\Students";
	FindAllFiles(folderName);

	return 0;
}
