// basicinjector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

BOOL CurrentProcessAdjustToken(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;

	//grab our current processes token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		//lookup the luid of a specified priv and add it to our TOKEN_PRIVLIGES var
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}

		//make sure the priv is enabled
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		//update the privs
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}

DWORD FindRunningProcess(wchar_t* process) {

	/*
	Function takes in a string value for the process it is looking for like ST3Monitor.exe
	then loops through all of the processes that are currently running on windows.
	If the process is found it is running, therefore the function returns true.
	*/

	std::wstring compare;
	bool procRunning = false;

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		procRunning = false;
	}
	else {
		pe32.dwSize = sizeof(PROCESSENTRY32);
		// Gets first running process
		if (Process32First(hProcessSnap, &pe32)) {
			if (lstrcmpW(pe32.szExeFile, process) == 0) {

				return pe32.th32ProcessID;

			}
			else {
				// loop through all running processes looking for process
				while (Process32Next(hProcessSnap, &pe32)) {
					if (lstrcmpW(pe32.szExeFile,process) == 0) {

						return pe32.th32ProcessID;

					}
				}
			}
			// clean the snapshot object
			CloseHandle(hProcessSnap);
		}
	}

	return 0;
}


void inject(DWORD process, LPWSTR dll) {

	HANDLE phandle;
	TCHAR dllfullpath[2048] = TEXT("");
	LPVOID lpbuffer = NULL;
	LPVOID dllpathaddr;
	LPVOID loadlibaddr;
	HANDLE hthread;

	printf("Injecting into PID: %d", process);

	//get a handle to the process
	phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process);

	if (phandle == NULL) {
		printf("OpenProcess failed with Error 0x%08lx\n", GetLastError());
		return;
	}

	//Get the full path of our dll
	GetFullPathName(dll, 2048, dllfullpath, NULL);

	//Allocate space inside the process for our dll
	dllpathaddr = VirtualAllocEx(phandle, NULL, wcslen(dllfullpath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (dllpathaddr == NULL) {
		printf("VirtualAllocEx failed with Error 0x%08lx\n", GetLastError());
		return;
	}

	//Write the path to the memory of the process we are trying to inject to
	if (WriteProcessMemory(phandle, dllpathaddr, dllfullpath, wcslen(dllfullpath), NULL) == 0) {
		printf("WriteProcessMemory failed with Error 0x%08lx\n", GetLastError());
		return;
	}

	//Get the address of LoadLibrary which will be the starting execution point that we will use CreateRemoteThread to call
	loadlibaddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

	if (loadlibaddr == NULL) {
		printf("GetProcAddress failed with Error 0x%08lx\n", GetLastError());
		return;
	}

	hthread = CreateRemoteThread(phandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadlibaddr, NULL, 0, NULL);

	if (hthread == NULL) {
		printf("CreateRemoteThread failed with Error 0x%08lx\n", GetLastError());
		return;
	}

	WaitForSingleObject(hthread, INFINITE);

	CloseHandle(hthread);
	CloseHandle(phandle);

}


int main(int argc, char *argv[])
{
	BOOL status = CurrentProcessAdjustToken();
	std::wstring dll = L"testdll.dll";
	inject(4028, (LPWSTR)dll.c_str());


	

	return 0;
}

