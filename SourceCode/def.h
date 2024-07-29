typedef HANDLE(WINAPI* Fn_CreateFileMappingW)(
		_In_     HANDLE hFile,
		_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
		_In_     DWORD flProtect,
		_In_     DWORD dwMaximumSizeHigh,
		_In_     DWORD dwMaximumSizeLow,
		_In_opt_ LPCWSTR lpName
		);

typedef DWORD(WINAPI* Fn_ResumeThread)(
		_In_ HANDLE hThread
		);
typedef DWORD (WINAPI *Fn_WaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);
typedef	BOOL(WINAPI* Fn_SetThreadContext)(
		_In_ HANDLE hThread,
		_In_ CONST CONTEXT* lpContext
		);

typedef HANDLE (WINAPI *Fn_CreateThread)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ __drv_aliasesMem LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
);

typedef	BOOL(WINAPI* Fn_GetThreadContext)(
		_In_ HANDLE hThread,
		_Inout_ LPCONTEXT lpContext
		);
        
typedef DWORD(WINAPI* Fn_SuspendThread)(
		_In_ HANDLE hThread
		);
typedef HANDLE(WINAPI* Fn_CreateToolhelp32Snapshot)(
		DWORD dwFlags,
		DWORD th32ProcessID
		);
typedef	HANDLE(WINAPI* Fn_OpenThread)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwThreadId
	);
typedef	HANDLE(WINAPI* FN_CreateRemoteThread)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);
typedef BOOL(WINAPI* Fn_ReadFile)(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);
typedef DWORD(WINAPI* Fn_GetFileSize)(
	_In_ HANDLE hFile,
	_Out_opt_ LPDWORD lpFileSizeHigh
	);
typedef HANDLE(WINAPI* Fn_CreateFileW)(
		_In_ LPCWSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
		);

typedef HANDLE(WINAPI* Fn_OpenProcess)(
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwProcessId
		);
typedef DWORD(WINAPI* Fn_QueueUserAPC)(
	_In_ PAPCFUNC pfnAPC,
	_In_ HANDLE hThread,
	_In_ ULONG_PTR dwData
	);
typedef LPVOID(WINAPI* Fn_VirtualAllocEx)(
		_In_ HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flAllocationType,
		_In_ DWORD flProtect
		);


typedef		LPVOID (WINAPI *Fn_MapViewOfFile)(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    );

typedef BOOL(*Fn_WriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	);