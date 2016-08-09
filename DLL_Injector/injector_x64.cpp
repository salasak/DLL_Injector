/**----------------------------------------------------------------------------
* injector.cpp
*-----------------------------------------------------------------------------
*
*-----------------------------------------------------------------------------
* All rights reserved by ERAM (teseonic@gmail.com)
*-----------------------------------------------------------------------------
* 09:8:2016   15:04 created
**---------------------------------------------------------------------------*/

#include<stdio.h>
#include<Windows.h>
#include<tchar.h>
#include<sal.h>

#define DLL_PATH argv[2]
typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(WINAPI *PROC_RtlCreateUserThread)(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	SIZE_T StackReserve,
	SIZE_T StackCommit,
	PTHREAD_START_ROUTINE StartAddress,
	PVOID Parameter,
	PHANDLE ThreadHandle,
	PCLIENT_ID ClientId
	);

BOOL SetPrivilege(_In_z_ const wchar_t* privilege, _In_ bool enable)
{
	HANDLE token = INVALID_HANDLE_VALUE;
	if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token))
	{
		if (ERROR_NO_TOKEN == GetLastError())
		{
			if (ImpersonateSelf(SecurityImpersonation) != TRUE) { return FALSE; }

			if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token))
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}

	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid = { 0 };
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	bool ret = false;
	do
	{
		if (!LookupPrivilegeValueW(NULL, privilege, &luid)) { break; }

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (enable)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else
		{
			tp.Privileges[0].Attributes = 0;
		}

		AdjustTokenPrivileges(token, FALSE, &tp, cb, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS) { break; }

		ret = true;
	} while (false);

	CloseHandle(token);
	return ret;
}

HANDLE AdvancedOpenProcess(_In_ DWORD pid)
{
	HANDLE ret = NULL;
	if (true != SetPrivilege(L"SeDebugPrivilege", true)) return ret;

	do
	{
		ret = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (NULL == ret) 
			break;

		if (true != SetPrivilege(L"SeDebugPrivilege", false))
		{
			CloseHandle(ret); 
			ret = NULL;
			break;
		}
	} while (false);

	return ret;
}

BOOL myRtlCreateUserThread(_In_ HANDLE process_handle, _In_ TCHAR *buffer, _In_ unsigned int buffer_size)
{
	HMODULE ntdll = NULL;
	HMODULE kernel32 = NULL;
	HANDLE thread_handle =NULL;
	CLIENT_ID cid;
	PROC_RtlCreateUserThread RtlCreateUserThread = NULL;
	PTHREAD_START_ROUTINE start_address = NULL;

	__try
	{
		ntdll = LoadLibrary(L"ntdll.dll");
		if (NULL == ntdll)
		{
			_tprintf(_T("LoadLibrary(ntdll.dll) Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		RtlCreateUserThread = (PROC_RtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
		if (NULL == RtlCreateUserThread)
		{
			_tprintf(_T("GetProcAddress(RtlCreateUserThread) Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		kernel32 = LoadLibrary(L"kernel32.dll");
		if (NULL == kernel32)
		{
			_tprintf(_T("LoadLibrary(kernel32.dll) Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		start_address = (PTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
		if (NULL == start_address)
		{
			_tprintf(_T("GetProcAddress(LoadLibraryW) Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		NTSTATUS status = RtlCreateUserThread(process_handle, NULL, false, 0, 0, 0, start_address, buffer, &thread_handle, &cid);
		if (status > 0)
		{
			_tprintf(L"RtlCreateUserThread failed (0x%08x) status : %x\n", GetLastError(), status);
			return false;
		}

		status = WaitForSingleObject(thread_handle, INFINITE);
		if (status == WAIT_FAILED)
		{
			_tprintf(L"WaitForSingleObject failed (0x%08x) status : %x\n", GetLastError(), status);
			return false;
		}
	}
	__finally
	{
		if(kernel32 != NULL)
			FreeLibrary(kernel32);
		if(ntdll != NULL)
			FreeLibrary(ntdll);
		if(thread_handle != NULL)
			CloseHandle(thread_handle);
	}
	return true;
}

BOOL InjectThread(_In_ DWORD pid, _In_ const TCHAR* dll_path)
{
	HANDLE process_handle = NULL;
	unsigned int buffer_size = 0;
	TCHAR *buffer = NULL;
	SIZE_T byte_written = 0;

	__try
	{
		process_handle = AdvancedOpenProcess(pid);
		if (NULL == process_handle)
		{
			_tprintf(_T("OpenProcess Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		buffer_size = _tcslen(dll_path) * sizeof(TCHAR) + 1;
		buffer = (TCHAR*)VirtualAllocEx(process_handle, NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);
		if (NULL == buffer)
		{
			_tprintf(_T("VirtualAllocEx Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		if (true != WriteProcessMemory(process_handle, buffer, dll_path, buffer_size, &byte_written))
		{
			_tprintf(_T("WriteProcessMemory Func err gle : 0x%08X"), GetLastError());
			return false;
		}

		if (true != myRtlCreateUserThread(process_handle, buffer, buffer_size))
		{
			_tprintf(_T("myRtlCreateUserThread Func err gle : 0x%08X"), GetLastError());
			return false;
		}
	}
	__finally
	{
		if (buffer != NULL)
			VirtualFreeEx(process_handle, buffer, buffer_size, MEM_COMMIT);
		if (process_handle != NULL)
			CloseHandle(process_handle);
	}
	return true;
}

int _tmain(int argc, TCHAR* argv[])
{

	if (argc != 3)
	{
		_tprintf(_T("Usage: %s <PROCESS_NAME|PID> <DLL_PATH>\n"),argv[0]);
		return 0;
	}

	if (InjectThread(_ttoi(argv[1]) , DLL_PATH))
		_tprintf(_T("Injection \"%s\" Success\n"), DLL_PATH);
	else
		_tprintf(_T("Injection \"%s\" Failed\n"), DLL_PATH);

	return 0;
}