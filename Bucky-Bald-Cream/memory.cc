
#include <Windows.h>
#include <ntstatus.h>
#include "ntdll.h"
#include "memory.h"

#ifdef MEM_LEAK_CHECK
#include <stdlib.h>
#include <crtdbg.h>
#endif



#ifndef MEM_LEAK_CHECK
void* __cdecl operator new(size_t size)
{
	return MemAlloc(size);
}

void* operator new[](size_t size)
{
	return MemAlloc(size);
}

void __cdecl operator delete(void* ptr)
{
	return MemFree(ptr);
}

void operator delete[](void* ptr)
{
	MemFree(ptr);
}

#ifdef _WIN64
void __cdecl operator delete(void* ptr, unsigned __int64)
#else
void __cdecl operator delete(void* ptr, unsigned __int32)
#endif
{
	return MemFree(ptr);
}

void* __cdecl malloc(size_t size)
{
	return MemAlloc(size);
}

void* __cdecl calloc(size_t num, size_t size)
{
	return MemAllocAndClear(num * size);
}

void* __cdecl realloc(void* ptr, size_t size)
{
	return MemRealloc(ptr, size);
}

void __cdecl free(void* ptr)
{
	MemFree(ptr);
}
#endif

void m_memset(const void* Buffer, BYTE Sym, size_t Len)
{
	if (Buffer)
	{
		volatile char *Tmp = (volatile char *)Buffer;
		while (Len)
		{
			*Tmp = Sym;
			Len--;
			Tmp++;
		}
	}

}

void *m_memcpy(void *szBuf, const void *szStr, int nLen)
{
	if (szBuf && szStr)
	{
		volatile char *Buf = (volatile char *)szBuf;
		volatile char *Str = (volatile char *)szStr;
		while (nLen)
		{
			nLen--;
			*Buf = *Str;
			Buf++;
			Str++;
		}
	}
	return szBuf;
}

int m_memcmp(const void *buf1, const void *buf2, size_t count)
{
	if (!buf1 || !buf2)
	{
		return -1;
	}

	unsigned char *p1 = (unsigned char *)buf1;
	unsigned char *p2 = (unsigned char *)buf2;

	int   rc = 0;

	for (size_t i = 0; i < count; i++)
	{
		if (*p1 < *p2)
		{
			rc = -1;
			break;
		}

		if (*p1 > *p2)
		{
			rc = 1;
			break;
		}

		p1++;
		p2++;
	}

	return rc;
}

void* m_memmem(const void* mem1, int szMem1, const void* mem2, int szMem2)
{
	const char* p1 = (const char*)mem1;
	const char* p2 = (const char*)mem2;
	while (szMem1 >= szMem2)
	{
		if (*p1 == *p2)
		{
			int i = 1;
			while (i < szMem2)
				if (p1[i] != p2[i])
					break;
				else
					i++;
			if (i >= szMem2)
				return (void*)p1;
		}
		p1++;
		szMem1--;
	}
	return 0;
}

NTSTATUS pNtQueryVirtualMemory(
	HANDLE hProcess,
	DWORD baseAddress,
	MEMORY_INFORMATION_CLASS memoryInformationClass,
	PVOID memoryInformation,
	ULONG memoryInformationLength,
	PULONG returnLength
) {
	typedef NTSTATUS(NTAPI * _NtQueryVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN DWORD BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation,
		IN ULONG MemoryInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);
	_NtQueryVirtualMemory _Nt_Query_Virtual_Memory = reinterpret_cast<_NtQueryVirtualMemory>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryVirtualMemory"));
	return _Nt_Query_Virtual_Memory(
		hProcess,
		baseAddress,
		memoryInformationClass,
		memoryInformation,
		memoryInformationLength,
		returnLength
	);
}

NTSTATUS pNtReadVirtualMemory(
	HANDLE hProcess,
	DWORD baseAddress,
	PVOID buffer,
	ULONG numberOfBytesToRead,
	PULONG numberOfBytesRead
) {
	typedef NTSTATUS(NTAPI * _NtReadVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN DWORD BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL
		);
	_NtReadVirtualMemory _Nt_Query_Virtual_Memory = reinterpret_cast<_NtReadVirtualMemory>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory"));
	return _Nt_Query_Virtual_Memory(
		hProcess,
		baseAddress,
		buffer,
		numberOfBytesToRead,
		numberOfBytesRead
	);
}

NTSTATUS pNtQueryInformationProcess(
	HANDLE hProcess,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
) {
	typedef NTSTATUS(NTAPI * _NtQueryInformationProcess)(
		HANDLE hProcess,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);
	_NtQueryInformationProcess _Nt_Query_Information_Process = reinterpret_cast<_NtQueryInformationProcess>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess"));

	return _Nt_Query_Information_Process(
		hProcess,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength
	);
}

NTSTATUS pNtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	typedef NTSTATUS(NTAPI * _NtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);
	_NtQuerySystemInformation _Nt_Query_Systen_Information = reinterpret_cast<_NtQuerySystemInformation>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation"));

	return _Nt_Query_Systen_Information(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);
}

NTSTATUS pNtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
) {
	typedef NTSTATUS(NTAPI * _NtDuplicateObject)(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		ULONG Attributes,
		ULONG Options
		);
	_NtDuplicateObject _Nt_Duplicate_Object = reinterpret_cast<_NtDuplicateObject>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject"));

	return _Nt_Duplicate_Object(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		Attributes,
		Options
	);
}

NTSTATUS GetProcessBasicInformation(HANDLE hProcess,
	PROCESS_BASIC_INFORMATION* basic_info) {
	typedef NTSTATUS(NTAPI* MyNtQueryInformationProcess)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);
	auto nt_query_information_process =
		reinterpret_cast<MyNtQueryInformationProcess>(
			GetProcAddress(GetModuleHandle(L"ntdll.dll"),
				"NtQueryInformationProcess"));
	return nt_query_information_process(hProcess,
		ProcessBasicInformation,
		basic_info,
		sizeof(PROCESS_BASIC_INFORMATION),
		nullptr);
}


NTSTATUS pNtQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
) {
	typedef NTSTATUS(NTAPI * _NtQueryObject)(
		HANDLE ObjectHandle,
		ULONG ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength
		);
	_NtQueryObject _Nt_Query_Object = reinterpret_cast<_NtQueryObject>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject"));

	return _Nt_Query_Object(
		 ObjectHandle,
		 ObjectInformationClass,
		 ObjectInformation,
		 ObjectInformationLength,
		 ReturnLength
	);
}





DWORD GetMemSize(LPVOID lpAddr)
{
	if (!lpAddr)
		return 0;

	MEMORY_BASIC_INFORMATION MemInfo;
	VirtualQuery(lpAddr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
	return MemInfo.RegionSize;
}

VOID MemFree(LPVOID lpAddr)
{
#ifdef MEM_LEAK_CHECK
	free(lpAddr);
#else
	if (lpAddr)
		VirtualFree(lpAddr, 0, MEM_RELEASE);
#endif
}

LPVOID MemAlloc(SIZE_T Size)
{
#ifdef MEM_LEAK_CHECK
	return malloc(Size);
#else
	return VirtualAlloc(0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
}

LPVOID MemCalloc(size_t Num, size_t Size)
{
	return MemAllocAndClear(Num * Size);
}

LPVOID MemCallocEX(SIZE_T size)
{
#ifdef _DEBUG
	return calloc(1, size);
#else
	LPVOID memory = MemAlloc(size);
	if (NULL == memory)
		return NULL;
	ZeroMemory(memory, size);
	return memory;
#endif
}

LPVOID MemAllocAndClear(SIZE_T Size)
{
	if (Size == 0)
		return NULL;
	LPVOID Memory = MemAlloc(Size);
	if (!Memory)
		return NULL;
	m_memset(Memory, 0, Size);
	return Memory;
}

LPVOID MemRealloc(LPVOID lpAddr, SIZE_T Size)
{
	DWORD PrevLen = 0;

	if (lpAddr)
		PrevLen = GetMemSize(lpAddr);

	LPVOID NewAddr = NULL;
	if (Size > 0)
	{
		NewAddr = MemAlloc(Size);
		if (lpAddr && NewAddr && PrevLen)
		{
			if (Size < PrevLen)
				PrevLen = Size;
			m_memcpy(NewAddr, lpAddr, PrevLen);
		}
	}

	if (lpAddr != NULL)
		MemFree(lpAddr);

	return NewAddr;
}

DWORD GetCallAddress(DWORD dwAddress)
{
	return (*(PDWORD)(dwAddress + 1)) + dwAddress + 5;
}