#pragma once
#include <Windows.h>
#include "ntdll.h"

NTSTATUS pNtQueryVirtualMemory(
	HANDLE hProcess,
	DWORD baseAddress,
	MEMORY_INFORMATION_CLASS memoryInformationClass,
	PVOID memoryInformation,
	ULONG memoryInformationLength,
	PULONG returnLength
);
NTSTATUS pNtReadVirtualMemory(
	HANDLE hProcess,
	DWORD baseAddress,
	PVOID buffer,
	ULONG numberOfBytesToRead,
	PULONG numberOfBytesRead
);
NTSTATUS pNtQueryInformationProcess(
	HANDLE hProcess,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
);
NTSTATUS pNtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
NTSTATUS pNtQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);
NTSTATUS pNtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
);
NTSTATUS GetProcessBasicInformation(HANDLE hProcess,
	PROCESS_BASIC_INFORMATION* basic_info);

DWORD  GetMemSize(LPVOID lpAddr);
VOID   MemFree(LPVOID lpAddr);
LPVOID MemAlloc(SIZE_T dwSize);
LPVOID MemCalloc(size_t Num, size_t Size);
LPVOID MemAllocAndClear(SIZE_T Size);
LPVOID MemRealloc(LPVOID lpAddr, SIZE_T Size);
LPVOID MemCallocEX(SIZE_T size);
DWORD GetCallAddress(DWORD dwAddress);
