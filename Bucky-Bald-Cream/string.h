#pragma once
#include <Windows.h>
#include "ntdll.h"


extern BOOLEAN CharIsPrintable[256];

#define PAGE_SIZE 0x1000
#define INFO_SIZE 0x10000
#define ACCESS_DENIED 0x0012019f
#define DISPLAY_BUFFER_COUNT (PAGE_SIZE * 2 - 1)

char* ToAnsi(LPCWSTR str, DWORD dwLen);
char* WINAPI m_strstr(char *haystack, const char *needle);
char* WINAPI m_strstr(char *haystack, const char *needle);





