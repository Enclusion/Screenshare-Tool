#pragma once
#include <Windows.h>
#include <vector>

#pragma region Memory
#define FPBNAWT_CTX_FREE(ptr)				\
	do {									\
		if( ptr ) {							\
			if( ptr->Pids )					\
				MemFree( ptr->Pids );		\
			MemFree( ptr );					\
			ptr = NULL;						\
		}									\
	} while( 0 );


#define FFIDMS_CTX_FREE(ptr)							\
	do {												\
		if( ptr ) {										\
			if( ptr->Paths )	 {							\
				for( int iii = 0;						\
					 iii < ptr->PathsCount;				\
					 iii++ ) {							\
					if( ptr->Paths[iii] )				\
						MemFree( ptr->Paths[iii] );		\
				}										\
				MemFree( ptr->Paths );					\
			}											\
			MemFree( ptr );								\
			ptr = NULL;									\
		}												\
	} while( 0 );

#define GWOP_CTX_FREE(ptr)					\
	do {									\
		if( ptr ) {							\
			if( ptr->Windows )				\
				MemFree( ptr->Windows );		\
			MemFree( ptr );					\
			ptr = NULL;						\
		}									\
	} while( 0 );

#pragma endregion

#pragma region Process Structures
typedef struct ProcessWindows {
	DWORD TargetProcess;
	HWND* Windows;
	SIZE_T WindowCount;
} _ProcessWindows, *pWindows;

typedef struct ProcessMeta
{
	PDWORD Pids;
	SIZE_T PidCount;
} _pMeta, *pMeta;
#pragma endregion


bool GetProcess(std::vector<DWORD>& Pids);