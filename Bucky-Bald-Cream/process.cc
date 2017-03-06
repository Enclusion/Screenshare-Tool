#include <Windows.h>
#include <TlHelp32.h>

#include "memory.h"
#include "process.h"

BOOL CALLBACK GetWindowsOfProcessProc(HWND hwnd, LPARAM lParam)
{
	pWindows szWindows;
	DWORD dwProcessId;

	szWindows = (pWindows)lParam;
	GetWindowThreadProcessId(hwnd, &dwProcessId);

	if (dwProcessId == szWindows->TargetProcess)
	{
		HWND* newMemory = NULL;

		newMemory = (HWND*)realloc(szWindows->Windows, (szWindows->WindowCount + 1) * sizeof(HWND));
		if (NULL == newMemory)
			return FALSE;

		szWindows->Windows = newMemory;
		szWindows->Windows[szWindows->WindowCount++] = hwnd;
	}

	return TRUE;
}

pWindows GetWindowsOfProcess(DWORD dwProcessId)
{
	pWindows szWindows;

	if ((szWindows = (pWindows)MemCallocEX(sizeof(pWindows))))
	{
		szWindows->TargetProcess = dwProcessId;
		EnumWindows(GetWindowsOfProcessProc, (LPARAM)szWindows);
		return szWindows;
	}

	return NULL;
}

pMeta GetMineraftByWindowTitle(const wchar_t* name, const wchar_t* title) {
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	pMeta procMeta = NULL;

	if (INVALID_HANDLE_VALUE != (snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
	{
		PROCESSENTRY32 entry = { 0 };
		PDWORD pids = NULL;
		SIZE_T pidCount = 0;

		entry.dwSize = sizeof(PROCESSENTRY32);

		if (TRUE == Process32First(snapshot, &entry))
		{
			while (TRUE == Process32Next(snapshot, &entry))
			{
				if (0 == wcscmp(entry.szExeFile, name))
				{
					PDWORD newMemory = NULL;

					newMemory = (PDWORD)MemRealloc(pids, (pidCount + 1) * sizeof(DWORD));
					if (NULL == newMemory)
						break;

					pids = newMemory;
					pids[pidCount++] = entry.th32ProcessID;
				}
			}
		}

		if (NULL != pids)
		{
			procMeta = (pMeta)MemCallocEX(sizeof(pMeta));

			if (NULL != procMeta)
			{
				pWindows szWindow;
				wchar_t textBuf[256]; // Make configurable?
				BOOL outOfMemory = FALSE;

				for (SIZE_T iii = 0; iii < pidCount; iii++)
				{
					szWindow = GetWindowsOfProcess(pids[iii]);

					if (szWindow == NULL)
						// Failed to allocate memory
						break;

					for (SIZE_T jjj = 0; jjj < szWindow->WindowCount; jjj++)
					{
						ZeroMemory(textBuf, sizeof(textBuf));

						if (GetWindowText(szWindow->Windows[jjj], textBuf, sizeof(textBuf)) > 0)
						{
							BOOL match = FALSE;
							if (NULL != wcsstr(textBuf, title))
							{
								match = TRUE;
							}
							if (TRUE == match)
							{
								PDWORD newMemory = NULL;

								newMemory = (PDWORD)MemRealloc(procMeta->Pids, (procMeta->PidCount + 1) * sizeof(DWORD));
								if (NULL == newMemory) {
									outOfMemory = TRUE;
									break;
								}

								procMeta->Pids = newMemory;
								procMeta->Pids[procMeta->PidCount++] = pids[iii];
								break;
							}
						}
					}

					GWOP_CTX_FREE(szWindow);

					if (outOfMemory)
						break;
				}
			}

			MemFree(pids);
			pids = NULL;
		}
	}

	return procMeta;
}

bool GetProcess(std::vector<DWORD>& Pids) {
	pMeta procMeta = NULL;

	procMeta = GetMineraftByWindowTitle(L"javaw.exe", L"Minecraft 1.");
	if (NULL != procMeta) {
		for (int iii = 0; procMeta->PidCount > iii; iii++) {
			Pids.push_back(procMeta->Pids[iii]);
		}
		return true;
	}
	procMeta = GetMineraftByWindowTitle(L"java.exe", L"Minecraft 1.");
	if (NULL != procMeta) {
		for (int iii = 0; procMeta->PidCount > iii; iii++) {
			Pids.push_back(procMeta->Pids[iii]);
		}
		return true;
	}

	return false;
}