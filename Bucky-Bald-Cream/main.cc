// PHRASING //
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <psapi.h>

#include <boost/optional.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/crc.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/bind.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/uuid/sha1.hpp>
#include <boost/functional/hash.hpp> 


#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>
#include <unordered_map>

#include "ntdll.h"
#include "memory.h"
#include "string.h"
#include "process.h"

namespace fs = boost::filesystem;


struct BoostPathHasher {
	size_t operator()(const fs::wpath& t) const {
		return hash_value(t);
	}
};


boost::optional<std::wstring> GetAppDataPath() {
	const auto app_data = L"APPDATA";
	const auto bufflen = GetEnvironmentVariable(app_data, nullptr, 0);
	if (bufflen > 0) {
		auto buffer = std::unique_ptr<wchar_t[]>(new wchar_t[bufflen]);
		auto strlen = bufflen - 1;
		if (GetEnvironmentVariable(app_data, buffer.get(), bufflen) == strlen) {
			return boost::optional<std::wstring>{std::wstring(buffer.get(), strlen)};
		}
	}
	return boost::optional<std::wstring>{};
}

boost::optional<fs::wpath> GetDefaultModsPath() {
	const wchar_t kModsPath[] = L"\\mods";
	const wchar_t kMinecraftPath[] = L"\\.minecraft";
	const auto app_data = GetAppDataPath();
	if (app_data) {
		auto mods_path = fs::wpath(*app_data + kMinecraftPath + kModsPath);
		return boost::optional<fs::wpath>{mods_path.remove_trailing_separator()};
	}
	return boost::optional<fs::wpath>{};
}

bool GetAllFilesInFolder(boost::filesystem::wpath folderPath, const std::wstring& jarExt, std::vector<fs::wpath>* files)
{
	try
	{
		if (exists(folderPath))
		{
			if (is_directory(folderPath))
			{
				for (fs::recursive_directory_iterator dir(folderPath), end; dir != end; ++dir) {

					if (!is_directory(*dir) && dir->path().extension() == jarExt) {
						files->push_back(dir->path());
					}

				}
				return true;
			}
		}
	}
	catch (const boost::filesystem::filesystem_error& ex)
	{
		std::cout << ex.what() << '\n';
	}
	return false;
}


std::string GetSha1(const std::string& data) {
	boost::uuids::detail::sha1 sha1;
	sha1.process_bytes(data.data(), data.size());

	unsigned hash[5] = { 0 };
	sha1.get_digest(hash);

	std::ostringstream oss;
	boost::algorithm::hex(boost::make_iterator_range(
		reinterpret_cast<const char*>(hash),
		reinterpret_cast<const char*>(hash + 5)),
		std::ostream_iterator<char>(oss));

	return oss.str();
}

bool HashMods(std::vector<std::string> hashes) {
	const wchar_t kJarExt[] = L".jar";
	std::vector<fs::wpath> files;

	auto default_mods_path = GetDefaultModsPath();

	if (default_mods_path) {

		std::unordered_set<fs::wpath, BoostPathHasher> mods_directories;
		mods_directories.emplace(*default_mods_path);

		for (auto it = mods_directories.begin(); it != mods_directories.end(); it++) {

			fs::wpath mPath(it->wstring());

			if (GetAllFilesInFolder(mPath, kJarExt, &files)) {
				for (auto it = files.begin(); it != files.end(); it++) {
					hashes.push_back(GetSha1(it->string()));
				}
				return true;
			}
		}
	}
	return false;
}


// Could add your own DWORD hash function to hash the SHA-1 hashes.
SIZE_T CompareHashes() {
	SIZE_T hashesFound = 0;
	std::vector<std::string> HashList;
	std::vector<std::string> CheatHashList;

	CheatHashList.push_back("test meme");
	CheatHashList.push_back("test meme");
	CheatHashList.push_back("test meme");
	CheatHashList.push_back("test meme");

	if (HashMods(HashList)) {
		for (auto it = HashList.begin(); it != HashList.end(); it++) {
			for (auto cHash = CheatHashList.begin(); cHash != CheatHashList.end(); cHash++) {
				if (it->find(*cHash) != std::string::npos) {
					hashesFound++;
				}
			}
		}
	}
	return hashesFound;
}

SIZE_T SearchStringsInMemory(const DWORD dwProcessId, const ULONG minimumLength, const ULONG memoryTypeMask, const PWSTR szString) {
	HANDLE hProcess;
	MEMORY_BASIC_INFORMATION basicInfo;
	SIZE_T stringsFound = 0;
	DWORD baseAddress = 0;
	SIZE_T bufferSize = PAGE_SIZE * 64;
	PUCHAR buffer = (PUCHAR)malloc(bufferSize);
	SIZE_T displayBufferCount = DISPLAY_BUFFER_COUNT;
	PWSTR displayBuffer = (PWSTR)malloc((displayBufferCount + 1) * sizeof(WCHAR));

	if (!buffer)
		return false;

	if (!displayBuffer)
	{
		MemFree(buffer);
		return false;
	}

	if ((hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId)) == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, L"Open Process Failed", NULL, NULL);
		MemFree(buffer);
		return stringsFound;
	}

	while (NT_SUCCESS(pNtQueryVirtualMemory(
		hProcess,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION64),
		NULL
	))) {
		ULONG_PTR offset;
		SIZE_T readSize;


		if (basicInfo.State != MEM_COMMIT)
			goto ContinueLoop;
		if ((basicInfo.Type & memoryTypeMask) == 0)
			goto ContinueLoop;
		if (basicInfo.Protect == PAGE_NOACCESS)
			goto ContinueLoop;
		if (basicInfo.Protect & PAGE_GUARD)
			goto ContinueLoop;

		readSize = basicInfo.RegionSize;

		if (basicInfo.RegionSize > bufferSize)
		{
			if (basicInfo.RegionSize <= 16 * 1024 * 1024) // 16 MB
			{
				MemFree(buffer);
				bufferSize = basicInfo.RegionSize;
				buffer = (PUCHAR)MemAlloc(bufferSize);

				if (!buffer)
					break;
			}
			else
			{
				readSize = bufferSize;
			}
		}
		for (offset = 0; offset < basicInfo.RegionSize; offset += readSize)
		{

			ULONG_PTR i;
			UCHAR byte; // current byte
			UCHAR byte1; // previous byte
			UCHAR byte2; // byte before previous byte
			BOOLEAN printable;
			BOOLEAN printable1;
			BOOLEAN printable2;
			ULONG length;

			if (!NT_SUCCESS(pNtReadVirtualMemory(
				hProcess,
				baseAddress + (DWORD)offset,
				buffer,
				(ULONG)readSize,
				nullptr
			)))
				continue;

			byte1 = 0;
			byte2 = 0;
			printable1 = FALSE;
			printable2 = FALSE;
			length = 0;

			for (i = 0; i < readSize; i++)
			{
				byte = buffer[i];
				printable = CharIsPrintable[byte];

				if (printable2 && printable1 && printable)
				{
					if (length < displayBufferCount)
						displayBuffer[length] = byte;

					length++;
				}
				else if (printable2 && printable1 && !printable)
				{
					if (length >= minimumLength)
					{
						goto CreateResult;
					}
					else if (byte == 0)
					{
						length = 1;
						displayBuffer[0] = byte1;
					}
					else
					{
						length = 0;
					}
				}
				else if (printable2 && !printable1 && printable)
				{
					if (byte1 == 0)
					{
						if (length < displayBufferCount)
							displayBuffer[length] = byte;

						length++;
					}
				}
				else if (printable2 && !printable1 && !printable)
				{
					if (length >= minimumLength)
					{
						goto CreateResult;
					}
					else
					{
						length = 0;
					}
				}
				else if (!printable2 && printable1 && printable)
				{
					if (length >= minimumLength + 1) // length - 1 >= minimumLength but avoiding underflow
					{
						length--; // exclude byte1
						goto CreateResult;
					}
					else
					{
						length = 2;
						displayBuffer[0] = byte1;
						displayBuffer[1] = byte;
					}
				}
				else if (!printable2 && printable1 && !printable)
				{
					// Nothing
				}
				else if (!printable2 && !printable1 && printable)
				{
					if (length < displayBufferCount)
						displayBuffer[length] = byte;

					length++;
				}
				else if (!printable2 && !printable1 && !printable)
				{
					// Nothing
				}

				goto AfterCreateResult;

			CreateResult:
				{
					ULONG lengthInBytes;
					ULONG bias;
					BOOLEAN isWide;
					ULONG displayLength;

					lengthInBytes = length;
					bias = 0;
					isWide = FALSE;

					if (printable1 == printable)
					{
						isWide = TRUE;
						lengthInBytes *= 2;
					}
					if (printable)
					{
						bias = 1;
					}
					displayLength = (ULONG)(min(length, displayBufferCount) * sizeof(WCHAR));
					if (wcsstr(displayBuffer, szString) != 0)
					{
						std::wcout << "Found String: '" << displayBuffer << "'\n";
						stringsFound++;
					}
					length = 0;
				}

			AfterCreateResult:
				byte2 = byte1;
				byte1 = byte;
				printable2 = printable1;
				printable1 = printable;

			}
		}
	ContinueLoop:
		baseAddress += (DWORD)basicInfo.RegionSize;
	}


	CloseHandle(hProcess);
	MemFree(buffer);



	return stringsFound;
}

SIZE_T EnumerateHandles(const DWORD dwProcessId, const std::wstring dwRegType, const PWSTR szString) {
	ULONG iii;
	HANDLE hProcess;
	NTSTATUS ntStatus;
	SIZE_T handlesFound = 0;
	ULONG handleInfoSize = INFO_SIZE;
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)MemAlloc(handleInfoSize);

	if ((hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId)) == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, L"Open Process Failed", NULL, NULL);
		return handlesFound;
	}

	while ((ntStatus = pNtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)MemRealloc(handleInfo, handleInfoSize *= 2);
	}

	for (iii = 0; iii < handleInfo->HandleCount; iii++) {
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		SYSTEM_HANDLE handle = handleInfo->Handles[iii];
		HANDLE dupHandle = NULL;



		if (NT_SUCCESS(pNtDuplicateObject(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0))) {

			objectTypeInfo = (POBJECT_TYPE_INFORMATION)MemAlloc(PAGE_SIZE);
			if (NT_SUCCESS(pNtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, PAGE_SIZE, NULL))) {

				if (handle.GrantedAccess == ACCESS_DENIED) {
					MemFree(objectTypeInfo);
					CloseHandle(dupHandle);
					continue;
				}

				objectNameInfo = MemAlloc(PAGE_SIZE);

				if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, PAGE_SIZE, &returnLength))) {

					objectNameInfo = MemRealloc(objectNameInfo, returnLength);

					if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL))) {
						MemFree(objectTypeInfo);
						MemFree(objectNameInfo);
						CloseHandle(dupHandle);
						continue;
					}
				}
				objectName = *(PUNICODE_STRING)objectNameInfo;
				std::wstring objectType = objectTypeInfo->Name.Buffer;

				if (objectType.find(dwRegType) != std::wstring::npos) {
					if (objectName.Length) {
						if (wcsstr(objectName.Buffer, szString) != 0) {
							std::wcout << objectTypeInfo->Name.Buffer << " : " << objectName.Buffer << std::endl;
							handlesFound++;
						}
					}
				}
				MemFree(objectTypeInfo);
				MemFree(objectNameInfo);
				CloseHandle(dupHandle);
			}
		}
	}
	MemFree(handleInfo);
	CloseHandle(hProcess);
	return handlesFound;
}

SIZE_T RunChecks() {
	SIZE_T checksFailed = 0;
	std::vector<DWORD> Pids;

	if (GetProcess(Pids)) {
		for (auto it = Pids.begin(); it != Pids.end(); ++it) {
			checksFailed += SearchStringsInMemory(*it, 4, MEM_PRIVATE, L"test meme"); // MEM_MAPPED | MEM_IMAGE | MEM_PRIVATE
			checksFailed += CompareHashes();
			checksFailed += EnumerateHandles(*it, L"File", L"mememe"); // ALPC Port | Event | Mutant | Thread | Section | Key (Registry Key) | Directory | Desktop		
		}
	}

	return checksFailed;
}


int wmain(int argc, wchar_t *argv[], wchar_t *envp[]) {

	if (RunChecks() >= 1) {
		std::cout << "A Check Was Failed" << std::endl;
	}
	else {
		std::cout << "No Check Was Failed" << std::endl;
	}

	std::cin.get();
	return 0;
}
// PHRASING //