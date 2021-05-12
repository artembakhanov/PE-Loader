#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define RVA_TO_VA(ptype, base, offset)  (ptype) (((DWORD_PTR) (base)) + (offset))

typedef struct _RELOCATIONS
{
	WORD Offset : 12;
	WORD Type : 4;
} RELOCATIONS, *PRELOCATIONS;

int main()
{
	// \ex_original (2).exe
	HANDLE file = CreateFileA("C:\\Users\\artem\\Downloads\\simple.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	DWORD size = GetFileSize(file, NULL);

	HANDLE mapping = CreateFileMappingA(file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

	LPVOID pImageBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS32 pImageNtHeader = RVA_TO_VA(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);

	LPVOID peImage = VirtualAlloc(NULL, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	MoveMemory(peImage, pImageBase, pImageNtHeader->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeader);
	DWORD dwNumSections = pImageNtHeader->FileHeader.NumberOfSections;
	DWORD i = 0;

	while (i < dwNumSections)
	{
		LPVOID pDest = RVA_TO_VA(LPVOID, peImage, pSection->VirtualAddress);
		LPVOID pSrc = RVA_TO_VA(LPVOID, pImageBase, pSection->VirtualAddress);
		DWORD dwSize = pSection->SizeOfRawData;

		PCHAR name = pSection->Name;
		printf("Name: ", i); 

		for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			printf("%c", name[j]);
		}
		printf("\n");

		MoveMemory(pDest, pSrc, dwSize);

		pSection++;
		i++;

	}

	// import 

	DWORD imageImportDescrVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescr = RVA_TO_VA(PIMAGE_IMPORT_DESCRIPTOR, pImageDosHeader, imageImportDescrVA);
	PIMAGE_IMPORT_DESCRIPTOR currentDescr = pImageImportDescr;

	while (TRUE)
	{
		if (NULL == currentDescr || 0 == currentDescr->FirstThunk)
		{
			break;
		}	

		PTCHAR dllName = RVA_TO_VA(PTCHAR, peImage, currentDescr->Name);

		HMODULE dllModule = LoadLibrary(dllName);

		PIMAGE_THUNK_DATA32 pThunk = RVA_TO_VA(PIMAGE_THUNK_DATA32, peImage, currentDescr->FirstThunk);

		while (TRUE)
		{
			if (NULL == *(DWORD*)pThunk) 
			{
				break;
			}

			PTCHAR funcName = RVA_TO_VA(PTCHAR, RVA_TO_VA(DWORD, peImage, pThunk->u1.Function), 2);
			DWORD funcAddr = GetProcAddress(dllModule, funcName);

			_tprintf(_T("%s\n"), funcName);

			pThunk->u1.AddressOfData = funcAddr;

			pThunk++;
		}

		currentDescr++;
	}

	// relocation

	DWORD imageRelocVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_BASE_RELOCATION pImageBaseReloc = RVA_TO_VA(PIMAGE_BASE_RELOCATION, peImage, imageRelocVA);

	while (TRUE)
	{
		if (NULL == pImageBaseReloc->VirtualAddress)
		{
			break;
		}

		DWORD relocCount = (pImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PRELOCATIONS pRelocs = RVA_TO_VA(PRELOCATIONS, pImageBaseReloc, sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD j = 0; j < relocCount; j++)
		{
			if (pRelocs[j].Type == IMAGE_REL_BASED_HIGHLOW)
			{
				DWORD* address = RVA_TO_VA(PDWORD, peImage, pImageBaseReloc->VirtualAddress + pRelocs[j].Offset);
				DWORD oldAddress = *address;

				DWORD newAddress = oldAddress - pImageNtHeader->OptionalHeader.ImageBase + (DWORD)peImage;

				*address = newAddress;
			}
		}

		pImageBaseReloc = RVA_TO_VA(DWORD, pImageBaseReloc, pImageBaseReloc->SizeOfBlock);
	}
	


	// start

	DWORD peEntry = RVA_TO_VA(DWORD, peImage, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

	__asm
	{
		mov eax, [peEntry]
		jmp eax
	}

	return 1;
}