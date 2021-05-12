#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 5000

struct DataItem {
	DWORD data;
	DWORD key;
};

struct DataItem* hashArray[SIZE];
struct DataItem* dummyItem;
struct DataItem* item;

int hashCode(DWORD key) {
	return key % SIZE;
}

struct DataItem* search(DWORD key) {
	//get the hash 
	DWORD hashIndex = hashCode(key);

	//move in array until an empty 
	while (hashArray[hashIndex] != NULL) {

		if (hashArray[hashIndex]->key == key)
			return hashArray[hashIndex];

		//go to next cell
		++hashIndex;

		//wrap around the table
		hashIndex %= SIZE;
	}

	return NULL;
}

void insert(DWORD key, DWORD data) {

	struct DataItem* item = (struct DataItem*)malloc(sizeof(struct DataItem));
	item->data = data;
	item->key = key;

	//get the hash 
	DWORD hashIndex = hashCode(key);

	//move in array until an empty or deleted cell
	while (hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1) {
		//go to next cell
		++hashIndex;

		//wrap around the table
		hashIndex %= SIZE;
	}

	hashArray[hashIndex] = item;
}

#define RVA_TO_VA(ptype, base, offset)  (ptype) (((DWORD_PTR) (base)) + (offset))

typedef struct _RELOCATIONS
{
	WORD Offset : 12;
	WORD Type : 4;
} RELOCATIONS, *PRELOCATIONS;

int main()
{
	HANDLE file = CreateFileA("C:\\Users\\artem\\Downloads\\ex_original (2).exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

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

	LPVOID textPtr = 0;
	DWORD textSize = 0;


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

		TCHAR* textSection = _T(".text");

		if (0 == memcmp(textSection, name, sizeof(textSection))) 
		{
			_tprintf(_T("Found text: %s\n"), name);
			textPtr = pDest;
			textSize = dwSize;
		}

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

			DWORD key = RVA_TO_VA(DWORD, RVA_TO_VA(DWORD, pImageBase, pThunk->u1.Function), -8);
			insert(key, funcAddr);

			_tprintf(_T("%s\n"), funcName);

			pThunk->u1.AddressOfData = funcAddr;

			pThunk++;
		}

		currentDescr++;
	}

	BYTE test[] = { 0xFF, 0x15};

	// relocation
	// we do not need it right now
	BYTE toWrite[] = { 0xAC, 0x10, 0x40, 0xFF };

	
	PBYTE kek = RVA_TO_VA(LPVOID, textPtr, 0);
	PBYTE end = RVA_TO_VA(LPVOID, textPtr, textSize - 6 * sizeof(PBYTE));
	for (;;)
	{
		if (kek >= end) {
			break;
		}

		if (0 == memcmp(kek, test, sizeof(test)))
		{
			_tprintf(_T("Found one at: %x\n"), kek);
			if (NULL != search(*((PDWORD)(kek + 2)))) {
				_tprintf(_T("FOUND!!!!!! one at: %x\n"), kek);
				DWORD f = (search(*((PDWORD)(kek + 2))) -> data);
				DWORD f_ =  ((f >> 24) & 0xff) | // move byte 3 to byte 0
							((f << 8) & 0xff0000) | // move byte 1 to byte 2
							((f >> 8) & 0xff00) | // move byte 2 to byte 1
							((f << 24) & 0xff000000); // byte 0 to byte 3
				memcpy(kek + 2, &f_, sizeof(toWrite));
			}
			
		}

		

		kek++;
		
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