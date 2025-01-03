#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#define INITIAL_SEED	7

UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


//macros used to make the code neater & cleaner
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))


// Junkins One At A Time Hashing User32.dll Algorithm 0x81E3778E
// Junkins One At A Time Hashing MessageBoxA Algorithm 0xF10E27CA


#define USER32DLL_HASH		0x81E3778E
#define MessageBoxA_HASH	0xF10E27CA

FARPROC CustomGetProcProcess(IN HMODULE hModule, DWORD dwApiNameHash) {
	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;


	// Getting the DOS header and checking the signature
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// Getting the NT headers and checking the signature
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pImgDosHdr->e_lfanew + pBase);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}


	// Getting the optional header
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function name array
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the func address array
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the func ordinal array
	PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals); // Use PWORD, not PDWORD


	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) { // Iterate over NumberOfNames
		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		FARPROC pFunctionAddress = (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		printf("[+] Checking Function: %s\n", pFunctionName);

		// Searching for the function

		if (dwApiNameHash == HASHA(pFunctionName)) {
			printf("[+] Function found: %s\n", pFunctionName);
			return pFunctionAddress;
		}
	}

	printf("[-] Function not found.\n");
	return NULL;
}

HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {
	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	// getting the head of the linked list ( used to get the node & to check the end of the list)
	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	// getting the node of the linked list
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			CHAR UpperCaseDllName[MAX_PATH];
			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';


			//Hashing the dll name and comparing it to the input hash

			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)pDte->Reserved2[0];

		}
		else
		{
			break;
		}
	}

}


typedef int (WINAPI* fnMessageBoxA)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
	);



int main() {
	HMODULE hUser32 = GetModuleHandleA("user32.dll");
	if (hUser32 == NULL) {
		printf("[-] Failed to get handle to user32.dll\n");
		return -1;
	}

	FARPROC pMessageBoxA = CustomGetProcProcess(hUser32, MessageBoxA_HASH);
	if (pMessageBoxA == NULL) {
		printf("[-] Failed to get handle to MessageBoxA\n");
		return -1;
	}

	MessageBoxA(NULL, "Hello World!", "Hello", MB_OK);

	return 0;
}



