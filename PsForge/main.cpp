#include <iostream>
#include <memory>
#include <Windows.h>

using NtMapViewOfSectionPtr = NTSTATUS(NTAPI*)(HANDLE sectionHandle, HANDLE processHandle, PVOID* baseAddress,
	ULONG_PTR zeroBits, SIZE_T commitSize, PLARGE_INTEGER sectionOffset, PSIZE_T viewSize, ULONG inheritDisposition,
	ULONG allocationType, ULONG win32Protect);

template <typename Function>
class PtrDeleter
{
	Function _Closer;
public:
	void operator()(void* memBlock) const
	{
		_Closer(memBlock);
	}
};

int main()
{
	auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSectionPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));
	if (!NtMapViewOfSection)
	{
		std::wcout << L"NtMapViewOfSection not found.\n";
		return EXIT_FAILURE;
	}

	std::unique_ptr<void*, PtrDeleter<decltype(CloseHandle)>> ptr = std::make_unique<void*>((VOID*)32);
}