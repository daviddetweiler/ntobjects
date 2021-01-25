#include <Windows.h>

#include <winrt/base.h>

#include <iostream>
#include <string_view>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

BOOLEAN (*RtlCreateUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
);

VOID (*RtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
);

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

NTSTATUS (WINAPI *NtOpenDirectoryObject)(
	_Out_ PHANDLE            DirectoryHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

NTSTATUS (WINAPI *NtQueryDirectoryObject)(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);

std::wostream& tab_over(std::wostream& os, unsigned int n)
{
	for (int i {}; i < n; ++i)
		os << L"\t";

	return os;
}

void dump(std::wstring name, unsigned int level = 0)
{
	UNICODE_STRING new_name {};
	winrt::check_bool(RtlCreateUnicodeString(&new_name, name.c_str()));

	OBJECT_ATTRIBUTES attribs {};
	InitializeObjectAttributes(&attribs, &new_name, 0, nullptr, nullptr);

	winrt::handle root {};
	const auto open_status = NtOpenDirectoryObject(root.put(), 0x1 | 0x2, &attribs);
	if (open_status == 0xC0000022)
		return;

	winrt::check_nt(open_status);

	ULONG ctx {};
	while (true) {
		std::array<char, 512> buffer {};
		const auto status = NtQueryDirectoryObject(
			root.get(),
			buffer.data(),
			buffer.size(),
			true, false,
			&ctx,
			nullptr);

		if (status == 0x8000001a)
			break;

		winrt::check_nt(status);

		OBJECT_DIRECTORY_INFORMATION info {};
		std::memcpy(&info, buffer.data(), sizeof(info));
		const std::wstring_view item_name {info.Name.Buffer, info.Name.Length / sizeof(wchar_t)};
		const std::wstring_view type {info.TypeName.Buffer, info.TypeName.Length / sizeof(wchar_t)};
		tab_over(std::wcout, level) << item_name << L" (" << type << L")\n";

		if (type == L"Directory") {
			std::wstring subname {name};
			if (level != 0)
				subname += L"\\";
			
			subname += item_name;
			dump(subname, level + 1);
		}
	}

	RtlFreeUnicodeString(&new_name);
}

int main()
{
	const auto ntdll = winrt::check_pointer(LoadLibrary(L"ntdll"));
	RtlCreateUnicodeString = winrt::check_pointer(reinterpret_cast<decltype(RtlCreateUnicodeString)>(
		GetProcAddress(ntdll, "RtlCreateUnicodeString")));

	RtlFreeUnicodeString = winrt::check_pointer(reinterpret_cast<decltype(RtlFreeUnicodeString)>(
		GetProcAddress(ntdll, "RtlFreeUnicodeString")));

	NtOpenDirectoryObject = winrt::check_pointer(reinterpret_cast<decltype(NtOpenDirectoryObject)>(
		GetProcAddress(ntdll, "NtOpenDirectoryObject")));

	NtQueryDirectoryObject = winrt::check_pointer(reinterpret_cast<decltype(NtQueryDirectoryObject)>(
		GetProcAddress(ntdll, "NtQueryDirectoryObject")));

	dump(L"\\");

	winrt::check_bool(FreeLibrary(ntdll));
}
