---
title: "OpenFileMapping and KnownDlls"
date: 2023-08-17T16:02:16+01:00
draft: true
---

A common method of unhooking user-land API hooks is to load a fresh copy of NTDLL from `KnownDlls`, a special object directory that's used to essentially cache commonly used system DLLs. We can use [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj) to view the Object Manager namespace, where we can see the `KnownDlls` directory, and the mapped sections it contains for each system DLL.

![WinObj_KnownDlls](/winobj_knowndlls.png#center)

Whilst working through the excellent [Maldev Academy](https://maldevacademy.com) course material, it was pointed out that you can't seem to use `OpenFileMapping` to retrieve a handle to the `KnownDlls` directory, despite it's purpose being to open named file mapping objects. Attempting to use the function to open `\KnownDlls\ntdll.dll`, or any other DLL in that directory, will result in error 161 - `ERROR_BAD_PATHNAME`. Instead, most malware uses the native `NtOpenSection` instead.

I wanted to investigate why the function was failing in this manner, and this post is just a short walkthrough what I found.

***

## `OpenFileMapping` and `NtOpenSection`

As already mentioned, the `OpenFileMapping` function "Opens a named file mapping object". It's definition is as follows:

```c
HANDLE OpenFileMappingA(
    [in] DWORD  dwDesiredAccess,
    [in] BOOL   bInheritHandle,
    [in] LPCSTR lpName
);
```

These parameters are all pretty self-explanatory; `dwDesiredAccess` specifies the access level for the file mapping object and is checked against the security descriptor on the target object. `bInheritHandle` specifies whether the handle can be inherited by another process or not. The `lpname` obviously specifies the name of the file mapping object to be opened, and as noted in the documentation: "The name can have a "Global\" or "Local\" prefix to explicitly open an object in the global or session namespace.".

`OpenFileMapping` eventually calls the native function `NtOpenSection`, which is used to open a handle for an existing section object:

```c
NTSYSAPI NTSTATUS ZwOpenSection(
    [out] PHANDLE            SectionHandle,
    [in]  ACCESS_MASK        DesiredAccess,
    [in]  POBJECT_ATTRIBUTES ObjectAttributes
);
```

The most relevant parameter here is the pointer to the `OBJECT_ATTRIBUTES` structure, which is what really holds the meat of what object it is we want to open a handle to:

```c
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
```

So what's causing the `ERROR_BAD_PATHNAME` when we call the function with `\KnownDlls\ntdll.dll`?

A safe assumption is that the issue can be found in the `OBJECT_ATTRIBUTES` struct that  `OpenFileMapping` is constructing and passing to `NtOpenSection`. We'll write a simple program that calls the function, and then set a debugger breakpoint on `NtOpenSection` to see what is passed in the `ObjectAttributes` parameter.

![x64dbg NtOpenSection breakpoint](/x64dbg_ntopensection.png#center)

We know that the `NtOpenSection` function takes three parameters, and with WinAPI using fastcall, that means the `ObjectAttributes` pointer argument will be in the `R8` register when we hit our breakpoint. Following the pointer in `R8` in a memory dump section will lead us to the `OBJECT_ATTRIBUTES` object being passed:

- `Length` - red | `RootDirectory` - green
- `ObjectName` - blue | `Attributes` - orange
-  `SecurityDescriptor` - pink  | `SecurityQualityOfService` - purple

![x64dbg OPEN_ATTRIBUTES](/x64dbg_open_attributes.png#center)

Both of the final parameters are `NULL`, which is expected - the first one being `NULL` means the object will receive default security settings, and the second is optional and used to 'indicate the security impersonal level and context tracking mode,' which isn't likely to be causing our issue here. We can check the `ObjectName` field first and just make sure that the path we are passing to `OpenFileMapping` is actually what is being passed to `NtOpenSection`, and isn't mangled somewhere along the way.

Following the pointer will lead us to a `UNICODE_STRING` structure which is defined as such:

```c
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

![x64dbg UNICODE_STRING](/x64dbg_unicode_string.png#center)

We can see from debugger comment which has resolved the address of the string that the path is being passed as we expect, and there isn't anything unusual about the `Length` or `MaximumLength` values. Returning to the `OBJECT_ATTRIBUTES` structure, we are left with two other offending values - the `RootDirectory` and the `Attributes`. We can quickly check that the argument passed for the `Attributes` is `0x80` which is the value for `OBJ_OPENIF`. This attribute has a kinda confusing explanation in Microsoft's documentation, but seems to mean that if the object exists a handle to it should be opened, unless the routine is trying to create a new object with that name, in which case it will return an `NTSTATUS` of `STATUS_OBJECT_NAME_COLLISION`. If we actually step through the `syscall` with our debugger to see what is returned from `NtOpenSection`, we receive a `STATUS_OBJECT_PATH_SYNTAX_BAD` status, meaning this attribute is unlikely to be what is erroring.

That leaves us with the `RootDirectory`. This is an optional field, which if set to `NULL` means that the `ObjectName` field has to point to the fully qualified path to an object. If `RootDirectory` isn't `NULL`, `ObjectName` will point to an object _relative_ to the `RootDirectory`. So this quite obviously is what is causing us issues. We are passing in a fully qualified path to an object, `\KnownDlls\ntdll.dll`, which we are expecting to access at the root of the object manager namespace - but `NtOpenSection` is trying to open this path from presumably a different root. So what location is actually being passed as the `RootDirectory`? We can have a closer look at what `OpenFileMapping` is doing to find out:

![x64dbg OpenFileMapping disassembly](/x64dbg_open_file_mapping.png#center)

The `BaseFormatObjectAttributes` jumps out immediately. This function is what constructs our initial `OBJECT_ATTRIBUTES` structure. If we follow through the execution, we find that it later calls `BaseGetNamedObjectDirectory`, and this is the value that is set in the `RootDirectory` field. Some quick searching for this function returns some community documentation from [undoc.airesoft.co.uk](http://undoc.airesoft.co.uk/kernel32.dll/BaseGetNamedObjectDirectory.php). The provided overview of the function is that it returns a handle to a named object directory **for the current session**, in the remarks stating that 'the returned handle may refer to the `BaseNamedObject` directory if the current user can gain full access to it, or the `BaseNamedObjects\Restricted` directory if not.'

Returning to WinObj will give us a better visual image of the issue this causes:

![WinObj folder structure](/winobj_root.png#center)

The `RootDirectory` we are passing is being set to `\Sessions\1\BaseNamedObjects\`, and it doesn't seem possible to traverse back past the root directory and to `\KnownDlls`. This can be confirmed by using `OpenFileMapping` to successfully open a handle to a section included in this directory:

![WinObj BaseNamedObjects example](/winobj_basenamedobjects.png#center)
![Opening example relative BNO](/bno_example_open.png#center)


## Conclusion + Workaround

So that's it - that's why you can't use `OpenFileMapping` to open the `KnownDlls` mapped section. Is there a way around it? Yep but it's a stupid amount of work in order to call `OpenFileMapping` when you could just call `NtOpenSection`, and also requires us importing functions from the hokoed version of `ntdll.dll` - which is exactly what we are trying to bypass. But we'll do it anyway because who doesn't love wasting time overengineering solutions to problems that they've made up :)

The over-the-top workaround is symlinks, as inspired by James Forshaw in https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html.

We can create a symlink to to `\GLOBAL??` and then use it in the path to the `OpenFileMapping` call:


```c
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

typedef VOID(NTAPI *_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS (WINAPI * _BaseGetNamedObjectDirectory)(HANDLE* phDir);
typedef NTSTATUS(NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);

HANDLE CreateSymlink(LPCWSTR linkname, LPCWSTR targetname) {
    HANDLE rootDir = NULL;
    HANDLE hNtdll = GetModuleHandleW(L"NTDLL");
    NTSTATUS status = NULL;
    
    _RtlInitUnicodeString fRtlInitUnicodeString = (_RtlInitUnicodeString) GetProcAddress(hNtdll, "RtlInitUnicodeString");
    _NtCreateSymbolicLinkObject fNtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject) GetProcAddress(hNtdll, "NtCreateSymbolicLinkObject");
    _BaseGetNamedObjectDirectory fBaseGetNamedObjectDirectory = (_BaseGetNamedObjectDirectory) GetProcAddress(GetModuleHandleW(L"kernel32"), "BaseGetNamedObjectDirectory");
	
    if (!fRtlInitUnicodeString || !fNtCreateSymbolicLinkObject || !fBaseGetNamedObjectDirectory) {
        printf("[!] Error resolving functions:\n");
        printf("\tfRtlInitUnicodeString: %x\n", fRtlInitUnicodeString);
        printf("\tfNtCreateSymbolicLinkObject: %x\n", fNtCreateSymbolicLinkObject);
        printf("\tfBaseGetNamedObjectDirectory: %x\n",fBaseGetNamedObjectDirectory);
        return NULL;
    }

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING name;
	UNICODE_STRING target;
	HANDLE hLink = NULL;

	fRtlInitUnicodeString(&name, linkname);
	fRtlInitUnicodeString(&target, targetname);

    status = fBaseGetNamedObjectDirectory(&rootDir);
    if (!NT_SUCCESS(status)) {
        printf("[!] Error calling BaseGetNamedObjectDirectory: %0.8X\n", status);
        return NULL;
    }

	InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, rootDir, NULL);	

	status = fNtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &target);
	if (NT_SUCCESS(status)) {
		printf("[i] Created link %ls -> %ls: %p\n", linkname, targetname, hLink);
	} else {
		printf("[!] Error creating link: %ls -> %ls\n", linkname, targetname);
	}

    CloseHandle(hNtdll);

    return hLink;
}

INT main(VOID) {
    HANDLE hNtdll = NULL;
    HANDLE symlinkRedirector = NULL;

    puts("Starting execution. Press enter to continue...");
    getchar();

    if (!(symlinkRedirector = CreateSymlink(L"inbits", L"\\GLOBAL??"))) {
        printf("[!] CreateSymlink failed\n");
        return 1;
    }

    hNtdll = OpenFileMappingW(FILE_MAP_READ, FALSE, L"inbits\\GLOBALROOT\\KnownDlls\\ntdll.dll");
    if (!hNtdll || hNtdll == INVALID_HANDLE_VALUE) {
        printf("[!] OpenFileMappingW failed with error: %d\n", GetLastError());
        return 1;
    }

    printf("[i] Opened a handle to ntdll.dll: %x\n", hNtdll);
    getchar();

    /*
        Actually overwrite the hooked ntdll.dll with the clean one 
    */

    CloseHandle(symlinkRedirector);
    CloseHandle(hNtdll);

    return 0;
}
```