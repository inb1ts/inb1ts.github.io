---
title: "Reversing npsvctrig.sys - Named Pipe Service Triggers"
date: 2026-02-02
draft: true
showToc: false
tags: ["windows", "reversing"]
---

*This post is a writeup of my notes from reversing `npsvctrig.sys`. I was recently looking into Service Triggers and couldn't find any writeups or info on this driver - hence sharing this.*

# Overview

![fltmc output](/npsvctrig/fltmc_npsvctrig.png#center)

`npsvctrig.sys` is a native Windows filesystem minifilter driver that implements, as the name suggests, part of the functionality for Named Pipe Service Triggers. The driver is small and straightforward. In a nutshell, it maintains a list of active named pipe triggers, uses minifilter callbacks to intercept specific actions being performed against those named pipes, and then publishes an ETW event containing the name of the pipe when one occurs. The Service Control Manager (SCM) consumes these events, and takes them as an indicator it should start the corresponding service executable.

# Breakdown
### `DriverEntry`

When reversing a Windows driver it nearly always makes the most sense to start with the `DriverEntry` function. This is where the driver set up is performed, and where we should get an idea of the *type* of driver we are looking at. This will be often be indicated by the kernel subsystems the driver registers callbacks with. We are also interested in any global objects being initialised and the creation of any device objects that might provide an interface through which we can communicate with the driver.

In `npsvctrig.sys` there are four notable aspects to the `DriverEntry` function:

- The registering of a WNF subscriber (via `ExSubscribeWnfStateChange`)
- The registering of two ETW publishers (via `EtwRegister`)
- The registering of file system minifilter callbacks with the Filter Manager (via `FltRegisterFilter`)
- The absence of any device objects being created, or dispatch routines being registered.

The first three of these four points actually cover the entire workflow of the driver described in the overview. Here's an extremely simplified diagram:

![Driver overview](/npsvctrig/simplified_diagram.png#center)

The driver also allocates some memory for a driver context object that has the following structure:

```c
// Size 0x40 - Tag 'Nptg'
struct DriverContext {
	PEX_PUSH_LOCK TriggerListLock;        // 0x0
	LIST_ENTRY TriggerList;               // 0x8	 
	PEX_PUSH_LOCK InstanceListLock;       // 0x18
	LIST_ENTRY InstanceList;              // 0x20
	ULONGLONG NamedPipeTimeout;           // 0x30
	PVOID Reserved;                       // 0x38
}
```

In this object, the `NamedPipeTimeout` value is read from `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\NetworkServiceTriggers\Config\NamedPipeTimeout` during the initialisation of the object. If that key doesn't exist, it's set to a default value of `-300000000`.

The remaining fields will be revisited when looking at the minifilter callbacks.

Of the two ETW publishers that are registered - one is for the provider that is used to fire the triggers for the SCM subscriber - `Microsoft-Windows-EndpointTriggerProvider` - and the other appears to be for performance/auditing events, `Microsoft-Windows-ServiceTriggerPerfEventProvider`. In terms of the logical flow of the named pipe triggers, the former is of the most interest.
## Active Triggers

The driver has to maintain an internal list of active triggers that are synchronised with triggers registered with the SCM. This is done via the Windows Notification Facility (WNF). For further reading on WNF, I recommend referring to the work of [Yarden Shafir](https://blog.trailofbits.com/2023/05/15/introducing-windows-notification-facilitys-wnf-code-integrity/), or Alex Ionescu and Gabrielle Viala's [BlackHat Presentation](https://www.youtube.com/watch?v=MybmgE95weo), though it does not play a substantial role in this driver beyond being used to keep the trigger list up to date.

Registering the WNF subscriber and associated callbacks is performed in `RtdsRegisterUpdateCallback`, called from `DriverEntry`. Interestingly, the driver contains global variables pertaining to two different WNF State Names - `WNF_RTDS_NAMED_PIPE_TRIGGER_CHANGED` and `WNF_RTDS_RPC_INTERFACE_TRIGGER_CHANGED` - but only the former is actually subscribed to. The function loops through both global objects, but only matches and subscribes to the Named Pipe trigger State Name (unless I've completely borked this reversing).

The WNF State Name `WNF_RTDS_NAMED_PIPE_TRIGGER_CHANGED` is published to by `services.exe` when a new Named Pipe service trigger is created. The state name requires SYSTEM privileges for Read/Write access. The event does not actually provide the name of the newly registered trigger - instead, it prompts the driver to update it's list from the values in the `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\NetworkServiceTriggers\Triggers\` registry key. A list of objects is created based on the values in `RtdspGetTriggerEndpoints`, and that list is passed to `RtdspGenerateEndpointChangelist`, which compares the values against the current list saved to the `DriverContext`. This produces a third list containing only the triggers that have changed - either new to the driver, or that have been removed from the registry. This third list is passed to `NptrigTriggerChangeCallback`, where `NptrigCreateTrigger` is called for ones that are new, and `NptrigDestroyTrigger` for ones that have been removed.

The structure of the trigger object that is created and then saved to the driver object is as follows:
```c
// Size 0x28 + (name strlen) - Tag 'Nptg'
struct Trigger {
	LIST_ENTRY TriggerList;                 // 0x0
	UNICODE_STRING FileName;                // 0x10
	ULONG State;                            // 0x20
	WCHAR FileNameBuf[1];                   // 0x28
}
```

Upon creation, the default value of the `State` field is `1`.

## Minifilter callbacks

### Contexts and Instance Attachment

When looking at a minifilter registration I like to start by looking at the [contexts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/registering-context-types) that are registered at the `FLT_CONTEXT_REGISTRATION ContextRegistration` field in the `FLT_REGISTRATION` object. Much of the logic of the driver will be built upon these contexts - in particular, a lot of the control flow will be dictated by flags or options that are held in these objects, so building up a map of them throughout the reverse engineering process is a necessity.

In the case of `npsvctrig.sys`, it only registers an `FLT_INSTANCE_CONTEXT` entry. This leads nicely to what is often my follow-up task, understanding the `InstanceSetupCallback` function. This callback will be executed every time a new volume is mounted, and it's where the minifilter driver decides, based on information about the newly mounted volume, whether it wants to attach itself to the filesystem stack for that volume. This is generally where the previously mentioned `FLT_INSTANCE_CONTEXT` object will be allocated with `FltAllocateContext` and the context fields will be populated with information related to the volume.

This particular driver, unsurprisingly, only attaches to volumes where the filesystem type is `FLT_FSTYPE_NPFS` (for Named Pipe File System):

![NptrigInstanceSetup](/npsvctrig/NptrigInstanceSetup.png#center)

Little else of interest happens in this function for this little driver, other than the initialisation of a callback data queue via [`FltCbdqInitialize`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcbdqinitialize). This is a cancel-safe queue that minifilter drivers can use to store callback data from incoming I/O operations. `npsvctrig.sys` uses this queue to store pending `FSCTL_WAIT_PIPE` requests, which we will touch more on later.

### Operations

The driver only registers three minifilter callbacks, and they are all post-operation:

- Post-Create: `NptrigPostCreateCallback`
- Post-CreateNamedPipe: `NptrigPostCreateNamedPipeCallback`
- Post-FsControl: `NptrigPostFsControlCallback`

The post-Create and the post-FsControl callbacks serve the purpose of actually publishing an ETW event when the operation has been performed against a named pipe with an associated trigger, assuming certain flags and the right status is set. The post-CreateNamedPipe callback is used to clear any pending requests once the named pipe has been created, and reset the state on the trigger object so that future events can be emitted again.

#### `NptrigPostCreateCallback`

![NptrigPostCreateCallback Flags](/npsvctrig/NptrigPostCreateCallback_flags.png#center)

The callback starts with checking some input parameter flags and values to determine whether or not it should continue. The `Data->IoStatus.Status == 0xc0000034` assertion checks that the status returned from the Named Pipe filesystem driver `npfs.sys` is `STATUS_OBJECT_NAME_NOT_FOUND`. We will also see this same check in the `NptrigPostFsControlCallback` callback. This might seem self-explanatory, but this highlights that the intent of the named pipe service triggers is that a client asks for a named pipe that is yet to exist, and that the presence of the named pipe indicates the service is already running and doesn't need to be triggered - in effect, the named pipe is operating a bit like a mutex. The `Data->Iopb+0x20` check corresponds to `Options->FILE_DIRECTORY_FILE`. This is an interesting check in relation to named pipes, as they don't really support directories in the traditional sense, but use the flag to implement named pipe prefixes, as described by James Forshaw in [his blog post here](https://www.tiraniddo.dev/2017/11/named-pipe-secure-prefixes.html).

The last line in the above screen shot checks that the `FILE_OBJECT` from the `FltObjects` input parameter is populated, and that the `UNICODE_STRING FileName` field on it is not zero-length. This check is here because it's possible for minifilter callbacks to be intercepting `IRP_MJ_CREATE` requests where the `FileObject` is empty, but the `RelatedFileObject` is populated. This is described in one of the *fsfilters* [blog posts](https://fsfilters.blogspot.com/2011/09/fileobject-names-in-irpmjcreate.html) (an amazing resource for anyone looking at minifilters). Specifically, they note a "reopen" case where a new handle is opened to a `FILE_OBJECT`, specified by an existing handle in the `RootDirectory` field of the `OBJECT_ATTRIBUTES` used in the `NtCreateFile` request.
 
After these checks, the driver accounts for fact that the filename being opened might start with a backslash (`0x5C`), essentially skipping over it if it does. This logic is repeated in all of the callbacks:

![NptrigPostCreateCallback Backslash](/npsvctrig/NptrigPostCreateCallback_backslash.png#center)

Next, the driver loops over the list of triggers it has and checks to see whether the name of the pipe being opened matches any of the names of the triggers. The method of checking is a typical two-step process: first the length of the names are compared, and if they are equal then the contents are compared. One notable point here is that the comparison is made using `RtlCompareMemory`, meaning that the string comparison is case sensitive - despite service event triggers being generally documented as case insensitive.

![NptrigPostCreateCallback Name Comparison](/npsvctrig/NptrigPostCreateCallback_name_comparison.png#center)

If a match is found, the driver calls `NptrigHandleTriggerableIo`, passing in the trigger object from the driver's list.

![NptrigHandleTriggerableIo](/npsvctrig/NptrigHandleTriggerableIo.png#center)

The purpose of this function is to decide whether or not the trigger should be fired based on the current state of the trigger object. If the state is `1` the trigger will just go ahead and fire. As shown in the decompilation above, if the state is `3`, there is a step that modifies the state to `1`, before proceeding with the fire. So how does the trigger reach state `3`? We'll revisit that shortly.

`NptrigFireTrigger` starts by doing some reordering of the trigger list on the `DriverContext`, removing and then reinserting the fired trigger at the head of the list. It then sets the `State` to `2`, before actually triggering the ETW event publish. 

If the fire executes successfully, the driver returns to `NptrigPostCreateCallback`, and calls `NptrigAlterIoStatus`. This function takes `STATUS_OBJECT_NAME_NOT_FOUND` status on the IRP and overwrites it with `STATUS_PIPE_NOT_AVAILABLE`.  `FltSetCallbackDataDirty` is then called to indicate to any other minifilter drivers further up the altitude list that the `FLT_CALLBACK_DATA` has been modified whilst travelling back from the filesystem driver. 

#### `NptrigPostFsControlCallback`

This callback initially shares most of the logic of the post-Create callback, before also queuing a work item that will ensure the IRP status is updated accordingly at the end of the named pipe timeout.

The function starts with another check that the status returned from `NPFS.sys` is `STATUS_OBJECT_NAME_NOT_FOUND` (0xc0000034). If this is true, it checks that the `FsControlCode` of the request is `0x110018`, corresponding to `FSCTL_PIPE_WAIT`. It checks that the input buffer length, and the input buffer point, are not null.

The expected input object for `FSCTL_PIPE_WAIT` is a structure with the [following layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f030a3b9-539c-4c7b-a893-86b795b9b711):

```c
typedef struct _FILE_PIPE_WAIT_FOR_BUFFER {
    LARGE_INTEGER Timeout;
    ULONG NameLength;
    BOOLEAN TimeoutSpecified;
    UCHAR Padding[1];
    WCHAR Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;
```

![NptrigPostFsControlCallback Input Buffer](/npsvctrig/NptrigPostFsControlCallback_input_buffer.png#center)

This input structure is retrieved from the `FLT_IO_PARAMETER_BLOCK`, and it is used to construct a `UNICODE_STRING` representation of the pipe name being waited upon. As highlighted in the comment, there is truncation as the 4-byte `NameLength` from the input structure is assigned to the `USHORT` used for the `UNICODE_STRING` length, but the `NPFS.sys` driver quite strictly imposes a `0xFFFD` limit on this value, so it doesn't seem possible to actually achieve this vulnerable condition. 

The function then passes the `UNICODE_STRING` pipe name to `NptrigFindTrigger`, which implements essentially the same logic that is seen in `NptrigPostCreateCallback` when searching the driver context trigger list for matching entry:

![NptrigFindTrigger](/npsvctrig/NptrigFindTrigger.png#center)

If a matching trigger is found, `NptrigHandleTriggerableIo` is called - the same function that handles the firing of the trigger events in `NptrigPostCreateCallback`. Upon that call succeeding, this function has one additional step, calling `NptrigQueueWaitNamedPipeRequest`.

##### `NptrigQueueWaitNamedPipeRequest`

The first thing that happens in this function is a call to `NptrigCleanupOrphanedWaitNamedPipeRequests`, but we'll revisit it after looking at the caller function first because it'll make more sense. After this, `NptrigQueueWaitNamedPipeRequest` allocates a new object that represents a pending request for a named pipe wait. It allocates `0xd0` for the core structure, in additional to the length of the name pipe, which is appended to the end of the buffer. Not all of the fields on this structure seem to be used, but a general layout is:

```c
// Size 0xd0 + pipe name len - Tag 'Nptg'
struct WaitNamedPipeReq {
	PVOID DpcDeferredContext = Data;          // 0x0
	PKDPC Dpc;                                // 0x8
	// ...
	PFLT_CALLBACK_DATA_QUEUE_IO_CONTEXT Ctx;  // 0x48
	// ...
	UNICODE_STRING PipeName;                  // 0x60
	ULONG RefCount;                           // 0x70
	KTIMER * Timer;                           // 0x78
	
	ULONG DefaultTimeout;                     // 0xb8
	ULONG State;                              // 0xbc
	PVOID WorkItem;                           // 0xc0
	PVOID InstanceContext;                    // 0xc8
	WCHAR PipeNameBuffer[1];                  // 0xd0
}
```

The `State` field on this structure is also set to `1` upon initialisation, as with the previous trigger object.

Once the object is built, a DPC is initialised with the routine `NptrigWaitNamedPipeTimeoutCallback` and the `WaitNamePipeReq` is passed to it as the context. The callback data is inserted in the callback data queue that was initialised in the instance setup, once again with the `WaitNamePipeReq` attached as context.

Following this there is a check for whether a timeout was specified in the `FILE_PIPE_WAIT_FOR_BUFFER` input, and whether it falls within an acceptable range. If no timeout was supplied, or one was supplied but is invalid, the value at `0xb8` of the `WaitNamedPipeReq` object is set to `1`, and the default named pipe timeout value that was taken from the registry and saved to the `DriverContext` is used in the `KeSetTimer` call for the DPC. Otherwise, the supplied timeout from the input buffer is used for the `DueTime` in the `KeSetTimer` call.

##### `NptrigWaitNamedPipeTimeoutCallback`

The DPC is minimal, as they are supposed to be, and really exists to queue a work item via `FltQueueGenericWorkItem`, with the routine `NptrigWaitNamedPipeTimeoutWorkItem`. A flag at offset `0xbc` of the `waitNamedPipeReq` is used to protect against the DPC being scheduled by multiple cores simultaneously and therefore queuing multiple work items. 

![NptrigWaitNamedPipeTimeoutCallback DPC Handling](/npsvctrig/NptrigWaitNamedPipeTimeoutCallback_DPC_handling.png#center)

##### `NptrigWaitNamedPipeTimeoutWorkItem`

This is where the actual purpose of the DPC and work item is carried it - it basically just updates the status on the IRP to one of two outcomes. First the callback data is removed from the callback data queue. Then the `0xb8` field is checked on the `WaitNamedPipeReq` object that was provided as an a context argument. This field was set to indicate the presence of the default named pipe timeout value. If this field is set, the status of the IRP is set to `STATUS_OBJECT_NAME_NOT_FOUND`, otherwise it is `STATUS_IO_TIMEOUT`.

![Timeout Cancel Check](/npsvctrig/timeout_cancel_check.png#center)

`FltCompletePendedPostOperation` is called to signal the post-processing has been completed, and the `WaitNamedPipeReq` object is dereferenced and then freed.

If we revisit `NptrigCleanupOrphanedWaitNamedPipeRequests` that we saw is called at the beginning of every `NptrigQueueWaitNamedPipeRequest` call, we find the exact same logic is duplicated there. This function keeps the callback data queue clear of outstanding requests on the same instance, by looping through the queue via `FltCbdqRemoveNextIo`.


#### `NptrigPostCreateNamedPipeCallback`

The last minifilter callback is intended to catch a successful creation of a named pipe that has been triggered, so that any other pending requests can be cancelled and the state on the trigger object can be updated.

![NptrigPostCreateNamedPipe Flags](/npsvctrig/NptrigPostCreateNamedPipe_flags.png#center)

There's a check at the beginning that the minifilter isn't draining, that the status on the IRP has been set to `STATUS_SUCCESS` by the `NPFS.sys` driver, and that it's not a directory open.

![NptrigPostCreatenamedPipeCallback Match](/npsvctrig/NptrigPostCreateNamedPipeCallback_match.png#center)

The function then goes through the same name-matching process against the `DriverContext` list of triggers. When it finds a successful match, it checks the `State` field on the trigger object, and if it doesn't equal `3`, then `NptrigReleasePendingRequests` is called, and the `State` is updated. This is the final state option, and means we can summarise the state of the triggers as being something like:

1. Pre-trigger fire
2. Trigger Fired
3. Pipe created

`NptrigReleasePendingRequests`, loops through the callback data queue via `FltCbdqRemoveNextIo`, but unlike `NptrigCleanupOrphanedWaitNamedPipeRequests` it provides a `PeekContext`, passing in the pipe name of the recently created trigger. As such, only pending requests bound for the same object are cancelled - any DPCs are cancelled through `KeCancelTimer`, work items through `FltFreeGenericWorkItem`, and the `WaitNamedPipeReq` is torn down with the pended operation being completed.

***

# Wrap up

This covers the general functionality and implementation of the driver. Part of my initial intent for reversing it was that I had been hunting for vulnerabilities in third-party minifilter drivers, and wanted to jump into some native ones now I was more comfortable with them. From a vulnerability research perspective, `npsvctrig.sys` doesn't present a huge attack surface. Quite a few of the ways of interacting with the driver require administrator privileges. Most of the non-privileged ways of getting data through the driver pass through other parts of the filesystem stack, where more stringent security checks occur. So I found the driver to be pretty secure - which isn't a huge surprise given it is very small.

