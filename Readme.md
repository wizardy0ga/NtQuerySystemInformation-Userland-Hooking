# API Hooking: NtQuerySystemInformation

This project provides a demonstration on hooking the NtQuerySystemInformation system call to hide processes from programs on Windows. This technique is primarily used by ring 3 / user-land root kits to hide arbitrary processes on the system however it can be applied to any form of malware.

### What is API Hooking?

API Hooking is a programming technique that allows developers to modify how an API call functions. For example, a function call could be modified to always return a specific result. Another example would be processing the parameters that were passed to a function call or the output of the original function call. A good example of processing parameters is the [RdpThief](https://github.com/0x09AL/RdpThief) project which uses API Hooking to capture clear text account credentials when an RDP session is initiated from an mstsc.exe process which has the RdpThief.dll loaded.

Notably, EDR tools will also use API hooking to process the parameters of API calls that are frequently abused by threat actors. A function call like CreateRemoteThread may be hooked by the EDR to inspect the **lpStartAddress** parameter which points at the base address of the code to be executed by the new thread. If this parameter is pointing at a signatured shellcode such as anything from msfvenom, then the EDR will take appropriate action & alert or prevent the calling process from continuing.

API hooking can be done in userland or the kernel. This project uses userland API hooking. For windows, API hooking from user-land typically involves a DLL containing the modified function call & the code to install the hook in the target process. This DLL gets injected into the target process where it will install the hooks. When the hooks are installed, any function calls from the injected process to the hooked functions will be redirected to the hooked implementation. Note that this only effects the injected process. Any other process which doesn't have the DLL injected will continue to execute the standard functions when called.

### NtQuerySystemInformation

[NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) is an API call from the windows native API. The native API is the last stop before kernel land in Windows. By hooking native API calls, we can effectively intercept any function calls to higher level API's that rely on the native API.  

NtQuerySystemInformation is a versatile function call. It can be used to capture information on many things such as running processes, CPU count & much more. See the [SystemInformationClass](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#parameters) parameter for further information on the capabilities of this function call.

Our hook will target the SystemProcessInformation value of the SystemInformationClass parameter. This value instructs the NtQuerySystemInformation function to retrieve a list of all running processes on the system. These processes are returned as an array of pointers. Each pointer points to a [SYSTEM_PROCESS_INFORMATION](https://ntdoc.m417z.com/system_process_information) structure which represents a single process returned in the output. 

### Technical Details for Hiding Processes w/ the Hook
The core of this technique is offset manipulation. For each SYSTEM_PROCESS_INFORMATION structure, there is a member called **NextEntryOffset**. This member informs us how many bytes away the next structure is. By tampering with this value, we can make the previous process in the array point to the next entry in the array from the current entry. This will hide the current process in the array since the previous process is now pointing over the current process to the next process.

![Image](/Doc/visual.png)
###### In this depiction, beacon.exe will be hidden since svchost.exe now points to chrome.exe rather than beacon.exe.

### Demo

In this example, the hooking dll has been configured to hide **powershell.exe**. When the DLL is injected into [SystemInformer](https://systeminformer.com), the powershell processes will disappear. This is due to SystemInformers reliance on the NtQuerySystemInformation function, which has been hooked by our dll. The API call is intercepted & powershell is removed. This will work on any userland process monitoring application such as task manager & procexp.

![Hooking Demo](/Doc/Hook_Demo.gif)