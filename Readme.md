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

### Detecting the Hook

To detect hooks in a process, we can use [hollows hunter](https://github.com/hasherezade/hollows_hunter). Hollows hunter can detect hooks in a process using the **/hooks** argument. In this example, task manager has been injected with the hook. 

![Hollows Hunter](/Doc/hollows.png)

The additional arguments work as specified:
| Argument | Description |
| - | - |
| /pname | Target process by name |
| /jlvl 2 | Set the logging level of the json summary to verbose |
| /minidmp | Dump the processes memory |

When the scan is finished, a dump directory will be created which contains the memory dumps and reporting data. The scan_report.json file has been listed below.

```json
 {
  "pid" : 24556,
  "is_64_bit" : 1,
  "is_managed" : 0,
  "main_image_path" : "C:\\Windows\\System32\\Taskmgr.exe",
  "used_reflection" : 0,
  "scanner_version" : "0.4.0.0",
  "scanned" : 
  {
   "total" : 104,
   "skipped" : 0,
   "modified" : 
   {
    "total" : 1,
    "patched" : 1,
    "iat_hooked" : 0,
    "replaced" : 0,
    "hdr_modified" : 0,
    "implanted_pe" : 0,
    "implanted_shc" : 0,
    "unreachable_file" : 0,
    "other" : 0
   },
   "errors" : 0
  },
  "scans" : [
   {
    "code_scan" : {
     "module" : "7ffa65ff0000",
     "module_size" : "1f8000",
     "module_file" : "C:\\Windows\\System32\\ntdll.dll",
     "status" : 1,
     "scanned_sections" : 2,
     "patches" : 1,
     "patches_list" : [
      {
       "rva" : "9dba0",
       "size" : 5,
       "is_hook" : 1,
       "func_name" : "NtQuerySystemInformation",
       "hook_target" : {
        "module" : "0",
        "rva" : "7ffa65fe0fd6",
        "status" : 0
       }
      }
     ]
    }
   }
  ]
 }
```

The **scans** key shows the potential hooks that were found in each module. Hollows hunter will show the hooks as **patches** in it's output. This report shows NtQuerySystemInformation has been hooked. If we add the RVA (0x000000000009DBA0) of the function to the base of the ntdll module (0x00007FFA65FF0000), we get the address of the function in memory (0x00007FFA6608DBA0
). Using a tool such as [WinDbg](http://www.windbg.org/), we can analyze the disassembly of this function at the address.

![Disasm](/Doc/windbg.png)

From this analysis, we can confirm this is a true positive detection for a hook as the standard syscall stub has been overwritten with a direct jump instruction to another location in memory. This location in memory is also listed in the report under the **rva** key in the **hook_target** dictionary.