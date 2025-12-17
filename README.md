# Handle Leak Exploit PoC

A PowerShell proof-of-concept tool for detecting and exploiting leaked process/thread handles, similar to the vulnerability class described in CVE-2025-6759 (Citrix Virtual Apps and Desktops LPE).

## Description

This tool enumerates system handles to find high-privilege process/thread handles that have been leaked into low-privilege processes. When such handles are found, the tool can exploit them using Parent Process Spoofing to spawn processes with elevated privileges.

## Features

- **System-wide enumeration**: Scans all processes for leaked handles
- **Targeted scanning**: Scan handles in a specific process by PID
- **Manual handle mode**: Manually specify a handle value to exploit
- **Automatic exploitation**: Attempts to spawn privileged processes when vulnerable handles are found
- **Integrity level detection**: Identifies Low/Medium/High/System integrity processes

## Usage

### Scan all processes for leaked handles

```powershell
.\Invoke-HandleExploit.ps1
```

### Scan a specific process

```powershell
.\Invoke-HandleExploit.ps1 -TargetPid 1234
```

### Scan and exploit automatically

```powershell
.\Invoke-HandleExploit.ps1 -TargetPid 1234 -Exploit
```

### Manually exploit a known handle

```powershell
.\Invoke-HandleExploit.ps1 -TargetPid 1234 -ManualHandle 0x5678 -Exploit
```

### Custom command execution

```powershell
.\Invoke-HandleExploit.ps1 -TargetPid 1234 -Exploit -Command "powershell.exe -NoProfile"
```

## Parameters

- `-TargetPid`: (Optional) Only scan handles held by this specific Process ID
- `-TargetTid`: (Optional) Filter for specific Thread IDs (for thread handle exploitation)
- `-ManualHandle`: (Optional) Manually specify a handle value (hex format, e.g., "0x1234") to exploit. Requires `-TargetPid`
- `-Exploit`: (Switch) Attempt to spawn a shell when a vulnerable handle is found
- `-Command`: (Optional) Command to execute in the spawned process. Defaults to `cmd.exe`

## How It Works

1. **Enumeration**: Uses `NtQuerySystemInformation` to enumerate all open handles in the system
2. **Filtering**: Identifies handles that are:
   - Of type "Process" or "Thread"
   - Held by Low/Medium integrity processes
   - Pointing to High/System integrity processes/threads
   - Have dangerous access rights (PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, etc.)
3. **Exploitation**: Uses Parent Process Spoofing via `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to spawn a child process that inherits the privileges of the target process

## Requirements

- Windows OS
- PowerShell 5.1 or later
- Administrator privileges (for full system enumeration)
- Appropriate permissions to open target processes

## Limitations

- Handles in other processes require `PROCESS_DUP_HANDLE` rights on the owner process to duplicate
- Thread handle exploitation is not fully implemented
- Some handle types may not be exploitable depending on access rights

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized use of this tool on systems without explicit permission is illegal and unethical.

## References

- [CVE-2025-6759](https://www.rapid7.com/blog/post/cve-2025-6759-citrix-virtual-apps-and-desktops-fixed/)
- [GiveMeAHand Tool](https://github.com/bananabr/Givemeahand)
- [Leaked Handle Hunting](https://aptw.tf/2022/02/10/leaked-handle-hunting.html)

