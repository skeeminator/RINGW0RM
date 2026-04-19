# Ring0 Rootkit Plugin for Pulsar RAT

## Overview

Dropping this since the source got reversed/leaked by C5Hackr (lol thought it was pretty cool the project picked up enough traction to get cracked lol). It's a sloppy repo cuz it was meant to be private but I'd rather just drop it than let people get infected from some copies off Telegram lmao. Though it's organized awfully I was pretty proud of this project (aside from the pretty obviously bad licensing system lol I wanted to experiment with offline authentication cuz I didnt want to rent a server lol). Probably better to pick and pull from than for straight forward usage at this point in time I'd imagine. People talked shit that it was just a Chaos clone but there was lots of modifications made and actual months of research into this so I figure no point in holding it back at this point. Anyways you can thank C5Hackr, was an honor lol ;)

Ring0 is a kernel-level rootkit plugin that provides true Ring 0 (kernel) access for comprehensive system control. Unlike user-mode tools, Ring0 operates at the deepest level of Windows, enabling capabilities that are impossible to achieve from user-space.

## Key Features

### Kernel-Level Process Stealth

- **DKOM Process Hiding**: Processes become invisible to Task Manager, Process Explorer, and all enumeration APIs
- **SYSTEM Token Elevation**: Elevate any process to SYSTEM privileges without spawning new processes
- **PPL Protection**: Protect processes with Antimalware-Light protection level (same as Windows Defender)
- **SYSTEM Shell**: Interactive command shell running as NT AUTHORITY\SYSTEM

### Security Bypass

- **DSE Bypass**: Load unsigned drivers via UEFI bootkit
- **Callback Removal**: Disable EDR/AV kernel callbacks (process, thread, image load, registry)
- **ETW Blinding**: Disable Event Tracing for Windows at the kernel level
- **AMSI Bypass**: Kernel-level AMSI patching
- **Defender Killer**: Permanently disable Windows Defender and related security services

### Network Stealth

- **Port Hiding**: Hide any TCP/UDP port from netstat, Task Manager, and all network enumeration
- **DNS Interception**: Redirect or block DNS queries at the kernel level
- **IP Blocking**: Kernel-level firewall for blocking specific IPs

### Persistence

- **UEFI Bootkit**: Survives OS reinstalls, loads before Windows
- **Auto-Protection**: Payload automatically protected and hidden on boot
- **Multi-Layer Persistence**: Registry Run key, scheduled task, and startup folder shortcuts

## Installation

1. Place plugin DLLs in Pulsar's `Plugins` folder
2. Restart Pulsar Server
3. Right-click client → Ring0 → Install Rootkit
4. Reboot target (required for bootkit activation)

## Control Panel

The Ring0 Control Panel provides a graphical interface for all features:

- **Status Tab**: Driver connection, DSE status, protection state
- **Process Tab**: Hide, elevate, and protect processes
- **Network Tab**: Port hiding, IP blocking, DNS rules
- **Security Tab**: Callback killing, ETW/AMSI bypass
- **Bootkit Tab**: Installation status, diagnostics

## Requirements

- Windows 10/11 x64
- Secure Boot: Must be OFF for bootkit (test signing mode as fallback)
- Administrator privileges on target

## Comparison with User-Mode Tools

| Feature | Ring0 | User-Mode (r77, etc.) |
|---------|-------|----------------------|
| True invisibility | ✓ Kernel DKOM | ✗ API hooking only |
| Survives reboot | ✓ Bootkit | ✗ Requires re-injection |
| SYSTEM privileges | ✓ Token manipulation | ✗ Requires exploit |
| EDR bypass | ✓ Callback removal | ✗ Easy to detect |
| Port hiding | ✓ NDIS/TDI level | ✗ User-space hooks |

## Troubleshooting

**Driver won't load**: Check if Secure Boot is disabled and test signing is enabled.

**No connection after reboot**: Verify payload path exists and HKCU Run key is set.

**Features not working**: Ensure driver shows "Connected" in the Control Panel.

## Support

For technical support and updates, contact the vendor.
