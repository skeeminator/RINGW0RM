# Ring0 — Kernel Rootkit for Pulsar

A kernel-level rootkit plugin that provides true Ring 0 access on Windows x64 systems.

---

## Why Kernel Mode?

Most rootkits and RAT plugins operate entirely in user-space. This has fundamental limitations:

| Limitation | User-Mode Reality |
|------------|-------------------|
| **Process hiding** | Hooks user APIs, trivially detected by kernel-mode scanners |
| **Persistence** | Registry/startup folder, easily enumerated |
| **Privilege escalation** | Requires exploits or UAC bypass |
| **EDR evasion** | Can't touch kernel callbacks, EDR sees everything |

Ring0 operates at the kernel level, where these limitations don't apply.

---

## Key Features

### Kernel-Level Process Stealth
- **Process Hiding**: Processes become invisible to Task Manager, Process Explorer, and all enumeration APIs
- **SYSTEM Elevation**: Elevate any process to SYSTEM privileges without spawning new processes
- **PPL Protection**: Protect processes with Antimalware-Light protection level

### Security Bypass
- **DSE Bypass**: Load unsigned drivers via UEFI bootkit
- **Callback Removal**: Disable EDR/AV kernel callbacks
- **ETW Blinding**: Disable Event Tracing for Windows at the kernel level
- **AMSI Bypass**: Kernel-level AMSI patching

### Network Stealth
- **Port Hiding**: Hide listening ports from netstat and all enumeration
- **C2 Protection**: Automatic hiding of command & control connections
- **DNS Interception**: Redirect or block DNS queries
- **IP Blocking**: Kernel-level firewall

### Persistence
- **UEFI Bootkit**: Survives OS reinstalls, loads before Windows
- **Auto-Protection**: Payload automatically protected and hidden on boot
- **EFI Backup**: Payload backed up to EFI partition for restoration

---

## Comparison with r77 Rootkit

r77 is a popular open-source user-mode rootkit. Here's how the approaches differ:

| Aspect | Ring0 | r77 |
|--------|-------|-----|
| **Privilege level** | Kernel (Ring 0) | User (Ring 3) |
| **Hiding mechanism** | Kernel-level, invisible to user APIs | API hooking, detectable |
| **Detection surface** | Minimal | High |
| **Persistence** | UEFI bootkit, survives reinstalls | Registry-based |
| **SYSTEM access** | Native | Requires separate exploit |
| **EDR interaction** | Can disable kernel callbacks | Cannot touch kernel |

r77 is effective for scenarios where kernel access isn't feasible. Ring0 is for when you need capabilities that user-mode cannot provide.

---

## Comparison with User-Mode Tools

| Feature | Ring0 | Admin Only | User-Mode Tools |
|---------|-------|------------|-----------------|
| True invisibility | ✓ Kernel level | ✗ Visible in Task Manager | ✗ API hooking only |
| Survives reboot | ✓ Bootkit | ✗ No | ✗ Requires re-injection |
| SYSTEM privileges | ✓ Native | ✗ Still just Admin | ✗ Requires exploit |
| EDR/AV bypass | ✓ Callback removal | ✗ AV sees everything | ✗ Detectable hooks |
| Port hiding | ✓ Transport layer | ✗ netstat shows all | ✗ User-space hooks |
| Kill protection | ✓ PPL level | ✗ Can be terminated | ✗ Can be terminated |
| Survives OS reinstall | ✓ EFI persistence | ✗ No | ✗ No |

---

## Requirements

- Windows 10/11 x64
- Secure Boot: Must be OFF for bootkit
- Administrator privileges on target

---

## Integration

Ring0 integrates with Pulsar RAT as a plugin. The control panel provides access to all kernel features through a graphical interface. Driver deployment, bootkit installation, and persistence are handled automatically.

---

## Availability

**Sponsor's Edition License (first 10 customers only)**: $175 USD 

> Sponsors get _early_ access to the Beta plugin (current/ongoing) at a majorly discounted price + permanent 10% off other/future HopelessLabs products. You will also get priority support and priority feedback/suggestions for future updates as well as access to the RING0 Sponsor's Chat for priority support and occasional private builds and code snippetsand RING0 Beta Community

**Lifetime License (Release price)**: $300 USD 

> Base price for basic lifetime access + updates to the RING0 plugin/drivers as well as lifetime support and feedback

**Beta Lifetime License**: $350 USD 

> Beta access includes _early_ access to updates and experimental features, as well as access to the RING0 BETA Telegram Community where members can share and discuss tips, feedback, and help improve RING0 to fit their specific needs better

**VIP Edition License**: $500 USD

> VIP Edition is the same as Sponsor's Edition but with extra private features included such as a custom kernel-level R@nsomw@re encrypting faster than the majority of most existing r@nsomw@re and other features deemed "not safe for GitHub"


### What's Included
- Ring0 plugin (Server + Client DLLs)
- Kernel driver (ring0.sys)
- UEFI bootkit (ring0.efi)
- Documentation and setup guide
- Lifetime updates

### Payment
- Crypto payments only [BTC, ETH, XMR, LTC, RVN, USDT, SOL] (ETH, LTC, RVN, XMR preferred)  
- Plugin + drivers sent upon payment
- No refunds
  - If issues with payment process occurr we will troubleshoot however we can. We aren't bankers though, if it's screwed it's screwed 

---

## Contact

**Telegram**: [@skeeminator](https://t.me/skeeminator)

**Channel**: [@hopelesslabs](https://t.me/hopelesslabs)

*DM for questions, demos, or purchase*
