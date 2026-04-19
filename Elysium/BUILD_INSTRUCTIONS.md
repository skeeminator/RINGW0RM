# Elysium UEFI Bootkit - Build Instructions

## Overview

Elysium is a UEFI bootkit that bypasses Driver Signature Enforcement (DSE) by patching `winload.efi` at boot time. It allows loading unsigned, test-signed, or expired kernel drivers.

## How It Works

1. Replaces `bootmgfw.efi` (Windows Boot Manager) on the EFI partition
2. Hooks `FreePages` in EFI boot services
3. Detects when `winload.efi` is loading
4. Patches `ImgpValidateImageHash` to skip signature verification:
   - `jz short` → `jmp short`
   - `call ImgpValidateImageHash` → `xor eax, eax; nop; nop; nop`
5. Any Boot Start driver will now load regardless of signature

## Requirements

- **Visual Studio 2022** with:
  - Desktop development with C++
  - MSVC v143 toolset
  - Windows 10/11 SDK
- **Secure Boot DISABLED** in BIOS (unless you sign the bootkit)
- **UEFI system** (not legacy BIOS)

## Building

1. Open `Elysium.sln` in Visual Studio 2022
2. Select **Release | x64** configuration
3. Build the solution
4. Output: `x64\bootx64.efi`

## Driver Loading Integration

The Chaos-Rootkit plugin uses Elysium as follows:

1. **Install Driver as Boot Start**:
   ```
   sc create Chaos-Rootkit type= kernel start= boot binPath= "System32\drivers\Chaos-Rootkit.sys"
   ```

2. **Install Bootkit** (replaces bootmgfw.efi):
   ```
   copy bootx64.efi S:\EFI\Microsoft\Boot\bootmgfw.efi
   copy bootx64.efi S:\EFI\Boot\bootx64.efi
   ```

3. **Reboot** - Elysium patches DSE, driver loads automatically

## Plugin Integration

The plugin handles all of this automatically:
- `InstallRootkit` command installs driver as BOOT_START
- `EnableTestSigning` enables test signing as backup
- `InstallBootkit` deploys Elysium to EFI partition
- Original bootmgfw.efi is backed up as `bootmgfw.efi.bak.original`

## Files

| File | Purpose |
|------|---------|
| `EfiMain.c` | Entry point, hooks FreePages |
| `FreePages.c` | DSE bypass logic, patches ImgpValidateImageHash |
| `Stub.asm` | Assembly helpers |
| `edk2/` | UEFI headers (from EDK2) |

## Security Notes

- Bootkit is NOT signed - requires Secure Boot to be disabled
- Original boot manager is backed up and can be restored
- Test signing is also enabled as a fallback method
- Registry marker at `HKLM\SOFTWARE\Microsoft\Elysium` tracks installation

## Fallback: Test Signing Only

If bootkit installation fails (e.g., Secure Boot on), the plugin falls back to:
```
bcdedit /set testsigning on
```
This requires a reboot but allows test-signed drivers to load.
