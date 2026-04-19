using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Licensing_System.Models;
using Licensing_System.Services;
using WpfMessageBox = System.Windows.MessageBox;
using WpfOpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace Licensing_System
{
    public partial class MainWindow : Window
    {
        private readonly DatabaseService _db;
        private readonly string _projectRoot;
        private Customer? _selectedCustomer;
        private List<Customer> _allCustomers = new();
        
        public MainWindow()
        {
            InitializeComponent();
            
            _db = new DatabaseService();
            
            // Find project root (go up from Licensing-System to Pulsar.Plugin.Ring0)
            _projectRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            
            // If running from bin folder, adjust
            if (!Directory.Exists(Path.Combine(_projectRoot, "Pulsar.Plugin.Ring0.Client")))
            {
                _projectRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", ".."));
            }
            
            Log($"Project root: {_projectRoot}");
            
            LoadCustomers();
            ClearForm();
        }
        
        private void LoadCustomers()
        {
            try
            {
                _allCustomers = _db.GetAllCustomers();
                dgCustomers.ItemsSource = _allCustomers;
                Log($"Loaded {_allCustomers.Count} customers");
            }
            catch (Exception ex)
            {
                Log($"ERROR loading customers: {ex.Message}");
            }
        }
        
        private void Log(string message)
        {
            txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            txtLog.ScrollToEnd();
        }
        
        private void ClearForm()
        {
            _selectedCustomer = null;
            lblFormTitle.Text = "➕ Add New Customer";
            
            txtCustomerId.Text = "(Auto-generated)";
            txtAlias.Text = "";
            txtTelegram.Text = "";
            txtDiscord.Text = "";
            txtSignal.Text = "";
            txtEmail.Text = "";
            txtReceiptPath.Text = "";
            txtPrice.Text = "300";
            txtNotes.Text = "";
            txtKeyPrefix.Text = "(Generated on save)";
            txtKeyPrefix.Foreground = System.Windows.Media.Brushes.Gray;
            
            cboTier.SelectedIndex = 2; // Standard
            
            btnDelete.IsEnabled = false;
            btnBuild.IsEnabled = false;
            btnViewDetails.IsEnabled = false;
            btnOpenBuildFolder.IsEnabled = false;
        }
        
        private void PopulateForm(Customer customer)
        {
            _selectedCustomer = customer;
            lblFormTitle.Text = $"✏️ Edit: {customer.Id}";
            
            txtCustomerId.Text = !string.IsNullOrEmpty(customer.CustomerId) 
                ? customer.CustomerId 
                : customer.Id;
            txtAlias.Text = customer.Alias;
            txtTelegram.Text = customer.Telegram;
            txtDiscord.Text = customer.Discord;
            txtSignal.Text = customer.Signal;
            txtEmail.Text = customer.Email;
            txtReceiptPath.Text = customer.ReceiptPath;
            txtPrice.Text = customer.PricePaid.ToString();
            txtNotes.Text = customer.Notes;
            txtKeyPrefix.Text = customer.KeyPrefix;
            txtKeyPrefix.Foreground = System.Windows.Media.Brushes.LimeGreen;
            
            // Set combo box
            foreach (ComboBoxItem item in cboTier.Items)
            {
                if (item.Tag?.ToString() == customer.Tier.ToString())
                {
                    cboTier.SelectedItem = item;
                    break;
                }
            }
            
            btnDelete.IsEnabled = true;
            btnBuild.IsEnabled = customer.UniqueKey.Length > 0;
            btnViewDetails.IsEnabled = true;
            btnOpenBuildFolder.IsEnabled = !string.IsNullOrEmpty(customer.LastBuildPath) && Directory.Exists(customer.LastBuildPath);
        }
        
        private Customer GetFormData()
        {
            var customer = _selectedCustomer ?? new Customer
            {
                Id = _db.GenerateNextId()
            };
            
            customer.Alias = txtAlias.Text.Trim();
            customer.Telegram = txtTelegram.Text.Trim();
            customer.Discord = txtDiscord.Text.Trim();
            customer.Signal = txtSignal.Text.Trim();
            customer.Email = txtEmail.Text.Trim();
            customer.ReceiptPath = txtReceiptPath.Text.Trim();
            customer.Notes = txtNotes.Text.Trim();
            
            if (decimal.TryParse(txtPrice.Text, out decimal price))
                customer.PricePaid = price;
            
            var selectedItem = cboTier.SelectedItem as ComboBoxItem;
            if (selectedItem?.Tag != null && Enum.TryParse<LicenseTier>(selectedItem.Tag.ToString(), out var tier))
                customer.Tier = tier;
            
            // Generate key for new customers
            if (customer.UniqueKey.Length == 0)
            {
                customer.UniqueKey = KeyGenerator.GenerateUniqueKey();
                customer.KeyPrefix = KeyGenerator.GetKeyPrefix(customer.UniqueKey);
                customer.CustomerId = KeyGenerator.GenerateCustomerId(customer.UniqueKey);
                customer.PurchaseDate = DateTime.Now;
            }
            
            return customer;
        }
        
        #region Event Handlers
        
        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            string search = txtSearch.Text.ToLower().Trim();
            
            if (string.IsNullOrEmpty(search))
            {
                dgCustomers.ItemsSource = _allCustomers;
            }
            else
            {
                dgCustomers.ItemsSource = _allCustomers.Where(c => 
                    c.Id.ToLower().Contains(search) ||
                    c.Alias.ToLower().Contains(search) ||
                    c.KeyPrefix.ToLower().Contains(search) ||
                    c.CustomerId.ToLower().Contains(search) ||
                    c.Telegram.ToLower().Contains(search) ||
                    c.Discord.ToLower().Contains(search)
                ).ToList();
            }
        }
        
        private void DgCustomers_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (dgCustomers.SelectedItem is Customer customer)
            {
                PopulateForm(customer);
            }
        }
        
        private void DgCustomers_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (dgCustomers.SelectedItem is Customer customer)
            {
                ShowCustomerDetails(customer);
            }
        }
        
        private void BtnViewDetails_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedCustomer != null)
            {
                ShowCustomerDetails(_selectedCustomer);
            }
        }
        
        private void ShowCustomerDetails(Customer customer)
        {
            string details = $@"═══════════════════════════════════════
CUSTOMER DETAILS: {customer.Id}
═══════════════════════════════════════

Alias:          {customer.Alias}
Customer ID:    {(string.IsNullOrEmpty(customer.CustomerId) ? "(not generated)" : customer.CustomerId)}
License Tier:   {customer.Tier}
Price Paid:     ${customer.PricePaid}
Purchase Date:  {customer.PurchaseDate:yyyy-MM-dd HH:mm}

── Contact Information ──
Telegram:       {(string.IsNullOrEmpty(customer.Telegram) ? "(none)" : customer.Telegram)}
Discord:        {(string.IsNullOrEmpty(customer.Discord) ? "(none)" : customer.Discord)}
Signal:         {(string.IsNullOrEmpty(customer.Signal) ? "(none)" : customer.Signal)}
Email:          {(string.IsNullOrEmpty(customer.Email) ? "(none)" : customer.Email)}

── License Key ──
Key Prefix:     {customer.KeyPrefix}
Customer ID:    {(string.IsNullOrEmpty(customer.CustomerId) ? "(not generated)" : customer.CustomerId)}
Full Key (hex): {KeyGenerator.KeyToHex(customer.UniqueKey)}

── Build Info ──
Last Build:     {(customer.LastBuildDate.HasValue ? customer.LastBuildDate.Value.ToString("yyyy-MM-dd HH:mm") : "(never)")}
Build Path:     {(string.IsNullOrEmpty(customer.LastBuildPath) ? "(none)" : customer.LastBuildPath)}

── Notes ──
{(string.IsNullOrEmpty(customer.Notes) ? "(no notes)" : customer.Notes)}";

            WpfMessageBox.Show(details, $"Customer: {customer.Id} - {customer.Alias}", 
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        
        private void BtnOpenBuildFolder_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedCustomer != null && !string.IsNullOrEmpty(_selectedCustomer.LastBuildPath))
            {
                if (Directory.Exists(_selectedCustomer.LastBuildPath))
                {
                    Process.Start("explorer.exe", _selectedCustomer.LastBuildPath);
                }
                else
                {
                    WpfMessageBox.Show($"Build folder not found:\n{_selectedCustomer.LastBuildPath}", 
                        "Folder Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }
        
        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            txtLog.Clear();
            Log("Log cleared");
        }
        
        private void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            LoadCustomers();
        }
        
        private void BtnNew_Click(object sender, RoutedEventArgs e)
        {
            dgCustomers.SelectedItem = null;
            ClearForm();
            Log("Ready to add new customer");
        }
        
        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(txtAlias.Text))
                {
                    WpfMessageBox.Show("Please enter an alias/username", "Validation", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                var customer = GetFormData();
                
                if (_selectedCustomer == null)
                {
                    _db.AddCustomer(customer);
                    Log($"✓ Added new customer: {customer.Id} ({customer.Alias}) - Key: {customer.KeyPrefix}");
                }
                else
                {
                    _db.UpdateCustomer(customer);
                    Log($"✓ Updated customer: {customer.Id}");
                }
                
                LoadCustomers();
                
                // Select the saved customer
                dgCustomers.SelectedItem = _allCustomers.FirstOrDefault(c => c.Id == customer.Id);
            }
            catch (Exception ex)
            {
                Log($"✗ ERROR saving: {ex.Message}");
                WpfMessageBox.Show($"Error saving customer: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedCustomer == null) return;
            
            var result = WpfMessageBox.Show(
                $"Delete customer {_selectedCustomer.Id} ({_selectedCustomer.Alias})?\n\nThis cannot be undone.",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            
            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    _db.DeleteCustomer(_selectedCustomer.Id);
                    Log($"✓ Deleted customer: {_selectedCustomer.Id}");
                    LoadCustomers();
                    ClearForm();
                }
                catch (Exception ex)
                {
                    Log($"✗ ERROR deleting: {ex.Message}");
                }
            }
        }
        
        private void BtnBrowseReceipt_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new WpfOpenFileDialog
            {
                Title = "Select Receipt/Proof of Purchase",
                Filter = "Image Files|*.png;*.jpg;*.jpeg|PDF Files|*.pdf|Documents|*.doc;*.docx|All Files|*.*"
            };
            
            if (dialog.ShowDialog() == true)
            {
                // Copy to receipts folder
                string receiptsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Receipts");
                if (!Directory.Exists(receiptsDir))
                    Directory.CreateDirectory(receiptsDir);
                
                string fileName = $"{_selectedCustomer?.Id ?? "NEW"}_{Path.GetFileName(dialog.FileName)}";
                string destPath = Path.Combine(receiptsDir, fileName);
                
                File.Copy(dialog.FileName, destPath, true);
                txtReceiptPath.Text = destPath;
                
                Log($"✓ Receipt saved: {fileName}");
            }
        }
        
        private async void BtnBuild_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedCustomer == null || _selectedCustomer.UniqueKey.Length == 0)
            {
                WpfMessageBox.Show("Please save the customer first to generate their key.", 
                    "No Customer Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            // Get selected build type
            var selectedBuildItem = cboBuildType.SelectedItem as ComboBoxItem;
            BuildType buildType = selectedBuildItem?.Tag?.ToString() == "CustomerDebug" 
                ? BuildType.CustomerDebug 
                : BuildType.Release;
            
            string buildTypeLabel = buildType == BuildType.CustomerDebug ? "Debug" : "Release";
            
            // Get output directory
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = $"Select output folder for {_selectedCustomer.Id} {buildTypeLabel} build"
            };
            
            if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;
            
            string outputDir = Path.Combine(dialog.SelectedPath, $"{_selectedCustomer.Id}_{_selectedCustomer.Alias}_{buildTypeLabel}");
            
            btnBuild.IsEnabled = false;
            btnBuild.Content = $"⏳ Building {buildTypeLabel}...";
            
            try
            {
                var buildService = new BuildService(_projectRoot, Log);
                bool success = await buildService.BuildForCustomer(_selectedCustomer, outputDir, buildType);
                
                if (success)
                {
                    // Update customer record
                    _selectedCustomer.LastBuildPath = outputDir;
                    _selectedCustomer.LastBuildDate = DateTime.Now;
                    _db.UpdateCustomer(_selectedCustomer);
                    
                    // Re-populate form to update button states
                    PopulateForm(_selectedCustomer);
                    
                    WpfMessageBox.Show($"Build complete!\n\nBuild Type: {buildTypeLabel}\nFiles saved to:\n{outputDir}", 
                        "Build Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    WpfMessageBox.Show("Build failed. Check the log for details.", 
                        "Build Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                Log($"✗ BUILD EXCEPTION: {ex.Message}");
                WpfMessageBox.Show($"Build error: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnBuild.IsEnabled = true;
                btnBuild.Content = "🔨 Build Selected";
            }
        }
        
        #endregion
        
        protected override void OnClosed(EventArgs e)
        {
            _db.Dispose();
            base.OnClosed(e);
        }
    }
}
