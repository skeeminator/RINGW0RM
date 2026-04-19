using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// HWID-based licensing system - locks plugin to first machine it runs on.
    /// Protected by obfuscation - do not expose internal logic.
    /// </summary>
    internal static class LicenseManager
    {
        private static readonly string LicenseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "RINGW0RM");
        private static readonly string LicenseFile = Path.Combine(LicenseDir, "ringw0rm.lic");
        
        
        // Derived key - unique per build (change for each customer if needed)
        private static readonly byte[] EncryptionKey = DeriveKey();
        
        private static bool _validated = false;
        private static readonly object _lock = new object();
        
        // Anti-tamper: checksummed validation state
        private static volatile int _authState = 0x00;
        private static volatile int _authCheck = 0x00;
        private static readonly int _runtimeSalt = Environment.TickCount ^ 0x5A5A;
        
        /// <summary>
        /// Main entry point - validates existing license or creates new one on first run.
        /// Returns true if plugin is authorized to run on this machine.
        /// </summary>
        public static bool ValidateOrActivate()
        {
            lock (_lock)
            {
                if (_validated) return true;
                
                try
                {
                    // First run - no license exists
                    if (!File.Exists(LicenseFile))
                    {
                        return ActivateFirstRun();
                    }
                    
                    // Subsequent run - validate
                    return ValidateLicense();
                }
                catch
                {
                    // Any error = unauthorized
                    return false;
                }
            }
        }
        
        /// <summary>
        /// First run: Generate HWID and create license file
        /// </summary>
        private static bool ActivateFirstRun()
        {
            try
            {
                string hwid = GenerateHWID();
                if (string.IsNullOrEmpty(hwid)) return false;
                
                // Create license directory
                if (!Directory.Exists(LicenseDir))
                {
                    Directory.CreateDirectory(LicenseDir);
                }
                
                // Encrypt and save
                byte[] encrypted = AesEncrypt(Encoding.UTF8.GetBytes(hwid), EncryptionKey);
                File.WriteAllBytes(LicenseFile, encrypted);
                
                _validated = true;
                SetAuthState();
                
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Validate stored license matches current machine
        /// </summary>
        private static bool ValidateLicense()
        {
            try
            {
                byte[] encrypted = File.ReadAllBytes(LicenseFile);
                byte[] decrypted = AesDecrypt(encrypted, EncryptionKey);
                string storedHwid = Encoding.UTF8.GetString(decrypted);
                
                string currentHwid = GenerateHWID();
                
                if (storedHwid == currentHwid)
                {
                    _validated = true;
                    SetAuthState();
                    return true;
                }
                
                // Mismatch - unauthorized machine
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Secondary checkpoint - call from multiple places to prevent simple patches
        /// Uses checksummed state to detect memory patches
        /// </summary>
        public static bool IsValid()
        {
            // Quick check using checksummed state
            return _validated && 
                   _authState == (0x5A ^ _runtimeSalt) &&
                   _authCheck == ComputeCRC(_authState) &&
                   IntegrityCheck();
        }
        
        /// <summary>
        /// Fast inline check for distributed validation
        /// </summary>
        public static bool QuickCheck() => _authState != 0 && _authCheck == ComputeCRC(_authState);
        
        private static void SetAuthState()
        {
            _authState = 0x5A ^ _runtimeSalt;
            _authCheck = ComputeCRC(_authState);
        }
        
        private static int ComputeCRC(int value)
        {
            return (value * 31) ^ 0xDEAD;
        }
        
        /// <summary>
        /// Generate hardware fingerprint from multiple sources
        /// </summary>
        private static string GenerateHWID()
        {
            var sb = new StringBuilder();
            
            try
            {
                // CPU ID
                using (var wmi = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                {
                    foreach (var obj in wmi.Get())
                    {
                        sb.Append(obj["ProcessorId"]?.ToString() ?? "");
                        break;
                    }
                }
                
                // Motherboard Serial
                using (var wmi = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                {
                    foreach (var obj in wmi.Get())
                    {
                        sb.Append(obj["SerialNumber"]?.ToString() ?? "");
                        break;
                    }
                }
                
                // BIOS Serial
                using (var wmi = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                {
                    foreach (var obj in wmi.Get())
                    {
                        sb.Append(obj["SerialNumber"]?.ToString() ?? "");
                        break;
                    }
                }
                
                // First Disk Serial
                using (var wmi = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_DiskDrive"))
                {
                    foreach (var obj in wmi.Get())
                    {
                        sb.Append(obj["SerialNumber"]?.ToString() ?? "");
                        break;
                    }
                }
                
                // First MAC Address
                var mac = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up && 
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(n => n.GetPhysicalAddress().ToString())
                    .FirstOrDefault();
                sb.Append(mac ?? "");
            }
            catch
            {
                // If WMI fails, fall back to basic identifiers
                sb.Append(Environment.MachineName);
                sb.Append(Environment.UserName);
            }
            
            // Hash the combined fingerprint
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }
        
        /// <summary>
        /// Derive encryption key (unique per build)
        /// </summary>
        private static byte[] DeriveKey()
        {
            // Obfuscated key derivation - change these constants per customer build
            const string salt = "R1ng0K3y$@lt2024!";
            const string secret = "Ch@0sR00tk1tM@st3r";
            
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(salt + secret));
            }
        }
        
        /// <summary>
        /// Integrity check - verify license validation code hasn't been tampered
        /// </summary>
        private static bool IntegrityCheck()
        {
            // Simple check - if _validated is true but license file doesn't exist, we've been patched
            if (_validated && !File.Exists(LicenseFile))
            {
                _validated = false;
                return false;
            }
            return true;
        }
        
        #region AES Encryption
        
        private static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                
                using (var ms = new MemoryStream())
                {
                    // Write IV first
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                    }
                    
                    return ms.ToArray();
                }
            }
        }
        
        private static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                
                // Extract IV from beginning
                byte[] iv = new byte[16];
                Array.Copy(data, 0, iv, 0, 16);
                aes.IV = iv;
                
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 16, data.Length - 16);
                    }
                    
                    return ms.ToArray();
                }
            }
        }
        
        #endregion
    }
}
