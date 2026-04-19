using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Licensing_System.Models;

namespace Licensing_System.Services
{
    /// <summary>
    /// Build types for customer releases
    /// </summary>
    public enum BuildType
    {
        Release,        // Production build - obfuscated, no debug logging
        CustomerDebug   // Troubleshooting build - obfuscated, component logging enabled
    }

    /// <summary>
    /// Service to build customer-specific releases
    /// </summary>
    public class BuildService
    {
        private readonly string _projectRoot;
        private readonly Action<string> _log;
        
        public BuildService(string projectRoot, Action<string> log)
        {
            _projectRoot = projectRoot;
            _log = log;
        }
        
        /// <summary>
        /// Build a customer-specific release with their unique key embedded
        /// </summary>
        public async Task<bool> BuildForCustomer(Customer customer, string outputDir, BuildType buildType = BuildType.Release)
        {
            try
            {
                string buildTypeName = buildType == BuildType.CustomerDebug ? "Customer Debug" : "Release";
                _log($"[BUILD] Starting {buildTypeName} build for {customer.Id} ({customer.Alias})...");
                
                // Step 1: Inject customer key into source
                _log("[BUILD] Injecting customer key...");
                if (!InjectCustomerKey(customer))
                {
                    _log("[BUILD] ERROR: Failed to inject customer key");
                    return false;
                }
                
                // Step 2: Run the appropriate build script
                string buildScript = GetBuildScript(buildType);
                _log($"[BUILD] Running {buildScript}...");
                var (success, output) = await RunBuildScript(buildScript, buildType);
                
                if (!success)
                {
                    _log($"[BUILD] ERROR: Build failed\n{output}");
                    // Restore original key
                    RestoreOriginalKey();
                    return false;
                }
                
                _log("[BUILD] Build successful!");
                
                // Step 3: Copy output to customer directory
                _log($"[BUILD] Copying files to {outputDir}...");
                CopyBuildOutput(outputDir, buildType);
                
                // Step 4: Restore original key placeholder for next build
                _log("[BUILD] Restoring key placeholder...");
                RestoreOriginalKey();
                
                _log($"[BUILD] Complete! Files saved to: {outputDir}");
                return true;
            }
            catch (Exception ex)
            {
                _log($"[BUILD] EXCEPTION: {ex.Message}");
                RestoreOriginalKey();
                return false;
            }
        }
        
        private string GetBuildScript(BuildType buildType)
        {
            return buildType switch
            {
                BuildType.CustomerDebug => "build_customer_debug.bat",
                _ => "build_release.bat"
            };
        }
        
        private bool InjectCustomerKey(Customer customer)
        {
            // Client-side key injection
            string licenseManagerPath = Path.Combine(_projectRoot, 
                "Pulsar.Plugin.Ring0.Client", "LicenseManager.cs");
            
            if (!File.Exists(licenseManagerPath))
            {
                _log($"[BUILD] LicenseManager.cs not found at {licenseManagerPath}");
                return false;
            }
            
            string content = File.ReadAllText(licenseManagerPath);
            
            // The key derivation method - replace with customer-specific key
            string keyHex = KeyGenerator.KeyToHex(customer.UniqueKey);
            
            // Find and replace the DeriveKey method content
            // We'll inject the key by replacing the salt/secret constants
            string customerSalt = $"CUST_{customer.Id}_{keyHex.Substring(0, 16)}";
            string customerSecret = keyHex.Substring(16);
            
            // Replace the hardcoded constants
            content = content.Replace(
                "const string salt = \"R1ng0K3y$@lt2024!\";",
                $"const string salt = \"{customerSalt}\";"
            );
            content = content.Replace(
                "const string secret = \"Ch@0sR00tk1tM@st3r\";",
                $"const string secret = \"{customerSecret}\";"
            );
            
            // Backup original
            File.Copy(licenseManagerPath, licenseManagerPath + ".bak", true);
            
            // Write modified
            File.WriteAllText(licenseManagerPath, content);
            
            // Server plugin - inject Customer ID directly for display
            string pluginServerPath = Path.Combine(_projectRoot, 
                "Pulsar.Plugin.Ring0.Server", "PluginServer.cs");
            
            if (File.Exists(pluginServerPath))
            {
                string serverContent = File.ReadAllText(pluginServerPath);
                
                // Replace the placeholder with the actual Customer ID
                serverContent = serverContent.Replace(
                    "const string customerId = \"XXXX-XXXX-XXXX-XXXX\";",
                    $"const string customerId = \"{customer.CustomerId}\";"
                );
                
                File.Copy(pluginServerPath, pluginServerPath + ".bak", true);
                File.WriteAllText(pluginServerPath, serverContent);
            }
            
            return true;
        }
        
        private void RestoreOriginalKey()
        {
            // Restore Client LicenseManager.cs
            string licenseManagerPath = Path.Combine(_projectRoot, 
                "Pulsar.Plugin.Ring0.Client", "LicenseManager.cs");
            string backupPath = licenseManagerPath + ".bak";
            
            if (File.Exists(backupPath))
            {
                File.Copy(backupPath, licenseManagerPath, true);
                File.Delete(backupPath);
            }
            
            // Restore Server PluginServer.cs
            string pluginServerPath = Path.Combine(_projectRoot, 
                "Pulsar.Plugin.Ring0.Server", "PluginServer.cs");
            string serverBackupPath = pluginServerPath + ".bak";
            
            if (File.Exists(serverBackupPath))
            {
                File.Copy(serverBackupPath, pluginServerPath, true);
                File.Delete(serverBackupPath);
            }
        }
        
        private async Task<(bool success, string output)> RunBuildScript(string scriptName, BuildType buildType)
        {
            string buildScript = Path.Combine(_projectRoot, scriptName);
            
            if (!File.Exists(buildScript))
            {
                return (false, $"Build script not found: {buildScript}");
            }
            
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{buildScript}\"",
                WorkingDirectory = _projectRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            var output = new StringBuilder();
            
            using var process = new Process { StartInfo = psi };
            
            process.OutputDataReceived += (s, e) => 
            {
                if (e.Data != null) output.AppendLine(e.Data);
            };
            process.ErrorDataReceived += (s, e) => 
            {
                if (e.Data != null) output.AppendLine(e.Data);
            };
            
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            
            await process.WaitForExitAsync();
            
            return (process.ExitCode == 0, output.ToString());
        }
        
        private void CopyBuildOutput(string outputDir, BuildType buildType)
        {
            if (!Directory.Exists(outputDir))
                Directory.CreateDirectory(outputDir);
            
            // Select correct source directory based on build type
            string pluginsDir = buildType == BuildType.CustomerDebug 
                ? Path.Combine(_projectRoot, "plugins_customer_debug")
                : Path.Combine(_projectRoot, "plugins");
            
            _log($"[BUILD] Copying from: {pluginsDir}");
            
            // Required files
            string[] requiredFiles = 
            {
                "Pulsar.Plugin.Ring0.Client.dll",
                "Pulsar.Plugin.Ring0.Common.dll",
                "Pulsar.Plugin.Ring0.Server.dll",
                "ringw0rm.sys"
            };
            
            // Optional files (may not exist)
            string[] optionalFiles =
            {
                "ringw0rm.efi",
                "Pulsar.Plugin.Ring0.Server.deps.json"
            };
            
            int copied = 0;
            
            foreach (var file in requiredFiles)
            {
                string src = Path.Combine(pluginsDir, file);
                string dst = Path.Combine(outputDir, file);
                
                if (File.Exists(src))
                {
                    File.Copy(src, dst, true);
                    _log($"  ✓ Copied: {file}");
                    copied++;
                }
                else
                {
                    _log($"  ✗ MISSING (required): {file}");
                }
            }
            
            foreach (var file in optionalFiles)
            {
                string src = Path.Combine(pluginsDir, file);
                string dst = Path.Combine(outputDir, file);
                
                if (File.Exists(src))
                {
                    File.Copy(src, dst, true);
                    _log($"  ✓ Copied: {file}");
                    copied++;
                }
                else
                {
                    _log($"  ⚠ Not found (optional): {file}");
                }
            }
            
            _log($"[BUILD] Copied {copied} files to output directory");
        }
    }
}
