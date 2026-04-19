using System;
using System.Security.Cryptography;

namespace Licensing_System.Services
{
    /// <summary>
    /// Generates unique cryptographic keys for customers
    /// </summary>
    public static class KeyGenerator
    {
        private const int KEY_SIZE = 32; // 256-bit AES key
        
        /// <summary>
        /// Generate a cryptographically secure unique 32-byte key
        /// </summary>
        public static byte[] GenerateUniqueKey()
        {
            byte[] key = new byte[KEY_SIZE];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }
        
        /// <summary>
        /// Get the first 8 hex characters of a key (for identification)
        /// </summary>
        public static string GetKeyPrefix(byte[] key)
        {
            if (key == null || key.Length < 4)
                return "";
            
            return BitConverter.ToString(key, 0, 4).Replace("-", "");
        }
        
        /// <summary>
        /// Convert key to hex string for display/storage
        /// </summary>
        public static string KeyToHex(byte[] key)
        {
            return BitConverter.ToString(key).Replace("-", "");
        }
        
        /// <summary>
        /// Convert hex string back to key bytes
        /// </summary>
        public static byte[] HexToKey(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        
        /// <summary>
        /// Generate a human-readable Customer ID (XXXX-XXXX-XXXX-XXXX) from the unique key.
        /// This matches the client-side GetCustomerId() logic.
        /// </summary>
        public static string GenerateCustomerId(byte[] key)
        {
            if (key == null || key.Length < 16)
                return "";
            
            // Use first 16 bytes (first half = salt, second half = secret equivalent)
            byte[] idBytes = new byte[16];
            Array.Copy(key, 0, idBytes, 0, Math.Min(16, key.Length));
            
            // XOR with second half if available (like client does with salt ^ secret)
            if (key.Length >= 32)
            {
                for (int i = 0; i < 16; i++)
                {
                    idBytes[i] ^= key[i + 16];
                }
            }
            
            // Convert to hex and format as XXXX-XXXX-XXXX-XXXX
            string hex = BitConverter.ToString(idBytes).Replace("-", "").ToUpperInvariant();
            return $"{hex.Substring(0, 4)}-{hex.Substring(4, 4)}-{hex.Substring(8, 4)}-{hex.Substring(12, 4)}";
        }
    }
}
