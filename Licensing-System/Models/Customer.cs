using System;

namespace Licensing_System.Models
{
    /// <summary>
    /// Customer data model for RINGW0RM licensing
    /// </summary>
    public class Customer
    {
        // Identity
        public string Id { get; set; } = "";              // AUTO: CUST0001
        public string Alias { get; set; } = "";           // User/Alias name
        
        // Contact (multi-platform)
        public string Telegram { get; set; } = "";
        public string Discord { get; set; } = "";
        public string Signal { get; set; } = "";
        public string Email { get; set; } = "";
        
        // Proof of Purchase
        public string ReceiptPath { get; set; } = "";     // File path to receipt
        
        // License Info
        public LicenseTier Tier { get; set; } = LicenseTier.Standard;
        public decimal PricePaid { get; set; }
        public DateTime PurchaseDate { get; set; } = DateTime.Now;
        
        // Technical
        public byte[] UniqueKey { get; set; } = Array.Empty<byte>();  // 32 bytes
        public string KeyPrefix { get; set; } = "";       // First 8 hex chars
        public string CustomerId { get; set; } = "";      // XXXX-XXXX-XXXX-XXXX (what customer sees)
        public string Notes { get; set; } = "";
        
        // Build tracking
        public string LastBuildPath { get; set; } = "";
        public DateTime? LastBuildDate { get; set; }
    }

    public enum LicenseTier
    {
        Sponsor,           // $150 - First 10, priority support, 10% off
        LifetimeNoUpdates, // $175 - Current version only
        Standard,          // $300 - Lifetime + updates
        Beta,              // $400 - Early access, private features
        Standalone         // TBD - Coming soon
    }
}
