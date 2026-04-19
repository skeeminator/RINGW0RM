using System;
using System.Collections.Generic;
using System.IO;
using Licensing_System.Models;
using Microsoft.Data.Sqlite;

namespace Licensing_System.Services
{
    /// <summary>
    /// SQLite database service for customer management
    /// </summary>
    public class DatabaseService : IDisposable
    {
        private readonly string _connectionString;
        private readonly string _dbPath;
        
        public DatabaseService()
        {
            // Store database in app directory
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            _dbPath = Path.Combine(appDir, "customers.db");
            _connectionString = $"Data Source={_dbPath}";
            
            InitializeDatabase();
        }
        
        private void InitializeDatabase()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            string createTable = @"
                CREATE TABLE IF NOT EXISTS Customers (
                    Id TEXT PRIMARY KEY,
                    Alias TEXT,
                    Telegram TEXT,
                    Discord TEXT,
                    Signal TEXT,
                    Email TEXT,
                    ReceiptPath TEXT,
                    Tier INTEGER,
                    PricePaid REAL,
                    PurchaseDate TEXT,
                    UniqueKey BLOB,
                    KeyPrefix TEXT,
                    CustomerId TEXT,
                    Notes TEXT,
                    LastBuildPath TEXT,
                    LastBuildDate TEXT
                )";
            
            using var command = new SqliteCommand(createTable, connection);
            command.ExecuteNonQuery();
            
            // Migration: Add CustomerId column to existing tables that don't have it
            MigrateDatabase(connection);
        }
        
        private void MigrateDatabase(SqliteConnection connection)
        {
            // Check if CustomerId column exists
            using var pragmaCmd = new SqliteCommand("PRAGMA table_info(Customers)", connection);
            using var reader = pragmaCmd.ExecuteReader();
            
            bool hasCustomerId = false;
            while (reader.Read())
            {
                if (reader.GetString(1) == "CustomerId")
                {
                    hasCustomerId = true;
                    break;
                }
            }
            reader.Close();
            
            // Add column if missing
            if (!hasCustomerId)
            {
                using var alterCmd = new SqliteCommand("ALTER TABLE Customers ADD COLUMN CustomerId TEXT", connection);
                alterCmd.ExecuteNonQuery();
            }
        }
        
        public string GenerateNextId()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            // Get the highest existing CUST number to avoid conflicts after deletions
            using var command = new SqliteCommand(
                "SELECT MAX(CAST(SUBSTR(Id, 5) AS INTEGER)) FROM Customers WHERE Id LIKE 'CUST%'", 
                connection);
            var result = command.ExecuteScalar();
            
            int nextNum = 1;
            if (result != null && result != DBNull.Value)
            {
                nextNum = Convert.ToInt32(result) + 1;
            }
            
            return $"CUST{nextNum:D4}";
        }
        
        public void AddCustomer(Customer customer)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            string sql = @"
                INSERT OR REPLACE INTO Customers (Id, Alias, Telegram, Discord, Signal, Email, ReceiptPath, 
                    Tier, PricePaid, PurchaseDate, UniqueKey, KeyPrefix, CustomerId, Notes, LastBuildPath, LastBuildDate)
                VALUES (@Id, @Alias, @Telegram, @Discord, @Signal, @Email, @ReceiptPath,
                    @Tier, @PricePaid, @PurchaseDate, @UniqueKey, @KeyPrefix, @CustomerId, @Notes, @LastBuildPath, @LastBuildDate)";
            
            using var command = new SqliteCommand(sql, connection);
            command.Parameters.AddWithValue("@Id", customer.Id);
            command.Parameters.AddWithValue("@Alias", customer.Alias ?? "");
            command.Parameters.AddWithValue("@Telegram", customer.Telegram ?? "");
            command.Parameters.AddWithValue("@Discord", customer.Discord ?? "");
            command.Parameters.AddWithValue("@Signal", customer.Signal ?? "");
            command.Parameters.AddWithValue("@Email", customer.Email ?? "");
            command.Parameters.AddWithValue("@ReceiptPath", customer.ReceiptPath ?? "");
            command.Parameters.AddWithValue("@Tier", (int)customer.Tier);
            command.Parameters.AddWithValue("@PricePaid", (double)customer.PricePaid);
            command.Parameters.AddWithValue("@PurchaseDate", customer.PurchaseDate.ToString("O"));
            command.Parameters.AddWithValue("@UniqueKey", customer.UniqueKey);
            command.Parameters.AddWithValue("@KeyPrefix", customer.KeyPrefix ?? "");
            command.Parameters.AddWithValue("@CustomerId", customer.CustomerId ?? "");
            command.Parameters.AddWithValue("@Notes", customer.Notes ?? "");
            command.Parameters.AddWithValue("@LastBuildPath", customer.LastBuildPath ?? "");
            command.Parameters.AddWithValue("@LastBuildDate", customer.LastBuildDate?.ToString("O") ?? (object)DBNull.Value);
            
            command.ExecuteNonQuery();
        }
        
        public void UpdateCustomer(Customer customer)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            string sql = @"
                UPDATE Customers SET 
                    Alias = @Alias, Telegram = @Telegram, Discord = @Discord, Signal = @Signal,
                    Email = @Email, ReceiptPath = @ReceiptPath, Tier = @Tier, PricePaid = @PricePaid,
                    PurchaseDate = @PurchaseDate, UniqueKey = @UniqueKey, KeyPrefix = @KeyPrefix,
                    CustomerId = @CustomerId, Notes = @Notes, LastBuildPath = @LastBuildPath, LastBuildDate = @LastBuildDate
                WHERE Id = @Id";
            
            using var command = new SqliteCommand(sql, connection);
            command.Parameters.AddWithValue("@Id", customer.Id);
            command.Parameters.AddWithValue("@Alias", customer.Alias ?? "");
            command.Parameters.AddWithValue("@Telegram", customer.Telegram ?? "");
            command.Parameters.AddWithValue("@Discord", customer.Discord ?? "");
            command.Parameters.AddWithValue("@Signal", customer.Signal ?? "");
            command.Parameters.AddWithValue("@Email", customer.Email ?? "");
            command.Parameters.AddWithValue("@ReceiptPath", customer.ReceiptPath ?? "");
            command.Parameters.AddWithValue("@Tier", (int)customer.Tier);
            command.Parameters.AddWithValue("@PricePaid", (double)customer.PricePaid);
            command.Parameters.AddWithValue("@PurchaseDate", customer.PurchaseDate.ToString("O"));
            command.Parameters.AddWithValue("@UniqueKey", customer.UniqueKey);
            command.Parameters.AddWithValue("@KeyPrefix", customer.KeyPrefix ?? "");
            command.Parameters.AddWithValue("@CustomerId", customer.CustomerId ?? "");
            command.Parameters.AddWithValue("@Notes", customer.Notes ?? "");
            command.Parameters.AddWithValue("@LastBuildPath", customer.LastBuildPath ?? "");
            command.Parameters.AddWithValue("@LastBuildDate", customer.LastBuildDate?.ToString("O") ?? (object)DBNull.Value);
            
            command.ExecuteNonQuery();
        }
        
        public void DeleteCustomer(string id)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            using var command = new SqliteCommand("DELETE FROM Customers WHERE Id = @Id", connection);
            command.Parameters.AddWithValue("@Id", id);
            command.ExecuteNonQuery();
        }
        
        public List<Customer> GetAllCustomers()
        {
            var customers = new List<Customer>();
            
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            using var command = new SqliteCommand("SELECT * FROM Customers ORDER BY PurchaseDate DESC", connection);
            using var reader = command.ExecuteReader();
            
            while (reader.Read())
            {
                customers.Add(ReadCustomer(reader));
            }
            
            return customers;
        }
        
        public Customer? GetCustomerById(string id)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            using var command = new SqliteCommand("SELECT * FROM Customers WHERE Id = @Id", connection);
            command.Parameters.AddWithValue("@Id", id);
            
            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadCustomer(reader) : null;
        }
        
        public Customer? FindByKeyPrefix(string keyPrefix)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            
            using var command = new SqliteCommand("SELECT * FROM Customers WHERE KeyPrefix LIKE @Prefix", connection);
            command.Parameters.AddWithValue("@Prefix", $"{keyPrefix}%");
            
            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadCustomer(reader) : null;
        }
        
        private static Customer ReadCustomer(SqliteDataReader reader)
        {
            // Read by column name to handle different column orders
            // (ALTER TABLE adds columns at end, but CREATE TABLE puts them in order)
            return new Customer
            {
                Id = GetSafeString(reader, "Id"),
                Alias = GetSafeString(reader, "Alias"),
                Telegram = GetSafeString(reader, "Telegram"),
                Discord = GetSafeString(reader, "Discord"),
                Signal = GetSafeString(reader, "Signal"),
                Email = GetSafeString(reader, "Email"),
                ReceiptPath = GetSafeString(reader, "ReceiptPath"),
                Tier = (LicenseTier)reader.GetInt32(reader.GetOrdinal("Tier")),
                PricePaid = (decimal)reader.GetDouble(reader.GetOrdinal("PricePaid")),
                PurchaseDate = DateTime.Parse(reader.GetString(reader.GetOrdinal("PurchaseDate"))),
                UniqueKey = GetSafeBlob(reader, "UniqueKey"),
                KeyPrefix = GetSafeString(reader, "KeyPrefix"),
                CustomerId = GetSafeString(reader, "CustomerId"),
                Notes = GetSafeString(reader, "Notes"),
                LastBuildPath = GetSafeString(reader, "LastBuildPath"),
                LastBuildDate = GetSafeDateTime(reader, "LastBuildDate")
            };
        }
        
        private static string GetSafeString(SqliteDataReader reader, string columnName)
        {
            int ordinal = reader.GetOrdinal(columnName);
            return reader.IsDBNull(ordinal) ? "" : reader.GetString(ordinal);
        }
        
        private static byte[] GetSafeBlob(SqliteDataReader reader, string columnName)
        {
            int ordinal = reader.GetOrdinal(columnName);
            return reader.IsDBNull(ordinal) ? Array.Empty<byte>() : (byte[])reader[ordinal];
        }
        
        private static DateTime? GetSafeDateTime(SqliteDataReader reader, string columnName)
        {
            int ordinal = reader.GetOrdinal(columnName);
            if (reader.IsDBNull(ordinal)) return null;
            return DateTime.Parse(reader.GetString(ordinal));
        }
        
        public void Dispose()
        {
            // SQLite connections are disposed per operation
        }
    }
}
