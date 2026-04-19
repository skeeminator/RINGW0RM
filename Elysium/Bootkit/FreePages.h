#pragma once
#include "Pch.h"

/*!
 *
 * Purpose:
 *
 * Detects when being executed from the winload.efi module
 * and patches the signature verification in the
 * ImgpLoadPEImage routine.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI FreePagesHook( IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages ) E_SEC;