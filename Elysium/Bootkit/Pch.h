#pragma once

#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>

#include "Native.h"
#include "Macros.h"
#include "General.h"
#include "Labels.h"
#include "Debug.h"

#include "FreePages.h"
#include "EfiMain.h"

/* GUID for EFI_FILE_INFO */
static EFI_GUID gEfiFileInfoGuid = { 0x09576e92, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };

//       |\      _,,,---,,_
// Zzz   /,`.-'`'    -.  ;-;;,_
//      |,4-  ) )-,_. ,\ (  `'-'
//     '---''(_/--'  `-\_)
