#pragma once
#include "Pch.h"

/* Cast as a pointer with the specified typedef */
#define D_API( x )	__typeof__( x )

/* Cast as a pointer-wide variable */
#define U_PTR( x )	( ULONG_PTR )( x )

/* Cast as a generic pointer */
#define C_PTR( x )	( PVOID )( x )

/* Calculates absolute address from a relative offset using GetPtr() */
#define G_PTR( x )	U_PTR( GetPtr( ) - ( U_PTR( & GetPtr ) - U_PTR( x ) ) )

/* Place function in a specific order */
#define D_SEC( x )	__pragma( code_seg( push, ".text$" #x ) )

/* End specific section alligment */
#define E_SEC       __pragma( code_seg( pop ) )

/* Arch Specific Macros */
#if defined( _WIN64 )
	/* Get the end of code: x64 */
	#define G_END   U_PTR( GetPtr( ) + 11 )
#else
	/* Get the end of code: x86 */
	#define G_END   U_PTR( GetPtr( ) + 10 )
#endif
