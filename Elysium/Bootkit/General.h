#pragma once
#include "Pch.h"

typedef struct __declspec( align( 1 ) ) 
{
    PEFI_SYSTEM_TABLE           SystemTable;
    PVOID                       FreePages;
} GENTBL, *PGENTBL;

