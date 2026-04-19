#pragma once
#include "Pch.h"

#define SLEEP(ms) Gen->SystemTable->BootServices->Stall(ms * 1000);

#define INFINITY_LOOP() for (;;)

#define SET_BACKGROUND(x)                                                      \
  Gen->SystemTable->ConOut->SetAttribute(Gen->SystemTable->ConOut, x);

#define CLEAR_SCREEN()                                                         \
  Gen->SystemTable->ConOut->ClearScreen(Gen->SystemTable->ConOut);

#define LOG(text, ...)                                                         \
  Gen->SystemTable->ConOut->OutputString(Gen->SystemTable->ConOut,             \
                                         (CHAR16 *)text L"\r\n");

#define Error(text, ...)                                                       \
  LOG(text, ##__VA_ARGS__);                                                    \
  INFINITY_LOOP();

/* ================================================================
 * CUSTOMER DEBUG LOGGING
 * Enabled by defining CUSTOMER_DEBUG preprocessor symbol
 * Provides status output during boot for troubleshooting
 * ================================================================ */
#ifdef CUSTOMER_DEBUG
#define LOG_DEBUG(text)                                                        \
  Gen->SystemTable->ConOut->OutputString(Gen->SystemTable->ConOut,             \
                                         L"[RINGW0RM] ");                      \
  Gen->SystemTable->ConOut->OutputString(Gen->SystemTable->ConOut,             \
                                         (CHAR16 *)text L"\r\n");

#define LOG_DEBUG_STATUS(component, status)                                    \
  Gen->SystemTable->ConOut->OutputString(Gen->SystemTable->ConOut,             \
                                         L"[RINGW0RM] ");                      \
  Gen->SystemTable->ConOut->OutputString(Gen->SystemTable->ConOut,             \
                                         (CHAR16 *)component);                 \
  Gen->SystemTable->ConOut->OutputString(                                      \
      Gen->SystemTable->ConOut,                                                \
      (CHAR16 *)((status) ? L": OK\r\n" : L": FAIL\r\n"));
#else
#define LOG_DEBUG(text)
#define LOG_DEBUG_STATUS(component, status)
#endif
