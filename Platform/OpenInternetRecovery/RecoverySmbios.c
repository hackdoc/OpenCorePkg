/** @file
  SMBIOS and Apple variable detection for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

STATIC
EFI_STATUS
InternalReadAsciiVariable (
  IN  CHAR16    *Name,
  IN  EFI_GUID  *Guid,
  OUT CHAR8     *Buffer,
  IN  UINTN     BufferSize
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  UINT32      Attributes;

  if (BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Size = BufferSize - 1;
  ZeroMem (Buffer, BufferSize);

  Status = gRT->GetVariable (
                  Name,
                  Guid,
                  &Attributes,
                  &Size,
                  Buffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Buffer[Size] = '\0';
  return EFI_SUCCESS;
}

STATIC
VOID
InternalDebugMaskedValue (
  IN CONST CHAR8  *Label,
  IN CONST CHAR8  *Value
  )
{
  UINTN  Length;

  Length = AsciiStrLen (Value);
  if (Length > 8) {
    DEBUG ((
      DEBUG_INFO,
      "OIR: %a %c%c%c%c...%c%c%c%c (%u)\n",
      Label,
      Value[0],
      Value[1],
      Value[2],
      Value[3],
      Value[Length - 4],
      Value[Length - 3],
      Value[Length - 2],
      Value[Length - 1],
      (UINT32)Length
      ));
  } else {
    DEBUG ((DEBUG_INFO, "OIR: %a present (%u)\n", Label, (UINT32)Length));
  }
}

VOID
OirPrintPlatformInfo (
  OUT OIR_PLATFORM_INFO  *PlatformInfo
  )
{
  EFI_STATUS  Status;

  ASSERT (PlatformInfo != NULL);

  ZeroMem (PlatformInfo, sizeof (*PlatformInfo));
  PlatformInfo->MinMajor = 10;
  PlatformInfo->MinMinor = 15;
  PlatformInfo->MaxMajor = 26;
  PlatformInfo->MaxMinor = 0;

  Status = InternalReadAsciiVariable (
             L"HW_BID",
             &gAppleVendorVariableGuid,
             PlatformInfo->BoardId,
             sizeof (PlatformInfo->BoardId)
             );
  PlatformInfo->HasBoardId = !EFI_ERROR (Status);
  if (PlatformInfo->HasBoardId) {
    DEBUG ((DEBUG_INFO, "OIR: HW_BID %a\n", PlatformInfo->BoardId));
  } else {
    AsciiStrCpyS (PlatformInfo->BoardId, sizeof (PlatformInfo->BoardId), OIR_RECENT_BOARD_ID);
    DEBUG ((DEBUG_WARN, "OIR: HW_BID missing, using fallback %a - %r\n", PlatformInfo->BoardId, Status));
  }

  Status = InternalReadAsciiVariable (
             L"HW_MLB",
             &gAppleVendorVariableGuid,
             PlatformInfo->Mlb,
             sizeof (PlatformInfo->Mlb)
             );
  if (EFI_ERROR (Status)) {
    Status = InternalReadAsciiVariable (
               L"MLB",
               &gAppleVendorVariableGuid,
               PlatformInfo->Mlb,
               sizeof (PlatformInfo->Mlb)
               );
  }

  PlatformInfo->HasMlb = !EFI_ERROR (Status);
  if (PlatformInfo->HasMlb) {
    InternalDebugMaskedValue ("MLB", PlatformInfo->Mlb);
  } else {
    AsciiStrCpyS (PlatformInfo->Mlb, sizeof (PlatformInfo->Mlb), OIR_ZERO_MLB);
    DEBUG ((DEBUG_WARN, "OIR: MLB missing, using zero MLB - %r\n", Status));
  }

  Status = InternalReadAsciiVariable (
             L"HW_SSN",
             &gAppleVendorVariableGuid,
             PlatformInfo->Serial,
             sizeof (PlatformInfo->Serial)
             );
  if (EFI_ERROR (Status)) {
    Status = InternalReadAsciiVariable (
               L"SSN",
               &gAppleVendorVariableGuid,
               PlatformInfo->Serial,
               sizeof (PlatformInfo->Serial)
               );
  }

  PlatformInfo->HasSerial = !EFI_ERROR (Status);
  if (PlatformInfo->HasSerial) {
    InternalDebugMaskedValue ("SSN", PlatformInfo->Serial);
  } else {
    DEBUG ((DEBUG_WARN, "OIR: SSN missing - %r\n", Status));
  }

  if (!PlatformInfo->HasBoardId && !PlatformInfo->HasMlb && !PlatformInfo->HasSerial) {
    DEBUG ((
      DEBUG_WARN,
      "OIR: No SMBIOS recovery identity, using macOS %u.%u..%u range\n",
      (UINT32)PlatformInfo->MinMajor,
      (UINT32)PlatformInfo->MinMinor,
      (UINT32)PlatformInfo->MaxMajor
      ));
  }
}
