/** @file
  Apple recovery session handling for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

STATIC
VOID
InternalGenerateHex (
  OUT CHAR8  *Buffer,
  IN  UINTN  Length
  )
{
  EFI_TIME  Time;
  UINT64    State;
  UINTN     Index;

  ASSERT (Buffer != NULL);

  ZeroMem (&Time, sizeof (Time));
  gRT->GetTime (&Time, NULL);

  State  = AsmReadTsc ();
  State ^= LShiftU64 ((UINT64)Time.Year, 48);
  State ^= LShiftU64 ((UINT64)Time.Month, 40);
  State ^= LShiftU64 ((UINT64)Time.Day, 32);
  State ^= LShiftU64 ((UINT64)Time.Hour, 24);
  State ^= LShiftU64 ((UINT64)Time.Minute, 16);
  State ^= LShiftU64 ((UINT64)Time.Second, 8);

  for (Index = 0; Index < Length; ++Index) {
    State         = MultU64x64 (State, 6364136223846793005ULL) + 1442695040888963407ULL;
    Buffer[Index] = "0123456789ABCDEF"[(State >> 60) & 0xF];
  }

  Buffer[Length] = '\0';
}

STATIC
EFI_STATUS
InternalBuildPostBody (
  IN  OIR_RECOVERY_MODE        Mode,
  IN  CONST OIR_PLATFORM_INFO  *PlatformInfo,
  OUT CHAR8                    *Body,
  IN  UINTN                    BodySize
  )
{
  CHAR8        Cid[17];
  CHAR8        Key[65];
  CHAR8        FirmwareGroup[65];
  CONST CHAR8  *OsType;
  CONST CHAR8  *Mlb;
  CONST CHAR8  *BoardId;
  UINTN        Written;

  ASSERT (PlatformInfo != NULL);
  ASSERT (Body != NULL);

  InternalGenerateHex (Cid, sizeof (Cid) - 1);
  InternalGenerateHex (Key, sizeof (Key) - 1);
  InternalGenerateHex (FirmwareGroup, sizeof (FirmwareGroup) - 1);

  OsType  = (Mode == OirRecoveryLatest) ? "latest" : "default";
  Mlb     = PlatformInfo->HasMlb ? PlatformInfo->Mlb : OIR_ZERO_MLB;
  BoardId = PlatformInfo->HasBoardId ? PlatformInfo->BoardId : OIR_RECENT_BOARD_ID;

  Written = AsciiSPrint (
              Body,
              BodySize,
              "cid=%a\nsn=%a\nbid=%a\nk=%a\nfg=%a\nos=%a",
              Cid,
              Mlb,
              BoardId,
              Key,
              FirmwareGroup,
              OsType
              );
  if ((Written == 0) || (Written >= BodySize)) {
    return EFI_BUFFER_TOO_SMALL;
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
InternalSetParsedField (
  IN OUT OIR_IMAGE_INFO  *ImageInfo,
  IN     CONST CHAR8     *Key,
  IN     CONST CHAR8     *Value,
  IN     UINTN           ValueLength
  )
{
  CHAR8  *Field;

  Field = NULL;
  if (AsciiStrCmp (Key, "AP") == 0) {
    Field = ImageInfo->Ap;
  } else if (AsciiStrCmp (Key, "AU") == 0) {
    Field = ImageInfo->Au;
  } else if (AsciiStrCmp (Key, "AH") == 0) {
    Field = ImageInfo->Ah;
  } else if (AsciiStrCmp (Key, "AT") == 0) {
    Field = ImageInfo->At;
  } else if (AsciiStrCmp (Key, "CU") == 0) {
    Field = ImageInfo->Cu;
  } else if (AsciiStrCmp (Key, "CH") == 0) {
    Field = ImageInfo->Ch;
  } else if (AsciiStrCmp (Key, "CT") == 0) {
    Field = ImageInfo->Ct;
  }

  if (Field == NULL) {
    return FALSE;
  }

  if (ValueLength >= OIR_MAX_RECOVERY_FIELD_SIZE) {
    ValueLength = OIR_MAX_RECOVERY_FIELD_SIZE - 1;
  }

  CopyMem (Field, Value, ValueLength);
  Field[ValueLength] = '\0';
  return TRUE;
}

STATIC
EFI_STATUS
InternalParseImageInfo (
  IN  CONST CHAR8     *Body,
  IN  UINTN           BodySize,
  OUT OIR_IMAGE_INFO  *ImageInfo
  )
{
  UINTN        Offset;
  UINTN        LineStart;
  UINTN        LineEnd;
  UINTN        KeyLength;
  CONST CHAR8  *Value;
  CHAR8        Key[3];

  ASSERT (Body != NULL);
  ASSERT (ImageInfo != NULL);

  Offset = 0;
  while (Offset < BodySize) {
    LineStart = Offset;
    while ((Offset < BodySize) && (Body[Offset] != '\n') && (Body[Offset] != '\r')) {
      ++Offset;
    }

    LineEnd = Offset;
    while ((Offset < BodySize) && ((Body[Offset] == '\n') || (Body[Offset] == '\r'))) {
      ++Offset;
    }

    if ((LineEnd - LineStart) < 4) {
      continue;
    }

    KeyLength = 0;
    while ((LineStart + KeyLength < LineEnd) && (Body[LineStart + KeyLength] != ':')) {
      ++KeyLength;
    }

    if ((KeyLength == 0) || (KeyLength > 2) || (LineStart + KeyLength + 1 >= LineEnd)) {
      continue;
    }

    Key[0] = Body[LineStart];
    Key[1] = (KeyLength == 2) ? Body[LineStart + 1] : '\0';
    Key[2] = '\0';

    Value = &Body[LineStart + KeyLength + 1];
    if (*Value == ' ') {
      ++Value;
    }

    InternalSetParsedField (ImageInfo, Key, Value, LineEnd - (UINTN)(Value - Body));
  }

  if ((ImageInfo->Ap[0] == '\0') || (ImageInfo->Au[0] == '\0') || (ImageInfo->Ah[0] == '\0') ||
      (ImageInfo->At[0] == '\0') || (ImageInfo->Cu[0] == '\0') || (ImageInfo->Ch[0] == '\0') ||
      (ImageInfo->Ct[0] == '\0'))
  {
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
OirGetRecoveryImageInfo (
  IN  OIR_RECOVERY_MODE        Mode,
  IN  CONST OIR_PLATFORM_INFO  *PlatformInfo,
  OUT OIR_IMAGE_INFO           *ImageInfo
  )
{
  EFI_STATUS  Status;
  CHAR8       Session[OIR_MAX_SESSION_SIZE];
  CHAR8       PostBody[512];
  VOID        *ResponseBody;
  UINTN       ResponseBodySize;

  ASSERT (PlatformInfo != NULL);
  ASSERT (ImageInfo != NULL);

  ZeroMem (ImageInfo, sizeof (*ImageInfo));
  ZeroMem (Session, sizeof (Session));
  ZeroMem (PostBody, sizeof (PostBody));
  ResponseBody     = NULL;
  ResponseBodySize = 0;

  DEBUG ((
    DEBUG_INFO,
    "OIR: RecoveryImage request bid=%a sn=%a os=%a\n",
    PlatformInfo->HasBoardId ? PlatformInfo->BoardId : OIR_RECENT_BOARD_ID,
    PlatformInfo->HasMlb ? "<masked>" : OIR_ZERO_MLB,
    (Mode == OirRecoveryLatest) ? "latest" : "default"
    ));

  Status = OirHttpRequest (
             HttpMethodGet,
             OIR_APPLE_RECOVERY_BASE_URL,
             NULL,
             NULL,
             NULL,
             0,
             NULL,
             NULL,
             Session,
             sizeof (Session)
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (AsciiStrnCmp (Session, "session=", sizeof ("session=") - 1) != 0) {
    DEBUG ((DEBUG_WARN, "OIR: Recovery session cookie missing\n"));
    return EFI_PROTOCOL_ERROR;
  }

  Status = InternalBuildPostBody (Mode, PlatformInfo, PostBody, sizeof (PostBody));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = OirHttpRequest (
             HttpMethodPost,
             OIR_APPLE_RECOVERY_IMAGE_URL,
             Session,
             "text/plain",
             PostBody,
             AsciiStrLen (PostBody),
             &ResponseBody,
             &ResponseBodySize,
             NULL,
             0
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = InternalParseImageInfo (ResponseBody, ResponseBodySize, ImageInfo);
  FreePool (ResponseBody);
  return Status;
}

STATIC
EFI_STATUS
InternalBuildAssetCookie (
  OUT CHAR8        *Cookie,
  IN  UINTN        CookieSize,
  IN  CONST CHAR8  *Token
  )
{
  UINTN  Written;

  ASSERT (Cookie != NULL);
  ASSERT (Token != NULL);

  Written = AsciiSPrint (Cookie, CookieSize, "AssetToken=%a", Token);
  if ((Written == 0) || (Written >= CookieSize)) {
    return EFI_BUFFER_TOO_SMALL;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
OirDownloadRecoveryAssets (
  IN OUT OIR_CUSTOM_FREE_CONTEXT  *Context,
  IN     CONST OIR_IMAGE_INFO     *ImageInfo
  )
{
  EFI_STATUS  Status;
  CHAR8       Cookie[OIR_MAX_COOKIE_SIZE];
  VOID        *ChunklistBuffer;
  UINTN       ChunklistSize;

  if ((Context == NULL) || (ImageInfo == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ChunklistBuffer = NULL;
  ChunklistSize   = 0;

  Status = InternalBuildAssetCookie (Cookie, sizeof (Cookie), ImageInfo->Ct);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Print (L"OpenInternetRecovery: downloading chunklist\n");
  Status = OirHttpRequest (
             HttpMethodGet,
             ImageInfo->Cu,
             Cookie,
             NULL,
             NULL,
             0,
             &ChunklistBuffer,
             &ChunklistSize,
             NULL,
             0
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((ChunklistSize == 0) || (ChunklistSize > MAX_UINT32)) {
    FreePool (ChunklistBuffer);
    return EFI_BAD_BUFFER_SIZE;
  }

  Context->ChunklistBuffer = ChunklistBuffer;
  Context->ChunklistSize   = (UINT32)ChunklistSize;

  Status = InternalBuildAssetCookie (Cookie, sizeof (Cookie), ImageInfo->At);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Print (L"OpenInternetRecovery: downloading recovery image\n");
  Status = OirHttpDownloadToRamDisk (
             ImageInfo->Au,
             Cookie,
             &Context->DmgExtentTable,
             &Context->DmgSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((Context->DmgSize == 0) || (Context->DmgSize > MAX_UINT32)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  return EFI_SUCCESS;
}
