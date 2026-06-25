/** @file
  Chunklist validation for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

EFI_STATUS
OirValidateDownloadedRecovery (
  IN OIR_CUSTOM_FREE_CONTEXT  *Context,
  IN CONST OIR_IMAGE_INFO     *ImageInfo
  )
{
  BOOLEAN                     Result;
  OC_APPLE_CHUNKLIST_CONTEXT  ChunklistContext;
  UINTN                       Index;
  UINTN                       Offset;
  UINTN                       MaxChunkSize;
  UINT8                       *ChunkBuffer;
  UINT8                       Digest[SHA256_DIGEST_SIZE];

  if ((Context == NULL) || (ImageInfo == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Context->ChunklistBuffer == NULL) || (Context->ChunklistSize == 0) ||
      (Context->DmgExtentTable == NULL) || (Context->DmgSize == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&ChunklistContext, sizeof (ChunklistContext));
  Result = OcAppleChunklistInitializeContext (
             &ChunklistContext,
             Context->ChunklistBuffer,
             Context->ChunklistSize
             );
  if (!Result) {
    DEBUG ((DEBUG_WARN, "OIR: Failed to initialise chunklist for AP=%a\n", ImageInfo->Ap));
    return EFI_UNSUPPORTED;
  }

  Result = OcAppleChunklistVerifySignature (&ChunklistContext, PkDataBase[0].PublicKey);
  if (!Result) {
    Result = OcAppleChunklistVerifySignature (&ChunklistContext, PkDataBase[1].PublicKey);
  }

  if (!Result) {
    DEBUG ((DEBUG_WARN, "OIR: Chunklist signature verification failed for AP=%a\n", ImageInfo->Ap));
    return EFI_COMPROMISED_DATA;
  }

  MaxChunkSize = 0;
  for (Index = 0; Index < ChunklistContext.ChunkCount; ++Index) {
    if (ChunklistContext.Chunks[Index].Length > MaxChunkSize) {
      MaxChunkSize = ChunklistContext.Chunks[Index].Length;
    }
  }

  if (MaxChunkSize == 0) {
    return EFI_COMPROMISED_DATA;
  }

  ChunkBuffer = AllocatePool (MaxChunkSize);
  if (ChunkBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Offset = 0;
  for (Index = 0; Index < ChunklistContext.ChunkCount; ++Index) {
    if ((Offset > Context->DmgSize) || (ChunklistContext.Chunks[Index].Length > Context->DmgSize - Offset)) {
      FreePool (ChunkBuffer);
      return EFI_COMPROMISED_DATA;
    }

    Print (L"OpenInternetRecovery: validate chunk %u of %u\r", (UINT32)(Index + 1), (UINT32)ChunklistContext.ChunkCount);
    Result = OcAppleRamDiskRead (
               Context->DmgExtentTable,
               Offset,
               ChunklistContext.Chunks[Index].Length,
               ChunkBuffer
               );
    if (!Result) {
      FreePool (ChunkBuffer);
      return EFI_DEVICE_ERROR;
    }

    Sha256 (Digest, ChunkBuffer, ChunklistContext.Chunks[Index].Length);
    if (CompareMem (Digest, ChunklistContext.Chunks[Index].Checksum, SHA256_DIGEST_SIZE) != 0) {
      FreePool (ChunkBuffer);
      return EFI_COMPROMISED_DATA;
    }

    Offset += ChunklistContext.Chunks[Index].Length;
  }

  Print (L"\n");
  FreePool (ChunkBuffer);

  if (Offset != Context->DmgSize) {
    DEBUG ((DEBUG_WARN, "OIR: DMG size %Lu does not match chunklist size %Lu\n", (UINT64)Context->DmgSize, (UINT64)Offset));
    return EFI_COMPROMISED_DATA;
  }

  DEBUG ((DEBUG_INFO, "OIR: Recovery image validated for AP=%a\n", ImageInfo->Ap));
  return EFI_SUCCESS;
}
