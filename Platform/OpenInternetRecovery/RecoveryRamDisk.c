/** @file
  RAM disk helpers for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

EFI_STATUS
OirCheckFreeMemory (
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapWalker;
  UINTN                  MemoryMapSize;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
  UINT64                 FreePages;
  UINT64                 RequiredPages;
  UINTN                  Index;

  MemoryMapSize = 0;
  MemoryMap     = NULL;

  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  MemoryMapSize += DescriptorSize * 8;
  MemoryMap      = AllocatePool (MemoryMapSize);
  if (MemoryMap == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR (Status)) {
    FreePool (MemoryMap);
    return Status;
  }

  FreePages = 0;
  for (Index = 0; Index < MemoryMapSize / DescriptorSize; ++Index) {
    MemoryMapWalker = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + Index * DescriptorSize);
    if (MemoryMapWalker->Type == EfiConventionalMemory) {
      FreePages += MemoryMapWalker->NumberOfPages;
    }
  }

  FreePool (MemoryMap);

  RequiredPages = EFI_SIZE_TO_PAGES (OIR_REQUIRED_FREE_SIZE);
  DEBUG ((
    DEBUG_INFO,
    "OIR: Free conventional memory %Lu MB, required %Lu MB\n",
    MultU64x64 (FreePages, EFI_PAGE_SIZE) / BASE_1MB,
    MultU64x64 (RequiredPages, EFI_PAGE_SIZE) / BASE_1MB
    ));

  if (FreePages < RequiredPages) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
OirCreateRecoveryRamDisk (
  OUT OIR_CUSTOM_FREE_CONTEXT  **Context
  )
{
  OIR_CUSTOM_FREE_CONTEXT  *FreeContext;

  ASSERT (Context != NULL);
  *Context = NULL;

  FreeContext = AllocateZeroPool (sizeof (*FreeContext));
  if (FreeContext == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_INFO, "OIR: Created recovery download context\n"));

  *Context = FreeContext;
  return EFI_SUCCESS;
}

VOID
OirDestroyRecoveryRamDisk (
  IN OUT OIR_CUSTOM_FREE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return;
  }

  if ((Context->DmgContext != NULL) && !Context->DmgContextTransferred) {
    OcAppleDiskImageFreeContext (Context->DmgContext);
    FreePool (Context->DmgContext);
  }

  if ((Context->DmgExtentTable != NULL) && !Context->DmgContextTransferred) {
    OcAppleRamDiskFree (Context->DmgExtentTable);
  }

  if ((Context->ChunklistBuffer != NULL) && !Context->ChunklistTransferred) {
    FreePool (Context->ChunklistBuffer);
  }

  FreePool (Context);
}
