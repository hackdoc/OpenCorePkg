/** @file
  Boot entry protocol handler for Apple Internet Recovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

STATIC OIR_ENTRY_CONTEXT  mLatestContext = {
  OirRecoveryLatest,
  "latest macOS 26"
};

STATIC OIR_ENTRY_CONTEXT  mOldestContext = {
  OirRecoveryOldest,
  "oldest macOS 10.15"
};

STATIC
OIR_ENTRY_CONTEXT *
InternalGetEntryContext (
  IN  OC_BOOT_ENTRY  *ChosenEntry
  )
{
  if (ChosenEntry->Id == NULL) {
    return NULL;
  }

  if (StrCmp (ChosenEntry->Id, L"internet_recovery_latest") == 0) {
    return &mLatestContext;
  }

  if (StrCmp (ChosenEntry->Id, L"internet_recovery_oldest") == 0) {
    return &mOldestContext;
  }

  return NULL;
}

STATIC
EFI_STATUS
EFIAPI
InternetRecoveryCustomFree (
  IN  VOID  *Context
  )
{
  if (Context != NULL) {
    OirDestroyRecoveryRamDisk (Context);
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
InternetRecoveryCustomRead (
  IN  OC_STORAGE_CONTEXT                   *Storage,
  IN  OC_BOOT_ENTRY                        *ChosenEntry,
  OUT VOID                                 **Data,
  OUT UINT32                               *DataSize,
  OUT EFI_DEVICE_PATH_PROTOCOL             **DevicePath,
  OUT EFI_HANDLE                           *StorageHandle,
  OUT EFI_DEVICE_PATH_PROTOCOL             **StoragePath,
  IN  OC_DMG_LOADING_SUPPORT               DmgLoading,
  OUT OC_APPLE_DISK_IMAGE_PRELOAD_CONTEXT  *DmgPreloadContext,
  OUT VOID                                 **Context
  )
{
  EFI_STATUS               Status;
  OIR_PLATFORM_INFO        PlatformInfo;
  OIR_IMAGE_INFO           ImageInfo;
  OIR_ENTRY_CONTEXT        *EntryContext;
  OIR_CUSTOM_FREE_CONTEXT  *FreeContext;

  ASSERT (ChosenEntry != NULL);
  ASSERT (Data != NULL);
  ASSERT (DataSize != NULL);
  ASSERT (DevicePath != NULL);
  ASSERT (StorageHandle != NULL);
  ASSERT (StoragePath != NULL);
  ASSERT (DmgPreloadContext != NULL);
  ASSERT (Context != NULL);

  *Data          = NULL;
  *DataSize      = 0;
  *DevicePath    = NULL;
  *StorageHandle = NULL;
  *StoragePath   = NULL;
  ZeroMem (DmgPreloadContext, sizeof (*DmgPreloadContext));
  *Context       = NULL;

  EntryContext = InternalGetEntryContext (ChosenEntry);
  if (EntryContext == NULL) {
    DEBUG ((DEBUG_WARN, "OIR: Missing entry context\n"));
    return EFI_INVALID_PARAMETER;
  }

  OcConsoleControlSetMode (EfiConsoleControlScreenText);

  DEBUG ((DEBUG_INFO, "OIR: Starting %a Internet Recovery\n", EntryContext->VersionName));
  Print (L"OpenInternetRecovery: %a\n", EntryContext->VersionName);

  OirPrintPlatformInfo (&PlatformInfo);

  Status = OirNetworkPreflight ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Network preflight failed - %r\n", Status));
    Print (L"OpenInternetRecovery: network preflight failed - %r\n", Status);
    return Status;
  }

  Status = OirCheckAppleConnectivity ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Apple connectivity check failed - %r\n", Status));
    Print (L"OpenInternetRecovery: Apple connectivity check failed - %r\n", Status);
    return Status;
  }

  Status = OirCheckFreeMemory ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Not enough free memory - %r\n", Status));
    Print (L"OpenInternetRecovery: need at least 3 GB free memory - %r\n", Status);
    return Status;
  }

  Status = OirCreateRecoveryRamDisk (&FreeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Failed to create recovery RAM disk - %r\n", Status));
    Print (L"OpenInternetRecovery: RAM disk creation failed - %r\n", Status);
    return Status;
  }

  Status = OirGetRecoveryImageInfo (EntryContext->Mode, &PlatformInfo, &ImageInfo);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Failed to get recovery image info - %r\n", Status));
    Print (L"OpenInternetRecovery: recovery metadata request failed - %r\n", Status);
    InternetRecoveryCustomFree (FreeContext);
    return Status;
  }

  Print (L"OpenInternetRecovery: selected %a (%a)\n", EntryContext->VersionName, ImageInfo.Ap);
  DEBUG ((DEBUG_INFO, "OIR: AP=%a\n", ImageInfo.Ap));
  DEBUG ((DEBUG_INFO, "OIR: AU=%a\n", ImageInfo.Au));
  DEBUG ((DEBUG_INFO, "OIR: CU=%a\n", ImageInfo.Cu));

  Status = OirDownloadRecoveryAssets (FreeContext, &ImageInfo);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Recovery asset download failed - %r\n", Status));
    Print (L"OpenInternetRecovery: download failed - %r\n", Status);
    InternetRecoveryCustomFree (FreeContext);
    return Status;
  }

  Status = OirValidateDownloadedRecovery (FreeContext, &ImageInfo);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Recovery validation failed - %r\n", Status));
    Print (L"OpenInternetRecovery: validation failed - %r\n", Status);
    InternetRecoveryCustomFree (FreeContext);
    return Status;
  }

  FreeContext->DmgContext = AllocateZeroPool (sizeof (*FreeContext->DmgContext));
  if (FreeContext->DmgContext == NULL) {
    InternetRecoveryCustomFree (FreeContext);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!OcAppleDiskImageInitializeContext (FreeContext->DmgContext, FreeContext->DmgExtentTable, FreeContext->DmgSize)) {
    DEBUG ((DEBUG_WARN, "OIR: Failed to initialise downloaded DMG\n"));
    Print (L"OpenInternetRecovery: DMG initialisation failed\n");
    InternetRecoveryCustomFree (FreeContext);
    return EFI_COMPROMISED_DATA;
  }

  DmgPreloadContext->DmgContext        = FreeContext->DmgContext;
  DmgPreloadContext->DmgFile           = NULL;
  DmgPreloadContext->DmgFileSize       = (UINT32)FreeContext->DmgSize;
  DmgPreloadContext->ChunklistBuffer   = FreeContext->ChunklistBuffer;
  DmgPreloadContext->ChunklistFileSize = FreeContext->ChunklistSize;

  *DevicePath = DuplicateDevicePath (ChosenEntry->DevicePath);
  if (*DevicePath == NULL) {
    ZeroMem (DmgPreloadContext, sizeof (*DmgPreloadContext));
    InternetRecoveryCustomFree (FreeContext);
    return EFI_OUT_OF_RESOURCES;
  }

  FreeContext->DmgContextTransferred = TRUE;
  FreeContext->ChunklistTransferred  = TRUE;
  *Context = FreeContext;

  return EFI_SUCCESS;
}

STATIC OC_PICKER_ENTRY  mInternetRecoveryBootEntries[2] = {
  {
    .Id                  = OIR_LATEST_ID,
    .Name                = OIR_LATEST_NAME,
    .Path                = OIR_RECOVERY_PATH,
    .Arguments           = NULL,
    .Flavour             = OC_FLAVOUR_APPLE_RECOVERY,
    .Auxiliary           = TRUE,
    .Tool                = FALSE,
    .TextMode            = TRUE,
    .RealPath            = FALSE,
    .CustomRead          = InternetRecoveryCustomRead,
    .CustomFree          = InternetRecoveryCustomFree,
    .External            = TRUE
  },
  {
    .Id                  = OIR_OLDEST_ID,
    .Name                = OIR_OLDEST_NAME,
    .Path                = OIR_RECOVERY_PATH,
    .Arguments           = NULL,
    .Flavour             = OC_FLAVOUR_APPLE_RECOVERY,
    .Auxiliary           = TRUE,
    .Tool                = FALSE,
    .TextMode            = TRUE,
    .RealPath            = FALSE,
    .CustomRead          = InternetRecoveryCustomRead,
    .CustomFree          = InternetRecoveryCustomFree,
    .External            = TRUE
  }
};

STATIC
EFI_STATUS
EFIAPI
InternetRecoveryGetBootEntries (
  IN OUT          OC_PICKER_CONTEXT  *PickerContext,
  IN     CONST EFI_HANDLE            Device OPTIONAL,
  OUT       OC_PICKER_ENTRY          **Entries,
  OUT       UINTN                    *NumEntries
  )
{
  if (Device != NULL) {
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, "OIR: Internet Recovery entries\n"));

  *Entries    = mInternetRecoveryBootEntries;
  *NumEntries = ARRAY_SIZE (mInternetRecoveryBootEntries);

  return EFI_SUCCESS;
}

STATIC
CHAR8 *
EFIAPI
InternetRecoveryCheckHotKeys (
  IN OUT OC_PICKER_CONTEXT  *Context,
  IN UINTN                  NumKeys,
  IN APPLE_MODIFIER_MAP     Modifiers,
  IN APPLE_KEY_CODE         *Keys
  )
{
  BOOLEAN  HasCommand;
  BOOLEAN  HasOption;
  BOOLEAN  HasShift;
  BOOLEAN  HasKeyR;

  HasCommand = (Modifiers & APPLE_MODIFIERS_COMMAND) != 0;
  HasOption  = (Modifiers & APPLE_MODIFIERS_OPTION) != 0;
  HasShift   = (Modifiers & APPLE_MODIFIERS_SHIFT) != 0;
  HasKeyR    = OcKeyMapHasKey (Keys, NumKeys, AppleHidUsbKbUsageKeyR);

  if (HasCommand && HasOption && HasShift && HasKeyR) {
    DEBUG ((DEBUG_INFO, "OIR: CMD+OPT+SHIFT+R starts oldest Internet Recovery\n"));
    return OIR_OLDEST_ID;
  }

  if (HasCommand && !HasOption && HasShift && HasKeyR) {
    DEBUG ((DEBUG_INFO, "OIR: CMD+SHIFT+R starts latest Internet Recovery\n"));
    return OIR_LATEST_ID;
  }

  return NULL;
}

STATIC
OC_BOOT_ENTRY_PROTOCOL
  mInternetRecoveryBootEntryProtocol = {
  OC_BOOT_ENTRY_PROTOCOL_REVISION,
  InternetRecoveryGetBootEntries,
  NULL,
  InternetRecoveryCheckHotKeys
};

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return gBS->InstallMultipleProtocolInterfaces (
                &ImageHandle,
                &gOcBootEntryProtocolGuid,
                &mInternetRecoveryBootEntryProtocol,
                NULL
                );
}
