/** @file
  Internal declarations for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#ifndef OPEN_INTERNET_RECOVERY_INTERNAL_H
#define OPEN_INTERNET_RECOVERY_INTERNAL_H

#include <Guid/AppleVariable.h>

#include <Uefi.h>

#include <IndustryStandard/AppleHid.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/HttpIoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/NetLib.h>
#include <Library/OcAppleChunklistLib.h>
#include <Library/OcAppleDiskImageLib.h>
#include <Library/OcAppleKeysLib.h>
#include <Library/OcAppleRamDiskLib.h>
#include <Library/OcBootManagementLib.h>
#include <Library/OcConsoleLib.h>
#include <Library/OcCryptoLib.h>
#include <Library/OcFileLib.h>
#include <Library/OcStringLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/Http.h>
#include <Protocol/OcBootEntry.h>
#include <Protocol/ServiceBinding.h>
#include <Protocol/SimpleNetwork.h>
#include <Protocol/Tcp4.h>
#include <Protocol/Tcp6.h>

#define OIR_APPLE_RECOVERY_HOST       "osrecovery.apple.com"
#define OIR_APPLE_RECOVERY_BASE_URL   "http://osrecovery.apple.com/"
#define OIR_APPLE_RECOVERY_IMAGE_URL  "http://osrecovery.apple.com/InstallationPayload/RecoveryImage"
#define OIR_RECENT_BOARD_ID           "Mac-27AD2F918AE68F61"
#define OIR_ZERO_MLB                  "00000000000000000"

#define OIR_LATEST_ID      "internet_recovery_latest"
#define OIR_OLDEST_ID      "internet_recovery_oldest"
#define OIR_LATEST_NAME    "Internet Recovery (latest macOS 26)"
#define OIR_OLDEST_NAME    "Internet Recovery (oldest macOS 10.15)"
#define OIR_RECOVERY_PATH  "\\com.apple.recovery.boot\\boot.efi"

#define OIR_REQUIRED_FREE_SIZE   (BASE_2GB + BASE_1GB)
#define OIR_RAM_DISK_SIZE        (BASE_2GB + BASE_512MB)
#define OIR_DOWNLOAD_CHUNK_SIZE  BASE_4MB
#define OIR_HTTP_TIMEOUT_MS      30000U

#define OIR_MAX_BOARD_ID_SIZE        64
#define OIR_MAX_MLB_SIZE             32
#define OIR_MAX_SERIAL_SIZE          32
#define OIR_MAX_SESSION_SIZE         256
#define OIR_MAX_RECOVERY_FIELD_SIZE  1024
#define OIR_MAX_COOKIE_SIZE          256

typedef enum {
  OirRecoveryLatest,
  OirRecoveryOldest
} OIR_RECOVERY_MODE;

typedef struct {
  CHAR8      BoardId[OIR_MAX_BOARD_ID_SIZE];
  CHAR8      Mlb[OIR_MAX_MLB_SIZE];
  CHAR8      Serial[OIR_MAX_SERIAL_SIZE];
  BOOLEAN    HasBoardId;
  BOOLEAN    HasMlb;
  BOOLEAN    HasSerial;
  UINTN      MinMajor;
  UINTN      MinMinor;
  UINTN      MaxMajor;
  UINTN      MaxMinor;
} OIR_PLATFORM_INFO;

typedef struct {
  CHAR8    Ap[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    Au[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    Ah[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    At[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    Cu[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    Ch[OIR_MAX_RECOVERY_FIELD_SIZE];
  CHAR8    Ct[OIR_MAX_RECOVERY_FIELD_SIZE];
} OIR_IMAGE_INFO;

typedef struct {
  OIR_RECOVERY_MODE    Mode;
  CONST CHAR8          *VersionName;
} OIR_ENTRY_CONTEXT;

typedef struct {
  OC_APPLE_DISK_IMAGE_CONTEXT          *DmgContext;
  CONST APPLE_RAM_DISK_EXTENT_TABLE    *DmgExtentTable;
  UINTN                                DmgSize;
  VOID                                 *ChunklistBuffer;
  UINT32                               ChunklistSize;
  BOOLEAN                              DmgContextTransferred;
  BOOLEAN                              ChunklistTransferred;
} OIR_CUSTOM_FREE_CONTEXT;

typedef struct {
  UINTN                   HeaderCount;
  EFI_HTTP_HEADER         *Headers;
  UINTN                   BodySize;
  VOID                    *Body;
  EFI_HTTP_STATUS_CODE    StatusCode;
} OIR_HTTP_RESPONSE;

VOID
OirPrintPlatformInfo (
  OUT OIR_PLATFORM_INFO  *PlatformInfo
  );

EFI_STATUS
OirNetworkPreflight (
  VOID
  );

EFI_STATUS
OirCheckAppleConnectivity (
  VOID
  );

EFI_STATUS
OirHttpRequest (
  IN  EFI_HTTP_METHOD  Method,
  IN  CONST CHAR8      *Url,
  IN  CONST CHAR8      *Cookie OPTIONAL,
  IN  CONST CHAR8      *ContentType OPTIONAL,
  IN  CONST VOID       *RequestBody OPTIONAL,
  IN  UINTN            RequestBodySize,
  OUT VOID             **ResponseBody OPTIONAL,
  OUT UINTN            *ResponseBodySize OPTIONAL,
  OUT CHAR8            *SetCookie OPTIONAL,
  IN  UINTN            SetCookieSize OPTIONAL
  );

EFI_STATUS
OirHttpRequestEx (
  IN  EFI_HTTP_METHOD    Method,
  IN  CONST CHAR8        *Url,
  IN  CONST CHAR8        *Cookie OPTIONAL,
  IN  CONST CHAR8        *ContentType OPTIONAL,
  IN  CONST VOID         *RequestBody OPTIONAL,
  IN  UINTN              RequestBodySize,
  OUT OIR_HTTP_RESPONSE  *Response
  );

EFI_STATUS
OirHttpDownloadToRamDisk (
  IN     CONST CHAR8                        *Url,
  IN     CONST CHAR8                        *Cookie OPTIONAL,
  OUT    CONST APPLE_RAM_DISK_EXTENT_TABLE  **ExtentTable,
  OUT    UINTN                              *DownloadSize
  );

EFI_STATUS
OirGetRecoveryImageInfo (
  IN  OIR_RECOVERY_MODE        Mode,
  IN  CONST OIR_PLATFORM_INFO  *PlatformInfo,
  OUT OIR_IMAGE_INFO           *ImageInfo
  );

EFI_STATUS
OirCheckFreeMemory (
  VOID
  );

EFI_STATUS
OirCreateRecoveryRamDisk (
  OUT OIR_CUSTOM_FREE_CONTEXT  **Context
  );

VOID
OirDestroyRecoveryRamDisk (
  IN OUT OIR_CUSTOM_FREE_CONTEXT  *Context
  );

EFI_STATUS
OirDownloadRecoveryAssets (
  IN OUT OIR_CUSTOM_FREE_CONTEXT  *Context,
  IN     CONST OIR_IMAGE_INFO     *ImageInfo
  );

EFI_STATUS
OirValidateDownloadedRecovery (
  IN OIR_CUSTOM_FREE_CONTEXT  *Context,
  IN CONST OIR_IMAGE_INFO     *ImageInfo
  );

#endif // OPEN_INTERNET_RECOVERY_INTERNAL_H
