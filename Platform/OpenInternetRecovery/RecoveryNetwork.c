/** @file
  Network preflight for OpenInternetRecovery.

  Copyright (C) 2026, Ghltbm. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-3-Clause
**/

#include "InternetRecoveryInternal.h"

EFI_STATUS
OirNetworkPreflight (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_HANDLE                   *HandleBuffer;
  UINTN                        HandleCount;
  UINTN                        Index;
  EFI_SIMPLE_NETWORK_PROTOCOL  *Snp;
  BOOLEAN                      HasWiredNetwork;
  UINT32                       IfType;

  HasWiredNetwork = FALSE;
  HandleBuffer    = NULL;
  HandleCount     = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleNetworkProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: No SNP handles - %r\n", Status));
    return Status;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleNetworkProtocolGuid,
                    (VOID **)&Snp
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    IfType = (Snp->Mode != NULL) ? Snp->Mode->IfType : 0;
    DEBUG ((DEBUG_INFO, "OIR: SNP[%u] IfType %u\n", (UINT32)Index, IfType));

    //
    // UEFI generally exposes Ethernet as ARP hardware type 1. Wi-Fi is not
    // supported by this driver, and many firmwares do not expose it as SNP at
    // all. Accept Ethernet explicitly, keep unknown types rejected for now.
    //
    if (IfType == 1) {
      HasWiredNetwork = TRUE;
      break;
    }
  }

  FreePool (HandleBuffer);

  if (!HasWiredNetwork) {
    DEBUG ((DEBUG_WARN, "OIR: No supported wired network adapter found\n"));
    return EFI_UNSUPPORTED;
  }

  Status = gBS->LocateProtocol (
                  &gEfiHttpServiceBindingProtocolGuid,
                  NULL,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP service binding missing - %r\n", Status));
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gEfiTcp4ServiceBindingProtocolGuid,
                  NULL,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OIR: TCP4 service binding missing - %r\n", Status));

    Status = gBS->LocateProtocol (
                    &gEfiTcp6ServiceBindingProtocolGuid,
                    NULL,
                    NULL
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "OIR: TCP6 service binding missing - %r\n", Status));
      return Status;
    }
  }

  DEBUG ((DEBUG_INFO, "OIR: Wired network preflight passed\n"));
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
InternalHttpStatusOk (
  IN EFI_HTTP_STATUS_CODE  StatusCode
  )
{
  switch (StatusCode) {
    case HTTP_STATUS_200_OK:
    case HTTP_STATUS_201_CREATED:
    case HTTP_STATUS_202_ACCEPTED:
    case HTTP_STATUS_203_NON_AUTHORITATIVE_INFORMATION:
    case HTTP_STATUS_204_NO_CONTENT:
    case HTTP_STATUS_205_RESET_CONTENT:
    case HTTP_STATUS_206_PARTIAL_CONTENT:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
EFI_STATUS
InternalAsciiToUnicode (
  IN  CONST CHAR8  *Ascii,
  OUT CHAR16       **Unicode
  )
{
  UINTN   Index;
  UINTN   Size;
  CHAR16  *Result;

  ASSERT (Ascii != NULL);
  ASSERT (Unicode != NULL);

  Size   = AsciiStrSize (Ascii);
  Result = AllocateZeroPool (Size * sizeof (CHAR16));
  if (Result == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  for (Index = 0; Index < Size; ++Index) {
    Result[Index] = (CHAR16)Ascii[Index];
  }

  *Unicode = Result;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
InternalParseHttpUrl (
  IN  CONST CHAR8  *Url,
  OUT CHAR8        *Host,
  IN  UINTN        HostSize
  )
{
  CONST CHAR8  *Walker;
  UINTN        HostLength;

  ASSERT (Url != NULL);
  ASSERT (Host != NULL);

  if ((HostSize == 0) || (AsciiStrnCmp (Url, "http://", sizeof ("http://") - 1) != 0)) {
    return EFI_UNSUPPORTED;
  }

  Walker     = Url + sizeof ("http://") - 1;
  HostLength = 0;
  while ((Walker[HostLength] != '\0') && (Walker[HostLength] != '/') && (Walker[HostLength] != ':')) {
    ++HostLength;
  }

  if ((HostLength == 0) || (HostLength >= HostSize)) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Host, Walker, HostLength);
  Host[HostLength] = '\0';
  return EFI_SUCCESS;
}

STATIC
VOID
InternalFreeHttpResponse (
  IN OUT OIR_HTTP_RESPONSE  *Response
  )
{
  if (Response == NULL) {
    return;
  }

  if (Response->Headers != NULL) {
    FreePool (Response->Headers);
  }

  if (Response->Body != NULL) {
    FreePool (Response->Body);
  }

  ZeroMem (Response, sizeof (*Response));
}

STATIC
VOID
InternalCopySetCookie (
  IN  CONST OIR_HTTP_RESPONSE  *Response,
  OUT CHAR8                    *SetCookie OPTIONAL,
  IN  UINTN                    SetCookieSize OPTIONAL
  )
{
  UINTN        Index;
  CONST CHAR8  *Value;
  UINTN        Length;

  if ((Response == NULL) || (SetCookie == NULL) || (SetCookieSize == 0)) {
    return;
  }

  SetCookie[0] = '\0';
  for (Index = 0; Index < Response->HeaderCount; ++Index) {
    if (OcAsciiStrniCmp (Response->Headers[Index].FieldName, "Set-Cookie", sizeof ("Set-Cookie") - 1) != 0) {
      continue;
    }

    Value  = Response->Headers[Index].FieldValue;
    Length = 0;
    while ((Value[Length] != '\0') && (Value[Length] != ';') && (Length + 1 < SetCookieSize)) {
      ++Length;
    }

    CopyMem (SetCookie, Value, Length);
    SetCookie[Length] = '\0';
    return;
  }
}

STATIC
EFI_STATUS
InternalGetContentLength (
  IN  UINTN            HeaderCount,
  IN  EFI_HTTP_HEADER  *Headers,
  OUT UINTN            *ContentLength
  )
{
  UINTN  Index;

  if ((Headers == NULL) || (ContentLength == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < HeaderCount; ++Index) {
    if (OcAsciiStrniCmp (Headers[Index].FieldName, "Content-Length", sizeof ("Content-Length") - 1) == 0) {
      return AsciiStrDecimalToUintnS (Headers[Index].FieldValue, NULL, ContentLength);
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
OirHttpRequestEx (
  IN  EFI_HTTP_METHOD    Method,
  IN  CONST CHAR8        *Url,
  IN  CONST CHAR8        *Cookie OPTIONAL,
  IN  CONST CHAR8        *ContentType OPTIONAL,
  IN  CONST VOID         *RequestBody OPTIONAL,
  IN  UINTN              RequestBodySize,
  OUT OIR_HTTP_RESPONSE  *Response
  )
{
  EFI_STATUS             Status;
  HTTP_IO                HttpIo;
  HTTP_IO_CONFIG_DATA    ConfigData;
  EFI_HTTP_REQUEST_DATA  Request;
  EFI_HANDLE             *HandleBuffer;
  UINTN                  HandleCount;
  CHAR16                 *UnicodeUrl;
  CHAR8                  Host[128];
  EFI_HTTP_HEADER        Headers[6];
  UINTN                  HeaderCount;
  HTTP_IO_RESPONSE_DATA  ResponseData;
  UINTN                  ContentLength;
  UINT8                  *Body;
  UINTN                  Offset;

  if ((Url == NULL) || (Response == NULL) || ((RequestBody == NULL) && (RequestBodySize != 0))) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Response, sizeof (*Response));
  ZeroMem (&HttpIo, sizeof (HttpIo));
  ZeroMem (&ConfigData, sizeof (ConfigData));
  ZeroMem (&Request, sizeof (Request));
  ZeroMem (&ResponseData, sizeof (ResponseData));

  UnicodeUrl   = NULL;
  Body         = NULL;
  HandleBuffer = NULL;
  HandleCount  = 0;

  Status = InternalParseHttpUrl (Url, Host, sizeof (Host));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = InternalAsciiToUnicode (Url, &UnicodeUrl);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ConfigData.Config4.HttpVersion       = HttpVersion11;
  ConfigData.Config4.RequestTimeOut    = OIR_HTTP_TIMEOUT_MS;
  ConfigData.Config4.ResponseTimeOut   = OIR_HTTP_TIMEOUT_MS;
  ConfigData.Config4.UseDefaultAddress = TRUE;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiHttpServiceBindingProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP service binding handle missing - %r\n", Status));
    FreePool (UnicodeUrl);
    return EFI_ERROR (Status) ? Status : EFI_NOT_FOUND;
  }

  Status = HttpIoCreateIo (
             gImageHandle,
             HandleBuffer[0],
             IP_VERSION_4,
             &ConfigData,
             NULL,
             NULL,
             &HttpIo
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP create failed for %a - %r\n", Url, Status));
    FreePool (UnicodeUrl);
    if (HandleBuffer != NULL) {
      FreePool (HandleBuffer);
    }

    return Status;
  }

  HeaderCount = 0;
  Headers[HeaderCount].FieldName  = "Host";
  Headers[HeaderCount].FieldValue = Host;
  ++HeaderCount;
  Headers[HeaderCount].FieldName  = "Connection";
  Headers[HeaderCount].FieldValue = "close";
  ++HeaderCount;
  Headers[HeaderCount].FieldName  = "User-Agent";
  Headers[HeaderCount].FieldValue = "InternetRecovery/1.0";
  ++HeaderCount;
  if ((Cookie != NULL) && (Cookie[0] != '\0')) {
    Headers[HeaderCount].FieldName  = "Cookie";
    Headers[HeaderCount].FieldValue = (CHAR8 *)Cookie;
    ++HeaderCount;
  }

  if ((ContentType != NULL) && (ContentType[0] != '\0')) {
    Headers[HeaderCount].FieldName  = "Content-Type";
    Headers[HeaderCount].FieldValue = (CHAR8 *)ContentType;
    ++HeaderCount;
  }

  Request.Method = Method;
  Request.Url    = UnicodeUrl;

  Status = HttpIoSendRequest (
             &HttpIo,
             &Request,
             HeaderCount,
             Headers,
             RequestBodySize,
             (VOID *)RequestBody
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP send failed for %a - %r\n", Url, Status));
    goto Done;
  }

  ZeroMem (&ResponseData, sizeof (ResponseData));
  Status = HttpIoRecvResponse (&HttpIo, TRUE, &ResponseData);
  if (EFI_ERROR (Status) && (Status != EFI_HTTP_ERROR)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP response header failed for %a - %r\n", Url, Status));
    goto Done;
  }

  Response->StatusCode  = ResponseData.Response.StatusCode;
  Response->HeaderCount = ResponseData.HeaderCount;
  Response->Headers     = ResponseData.Headers;
  if (!InternalHttpStatusOk (Response->StatusCode)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP status %u for %a\n", Response->StatusCode, Url));
    Status = EFI_PROTOCOL_ERROR;
    goto Done;
  }

  if (Method == HttpMethodHead) {
    Status = EFI_SUCCESS;
    goto Done;
  }

  Status = InternalGetContentLength (Response->HeaderCount, Response->Headers, &ContentLength);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OIR: Missing Content-Length for %a - %r\n", Url, Status));
    Status = EFI_PROTOCOL_ERROR;
    goto Done;
  }

  if (ContentLength == 0) {
    Status = EFI_SUCCESS;
    goto Done;
  }

  Body = AllocateZeroPool (ContentLength + 1);
  if (Body == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Offset = 0;
  while (Offset < ContentLength) {
    ZeroMem (&ResponseData, sizeof (ResponseData));
    ResponseData.BodyLength = ContentLength - Offset;
    ResponseData.Body       = (CHAR8 *)&Body[Offset];

    Status = HttpIoRecvResponse (&HttpIo, FALSE, &ResponseData);
    if (EFI_ERROR (Status) && (Status != EFI_HTTP_ERROR)) {
      DEBUG ((DEBUG_WARN, "OIR: HTTP response body failed for %a - %r\n", Url, Status));
      goto Done;
    }

    if (ResponseData.BodyLength == 0) {
      Status = EFI_PROTOCOL_ERROR;
      goto Done;
    }

    Offset += ResponseData.BodyLength;
  }

  Response->Body     = Body;
  Response->BodySize = ContentLength;
  Body               = NULL;
  Status             = EFI_SUCCESS;

Done:
  if (Body != NULL) {
    FreePool (Body);
  }

  if (EFI_ERROR (Status)) {
    InternalFreeHttpResponse (Response);
  }

  HttpIoDestroyIo (&HttpIo);
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  FreePool (UnicodeUrl);
  return Status;
}

EFI_STATUS
OirHttpDownloadToRamDisk (
  IN     CONST CHAR8                        *Url,
  IN     CONST CHAR8                        *Cookie OPTIONAL,
  OUT    CONST APPLE_RAM_DISK_EXTENT_TABLE  **ExtentTable,
  OUT    UINTN                              *DownloadSize
  )
{
  EFI_STATUS             Status;
  HTTP_IO                HttpIo;
  HTTP_IO_CONFIG_DATA    ConfigData;
  EFI_HTTP_REQUEST_DATA  Request;
  EFI_HANDLE             *HandleBuffer;
  UINTN                  HandleCount;
  CHAR16                 *UnicodeUrl;
  CHAR8                  Host[128];
  EFI_HTTP_HEADER        Headers[4];
  UINTN                  HeaderCount;
  HTTP_IO_RESPONSE_DATA  ResponseData;
  UINTN                  ContentLength;
  UINTN                  ResponseHeaderCount;
  EFI_HTTP_HEADER        *ResponseHeaders;
  UINT8                  *ChunkBuffer;
  UINTN                  Offset;
  CONST APPLE_RAM_DISK_EXTENT_TABLE  *RamDisk;

  if ((Url == NULL) || (ExtentTable == NULL) || (DownloadSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *ExtentTable  = NULL;
  *DownloadSize = 0;
  ZeroMem (&HttpIo, sizeof (HttpIo));
  ZeroMem (&ConfigData, sizeof (ConfigData));
  ZeroMem (&Request, sizeof (Request));
  ZeroMem (&ResponseData, sizeof (ResponseData));

  HandleBuffer = NULL;
  HandleCount  = 0;
  UnicodeUrl   = NULL;
  ChunkBuffer         = NULL;
  RamDisk             = NULL;
  ResponseHeaderCount = 0;
  ResponseHeaders     = NULL;

  Status = InternalParseHttpUrl (Url, Host, sizeof (Host));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = InternalAsciiToUnicode (Url, &UnicodeUrl);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiHttpServiceBindingProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    Status = EFI_ERROR (Status) ? Status : EFI_NOT_FOUND;
    goto Done;
  }

  ConfigData.Config4.HttpVersion       = HttpVersion11;
  ConfigData.Config4.RequestTimeOut    = OIR_HTTP_TIMEOUT_MS;
  ConfigData.Config4.ResponseTimeOut   = OIR_HTTP_TIMEOUT_MS;
  ConfigData.Config4.UseDefaultAddress = TRUE;

  Status = HttpIoCreateIo (
             gImageHandle,
             HandleBuffer[0],
             IP_VERSION_4,
             &ConfigData,
             NULL,
             NULL,
             &HttpIo
             );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  HeaderCount = 0;
  Headers[HeaderCount].FieldName  = "Host";
  Headers[HeaderCount].FieldValue = Host;
  ++HeaderCount;
  Headers[HeaderCount].FieldName  = "Connection";
  Headers[HeaderCount].FieldValue = "close";
  ++HeaderCount;
  Headers[HeaderCount].FieldName  = "User-Agent";
  Headers[HeaderCount].FieldValue = "InternetRecovery/1.0";
  ++HeaderCount;
  if ((Cookie != NULL) && (Cookie[0] != '\0')) {
    Headers[HeaderCount].FieldName  = "Cookie";
    Headers[HeaderCount].FieldValue = (CHAR8 *)Cookie;
    ++HeaderCount;
  }

  Request.Method = HttpMethodGet;
  Request.Url    = UnicodeUrl;

  Status = HttpIoSendRequest (&HttpIo, &Request, HeaderCount, Headers, 0, NULL);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = HttpIoRecvResponse (&HttpIo, TRUE, &ResponseData);
  if (EFI_ERROR (Status) && (Status != EFI_HTTP_ERROR)) {
    goto Done;
  }

  if (!InternalHttpStatusOk (ResponseData.Response.StatusCode)) {
    DEBUG ((DEBUG_WARN, "OIR: HTTP status %u for %a\n", ResponseData.Response.StatusCode, Url));
    Status = EFI_PROTOCOL_ERROR;
    goto Done;
  }

  ResponseHeaderCount = ResponseData.HeaderCount;
  ResponseHeaders     = ResponseData.Headers;
  ResponseData.Headers = NULL;

  Status = InternalGetContentLength (ResponseHeaderCount, ResponseHeaders, &ContentLength);
  if (EFI_ERROR (Status) || (ContentLength == 0) || (ContentLength > OIR_RAM_DISK_SIZE)) {
    DEBUG ((DEBUG_WARN, "OIR: Invalid DMG Content-Length for %a - %r size %Lu\n", Url, Status, (UINT64)ContentLength));
    Status = EFI_PROTOCOL_ERROR;
    goto Done;
  }

  RamDisk = OcAppleRamDiskAllocate (ContentLength, EfiACPIMemoryNVS);
  if (RamDisk == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ChunkBuffer = AllocatePool (OIR_DOWNLOAD_CHUNK_SIZE);
  if (ChunkBuffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Offset = 0;
  while (Offset < ContentLength) {
    ZeroMem (&ResponseData, sizeof (ResponseData));
    ResponseData.BodyLength = MIN (OIR_DOWNLOAD_CHUNK_SIZE, ContentLength - Offset);
    ResponseData.Body       = (CHAR8 *)ChunkBuffer;

    Status = HttpIoRecvResponse (&HttpIo, FALSE, &ResponseData);
    if (EFI_ERROR (Status) && (Status != EFI_HTTP_ERROR)) {
      goto Done;
    }

    if ((ResponseData.BodyLength == 0) || !OcAppleRamDiskWrite (RamDisk, Offset, ResponseData.BodyLength, ChunkBuffer)) {
      Status = EFI_PROTOCOL_ERROR;
      goto Done;
    }

    Offset += ResponseData.BodyLength;
    Print (L"OpenInternetRecovery: downloaded %u/%u MB\r", (UINT32)(Offset / BASE_1MB), (UINT32)(ContentLength / BASE_1MB));
  }

  Print (L"\n");
  *ExtentTable  = RamDisk;
  *DownloadSize = ContentLength;
  RamDisk       = NULL;
  Status        = EFI_SUCCESS;

Done:
  if (ResponseHeaders != NULL) {
    FreePool (ResponseHeaders);
  }

  if (ResponseData.Headers != NULL) {
    FreePool (ResponseData.Headers);
  }

  if (ChunkBuffer != NULL) {
    FreePool (ChunkBuffer);
  }

  if (RamDisk != NULL) {
    OcAppleRamDiskFree (RamDisk);
  }

  HttpIoDestroyIo (&HttpIo);
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  if (UnicodeUrl != NULL) {
    FreePool (UnicodeUrl);
  }

  return Status;
}

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
  )
{
  EFI_STATUS         Status;
  OIR_HTTP_RESPONSE  Response;

  if (ResponseBody != NULL) {
    *ResponseBody = NULL;
  }

  if (ResponseBodySize != NULL) {
    *ResponseBodySize = 0;
  }

  Status = OirHttpRequestEx (
             Method,
             Url,
             Cookie,
             ContentType,
             RequestBody,
             RequestBodySize,
             &Response
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  InternalCopySetCookie (&Response, SetCookie, SetCookieSize);
  if (ResponseBody != NULL) {
    *ResponseBody = Response.Body;
    Response.Body = NULL;
  }

  if (ResponseBodySize != NULL) {
    *ResponseBodySize = Response.BodySize;
  }

  InternalFreeHttpResponse (&Response);
  return EFI_SUCCESS;
}

EFI_STATUS
OirCheckAppleConnectivity (
  VOID
  )
{
  return OirHttpRequest (
           HttpMethodHead,
           OIR_APPLE_RECOVERY_BASE_URL,
           NULL,
           NULL,
           NULL,
           0,
           NULL,
           NULL,
           NULL,
           0
           );
}
