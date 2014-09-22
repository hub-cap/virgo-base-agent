/*
 *  Copyright 2012 Rackspace
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "virgo.h"
#include "virgo__util.h"
#include "virgo__lua.h"
#include "virgo__types.h"
#include "virgo_error.h"
#include "virgo_paths.h"

#ifdef _WIN32

#include <windows.h>
#include <msi.h>

int virgo__lua_fetch_msi_version(lua_State *L)
{
  const char *msi = luaL_checkstring(L, 1);
  UINT ret;
  MSIHANDLE hProduct;
  HANDLE hFile;
  LPSTR pszVersion = NULL;
  DWORD dwSizeVersion = 0;
  LPCSTR prop = "ProductVersion";

  if (!msi) {
    luaL_error(L, "argument 2 must be a string");
  }

  hFile = CreateFile(msi, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    LPSTR errorMsg = NULL;
    DWORD err = GetLastError();
    int ret;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, err, 0, (LPSTR)&errorMsg, 0, NULL);
    ret = luaL_error(L, "msi open failed: %s ; %d, %s", msi, err, errorMsg);
    LocalFree(errorMsg);
  }
  CloseHandle(hFile);

  ret = MsiOpenPackage(msi, &hProduct);
  if (ret != ERROR_SUCCESS)
  {
    return luaL_error(L, "msi open package failed");
  }

  ret = MsiGetProductProperty(hProduct, prop, pszVersion, &dwSizeVersion);
  if (!(ret == ERROR_MORE_DATA || (ret == ERROR_SUCCESS && dwSizeVersion > 0)))
  {
    MsiCloseHandle(hProduct);
    return luaL_error(L, "msi get product property size failed");
  }

  ++dwSizeVersion; /* add one for the null term */
  pszVersion = (LPSTR)malloc(dwSizeVersion);

  ret = MsiGetProductProperty(hProduct, prop, pszVersion, &dwSizeVersion);

  MsiCloseHandle(hProduct);

  if (ret != ERROR_SUCCESS)
  {
    free(pszVersion);
    return luaL_error(L, "msi get product property failed");
  }
  
  lua_pushlstring(L, pszVersion, dwSizeVersion);
  free(pszVersion);
  return 1;
}

int virgo__lua_fetch_msi_signature(lua_State *L)
{
  const char *msi = luaL_checkstring(L, 1);
  UINT ret;
  HANDLE hFile;
  MSIHANDLE hProduct;
  CERT_CONTEXT cert_context; 
  LPSTR pszSigner = NULL;
  DWORD dwSizeSigner = 0;

  if (!msi) {
    luaL_error(L, "argument 2 must be a string");
  }

  hFile = CreateFile(msi, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    LPSTR errorMsg = NULL;
    DWORD err = GetLastError();
    int ret;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, err, 0, (LPSTR)&errorMsg, 0, NULL);
    ret = luaL_error(L, "msi open failed: %s ; %d, %s", msi, err, errorMsg);
    LocalFree(errorMsg);
  }
  CloseHandle(hFile);

  ret = MsiOpenPackage(msi, &hProduct);
  if (ret != ERROR_SUCCESS)
  {
    return luaL_error(L, "msi open package failed");
  }

  ret = MsiGetFileSignatureInformation(msi, MSI_INVALID_HASH_IS_FATAL, &cert_context, NULL, NULL);

  if (ret != ERROR_SUCCESS)
  {
    MsiCloseHandle(hProduct);
    return luaL_error(L, "msi get file signature info failed, %d", ret);
  }

  MsiCloseHandle(hProduct);

  dwSizeSigner = CertGetNameString(&cert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pszSigner, dwSizeSigner);
  if (dwSizeSigner <= 1)
  {
    return luaL_error(L, "cert get name string failed");
  }

  pszSigner = (LPSTR)malloc(dwSizeSigner);

  CertGetNameString(&cert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pszSigner, dwSizeSigner);

  lua_pushlstring(L, pszSigner, dwSizeSigner);
  free(pszSigner);
  return 1;
}

#endif
