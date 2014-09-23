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
  PCERT_CONTEXT pcert_context;
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
    int lret;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, err, 0, (LPSTR)&errorMsg, 0, NULL);
    lret = luaL_error(L, "msi open failed: %s ; %d, %s", msi, err, errorMsg);
    LocalFree(errorMsg);
    return lret;
  }
  CloseHandle(hFile);

  ret = MsiOpenPackage(msi, &hProduct);
  if (ret != ERROR_SUCCESS)
  {
    return luaL_error(L, "msi open package failed");
  }

  ret = MsiGetFileSignatureInformation(msi, MSI_INVALID_HASH_IS_FATAL, &pcert_context, NULL, NULL);

  if (ret != ERROR_SUCCESS)
  {
    LPSTR errorMsg = NULL;
    DWORD err = HRESULT_CODE(ret);
    int lret;
    switch (ret)
    {
    case ERROR_INVALID_PARAMETER:
      errorMsg = "Invalid parameter was specified.";
      break;
    case ERROR_FUNCTION_FAILED:
      errorMsg = "WinVerifyTrust is not available on the system. MsiGetFileSignatureInformation requires the presence of the Wintrust.dll file on the system.";
      break;
    case ERROR_MORE_DATA:
      errorMsg = "A buffer is too small to hold the requested data. If ERROR_MORE_DATA is returned, pcbHashData gives the size of the buffer required to hold the hash data.";
      break;
    case TRUST_E_NOSIGNATURE:
      errorMsg = "File is not signed";
      break;
    case TRUST_E_BAD_DIGEST:
      errorMsg = "The file's current hash is invalid according to the hash stored in the file's digital signature.";
      break;
    case CERT_E_REVOKED:
      errorMsg = "The file's signer certificate has been revoked. The file's digital signature is compromised.";
      break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
      errorMsg = "The subject failed the specified verification action. Most trust providers return a more detailed error code that describes the reason for the failure.";
      break;
    case TRUST_E_PROVIDER_UNKNOWN:
      errorMsg = "The trust provider is not recognized on this system.";
      break;
    case TRUST_E_ACTION_UNKNOWN:
      errorMsg = "The trust provider does not support the specified action.";
      break;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
      errorMsg = "The trust provider does not support the form specified for the subject.";
      break;
    default:
      errorMsg = "Unknown error";
      break;
    }
    lret = luaL_error(L, "msi get file signature info failed: %s ; %d, %s", msi, err, errorMsg);
    MsiCloseHandle(hProduct);
    return lret;
  }

  MsiCloseHandle(hProduct);

  dwSizeSigner = CertGetNameString(pcert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszSigner, dwSizeSigner);
  if (dwSizeSigner <= 1)
  {
    CertFreeCertificateContext(pcert_context);
    return luaL_error(L, "cert get name string failed");
  }

  pszSigner = (LPSTR)malloc(dwSizeSigner);

  CertGetNameString(pcert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszSigner, dwSizeSigner);

  lua_pushlstring(L, pszSigner, dwSizeSigner);
  CertFreeCertificateContext(pcert_context);
  free(pszSigner);
  return 1;
}

#endif
