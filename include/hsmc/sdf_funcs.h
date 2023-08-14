// Copyright (C) 2021 Institute of Data Security, HIT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <functional>

#include "base.h"
#include "instrument.h"
#include "sdf.h"

namespace hsmc {

using SDF_OpenDevice_t = \
 int (*)(void **hDeviceHandle);

using SDF_CloseDevice_t = \
 int (*)(void *hDeviceHandle);

using SDF_OpenSession_t = \
 int (*)(void *hDeviceHandle,
         void **phSessionHandle);

using SDF_CloseSession_t = \
 int (*)(void *hSessionHandle);

using SDF_GetDeviceInfo_t = \
 int (*)(void *hSessionHandle,
         DEVICEINFO *pstDeviceInfo);

using SDF_GenerateRandom_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiLength,
         unsigned char *pucRandom);

using SDF_GetPrivateKeyAccessRight_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         unsigned char *pucPassword,
         unsigned int uiPwdLength);

using SDF_ReleasePrivateKeyAccessRight_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex);

using SDF_ExportSignPublicKey_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         RSArefPublicKey *pucPublicKey);

using SDF_ExportEncPublicKey_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         RSArefPublicKey *pucPublicKey);

using SDF_GenerateKeyPair_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyBits,
         RSArefPublicKey *pucPublicKey,
         RSArefPrivateKey *pucPrivateKey);

using SDF_GenerateKeyWithIPK_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiIPKIndex,
         unsigned int uiKeyBits,
         unsigned char *pucKey,
         unsigned int *puiKeyLength,
         void **phKeyHandle);

using SDF_GenerateKeyWithEPK_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyBits,
         RSArefPublicKey *pucPublicKey,
         unsigned char *pucKey,
         unsigned int *puiKeyLength,
         void **phKeyHandle);

using SDF_ImportKeyWithISK_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiISKIndex,
         unsigned char *pucKey,
         unsigned int uiKeyLength,
         void **phKeyHandle);

using SDF_ExchangeDigitEnvelopeBaseOnRSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         RSArefPublicKey *pucPublicKey,
         unsigned char *pucDEInput,
         unsigned int uiDELength,
         unsigned char *pucDEOutput,
         unsigned int *puiDELength);

using SDF_ExportSignPublicKey_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         ECCrefPublicKey *pucPublicKey);

using SDF_ExportEncPublicKey_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         ECCrefPublicKey *pucPublicKey);

using SDF_GenerateKeyPair_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         unsigned int uiKeyBits,
         ECCrefPublicKey *pucPublicKey,
         ECCrefPrivateKey *pucPrivateKey);

using SDF_GenerateKeyWithIPK_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiIPKIndex,
         unsigned int uiKeyBits,
         ECCCipher *pucKey,
         void **phKeyHandle);

using SDF_GenerateKeyWithEPK_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyBits,
         unsigned int uiAlgID,
         ECCrefPublicKey *pucPublicKey,
         ECCCipher *pucKey,
         void **phKeyHandle);

using SDF_ImportKeyWithISK_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiISKIndex,
         ECCCipher *pucKey,
         void **phKeyHandle);

using SDF_GenerateAgreementDataWithECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiISKIndex,
         unsigned int uiKeyBits,
         unsigned char *pucSponsorID,
         unsigned int uiSponsorIDLength,
         ECCrefPublicKey *pucSponsorPublicKey,
         ECCrefPublicKey *pucSponsorTmpPublicKey,
         void **phAgreementHandle);

using SDF_GenerateKeyWithECC_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucResponseID,
         unsigned int uiResponseIDLength,
         ECCrefPublicKey *pucResponsePublicKey,
         ECCrefPublicKey *pucResponseTmpPublicKey,
         void *hAgreementHandle,
         void **phKeyHandle);

using SDF_GenerateAgreementDataAndKeyWithECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiISKIndex,
         unsigned int uiKeyBits,
         unsigned char *pucResponseID,
         unsigned int uiResponseIDLength,
         unsigned char *pucSponsorID,
         unsigned int uiSponsorIDLength,
         ECCrefPublicKey *pucSponsorPublicKey,
         ECCrefPublicKey *pucSponsorTmpPublicKey,
         ECCrefPublicKey *pucResponsePublicKey,
         ECCrefPublicKey *pucResponseTmpPublicKey,
         void **phKeyHandle);

using SDF_ExchangeDigitEnvelopeBaseOnECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         unsigned int uiAlgID,
         ECCrefPublicKey *pucPublicKey,
         ECCCipher *pucEncDataIn,
         ECCCipher *pucEncDataOut);

using SDF_GenerateKeyWithKEK_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyBits,
         unsigned int uiAlgID,
         unsigned int uiKEKIndex,
         unsigned char *pucKey,
         unsigned int *puiKeyLength,
         void **phKeyHandle);

using SDF_ImportKeyWithKEK_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         unsigned int uiKEKIndex,
         unsigned char *pucKey,
         unsigned int uiKeyLength,
         void **phKeyHandle);

using SDF_ImportKey_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucKey,
         unsigned int uiKeyLength,
         void **phKeyHandle);

using SDF_DestroyKey_t = \
 int (*)(void *hSessionHandle,
         void *hKeyHandle);

using SDF_ExternalPublicKeyOperation_RSA_t = \
 int (*)(void *hSessionHandle,
         RSArefPublicKey *pucPublicKey,
         unsigned char *pucDataInput,
         unsigned int uiInputLength,
         unsigned char *pucDataOutput,
         unsigned int *puiOutputLength);
using SDF_InternalPublicKeyOperation_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         unsigned char *pucDataInput,
         unsigned int uiInputLength,
         unsigned char *pucDataOutput,
         unsigned int *puiOutputLength);

using SDF_InternalPrivateKeyOperation_RSA_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiKeyIndex,
         unsigned char *pucDataInput,
         unsigned int uiInputLength,
         unsigned char *pucDataOutput,
         unsigned int *puiOutputLength);

using SDF_ExternalPrivateKeyOperation_RSA_t = \
 int (*)(void *hSessionHandle,
         RSArefPrivateKey *pucPrivateKey,
         unsigned char *pucDataInput,
         unsigned int uiInputLength,
         unsigned char *pucDataOutput,
         unsigned int *puiOutputLength);

using SDF_ExternalSign_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         ECCrefPrivateKey *pucPrivateKey,
         unsigned char *pucData,
         unsigned int uiDataLength,
         ECCSignature *pucSignature);

using SDF_ExternalVerify_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         ECCrefPublicKey *pucPublicKey,
         unsigned char *pucDataInput,
         unsigned int uiInputLength,
         ECCSignature *pucSignature);

using SDF_InternalSign_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiISKIndex,
         unsigned char *pucData,
         unsigned int uiDataLength,
         ECCSignature *pucSignature);

using SDF_InternalVerify_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiIPKIndex,
         unsigned char *pucData,
         unsigned int uiDataLength,
         ECCSignature *pucSignature);

using SDF_ExternalEncrypt_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         ECCrefPublicKey *pucPublicKey,
         unsigned char *pucData,
         unsigned int uiDataLength,
         ECCCipher *pucEncData);

using SDF_ExternalDecrypt_ECC_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         ECCrefPrivateKey *pucPrivateKey,
         ECCCipher *pucEncData,
         unsigned char *pucData,
         unsigned int *puiDataLength);

using SDF_Encrypt_t = \
 int (*)(void *hSessionHandle,
         void *hKeyHandle,
         unsigned int uiAlgID,
         unsigned char *pucIV,
         unsigned char *pucData,
         unsigned int uiDataLength,
         unsigned char *pucEncData,
         unsigned int *puiEncDataLength);

using SDF_Decrypt_t = \
 int (*)(void *hSessionHandle,
         void *hKeyHandle,
         unsigned int uiAlgID,
         unsigned char *pucIV,
         unsigned char *pucEncData,
         unsigned int uiEncDataLength,
         unsigned char *pucData,
         unsigned int *puiDataLength);

using SDF_CalculateMAC_t = \
 int (*)(void *hSessionHandle,
         void *hKeyHandle,
         unsigned int uiAlgID,
         unsigned char *pucIV,
         unsigned char *pucData,
         unsigned int uiDataLength,
         unsigned char *pucMAC,
         unsigned int *puiMACLength);

using SDF_HashInit_t = \
 int (*)(void *hSessionHandle,
         unsigned int uiAlgID,
         ECCrefPublicKey *pucPublicKey,
         unsigned char *pucID,
         unsigned int uiIDLength);

using SDF_HashUpdate_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucData,
         unsigned int uiDataLength);

using SDF_HashFinal_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucHash,
         unsigned int *puiHashLength);

using SDF_CreateFile_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucFileName,
         unsigned int uiNameLen,/* max 128-byte */
         unsigned int uiFileSize);

using SDF_ReadFile_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucFileName,
         unsigned int uiNameLen,
         unsigned int uiOffset,
         unsigned int *puiFileLength,
         unsigned char *pucBuffer);

using SDF_WriteFile_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucFileName,
         unsigned int uiNameLen,
         unsigned int uiOffset,
         unsigned int uiFileLength,
         unsigned char *pucBuffer);

using SDF_DeleteFile_t = \
 int (*)(void *hSessionHandle,
         unsigned char *pucFileName,
         unsigned int uiNameLen);

DECLARE_INSTRUMENTED_FUNCTYPE(SDF_OpenDevice)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_CloseDevice)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_OpenSession)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_CloseSession)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GetDeviceInfo)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateRandom)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GetPrivateKeyAccessRight)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ReleasePrivateKeyAccessRight)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExportSignPublicKey_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExportEncPublicKey_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyPair_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithIPK_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithEPK_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ImportKeyWithISK_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExchangeDigitEnvelopeBaseOnRSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExportSignPublicKey_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExportEncPublicKey_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyPair_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithIPK_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithEPK_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ImportKeyWithISK_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateAgreementDataWithECC);
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateAgreementDataAndKeyWithECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExchangeDigitEnvelopeBaseOnECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_GenerateKeyWithKEK)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ImportKeyWithKEK)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ImportKey)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_DestroyKey)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalPublicKeyOperation_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_InternalPublicKeyOperation_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_InternalPrivateKeyOperation_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalPrivateKeyOperation_RSA)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalSign_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalVerify_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_InternalSign_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_InternalVerify_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalEncrypt_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ExternalDecrypt_ECC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_Encrypt)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_Decrypt)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_CalculateMAC)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_HashInit)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_HashUpdate)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_HashFinal)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_CreateFile)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_ReadFile)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_WriteFile)
DECLARE_INSTRUMENTED_FUNCTYPE(SDF_DeleteFile)

class HSMC_API SDFFuncs {
 public:
  SDFFuncs() = default;

  SDF_OpenDevice SDF_OpenDevice_;
  SDF_CloseDevice SDF_CloseDevice_;
  SDF_OpenSession SDF_OpenSession_;
  SDF_CloseSession SDF_CloseSession_;
  SDF_GetDeviceInfo SDF_GetDeviceInfo_;
  SDF_GenerateRandom SDF_GenerateRandom_;
  SDF_GetPrivateKeyAccessRight SDF_GetPrivateKeyAccessRight_;
  SDF_ReleasePrivateKeyAccessRight SDF_ReleasePrivateKeyAccessRight_;
  SDF_ExportSignPublicKey_RSA SDF_ExportSignPublicKey_RSA_;
  SDF_ExportEncPublicKey_RSA SDF_ExportEncPublicKey_RSA_;
  SDF_GenerateKeyPair_RSA SDF_GenerateKeyPair_RSA_;
  SDF_GenerateKeyWithIPK_RSA SDF_GenerateKeyWithIPK_RSA_;
  SDF_GenerateKeyWithEPK_RSA SDF_GenerateKeyWithEPK_RSA_;
  SDF_ImportKeyWithISK_RSA SDF_ImportKeyWithISK_RSA_;
  SDF_ExchangeDigitEnvelopeBaseOnRSA SDF_ExchangeDigitEnvelopeBaseOnRSA_;
  SDF_ExportSignPublicKey_ECC SDF_ExportSignPublicKey_ECC_;
  SDF_ExportEncPublicKey_ECC SDF_ExportEncPublicKey_ECC_;
  SDF_GenerateKeyPair_ECC SDF_GenerateKeyPair_ECC_;
  SDF_GenerateKeyWithIPK_ECC SDF_GenerateKeyWithIPK_ECC_;
  SDF_GenerateKeyWithEPK_ECC SDF_GenerateKeyWithEPK_ECC_;
  SDF_ImportKeyWithISK_ECC SDF_ImportKeyWithISK_ECC_;
  SDF_GenerateAgreementDataWithECC SDF_GenerateAgreementDataWithECC_;
  SDF_GenerateKeyWithECC SDF_GenerateKeyWithECC_;
  SDF_GenerateAgreementDataAndKeyWithECC SDF_GenerateAgreementDataAndKeyWithECC_;
  SDF_ExchangeDigitEnvelopeBaseOnECC SDF_ExchangeDigitEnvelopeBaseOnECC_;
  SDF_GenerateKeyWithKEK SDF_GenerateKeyWithKEK_;
  SDF_ImportKeyWithKEK SDF_ImportKeyWithKEK_;
  SDF_ImportKey SDF_ImportKey_;
  SDF_DestroyKey SDF_DestroyKey_;
  SDF_ExternalPublicKeyOperation_RSA SDF_ExternalPublicKeyOperation_RSA_;
  SDF_InternalPublicKeyOperation_RSA SDF_InternalPublicKeyOperation_RSA_;
  SDF_InternalPrivateKeyOperation_RSA SDF_InternalPrivateKeyOperation_RSA_;
  SDF_ExternalPrivateKeyOperation_RSA SDF_ExternalPrivateKeyOperation_RSA_;
  SDF_ExternalSign_ECC SDF_ExternalSign_ECC_;
  SDF_ExternalVerify_ECC SDF_ExternalVerify_ECC_;
  SDF_InternalSign_ECC SDF_InternalSign_ECC_;
  SDF_InternalVerify_ECC SDF_InternalVerify_ECC_;
  SDF_ExternalEncrypt_ECC SDF_ExternalEncrypt_ECC_;
  SDF_ExternalDecrypt_ECC SDF_ExternalDecrypt_ECC_;
  SDF_Encrypt SDF_Encrypt_;
  SDF_Decrypt SDF_Decrypt_;
  SDF_CalculateMAC SDF_CalculateMAC_;
  SDF_HashInit SDF_HashInit_;
  SDF_HashUpdate SDF_HashUpdate_;
  SDF_HashFinal SDF_HashFinal_;
  SDF_CreateFile SDF_CreateFile_;
  SDF_ReadFile SDF_ReadFile_;
  SDF_WriteFile SDF_WriteFile_;
  SDF_DeleteFile SDF_DeleteFile_;
};

}
