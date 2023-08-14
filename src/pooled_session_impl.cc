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

#include "hsmc/pooled_session_impl.h"

#include "hsmc/session_pool.h"
#include "hsmc/exception.h"

namespace hsmc {

PooledSessionImpl::PooledSessionImpl(PooledSessionHolder::Ptr pHolder) :
    SessionImpl(pHolder->session()->getConnector()),
    pHolder_(pHolder) {
}

PooledSessionImpl::~PooledSessionImpl() {
  if (pHolder_) {
    pHolder_->owner().putBack(pHolder_);
    pHolder_.reset();
  }
}

SessionImpl::Ptr PooledSessionImpl::impl() const {
  return pHolder_->session();
}

SessionImpl::Ptr PooledSessionImpl::access() const {
  if (pHolder_) {
    pHolder_->access();
    return impl();
  } else {
    throw NullValueException("pooled session access failure");
  }
}

void PooledSessionImpl::open() {
  access()->open();
}

void PooledSessionImpl::close() {
  access()->close();
}

bool PooledSessionImpl::isGood(int *errcode, bool *dev_reopen) const {
  return access()->isGood(errcode, dev_reopen);
}

void *PooledSessionImpl::getSessionHandle() const {
  return access()->getSessionHandle();
}

std::string PooledSessionImpl::getId() const {
  return access()->getId();
}

int PooledSessionImpl::SDF_GetDeviceInfo(
    DEVICEINFO *pstDeviceInfo) const {
  return access()->SDF_GetDeviceInfo(pstDeviceInfo);
}

int PooledSessionImpl::SDF_GenerateRandom(
    unsigned int uiLength,
    unsigned char *pucRandom) const {
  return access()->SDF_GenerateRandom(uiLength, pucRandom);
}

int PooledSessionImpl::SDF_GetPrivateKeyAccessRight(
    unsigned int uiKeyIndex,
    unsigned char *pucPassword,
    unsigned int uiPwdLength) const {
  return access()->SDF_GetPrivateKeyAccessRight(uiKeyIndex, pucPassword, uiPwdLength);
}

int PooledSessionImpl::SDF_ReleasePrivateKeyAccessRight(unsigned int uiKeyIndex) const {
  return access()->SDF_ReleasePrivateKeyAccessRight(uiKeyIndex);
}

int PooledSessionImpl::SDF_ExportSignPublicKey_RSA(
    unsigned int uiKeyIndex,
    RSArefPublicKey *pucPublicKey) const {
  return access()->SDF_ExportSignPublicKey_RSA(uiKeyIndex, pucPublicKey);
}

int PooledSessionImpl::SDF_ExportEncPublicKey_RSA(unsigned int uiKeyIndex,
                                                  RSArefPublicKey *pucPublicKey) const {
  return access()->SDF_ExportEncPublicKey_RSA(uiKeyIndex, pucPublicKey);
}

int PooledSessionImpl::SDF_GenerateKeyPair_RSA(
    unsigned int uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    RSArefPrivateKey *pucPrivateKey) const {
  return access()->SDF_GenerateKeyPair_RSA(uiKeyBits, pucPublicKey, pucPrivateKey);
}

int PooledSessionImpl::SDF_GenerateKeyWithIPK_RSA(
    unsigned int uiIPKIndex,
    unsigned int uiKeyBits,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithIPK_RSA(uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_GenerateKeyWithEPK_RSA(
    unsigned int uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithEPK_RSA(uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_ImportKeyWithISK_RSA(
    unsigned int uiISKIndex,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void **phKeyHandle) const {
  return access()->SDF_ImportKeyWithISK_RSA(uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_ExchangeDigitEnvelopeBaseOnRSA(
    unsigned int uiKeyIndex,
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucDEInput,
    unsigned int uiDELength,
    unsigned char *pucDEOutput,
    unsigned int *puiDELength) const {
  return access()->SDF_ExchangeDigitEnvelopeBaseOnRSA(uiKeyIndex,
                                                      pucPublicKey,
                                                      pucDEInput,
                                                      uiDELength,
                                                      pucDEOutput,
                                                      puiDELength);
}

int PooledSessionImpl::SDF_ExportSignPublicKey_ECC(
    unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return access()->SDF_ExportSignPublicKey_ECC(uiKeyIndex, pucPublicKey);
}

int PooledSessionImpl::SDF_ExportEncPublicKey_ECC(
    unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return access()->SDF_ExportEncPublicKey_ECC(uiKeyIndex, pucPublicKey);
}

int PooledSessionImpl::SDF_GenerateKeyPair_ECC(
    unsigned int uiAlgID,
    unsigned int uiKeyBits,
    ECCrefPublicKey *pucPublicKey,
    ECCrefPrivateKey *pucPrivateKey) const {
  return access()->SDF_GenerateKeyPair_ECC(uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
}

int PooledSessionImpl::SDF_GenerateKeyWithIPK_ECC(
    unsigned int uiIPKIndex,
    unsigned int uiKeyBits,
    ECCCipher *pucKey,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithIPK_ECC(uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
}

int PooledSessionImpl::SDF_GenerateKeyWithEPK_ECC(
    unsigned int uiKeyBits,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKey,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithEPK_ECC(uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
}

int PooledSessionImpl::SDF_ImportKeyWithISK_ECC(
    unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const {
  return access()->SDF_ImportKeyWithISK_ECC(uiISKIndex, pucKey, phKeyHandle);
}

int PooledSessionImpl::SDF_GenerateAgreementDataWithECC(
    unsigned int uiISKIndex,
    unsigned int uiKeyBits,
    unsigned char *pucSponsorID,
    unsigned int uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle) const {
  return access()->SDF_GenerateAgreementDataWithECC(uiISKIndex,
                                                    uiKeyBits,
                                                    pucSponsorID,
                                                    uiSponsorIDLength,
                                                    pucSponsorPublicKey,
                                                    pucSponsorTmpPublicKey,
                                                    phAgreementHandle);
}

int PooledSessionImpl::SDF_GenerateKeyWithECC(
    unsigned char *pucResponseID,
    unsigned int uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithECC(pucResponseID,
                                          uiResponseIDLength,
                                          pucResponsePublicKey,
                                          pucResponseTmpPublicKey,
                                          hAgreementHandle,
                                          phKeyHandle);
}

int PooledSessionImpl::SDF_GenerateAgreementDataAndKeyWithECC(
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
    void **phKeyHandle) const {
  return access()->SDF_GenerateAgreementDataAndKeyWithECC(uiISKIndex,
                                                          uiKeyBits,
                                                          pucResponseID,
                                                          uiResponseIDLength,
                                                          pucSponsorID,
                                                          uiSponsorIDLength,
                                                          pucSponsorPublicKey,
                                                          pucSponsorTmpPublicKey,
                                                          pucResponsePublicKey,
                                                          pucResponseTmpPublicKey,
                                                          phKeyHandle);
}

int PooledSessionImpl::SDF_ExchangeDigitEnvelopeBaseOnECC(
    unsigned int uiKeyIndex,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucEncDataIn,
    ECCCipher *pucEncDataOut) const {
  return access()->SDF_ExchangeDigitEnvelopeBaseOnECC(uiKeyIndex,
                                                      uiAlgID,
                                                      pucPublicKey,
                                                      pucEncDataIn,
                                                      pucEncDataOut);
}

int PooledSessionImpl::SDF_GenerateKeyWithKEK(
    unsigned int uiKeyBits,
    unsigned int uiAlgID,
    unsigned int uiKEKIndex,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle) const {
  return access()->SDF_GenerateKeyWithKEK(uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_ImportKeyWithKEK(
    unsigned int uiAlgID,
    unsigned int uiKEKIndex,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void **phKeyHandle) const {
  return access()->SDF_ImportKeyWithKEK(uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_ImportKey(
    unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const {
  return access()->SDF_ImportKey(pucKey, uiKeyLength, phKeyHandle);
}

int PooledSessionImpl::SDF_DestroyKey(void *hKeyHandle) const {
  return access()->SDF_DestroyKey(hKeyHandle);
}

int PooledSessionImpl::SDF_ExternalPublicKeyOperation_RSA(
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) const {
  return access()->SDF_ExternalPublicKeyOperation_RSA(pucPublicKey,
                                                      pucDataInput,
                                                      uiInputLength,
                                                      pucDataOutput,
                                                      puiOutputLength);
}

int PooledSessionImpl::SDF_InternalPublicKeyOperation_RSA(
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) const {
  return access()->SDF_InternalPublicKeyOperation_RSA(uiKeyIndex,
                                                      pucDataInput,
                                                      uiInputLength,
                                                      pucDataOutput,
                                                      puiOutputLength);
}

int PooledSessionImpl::SDF_InternalPrivateKeyOperation_RSA(
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) const {
  return access()->SDF_InternalPrivateKeyOperation_RSA(uiKeyIndex,
                                                       pucDataInput,
                                                       uiInputLength,
                                                       pucDataOutput,
                                                       puiOutputLength);
}

int PooledSessionImpl::SDF_ExternalPrivateKeyOperation_RSA(
    RSArefPrivateKey *pucPrivateKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) const {
  return access()->SDF_ExternalPrivateKeyOperation_RSA(pucPrivateKey,
                                                       pucDataInput,
                                                       uiInputLength,
                                                       pucDataOutput,
                                                       puiOutputLength);
}

int PooledSessionImpl::SDF_ExternalSign_ECC(
    unsigned int uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature) const {
  return access()->SDF_ExternalSign_ECC(uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
}

int PooledSessionImpl::SDF_ExternalVerify_ECC(
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    ECCSignature *pucSignature) const {
  return access()->SDF_ExternalVerify_ECC(uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature);
}

int PooledSessionImpl::SDF_InternalSign_ECC(
    unsigned int uiISKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature) const {
  return access()->SDF_InternalSign_ECC(uiISKIndex, pucData, uiDataLength, pucSignature);
}

int PooledSessionImpl::SDF_InternalVerify_ECC(
    unsigned int uiIPKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature) const {
  return access()->SDF_InternalVerify_ECC(uiIPKIndex, pucData, uiDataLength, pucSignature);
}

int PooledSessionImpl::SDF_ExternalEncrypt_ECC(
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCCipher *pucEncData) const {
  return access()->SDF_ExternalEncrypt_ECC(uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
}

int PooledSessionImpl::SDF_ExternalDecrypt_ECC(
    unsigned int uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    ECCCipher *pucEncData,
    unsigned char *pucData,
    unsigned int *puiDataLength) const {
  return access()->SDF_ExternalDecrypt_ECC(uiAlgID, pucPrivateKey, pucEncData, pucData, puiDataLength);
}

int PooledSessionImpl::SDF_Encrypt(
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucData,
    unsigned int uiDataLength,
    unsigned char *pucEncData,
    unsigned int *puiEncDataLength) const {
  return access()->SDF_Encrypt(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength);
}

int PooledSessionImpl::SDF_Decrypt(
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucEncData,
    unsigned int uiEncDataLength,
    unsigned char *pucData,
    unsigned int *puiDataLength) const {
  return access()->SDF_Decrypt(hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int PooledSessionImpl::SDF_CalculateMAC(
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucData,
    unsigned int uiDataLength,
    unsigned char *pucMAC,
    unsigned int *puiMACLength) const {
  return access()->SDF_CalculateMAC(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMACLength);
}

int PooledSessionImpl::SDF_HashInit(
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucID,
    unsigned int uiIDLength) const {
  return access()->SDF_HashInit(uiAlgID, pucPublicKey, pucID, uiIDLength);
}

int PooledSessionImpl::SDF_HashUpdate(unsigned char *pucData, unsigned int uiDataLength) const {
  return access()->SDF_HashUpdate(pucData, uiDataLength);
}

int PooledSessionImpl::SDF_HashFinal(unsigned char *pucHash, unsigned int *puiHashLength) const {
  return access()->SDF_HashFinal(pucHash, puiHashLength);
}

int PooledSessionImpl::SDF_CreateFile(
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiFileSize) const {
  return access()->SDF_CreateFile(pucFileName, uiNameLen, uiFileSize);
}

int PooledSessionImpl::SDF_ReadFile(
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiOffset,
    unsigned int *puiFileLength,
    unsigned char *pucBuffer) const {
  return access()->SDF_ReadFile(pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
}

int PooledSessionImpl::SDF_WriteFile(
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiOffset,
    unsigned int uiFileLength,
    unsigned char *pucBuffer) const {
  return access()->SDF_WriteFile(pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
}

int PooledSessionImpl::SDF_DeleteFile(unsigned char *pucFileName, unsigned int uiNameLen) const {
  return access()->SDF_DeleteFile(pucFileName, uiNameLen);
}

int PooledSessionImpl::SVS_ExportCert(
    const char *certId,
    uint8_t *certData,
    uint32_t *certDataLen) const {
  return access()->SVS_ExportCert(certId, certData, certDataLen);
}

int PooledSessionImpl::SVS_ParseCert(
    int certType,
    const uint8_t *certData,
    uint32_t certDataLen,
    uint8_t *certInfo,
    uint32_t *certInfoLen) const {
  return access()->SVS_ParseCert(certType, certData, certDataLen, certInfo, certInfoLen);
}

int PooledSessionImpl::SVS_ValidateCert(
    const uint8_t *certData,
    uint32_t certDataLen,
    bool ocsp,
    int *state) const {
  return access()->SVS_ValidateCert(certData, certDataLen, ocsp, state);
}

int PooledSessionImpl::SVS_SignData(
    int method,
    uint32_t signPrivateKeyIndex,
    const char *password,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *signData,
    uint32_t *signDataLen) const {
  return access()->SVS_SignData(method, signPrivateKeyIndex, password, data, dataLen, signData, signDataLen);
}

int PooledSessionImpl::SVS_VerifySignedData(
    int type,
    const uint8_t *certData,
    uint32_t certDataLen,
    const uint8_t *data,
    uint32_t dataLen,
    const uint8_t *signData,
    uint32_t signDataLen,
    int verifyLevel) const {
  return access()->SVS_VerifySignedData(
      type, certData, certDataLen, data, dataLen, signData, signDataLen, verifyLevel);
}

int PooledSessionImpl::SVS_SignDataInit(
    int method,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()->SVS_SignDataInit(method, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_SignDataUpdate(
    int method,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()
      ->SVS_SignDataUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_SignDataFinal(
    int method,
    uint32_t signPrivateKeyIndex,
    const char *password,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    uint8_t *signData,
    uint32_t *signDataLen) const {
  return access()->SVS_SignDataFinal(method,
                                     signPrivateKeyIndex,
                                     password,
                                     hashMediantData,
                                     hashMediantDataLen,
                                     signData,
                                     signDataLen);
}

int PooledSessionImpl::SVS_VerifySignedDataInit(
    int method,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()->SVS_VerifySignedDataInit(method, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_VerifySignedDataUpdate(
    int method,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()
      ->SVS_VerifySignedDataUpdate(
          method, hashMediantData, hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_VerifySignedDataFinal(
    int method,
    int type,
    const uint8_t *certData,
    uint32_t certDataLen,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *signData,
    uint32_t signDataLen,
    int verifyLevel) const {
  return access()->SVS_VerifySignedDataFinal(method,
                                             type,
                                             certData,
                                             certDataLen,
                                             hashMediantData,
                                             hashMediantDataLen,
                                             signData,
                                             signDataLen,
                                             verifyLevel);
}

int PooledSessionImpl::SVS_SignMessage(
    int method,
    uint32_t signPrivateKeyIndex,
    const char *password,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *signData,
    uint32_t *signDataLen,
    bool isHashFlag,
    bool isOriginalText,
    bool isCertificateChain,
    bool isCrl,
    bool isAuthenticationAttributes) const {
  return access()->SVS_SignMessage(method,
                                   signPrivateKeyIndex,
                                   password,
                                   data,
                                   dataLen,
                                   signData,
                                   signDataLen,
                                   isHashFlag,
                                   isOriginalText,
                                   isCertificateChain,
                                   isCrl,
                                   isAuthenticationAttributes);
}

int PooledSessionImpl::SVS_VerifySignedMessage(
    const uint8_t *data,
    uint32_t dataLen,
    const uint8_t *signData,
    uint32_t signDataLen,
    bool isHashFlag,
    bool isOriginalText,
    bool isCertificateChain,
    bool isCrl,
    bool isAuthenticationAttributes) const {
  return access()->SVS_VerifySignedMessage(data,
                                           dataLen,
                                           signData,
                                           signDataLen,
                                           isHashFlag,
                                           isOriginalText,
                                           isCertificateChain,
                                           isCrl,
                                           isAuthenticationAttributes);
}

int PooledSessionImpl::SVS_SignMessageInit(
    int method,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()->SVS_SignMessageInit(method, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_SignMessageUpdate(
    int method, const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()
      ->SVS_SignMessageUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_SignMessageFinal(
    int method,
    uint32_t signPrivateKeyIndex,
    const char *password,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    uint8_t *signData,
    uint32_t *signDataLen) const {
  return access()->SVS_SignMessageFinal(method,
                                        signPrivateKeyIndex,
                                        password,
                                        hashMediantData,
                                        hashMediantDataLen,
                                        signData,
                                        signDataLen);
}

int PooledSessionImpl::SVS_VerifySignedMessageInit(
    int method,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()->SVS_VerifySignedMessageInit(method, data, dataLen, hashData, hashDataLen);
}

int PooledSessionImpl::SVS_VerifySignedMessageUpdate(
    int method,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *data,
    uint32_t dataLen,
    uint8_t *hashData,
    uint32_t *hashDataLen) const {
  return access()->SVS_VerifySignedMessageUpdate(method,
                                                 hashMediantData,
                                                 hashMediantDataLen,
                                                 data,
                                                 dataLen,
                                                 hashData,
                                                 hashDataLen);
}

int PooledSessionImpl::SVS_VerifySignedMessageFinal(
    int method,
    const uint8_t *hashMediantData,
    uint32_t hashMediantDataLen,
    const uint8_t *signData,
    uint32_t signDataLen) const {
  return access()->SVS_VerifySignedMessageFinal(method, hashMediantData, hashMediantDataLen, signData, signDataLen);
}

SGD_UINT32 PooledSessionImpl::STF_CreateTSRequest(
    SGD_UINT8 *pucInData,
    SGD_UINT32 uiInDataLength,
    SGD_UINT32 uiReqType,
    SGD_UINT8 *pucTSExt,
    SGD_UINT32 uiTSExtLength,
    SGD_UINT32 uiHashAlgID,
    SGD_UINT8 *pucTSRequest,
    SGD_UINT32 *puiTSRequestLength) const {
  return access()->STF_CreateTSRequest(pucInData, uiInDataLength, uiReqType,
                                       pucTSExt, uiTSExtLength, uiHashAlgID,
                                       pucTSRequest, puiTSRequestLength);
}

SGD_UINT32 PooledSessionImpl::STF_CreateTSResponse(
    SGD_UINT8 *pucTSRequest,
    SGD_UINT32 uiTSRequestLength,
    SGD_UINT32 uiSignatureAlgID,
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 *puiTSResponseLength) const {
  return access()->STF_CreateTSResponse(pucTSRequest, uiTSRequestLength,
                                        uiSignatureAlgID, pucTSResponse, puiTSResponseLength);
}

SGD_UINT32 PooledSessionImpl::STF_VerifyTSValidity(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT32 uiHashAlgID,
    SGD_UINT32 uiSignatureAlgID,
    SGD_UINT8 *pucTSCert,
    SGD_UINT32 uiTSCertLength) const {
  return access()->STF_VerifyTSValidity(pucTSResponse, uiTSResponseLength,
                                        uiHashAlgID, uiSignatureAlgID,
                                        pucTSCert, uiTSCertLength);
}

SGD_UINT32 PooledSessionImpl::STF_GetTSInfo(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT8 *pucIssuerName,
    SGD_UINT32 *puiIssuerNameLength,
    SGD_UINT8 *pucTime,
    SGD_UINT32 *puiTimeLength) const {
  return access()->STF_GetTSInfo(pucTSResponse, uiTSResponseLength,
                                 pucIssuerName, puiIssuerNameLength,
                                 pucTime, puiTimeLength);
}

SGD_UINT32 PooledSessionImpl::STF_GetTSDetail(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT32 uiItemNumber,
    SGD_UINT8 *pucItemValue,
    SGD_UINT32 *puiItemValueLength) const {
  return access()->STF_GetTSDetail(pucTSResponse, uiTSResponseLength,
                                   uiItemNumber, pucItemValue, puiItemValueLength);
}

}
