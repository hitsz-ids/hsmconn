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

#include "hsmc/session_impl.h"

#include <utility>

#include "utils/uuid.h"

namespace hsmc {

SessionImpl::SessionImpl() = default;

SessionImpl::~SessionImpl() = default;

SessionImpl::SessionImpl(Connector::Ptr connector) :
    connector_(std::move(connector)) {
}

Connector::Ptr SessionImpl::getConnector() {
  return connector_;
}

int SessionImpl::SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo) const {
  return connector_->SDF_GetDeviceInfo(getSessionHandle(), pstDeviceInfo);
}

int SessionImpl::SDF_GenerateRandom(unsigned int uiLength, unsigned char *pucRandom) const {
  return connector_->SDF_GenerateRandom(getSessionHandle(), uiLength, pucRandom);
}

int SessionImpl::SDF_GetPrivateKeyAccessRight(unsigned int uiKeyIndex,
                                              unsigned char *pucPassword,
                                              unsigned int uiPwdLength) const {
  return connector_->SDF_GetPrivateKeyAccessRight(getSessionHandle(), uiKeyIndex, pucPassword, uiPwdLength);
}

int SessionImpl::SDF_ReleasePrivateKeyAccessRight(unsigned int uiKeyIndex) const {
  return connector_->SDF_ReleasePrivateKeyAccessRight(getSessionHandle(), uiKeyIndex);
}

int SessionImpl::SDF_ExportSignPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const {
  return connector_->SDF_ExportSignPublicKey_RSA(getSessionHandle(), uiKeyIndex, pucPublicKey);
}

int SessionImpl::SDF_ExportEncPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const {
  return connector_->SDF_ExportEncPublicKey_RSA(getSessionHandle(), uiKeyIndex, pucPublicKey);
}

int SessionImpl::SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits,
                                         RSArefPublicKey *pucPublicKey,
                                         RSArefPrivateKey *pucPrivateKey) const {
  return connector_->SDF_GenerateKeyPair_RSA(getSessionHandle(), uiKeyBits, pucPublicKey, pucPrivateKey);
}

int SessionImpl::SDF_GenerateKeyWithIPK_RSA(unsigned int uiIPKIndex,
                                            unsigned int uiKeyBits,
                                            unsigned char *pucKey,
                                            unsigned int *puiKeyLength,
                                            void **phKeyHandle) const {
  return connector_
      ->SDF_GenerateKeyWithIPK_RSA(getSessionHandle(), uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithEPK_RSA(unsigned int uiKeyBits,
                                            RSArefPublicKey *pucPublicKey,
                                            unsigned char *pucKey,
                                            unsigned int *puiKeyLength,
                                            void **phKeyHandle) const {
  return connector_->SDF_GenerateKeyWithEPK_RSA(getSessionHandle(),
                                                uiKeyBits,
                                                pucPublicKey,
                                                pucKey,
                                                puiKeyLength,
                                                phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithISK_RSA(unsigned int uiISKIndex,
                                          unsigned char *pucKey,
                                          unsigned int uiKeyLength,
                                          void **phKeyHandle) const {
  return connector_->SDF_ImportKeyWithISK_RSA(getSessionHandle(), uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int SessionImpl::SDF_ExchangeDigitEnvelopeBaseOnRSA(unsigned int uiKeyIndex,
                                                    RSArefPublicKey *pucPublicKey,
                                                    unsigned char *pucDEInput,
                                                    unsigned int uiDELength,
                                                    unsigned char *pucDEOutput,
                                                    unsigned int *puiDELength) const {
  return connector_->SDF_ExchangeDigitEnvelopeBaseOnRSA(getSessionHandle(),
                                                        uiKeyIndex,
                                                        pucPublicKey,
                                                        pucDEInput,
                                                        uiDELength,
                                                        pucDEOutput,
                                                        puiDELength);
}

int SessionImpl::SDF_ExportSignPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return connector_->SDF_ExportSignPublicKey_ECC(getSessionHandle(), uiKeyIndex, pucPublicKey);
}

int SessionImpl::SDF_ExportEncPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return connector_->SDF_ExportEncPublicKey_ECC(getSessionHandle(), uiKeyIndex, pucPublicKey);
}

int SessionImpl::SDF_GenerateKeyPair_ECC(unsigned int uiAlgID,
                                         unsigned int uiKeyBits,
                                         ECCrefPublicKey *pucPublicKey,
                                         ECCrefPrivateKey *pucPrivateKey) const {
  return connector_
      ->SDF_GenerateKeyPair_ECC(getSessionHandle(), uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
}

int SessionImpl::SDF_GenerateKeyWithIPK_ECC(unsigned int uiIPKIndex,
                                            unsigned int uiKeyBits,
                                            ECCCipher *pucKey,
                                            void **phKeyHandle) const {
  return connector_->SDF_GenerateKeyWithIPK_ECC(getSessionHandle(), uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithEPK_ECC(unsigned int uiKeyBits,
                                            unsigned int uiAlgID,
                                            ECCrefPublicKey *pucPublicKey,
                                            ECCCipher *pucKey,
                                            void **phKeyHandle) const {
  return connector_
      ->SDF_GenerateKeyWithEPK_ECC(getSessionHandle(), uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithISK_ECC(unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const {
  return connector_->SDF_ImportKeyWithISK_ECC(getSessionHandle(), uiISKIndex, pucKey, phKeyHandle);
}

int SessionImpl::SDF_GenerateAgreementDataWithECC(unsigned int uiISKIndex,
                                                  unsigned int uiKeyBits,
                                                  unsigned char *pucSponsorID,
                                                  unsigned int uiSponsorIDLength,
                                                  ECCrefPublicKey *pucSponsorPublicKey,
                                                  ECCrefPublicKey *pucSponsorTmpPublicKey,
                                                  void **phAgreementHandle) const {
  return connector_->SDF_GenerateAgreementDataWithECC(getSessionHandle(),
                                                      uiISKIndex,
                                                      uiKeyBits,
                                                      pucSponsorID,
                                                      uiSponsorIDLength,
                                                      pucSponsorPublicKey,
                                                      pucSponsorTmpPublicKey,
                                                      phAgreementHandle);
}

int SessionImpl::SDF_GenerateKeyWithECC(unsigned char *pucResponseID,
                                        unsigned int uiResponseIDLength,
                                        ECCrefPublicKey *pucResponsePublicKey,
                                        ECCrefPublicKey *pucResponseTmpPublicKey,
                                        void *hAgreementHandle,
                                        void **phKeyHandle) const {
  return connector_
      ->SDF_GenerateKeyWithECC(getSessionHandle(), pucResponseID, uiResponseIDLength, pucResponsePublicKey,
                               pucResponseTmpPublicKey, hAgreementHandle, phKeyHandle);
}

int SessionImpl::SDF_GenerateAgreementDataAndKeyWithECC(unsigned int uiISKIndex,
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
  return connector_
      ->SDF_GenerateAgreementDataAndKeyWithECC(getSessionHandle(),
                                               uiISKIndex,
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

int SessionImpl::SDF_ExchangeDigitEnvelopeBaseOnECC(unsigned int uiKeyIndex,
                                                    unsigned int uiAlgID,
                                                    ECCrefPublicKey *pucPublicKey,
                                                    ECCCipher *pucEncDataIn,
                                                    ECCCipher *pucEncDataOut) const {
  return connector_->SDF_ExchangeDigitEnvelopeBaseOnECC(getSessionHandle(),
                                                        uiKeyIndex,
                                                        uiAlgID,
                                                        pucPublicKey,
                                                        pucEncDataIn,
                                                        pucEncDataOut);
}

int SessionImpl::SDF_GenerateKeyWithKEK(unsigned int uiKeyBits,
                                        unsigned int uiAlgID,
                                        unsigned int uiKEKIndex,
                                        unsigned char *pucKey,
                                        unsigned int *puiKeyLength,
                                        void **phKeyHandle) const {
  return connector_->SDF_GenerateKeyWithKEK(getSessionHandle(),
                                            uiKeyBits,
                                            uiAlgID,
                                            uiKEKIndex,
                                            pucKey,
                                            puiKeyLength,
                                            phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithKEK(unsigned int uiAlgID,
                                      unsigned int uiKEKIndex,
                                      unsigned char *pucKey,
                                      unsigned int uiKeyLength,
                                      void **phKeyHandle) const {
  return connector_
      ->SDF_ImportKeyWithKEK(getSessionHandle(), uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int SessionImpl::SDF_ImportKey(unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const {
  return connector_->SDF_ImportKey(getSessionHandle(), pucKey, uiKeyLength, phKeyHandle);
}

int SessionImpl::SDF_DestroyKey(void *hKeyHandle) const {
  return connector_->SDF_DestroyKey(getSessionHandle(), hKeyHandle);
}

int SessionImpl::SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey,
                                                    unsigned char *pucDataInput,
                                                    unsigned int uiInputLength,
                                                    unsigned char *pucDataOutput,
                                                    unsigned int *puiOutputLength) const {
  return connector_
      ->SDF_ExternalPublicKeyOperation_RSA(getSessionHandle(), pucPublicKey, pucDataInput, uiInputLength,
                                           pucDataOutput, puiOutputLength);
}

int SessionImpl::SDF_InternalPublicKeyOperation_RSA(unsigned int uiKeyIndex,
                                                    unsigned char *pucDataInput,
                                                    unsigned int uiInputLength,
                                                    unsigned char *pucDataOutput,
                                                    unsigned int *puiOutputLength) const {
  return connector_
      ->SDF_InternalPublicKeyOperation_RSA(getSessionHandle(), uiKeyIndex, pucDataInput, uiInputLength,
                                           pucDataOutput, puiOutputLength);
}

int SessionImpl::SDF_InternalPrivateKeyOperation_RSA(unsigned int uiKeyIndex,
                                                     unsigned char *pucDataInput,
                                                     unsigned int uiInputLength,
                                                     unsigned char *pucDataOutput,
                                                     unsigned int *puiOutputLength) const {
  return connector_
      ->SDF_InternalPrivateKeyOperation_RSA(getSessionHandle(), uiKeyIndex, pucDataInput, uiInputLength,
                                            pucDataOutput, puiOutputLength);
}

int SessionImpl::SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey,
                                                     unsigned char *pucDataInput,
                                                     unsigned int uiInputLength,
                                                     unsigned char *pucDataOutput,
                                                     unsigned int *puiOutputLength) const {
  return connector_
      ->SDF_ExternalPrivateKeyOperation_RSA(getSessionHandle(), pucPrivateKey, pucDataInput, uiInputLength,
                                            pucDataOutput, puiOutputLength);
}

int SessionImpl::SDF_ExternalSign_ECC(unsigned int uiAlgID,
                                      ECCrefPrivateKey *pucPrivateKey,
                                      unsigned char *pucData,
                                      unsigned int uiDataLength,
                                      ECCSignature *pucSignature) const {
  return connector_
      ->SDF_ExternalSign_ECC(getSessionHandle(), uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
}

int SessionImpl::SDF_ExternalVerify_ECC(unsigned int uiAlgID,
                                        ECCrefPublicKey *pucPublicKey,
                                        unsigned char *pucDataInput,
                                        unsigned int uiInputLength,
                                        ECCSignature *pucSignature) const {
  return connector_
      ->SDF_ExternalVerify_ECC(getSessionHandle(), uiAlgID, pucPublicKey, pucDataInput, uiInputLength,
                               pucSignature);
}

int SessionImpl::SDF_InternalSign_ECC(unsigned int uiISKIndex,
                                      unsigned char *pucData,
                                      unsigned int uiDataLength,
                                      ECCSignature *pucSignature) const {
  return connector_->SDF_InternalSign_ECC(getSessionHandle(), uiISKIndex, pucData, uiDataLength, pucSignature);
}

int SessionImpl::SDF_InternalVerify_ECC(unsigned int uiIPKIndex,
                                        unsigned char *pucData,
                                        unsigned int uiDataLength,
                                        ECCSignature *pucSignature) const {
  return connector_->SDF_InternalVerify_ECC(getSessionHandle(), uiIPKIndex, pucData, uiDataLength, pucSignature);
}

int SessionImpl::SDF_ExternalEncrypt_ECC(unsigned int uiAlgID,
                                         ECCrefPublicKey *pucPublicKey,
                                         unsigned char *pucData,
                                         unsigned int uiDataLength,
                                         ECCCipher *pucEncData) const {
  return connector_
      ->SDF_ExternalEncrypt_ECC(getSessionHandle(), uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
}

int SessionImpl::SDF_ExternalDecrypt_ECC(unsigned int uiAlgID,
                                         ECCrefPrivateKey *pucPrivateKey,
                                         ECCCipher *pucEncData,
                                         unsigned char *pucData,
                                         unsigned int *puiDataLength) const {
  return connector_
      ->SDF_ExternalDecrypt_ECC(getSessionHandle(), uiAlgID, pucPrivateKey, pucEncData, pucData, puiDataLength);
}

int SessionImpl::SDF_Encrypt(void *hKeyHandle,
                             unsigned int uiAlgID,
                             unsigned char *pucIV,
                             unsigned char *pucData,
                             unsigned int uiDataLength,
                             unsigned char *pucEncData,
                             unsigned int *puiEncDataLength) const {
  return connector_->SDF_Encrypt(getSessionHandle(),
                                 hKeyHandle,
                                 uiAlgID,
                                 pucIV,
                                 pucData,
                                 uiDataLength,
                                 pucEncData,
                                 puiEncDataLength);
}

int SessionImpl::SDF_Decrypt(void *hKeyHandle,
                             unsigned int uiAlgID,
                             unsigned char *pucIV,
                             unsigned char *pucEncData,
                             unsigned int uiEncDataLength,
                             unsigned char *pucData,
                             unsigned int *puiDataLength) const {
  return connector_->SDF_Decrypt(getSessionHandle(),
                                 hKeyHandle,
                                 uiAlgID,
                                 pucIV,
                                 pucEncData,
                                 uiEncDataLength,
                                 pucData,
                                 puiDataLength);
}

int SessionImpl::SDF_CalculateMAC(void *hKeyHandle,
                                  unsigned int uiAlgID,
                                  unsigned char *pucIV,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  unsigned char *pucMAC,
                                  unsigned int *puiMACLength) const {
  return connector_->SDF_CalculateMAC(getSessionHandle(),
                                      hKeyHandle,
                                      uiAlgID,
                                      pucIV,
                                      pucData,
                                      uiDataLength,
                                      pucMAC,
                                      puiMACLength);
}

int SessionImpl::SDF_HashInit(unsigned int uiAlgID,
                              ECCrefPublicKey *pucPublicKey,
                              unsigned char *pucID,
                              unsigned int uiIDLength) const {
  return connector_->SDF_HashInit(getSessionHandle(), uiAlgID, pucPublicKey, pucID, uiIDLength);
}

int SessionImpl::SDF_HashUpdate(unsigned char *pucData, unsigned int uiDataLength) const {
  return connector_->SDF_HashUpdate(getSessionHandle(), pucData, uiDataLength);
}

int SessionImpl::SDF_HashFinal(unsigned char *pucHash, unsigned int *puiHashLength) const {
  return connector_->SDF_HashFinal(getSessionHandle(), pucHash, puiHashLength);
}

int SessionImpl::SDF_CreateFile(unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize) const {
  return connector_->SDF_CreateFile(getSessionHandle(), pucFileName, uiNameLen, uiFileSize);
}

int SessionImpl::SDF_ReadFile(unsigned char *pucFileName,
                              unsigned int uiNameLen,
                              unsigned int uiOffset,
                              unsigned int *puiFileLength,
                              unsigned char *pucBuffer) const {
  return connector_
      ->SDF_ReadFile(getSessionHandle(), pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
}

int SessionImpl::SDF_WriteFile(unsigned char *pucFileName,
                               unsigned int uiNameLen,
                               unsigned int uiOffset,
                               unsigned int uiFileLength,
                               unsigned char *pucBuffer) const {
  return connector_
      ->SDF_WriteFile(getSessionHandle(), pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
}

int SessionImpl::SDF_DeleteFile(unsigned char *pucFileName, unsigned int uiNameLen) const {
  return connector_->SDF_DeleteFile(getSessionHandle(), pucFileName, uiNameLen);
}

int SessionImpl::SVS_ExportCert(const char *certId, uint8_t *certData, uint32_t *certDataLen) const {
  return connector_->SVS_ExportCert(getSessionHandle(), certId, certData, certDataLen);
}

int SessionImpl::SVS_ParseCert(int certType,
                               const uint8_t *certData,
                               uint32_t certDataLen,
                               uint8_t *certInfo,
                               uint32_t *certInfoLen) const {
  return connector_->SVS_ParseCert(getSessionHandle(), certType, certData, certDataLen, certInfo, certInfoLen);
}

int SessionImpl::SVS_ValidateCert(const uint8_t *certData, uint32_t certDataLen, bool ocsp, int *state) const {
  return connector_->SVS_ValidateCert(getSessionHandle(), certData, certDataLen, ocsp, state);
}

int SessionImpl::SVS_SignData(int method,
                              uint32_t signPrivateKeyIndex,
                              const char *password,
                              const uint8_t *data,
                              uint32_t dataLen,
                              uint8_t *signData,
                              uint32_t *signDataLen) const {
  return connector_->SVS_SignData(getSessionHandle(), method, signPrivateKeyIndex, password, data, dataLen,
                                  signData, signDataLen);
}

int SessionImpl::SVS_VerifySignedData(int type,
                                      const uint8_t *certData,
                                      uint32_t certDataLen,
                                      const uint8_t *data,
                                      uint32_t dataLen,
                                      const uint8_t *signData,
                                      uint32_t signDataLen,
                                      int verifyLevel) const {
  return connector_->SVS_VerifySignedData(getSessionHandle(), type, certData, certDataLen, data, dataLen,
                                          signData, signDataLen, verifyLevel);
}

int SessionImpl::SVS_SignDataInit(int method,
                                  const uint8_t *data,
                                  uint32_t dataLen,
                                  uint8_t *hashData,
                                  uint32_t *hashDataLen) const {
  return connector_->SVS_SignDataInit(getSessionHandle(), method, data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_SignDataUpdate(int method,
                                    const uint8_t *hashMediantData,
                                    uint32_t hashMediantDataLen,
                                    const uint8_t *data,
                                    uint32_t dataLen,
                                    uint8_t *hashData,
                                    uint32_t *hashDataLen) const {
  return connector_->SVS_SignDataUpdate(getSessionHandle(), method, hashMediantData, hashMediantDataLen,
                                        data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_SignDataFinal(int method,
                                   uint32_t signPrivateKeyIndex,
                                   const char *password,
                                   const uint8_t *hashMediantData,
                                   uint32_t hashMediantDataLen,
                                   uint8_t *signData,
                                   uint32_t *signDataLen) const {
  return connector_->SVS_SignDataFinal(getSessionHandle(), method, signPrivateKeyIndex, password,
                                       hashMediantData, hashMediantDataLen, signData, signDataLen);
}

int SessionImpl::SVS_VerifySignedDataInit(int method,
                                          const uint8_t *data,
                                          uint32_t dataLen,
                                          uint8_t *hashData,
                                          uint32_t *hashDataLen) const {
  return connector_->SVS_VerifySignedDataInit(getSessionHandle(), method, data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_VerifySignedDataUpdate(int method,
                                            const uint8_t *hashMediantData,
                                            uint32_t hashMediantDataLen,
                                            const uint8_t *data,
                                            uint32_t dataLen,
                                            uint8_t *hashData,
                                            uint32_t *hashDataLen) const {
  return connector_->SVS_VerifySignedDataUpdate(getSessionHandle(), method, hashMediantData, hashMediantDataLen,
                                                data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_VerifySignedDataFinal(int method,
                                           int type,
                                           const uint8_t *certData,
                                           uint32_t certDataLen,
                                           const uint8_t *hashMediantData,
                                           uint32_t hashMediantDataLen,
                                           const uint8_t *signData,
                                           uint32_t signDataLen,
                                           int verifyLevel) const {
  return connector_->SVS_VerifySignedDataFinal(getSessionHandle(),
                                               method,
                                               type,
                                               certData,
                                               certDataLen,
                                               hashMediantData,
                                               hashMediantDataLen,
                                               signData,
                                               signDataLen,
                                               verifyLevel);
}

int SessionImpl::SVS_SignMessage(int method,
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
  return connector_->SVS_SignMessage(getSessionHandle(),
                                     method,
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

int SessionImpl::SVS_VerifySignedMessage(const uint8_t *data,
                                         uint32_t dataLen,
                                         const uint8_t *signData,
                                         uint32_t signDataLen,
                                         bool isHashFlag,
                                         bool isOriginalText,
                                         bool isCertificateChain,
                                         bool isCrl,
                                         bool sAuthenticationAttributes) const {
  return connector_->SVS_VerifySignedMessage(getSessionHandle(),
                                             data,
                                             dataLen,
                                             signData,
                                             signDataLen,
                                             isHashFlag,
                                             isOriginalText,
                                             isCertificateChain,
                                             isCrl,
                                             sAuthenticationAttributes);
}

int SessionImpl::SVS_SignMessageInit(int method,
                                     const uint8_t *data,
                                     uint32_t dataLen,
                                     uint8_t *hashData,
                                     uint32_t *hashDataLen) const {
  return connector_->SVS_SignMessageInit(getSessionHandle(), method, data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_SignMessageUpdate(int method,
                                       const uint8_t *hashMediantData,
                                       uint32_t hashMediantDataLen,
                                       const uint8_t *data,
                                       uint32_t dataLen,
                                       uint8_t *hashData,
                                       uint32_t *hashDataLen) const {
  return connector_->SVS_SignMessageUpdate(getSessionHandle(), method, hashMediantData,
                                           hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_SignMessageFinal(int method,
                                      uint32_t signPrivateKeyIndex,
                                      const char *password,
                                      const uint8_t *hashMediantData,
                                      uint32_t hashMediantDataLen,
                                      uint8_t *signData,
                                      uint32_t *signDataLen) const {
  return connector_->SVS_SignMessageFinal(getSessionHandle(), method, signPrivateKeyIndex, password,
                                          hashMediantData, hashMediantDataLen, signData, signDataLen);
}

int SessionImpl::SVS_VerifySignedMessageInit(int method,
                                             const uint8_t *data,
                                             uint32_t dataLen,
                                             uint8_t *hashData,
                                             uint32_t *hashDataLen) const {
  return connector_->SVS_VerifySignedMessageInit(getSessionHandle(), method, data, dataLen, hashData,
                                                 hashDataLen);
}

int SessionImpl::SVS_VerifySignedMessageUpdate(int method,
                                               const uint8_t *hashMediantData,
                                               uint32_t hashMediantDataLen,
                                               const uint8_t *data,
                                               uint32_t dataLen,
                                               uint8_t *hashData,
                                               uint32_t *hashDataLen) const {
  return connector_->SVS_VerifySignedDataUpdate(getSessionHandle(), method, hashMediantData,
                                                hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int SessionImpl::SVS_VerifySignedMessageFinal(int method,
                                              const uint8_t *hashMediantData,
                                              uint32_t hashMediantDataLen,
                                              const uint8_t *signData,
                                              uint32_t signDataLen) const {
  return connector_->SVS_VerifySignedMessageFinal(getSessionHandle(), method, hashMediantData,
                                                  hashMediantDataLen, signData, signDataLen);
}

SGD_UINT32 SessionImpl::STF_CreateTSRequest(
    SGD_UINT8 *pucInData,
    SGD_UINT32 uiInDataLength,
    SGD_UINT32 uiReqType,
    SGD_UINT8 *pucTSExt,
    SGD_UINT32 uiTSExtLength,
    SGD_UINT32 uiHashAlgID,
    SGD_UINT8 *pucTSRequest,
    SGD_UINT32 *puiTSRequestLength) const {
  return connector_->STF_CreateTSRequest(
      getSessionHandle(),
      pucInData,
      uiInDataLength,
      uiReqType,
      pucTSExt,
      uiTSExtLength,
      uiHashAlgID,
      pucTSRequest,
      puiTSRequestLength);
}

SGD_UINT32 SessionImpl::STF_CreateTSResponse(
    SGD_UINT8 *pucTSRequest,
    SGD_UINT32 uiTSRequestLength,
    SGD_UINT32 uiSignatureAlgID,
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 *puiTSResponseLength) const {
  return connector_->STF_CreateTSResponse(
      getSessionHandle(),
      pucTSRequest,
      uiTSRequestLength,
      uiSignatureAlgID,
      pucTSResponse,
      puiTSResponseLength);
}

SGD_UINT32 SessionImpl::STF_VerifyTSValidity(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT32 uiHashAlgID,
    SGD_UINT32 uiSignatureAlgID,
    SGD_UINT8 *pucTSCert,
    SGD_UINT32 uiTSCertLength) const {
  return connector_->STF_VerifyTSValidity(
      getSessionHandle(),
      pucTSResponse,
      uiTSResponseLength,
      uiHashAlgID,
      uiSignatureAlgID,
      pucTSCert,
      uiTSCertLength);
}

SGD_UINT32 SessionImpl::STF_GetTSInfo(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT8 *pucIssuerName,
    SGD_UINT32 *puiIssuerNameLength,
    SGD_UINT8 *pucTime,
    SGD_UINT32 *puiTimeLength) const {
  return connector_->STF_GetTSInfo(
      getSessionHandle(),
      pucTSResponse,
      uiTSResponseLength,
      pucIssuerName,
      puiIssuerNameLength,
      pucTime,
      puiTimeLength);
}

SGD_UINT32 SessionImpl::STF_GetTSDetail(
    SGD_UINT8 *pucTSResponse,
    SGD_UINT32 uiTSResponseLength,
    SGD_UINT32 uiItemNumber,
    SGD_UINT8 *pucItemValue,
    SGD_UINT32 *puiItemValueLength) const {
  return connector_->STF_GetTSDetail(
      getSessionHandle(),
      pucTSResponse,
      uiTSResponseLength,
      uiItemNumber,
      pucItemValue,
      puiItemValueLength);
}

}
