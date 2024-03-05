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

#include "hsmc/session.h"

#include <utility>

#include "utils/uuid.h"

namespace hsmc {

Session::Session(SessionImpl::Ptr impl) : pImpl_(std::move(impl)) {
}

Session::Session(const Session &other) = default;

Session::Session(Session &&other) noexcept: pImpl_(std::move(other.pImpl_)) {
}

Session &Session::operator=(Session &&other) noexcept {
  pImpl_ = std::move(other.pImpl_);
  return *this;
}

Session::~Session() = default;

void Session::open() {
  pImpl_->open();
}

void Session::close() {
  pImpl_->close();
}

bool Session::isGood() const {
  return pImpl_->isGood();
}

void *Session::getSessionHandle() const {
  return pImpl_->getSessionHandle();
}

std::string Session::getId() const {
  return pImpl_->getId();
}

std::string Session::getConnectorName() const {
  return pImpl_->getConnector()->getName();
}

SessionImpl::Ptr Session::impl() {
  return pImpl_;
}

int Session::SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo) const {
  return pImpl_->SDF_GetDeviceInfo(pstDeviceInfo);
}

int Session::SDF_GenerateRandom(unsigned int uiLength, unsigned char *pucRandom) const {
  return pImpl_->SDF_GenerateRandom(uiLength, pucRandom);
}

int Session::SDF_GetPrivateKeyAccessRight(unsigned int uiKeyIndex, unsigned char *pucPassword,
                                          unsigned int uiPwdLength) const {
  return pImpl_->SDF_GetPrivateKeyAccessRight(uiKeyIndex, pucPassword, uiPwdLength);
}

int Session::SDF_ReleasePrivateKeyAccessRight(unsigned int uiKeyIndex) const {
  return pImpl_->SDF_ReleasePrivateKeyAccessRight(uiKeyIndex);
}

int Session::SDF_ExportSignPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const {
  return pImpl_->SDF_ExportSignPublicKey_RSA(uiKeyIndex, pucPublicKey);
}

int Session::SDF_ExportEncPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const {
  return pImpl_->SDF_ExportEncPublicKey_RSA(uiKeyIndex, pucPublicKey);
}

int Session::SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                     RSArefPrivateKey *pucPrivateKey) const {
  return pImpl_->SDF_GenerateKeyPair_RSA(uiKeyBits, pucPublicKey, pucPrivateKey);
}

int Session::SDF_GenerateKeyWithIPK_RSA(unsigned int uiIPKIndex, unsigned int uiKeyBits, unsigned char *pucKey,
                                        unsigned int *puiKeyLength, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithIPK_RSA(uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
}

int Session::SDF_GenerateKeyWithEPK_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pucKey,
                                        unsigned int *puiKeyLength, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithEPK_RSA(uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
}

int Session::SDF_ImportKeyWithISK_RSA(unsigned int uiISKIndex, unsigned char *pucKey, unsigned int uiKeyLength,
                                      void **phKeyHandle) const {
  return pImpl_->SDF_ImportKeyWithISK_RSA(uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int Session::SDF_ExchangeDigitEnvelopeBaseOnRSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
                                                unsigned char *pucDEInput, unsigned int uiDELength,
                                                unsigned char *pucDEOutput, unsigned int *puiDELength) const {
  return pImpl_->SDF_ExchangeDigitEnvelopeBaseOnRSA(uiKeyIndex, pucPublicKey, pucDEInput, uiDELength, pucDEOutput,
                                                    puiDELength);
}

int Session::SDF_ExportSignPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return pImpl_->SDF_ExportSignPublicKey_ECC(uiKeyIndex, pucPublicKey);
}

int Session::SDF_ExportEncPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const {
  return pImpl_->SDF_ExportEncPublicKey_ECC(uiKeyIndex, pucPublicKey);
}

int Session::SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey,
                                     ECCrefPrivateKey *pucPrivateKey) const {
  return pImpl_->SDF_GenerateKeyPair_ECC(uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
}

int Session::SDF_GenerateKeyWithIPK_ECC(unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey,
                                        void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithIPK_ECC(uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
}

int Session::SDF_GenerateKeyWithEPK_ECC(unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                        ECCCipher *pucKey, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithEPK_ECC(uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
}

int Session::SDF_ImportKeyWithISK_ECC(unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const {
  return pImpl_->SDF_ImportKeyWithISK_ECC(uiISKIndex, pucKey, phKeyHandle);
}

int Session::SDF_GenerateAgreementDataWithECC(unsigned int uiISKIndex, unsigned int uiKeyBits,
                                              unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                              ECCrefPublicKey *pucSponsorPublicKey,
                                              ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle) const {
  return pImpl_->SDF_GenerateAgreementDataWithECC(uiISKIndex, uiKeyBits, pucSponsorID, uiSponsorIDLength,
                                                  pucSponsorPublicKey, pucSponsorTmpPublicKey, phAgreementHandle);
}

int Session::SDF_GenerateKeyWithECC(unsigned char *pucResponseID, unsigned int uiResponseIDLength,
                                    ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
                                    void *hAgreementHandle, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithECC(pucResponseID, uiResponseIDLength, pucResponsePublicKey,
                                        pucResponseTmpPublicKey, hAgreementHandle, phKeyHandle);
}

int Session::SDF_GenerateAgreementDataAndKeyWithECC(
    unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateAgreementDataAndKeyWithECC(
      uiISKIndex, uiKeyBits, pucResponseID, uiResponseIDLength, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey,
      pucSponsorTmpPublicKey, pucResponsePublicKey, pucResponseTmpPublicKey, phKeyHandle);
}

int Session::SDF_ExchangeDigitEnvelopeBaseOnECC(unsigned int uiKeyIndex, unsigned int uiAlgID,
                                                ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
                                                ECCCipher *pucEncDataOut) const {
  return pImpl_->SDF_ExchangeDigitEnvelopeBaseOnECC(uiKeyIndex, uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
}

int Session::SDF_GenerateKeyWithKEK(unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
                                    unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const {
  return pImpl_->SDF_GenerateKeyWithKEK(uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
}

int Session::SDF_ImportKeyWithKEK(unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
                                  unsigned int uiKeyLength, void **phKeyHandle) const {
  return pImpl_->SDF_ImportKeyWithKEK(uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int Session::SDF_ImportKey(unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const {
  return pImpl_->SDF_ImportKey(pucKey, uiKeyLength, phKeyHandle);
}

int Session::SDF_DestroyKey(void *hKeyHandle) const {
  return pImpl_->SDF_DestroyKey(hKeyHandle);
}

int Session::SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
                                                unsigned int uiInputLength, unsigned char *pucDataOutput,
                                                unsigned int *puiOutputLength) const {
  return pImpl_->SDF_ExternalPublicKeyOperation_RSA(pucPublicKey, pucDataInput, uiInputLength, pucDataOutput,
                                                    puiOutputLength);
}

int Session::SDF_InternalPublicKeyOperation_RSA(unsigned int uiKeyIndex, unsigned char *pucDataInput,
                                                unsigned int uiInputLength, unsigned char *pucDataOutput,
                                                unsigned int *puiOutputLength) const {
  return pImpl_->SDF_InternalPublicKeyOperation_RSA(uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput,
                                                    puiOutputLength);
}

int Session::SDF_InternalPrivateKeyOperation_RSA(unsigned int uiKeyIndex, unsigned char *pucDataInput,
                                                 unsigned int uiInputLength, unsigned char *pucDataOutput,
                                                 unsigned int *puiOutputLength) const {
  return pImpl_->SDF_InternalPrivateKeyOperation_RSA(uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput,
                                                     puiOutputLength);
}

int Session::SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
                                                 unsigned int uiInputLength, unsigned char *pucDataOutput,
                                                 unsigned int *puiOutputLength) const {
  return pImpl_->SDF_ExternalPrivateKeyOperation_RSA(pucPrivateKey, pucDataInput, uiInputLength, pucDataOutput,
                                                     puiOutputLength);
}

int Session::SDF_ExternalSign_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucData,
                                  unsigned int uiDataLength, ECCSignature *pucSignature) const {
  return pImpl_->SDF_ExternalSign_ECC(uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
}

int Session::SDF_ExternalVerify_ECC(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucDataInput,
                                    unsigned int uiInputLength, ECCSignature *pucSignature) const {
  return pImpl_->SDF_ExternalVerify_ECC(uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature);
}

int Session::SDF_InternalSign_ECC(unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
                                  ECCSignature *pucSignature) const {
  return pImpl_->SDF_InternalSign_ECC(uiISKIndex, pucData, uiDataLength, pucSignature);
}

int Session::SDF_InternalVerify_ECC(unsigned int uiIPKIndex, unsigned char *pucData, unsigned int uiDataLength,
                                    ECCSignature *pucSignature) const {
  return pImpl_->SDF_InternalVerify_ECC(uiIPKIndex, pucData, uiDataLength, pucSignature);
}

int Session::SDF_ExternalEncrypt_ECC(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucData,
                                     unsigned int uiDataLength, ECCCipher *pucEncData) const {
  return pImpl_->SDF_ExternalEncrypt_ECC(uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
}

int Session::SDF_ExternalDecrypt_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData,
                                     unsigned char *pucData, unsigned int *puiDataLength) const {
  return pImpl_->SDF_ExternalDecrypt_ECC(uiAlgID, pucPrivateKey, pucEncData, pucData, puiDataLength);
}

int Session::SDF_Encrypt(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
                         unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) const {
  return pImpl_->SDF_Encrypt(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength);
}

int Session::SDF_Decrypt(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
                         unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) const {
  return pImpl_->SDF_Decrypt(hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int Session::SDF_CalculateMAC(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
                              unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength) const {
  return pImpl_->SDF_CalculateMAC(hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMACLength);
}

int Session::SDF_HashInit(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID,
                          unsigned int uiIDLength) const {
  return pImpl_->SDF_HashInit(uiAlgID, pucPublicKey, pucID, uiIDLength);
}

int Session::SDF_HashUpdate(unsigned char *pucData, unsigned int uiDataLength) const {
  return pImpl_->SDF_HashUpdate(pucData, uiDataLength);
}

int Session::SDF_HashFinal(unsigned char *pucHash, unsigned int *puiHashLength) const {
  return pImpl_->SDF_HashFinal(pucHash, puiHashLength);
}

int Session::SDF_CreateFile(unsigned char *pucFileName, unsigned int uiNameLen, /* max 128-byte */
                            unsigned int uiFileSize) const {
  return pImpl_->SDF_CreateFile(pucFileName, uiNameLen, uiFileSize);
}

int Session::SDF_ReadFile(unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
                          unsigned int *puiFileLength, unsigned char *pucBuffer) const {
  return pImpl_->SDF_ReadFile(pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
}

int Session::SDF_WriteFile(unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
                           unsigned int uiFileLength, unsigned char *pucBuffer) const {
  return pImpl_->SDF_WriteFile(pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
}

int Session::SDF_DeleteFile(unsigned char *pucFileName, unsigned int uiNameLen) const {
  return pImpl_->SDF_DeleteFile(pucFileName, uiNameLen);
}

int Session::SVS_ExportCert(const char *certId, uint8_t *certData, uint32_t *certDataLen) const {
  return pImpl_->SVS_ExportCert(certId, certData, certDataLen);
}

int Session::SVS_ParseCert(int certType, const uint8_t *certData, uint32_t certDataLen, uint8_t *certInfo,
                           uint32_t *certInfoLen) const {
  return pImpl_->SVS_ParseCert(certType, certData, certDataLen, certInfo, certInfoLen);
}

int Session::SVS_ValidateCert(const uint8_t *certData, uint32_t certDataLen, bool ocsp, int *state) const {
  return pImpl_->SVS_ValidateCert(certData, certDataLen, ocsp, state);
}

int Session::SVS_SignData(int method, uint32_t signPrivateKeyIndex, const char *password, const uint8_t *data,
                          uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen) const {
  return pImpl_->SVS_SignData(method, signPrivateKeyIndex, password, data, dataLen, signData, signDataLen);
}

int Session::SVS_VerifySignedData(int type, const uint8_t *certData, uint32_t certDataLen, const uint8_t *data,
                                  uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen,
                                  int verifyLevel) const {
  return pImpl_->SVS_VerifySignedData(type, certData, certDataLen, data, dataLen, signData, signDataLen, verifyLevel);
}

int Session::SVS_SignDataInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                              uint32_t *hashDataLen) const {
  return pImpl_->SVS_SignDataInit(method, data, dataLen, hashData, hashDataLen);
}

int Session::SVS_SignDataUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                const uint8_t *data, uint32_t dataLen, uint8_t *hashData, uint32_t *hashDataLen) const {
  return pImpl_->SVS_SignDataUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData, hashDataLen);
}

int Session::SVS_SignDataFinal(int method, uint32_t signPrivateKeyIndex, const char *password,
                               const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                               uint32_t *signDataLen) const {
  return pImpl_->SVS_SignDataFinal(method, signPrivateKeyIndex, password, hashMediantData, hashMediantDataLen, signData,
                                   signDataLen);
}

int Session::SVS_VerifySignedDataInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                      uint32_t *hashDataLen) const {
  return pImpl_->SVS_VerifySignedDataInit(method, data, dataLen, hashData, hashDataLen);
}

int Session::SVS_VerifySignedDataUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                        const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                        uint32_t *hashDataLen) const {
  return pImpl_->SVS_VerifySignedDataUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData,
                                            hashDataLen);
}

int Session::SVS_VerifySignedDataFinal(int method, int type, const uint8_t *certData, uint32_t certDataLen,
                                       const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                       const uint8_t *signData, uint32_t signDataLen, int verifyLevel) const {
  return pImpl_->SVS_VerifySignedDataFinal(method, type, certData, certDataLen, hashMediantData, hashMediantDataLen,
                                           signData, signDataLen, verifyLevel);
}

int Session::SVS_SignMessage(int method, uint32_t signPrivateKeyIndex, const char *password, const uint8_t *data,
                             uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen, bool isHashFlag,
                             bool isOriginalText, bool isCertificateChain, bool isCrl,
                             bool isAuthenticationAttributes) const {
  return pImpl_->SVS_SignMessage(method, signPrivateKeyIndex, password, data, dataLen, signData, signDataLen,
                                 isHashFlag, isOriginalText, isCertificateChain, isCrl, isAuthenticationAttributes);
}

int Session::SVS_VerifySignedMessage(const uint8_t *data, uint32_t dataLen, const uint8_t *signData,
                                     uint32_t signDataLen, bool isHashFlag, bool isOriginalText,
                                     bool isCertificateChain, bool isCrl, bool isAuthenticationAttributes) const {
  return pImpl_->SVS_VerifySignedMessage(data, dataLen, signData, signDataLen, isHashFlag, isOriginalText,
                                         isCertificateChain, isCrl, isAuthenticationAttributes);
}

int Session::SVS_SignMessageInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                 uint32_t *hashDataLen) const {
  return pImpl_->SVS_SignMessageInit(method, data, dataLen, hashData, hashDataLen);
}

int Session::SVS_SignMessageUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                   const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                   uint32_t *hashDataLen) const {
  return pImpl_->SVS_SignMessageUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData,
                                       hashDataLen);
}

int Session::SVS_SignMessageFinal(int method, uint32_t signPrivateKeyIndex, const char *password,
                                  const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                                  uint32_t *signDataLen) const {
  return pImpl_->SVS_SignMessageFinal(method, signPrivateKeyIndex, password, hashMediantData, hashMediantDataLen,
                                      signData, signDataLen);
}

int Session::SVS_VerifySignedMessageInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                         uint32_t *hashDataLen) const {
  return pImpl_->SVS_VerifySignedMessageInit(method, data, dataLen, hashData, hashDataLen);
}

int Session::SVS_VerifySignedMessageUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                           const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                           uint32_t *hashDataLen) const {
  return pImpl_->SVS_VerifySignedMessageUpdate(method, hashMediantData, hashMediantDataLen, data, dataLen, hashData,
                                               hashDataLen);
}

int Session::SVS_VerifySignedMessageFinal(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                          const uint8_t *signData, uint32_t signDataLen) const {
  return pImpl_->SVS_VerifySignedMessageFinal(method, hashMediantData, hashMediantDataLen, signData, signDataLen);
}

SGD_UINT32 Session::STF_CreateTSRequest(SGD_UINT8 *pucInData, SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                                        SGD_UINT8 *pucTSExt, SGD_UINT32 uiTSExtLength, SGD_UINT32 uiHashAlgID,
                                        SGD_UINT8 *pucTSRequest, SGD_UINT32 *puiTSRequestLength) const {
  return pImpl_->STF_CreateTSRequest(pucInData, uiInDataLength, uiReqType, pucTSExt, uiTSExtLength, uiHashAlgID,
                                     pucTSRequest, puiTSRequestLength);
}

SGD_UINT32 Session::STF_CreateTSResponse(SGD_UINT8 *pucTSRequest, SGD_UINT32 uiTSRequestLength,
                                         SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSResponse,
                                         SGD_UINT32 *puiTSResponseLength) const {
  return pImpl_->STF_CreateTSResponse(pucTSRequest, uiTSRequestLength, uiSignatureAlgID, pucTSResponse,
                                      puiTSResponseLength);
}

SGD_UINT32 Session::STF_VerifyTSValidity(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                                         SGD_UINT32 uiHashAlgID, SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSCert,
                                         SGD_UINT32 uiTSCertLength) const {
  return pImpl_->STF_VerifyTSValidity(pucTSResponse, uiTSResponseLength, uiHashAlgID, uiSignatureAlgID, pucTSCert,
                                      uiTSCertLength);
}

SGD_UINT32 Session::STF_GetTSInfo(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength, SGD_UINT8 *pucIssuerName,
                                  SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                                  SGD_UINT32 *puiTimeLength) const {
  return pImpl_->STF_GetTSInfo(pucTSResponse, uiTSResponseLength, pucIssuerName, puiIssuerNameLength, pucTime,
                               puiTimeLength);
}

SGD_UINT32 Session::STF_GetTSDetail(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength, SGD_UINT32 uiItemNumber,
                                    SGD_UINT8 *pucItemValue, SGD_UINT32 *puiItemValueLength) const {
  return pImpl_->STF_GetTSDetail(pucTSResponse, uiTSResponseLength, uiItemNumber, pucItemValue, puiItemValueLength);
}
}  // namespace hsmc
