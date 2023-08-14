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

#include "hsmc/connector.h"

#include <absl/strings/str_format.h>

#include <iostream>
#include <unordered_map>

#ifdef ENABLE_OPENTELEMETRY_API
#include <opentelemetry/metrics/provider.h>
#endif

#include "version.h"

namespace hsmc {

// default weight is 10
static const uint16_t DEFAULT_WEIGHT = 10;

Connector::Connector(const std::string &nativeLibPath)
    : nativeLibPath_(nativeLibPath),
      hNativeLib_(nullptr),
      pooling_(true),
      connType_(ConnectorType::CT_HSM),
      port_(0),
      sdf_(),
      stf_(),
      pcie_(false),
      heartbeat_interval_(0),
      idle_timeout_(0),
      weight_(DEFAULT_WEIGHT) {
}

Connector::Connector() : Connector("") {
}

Connector::~Connector() = default;

void Connector::open() {
  if (hNativeLib_ != nullptr) return;

  // 加载动态库
  hNativeLib_ = dlopen(nativeLibPath_.c_str(), RTLD_LAZY);

  if (!hNativeLib_) {
    const char *dlsym_error = dlerror();
    throw LibraryLoadException(absl::StrFormat("fail to load library: %s, %s", this->nativeLibPath_.c_str(),
                                               dlsym_error ? dlsym_error : "unknown error"));
  }

  // reset errors
  dlerror();

  if (connType_ == ConnectorType::CT_HSM) {
    resolveSdfFuncs();
  } else if (connType_ == ConnectorType::CT_SVS) {
    resolveSvsFuncs();
  } else if (connType_ == ConnectorType::CT_TSS) {
    resolveStfFuncs();
  }

  // 初始化metric
#ifdef ENABLE_OPENTELEMETRY_API
  auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
  auto version = absl::StrFormat("%d.%d.%d", hsmc_VERSION_MAJOR, hsmc_VERSION_MINOR, hsmc_VERSION_PATCH);
  opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter =
      provider->GetMeter("hsmc", version);

  // create counter
  counter = meter->CreateUInt64Counter("sdf_invoked_counter", "SDF invoked counter");

  // create histogram
  histogram = meter->CreateUInt64Histogram("sdf_invoked_latency", "SDF invoked latency", "us");
#endif
}

void Connector::close() {
  if (this->hNativeLib_ != nullptr) {
    dlclose(this->hNativeLib_);
    this->hNativeLib_ = nullptr;
  }
}

void Connector::recover() {
  // 根据厂商的设备情况需要实现recover逻辑
  // 目前仅有九维数安密码机需要实现该逻辑
}

void Connector::enter(const std::string& fn) {
}

void Connector::leave(const std::string& fn, int result) {
#ifdef ENABLE_OPENTELEMETRY_API
  if (counter) {
    std::unordered_map<std::string, std::string> labels = {
        {"node", name_}, {"method", fn}, {"result", result == 0 ? "success" : "failure"}};
    counter->Add(1, labels);
  }
#endif
}

void Connector::elapsed(const std::string& fn, uint64_t macroseconds) {
#ifdef ENABLE_OPENTELEMETRY_API
  if (histogram) {
    auto context = opentelemetry::context::Context{};
    std::unordered_map<std::string, std::string> labels = {{"node", name_}, {"method", fn}};
    histogram->Record(macroseconds, labels, context);
  }
#endif
}

void Connector::resolveSdfFuncs() {
  sdf_.SDF_OpenDevice_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_OpenDevice);
  sdf_.SDF_CloseDevice_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_CloseDevice);
  sdf_.SDF_OpenSession_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_OpenSession);
  sdf_.SDF_CloseSession_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_CloseSession);
  sdf_.SDF_GetDeviceInfo_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GetDeviceInfo);
  sdf_.SDF_GenerateRandom_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateRandom);
  sdf_.SDF_GetPrivateKeyAccessRight_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GetPrivateKeyAccessRight);
  sdf_.SDF_ReleasePrivateKeyAccessRight_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ReleasePrivateKeyAccessRight);
  sdf_.SDF_ExportSignPublicKey_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExportSignPublicKey_RSA);
  sdf_.SDF_ExportEncPublicKey_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExportEncPublicKey_RSA);
  sdf_.SDF_GenerateKeyPair_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyPair_RSA);
  sdf_.SDF_GenerateKeyWithIPK_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithIPK_RSA);
  sdf_.SDF_GenerateKeyWithEPK_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithEPK_RSA);
  sdf_.SDF_ImportKeyWithISK_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ImportKeyWithISK_RSA);
  sdf_.SDF_ExchangeDigitEnvelopeBaseOnRSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExchangeDigitEnvelopeBaseOnRSA);
  sdf_.SDF_ExportSignPublicKey_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExportSignPublicKey_ECC);
  sdf_.SDF_ExportEncPublicKey_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExportEncPublicKey_ECC);
  sdf_.SDF_GenerateKeyPair_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyPair_ECC);
  sdf_.SDF_GenerateKeyWithIPK_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithIPK_ECC);
  sdf_.SDF_GenerateKeyWithEPK_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithEPK_ECC);
  sdf_.SDF_ImportKeyWithISK_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ImportKeyWithISK_ECC);
  sdf_.SDF_GenerateAgreementDataWithECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateAgreementDataWithECC);
  sdf_.SDF_GenerateKeyWithECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithECC);
  sdf_.SDF_GenerateAgreementDataAndKeyWithECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateAgreementDataAndKeyWithECC);
  sdf_.SDF_ExchangeDigitEnvelopeBaseOnECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExchangeDigitEnvelopeBaseOnECC);
  sdf_.SDF_GenerateKeyWithKEK_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_GenerateKeyWithKEK);
  sdf_.SDF_ImportKeyWithKEK_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ImportKeyWithKEK);
  sdf_.SDF_ImportKey_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ImportKey);
  sdf_.SDF_DestroyKey_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_DestroyKey);
  sdf_.SDF_ExternalPublicKeyOperation_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalPublicKeyOperation_RSA);
  sdf_.SDF_InternalPublicKeyOperation_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_InternalPublicKeyOperation_RSA);
  sdf_.SDF_InternalPrivateKeyOperation_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_InternalPrivateKeyOperation_RSA);
  sdf_.SDF_ExternalPrivateKeyOperation_RSA_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalPrivateKeyOperation_RSA);
  sdf_.SDF_ExternalSign_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalSign_ECC);
  sdf_.SDF_ExternalVerify_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalVerify_ECC);
  sdf_.SDF_InternalSign_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_InternalSign_ECC);
  sdf_.SDF_InternalVerify_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_InternalVerify_ECC);
  sdf_.SDF_ExternalEncrypt_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalEncrypt_ECC);
  sdf_.SDF_ExternalDecrypt_ECC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ExternalDecrypt_ECC);
  sdf_.SDF_Encrypt_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_Encrypt);
  sdf_.SDF_Decrypt_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_Decrypt);
  sdf_.SDF_CalculateMAC_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_CalculateMAC);
  sdf_.SDF_HashInit_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_HashInit);
  sdf_.SDF_HashUpdate_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_HashUpdate);
  sdf_.SDF_HashFinal_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_HashFinal);
  sdf_.SDF_CreateFile_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_CreateFile);
  sdf_.SDF_ReadFile_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_ReadFile);
  sdf_.SDF_WriteFile_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_WriteFile);
  sdf_.SDF_DeleteFile_ = INSTRUMENTED_FUNC_INITIALIZER(SDF_DeleteFile);
}

void Connector::resolveSvsFuncs() {
  char msg[256];
  std::string name = getName();
  snprintf(msg, sizeof(msg), "vendor %s must implement resolveSvsFuncs", name.c_str());
  throw SystemException(msg);
}

void Connector::resolveStfFuncs() {
  stf_.STF_InitEnvironment_ = FUNC_INITIALIZER(STF_InitEnvironment);
  stf_.STF_ClearEnvironment_ = FUNC_INITIALIZER(STF_ClearEnvironment);
  stf_.STF_CreateTSRequest_ = FUNC_INITIALIZER(STF_CreateTSRequest);
  stf_.STF_CreateTSResponse_ = FUNC_INITIALIZER(STF_CreateTSResponse);
  stf_.STF_VerifyTSValidity_ = FUNC_INITIALIZER(STF_VerifyTSValidity);
  stf_.STF_GetTSInfo_ = FUNC_INITIALIZER(STF_GetTSInfo);
  stf_.STF_GetTSDetail_ = FUNC_INITIALIZER(STF_GetTSDetail);
}

void Connector::setConfig(const std::string &configfile) {
  configFile_ = configfile;
}

void Connector::setLibrary(const std::string &library) {
  nativeLibPath_ = library;
}

std::string Connector::getConfig() const {
  return configFile_;
}

std::string Connector::getLibrary() const {
  return nativeLibPath_;
}

std::string Connector::getName() const {
  return name_;
}

void Connector::setName(const std::string &name) {
  name_ = name;
}

bool Connector::isPooling() const {
  return pooling_;
}

void Connector::setPooling(bool pooling) {
  pooling_ = pooling;
}

bool Connector::isPCIE() const {
  return pcie_;
}

void Connector::setPCIE(bool pcie) {
  pcie_ = pcie;
}

ConnectorType Connector::getConnectorType() const {
  return connType_;
}

void Connector::setConnectorType(ConnectorType conntype) {
  connType_ = conntype;
}

void Connector::SVS_SetIp(const std::string &ip) {
  ip_ = ip;
}

void Connector::SVS_SetPort(uint16_t port) {
  port_ = port;
}

void Connector::SVS_SetPassword(const std::string &password) {
  password_ = password;
}

int Connector::SVS_Open(void **p_handle) {
  return -1;
}

int Connector::SVS_Close(void *handle) {
  return -1;
}

int Connector::getWeight() {
  return weight_;
}

void Connector::setWeight(int weight) {
  weight_ = weight;
}

int Connector::getHeartbeatInterval() const {
  return heartbeat_interval_;
}

void Connector::setHeartbeatInterval(int interval) {
  heartbeat_interval_ = interval;
}

int Connector::getIdleTimeout() const {
  return idle_timeout_;
}

void Connector::setIdleTimeout(int timeout) {
  idle_timeout_ = timeout;
}

int Connector::SDF_OpenDevice(void **phDeviceHandle) {
  try {
    return sdf_.SDF_OpenDevice_(phDeviceHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_CloseDevice(void *hDeviceHandle) {
  try {
    return sdf_.SDF_CloseDevice_(hDeviceHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) {
  try {
    return sdf_.SDF_OpenSession_(hDeviceHandle, phSessionHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_CloseSession(void *hSessionHandle) {
  try {
    return sdf_.SDF_CloseSession_(hSessionHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo) const {
  try {
    return sdf_.SDF_GetDeviceInfo_(hSessionHandle, pstDeviceInfo);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom) const {
  try {
    return sdf_.SDF_GenerateRandom_(hSessionHandle, uiLength, pucRandom);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword,
                                            unsigned int uiPwdLength) const {
  try {
    return sdf_.SDF_GetPrivateKeyAccessRight_(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex) const {
  try {
    return sdf_.SDF_ReleasePrivateKeyAccessRight_(hSessionHandle, uiKeyIndex);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                           RSArefPublicKey *pucPublicKey) const {
  try {
    return sdf_.SDF_ExportSignPublicKey_RSA_(hSessionHandle, uiKeyIndex, pucPublicKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                          RSArefPublicKey *pucPublicKey) const {
  try {
    return sdf_.SDF_ExportEncPublicKey_RSA_(hSessionHandle, uiKeyIndex, pucPublicKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                       RSArefPrivateKey *pucPrivateKey) const {
  try {
    return sdf_.SDF_GenerateKeyPair_RSA_(hSessionHandle, uiKeyBits, pucPublicKey, pucPrivateKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
                                          unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithIPK_RSA_(hSessionHandle, uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                          unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithEPK_RSA_(hSessionHandle, uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey,
                                        unsigned int uiKeyLength, void **phKeyHandle) const {
  try {
    return sdf_.SDF_ImportKeyWithISK_RSA_(hSessionHandle, uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                  RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput,
                                                  unsigned int uiDELength, unsigned char *pucDEOutput,
                                                  unsigned int *puiDELength) const {
  try {
    return sdf_.SDF_ExchangeDigitEnvelopeBaseOnRSA_(hSessionHandle, uiKeyIndex, pucPublicKey, pucDEInput, uiDELength,
                                                    pucDEOutput, puiDELength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                           ECCrefPublicKey *pucPublicKey) const {
  try {
    return sdf_.SDF_ExportSignPublicKey_ECC_(hSessionHandle, uiKeyIndex, pucPublicKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                          ECCrefPublicKey *pucPublicKey) const {
  try {
    return sdf_.SDF_ExportEncPublicKey_ECC_(hSessionHandle, uiKeyIndex, pucPublicKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,
                                       ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) const {
  try {
    return sdf_.SDF_GenerateKeyPair_ECC_(hSessionHandle, uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
                                          ECCCipher *pucKey, void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithIPK_ECC_(hSessionHandle, uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
                                          ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithEPK_ECC_(hSessionHandle, uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey,
                                        void **phKeyHandle) const {
  try {
    return sdf_.SDF_ImportKeyWithISK_ECC_(hSessionHandle, uiISKIndex, pucKey, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
                                                unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                                ECCrefPublicKey *pucSponsorPublicKey,
                                                ECCrefPublicKey *pucSponsorTmpPublicKey,
                                                void **phAgreementHandle) const {
  try {
    return sdf_.SDF_GenerateAgreementDataWithECC_(hSessionHandle, uiISKIndex, uiKeyBits, pucSponsorID,
                                                  uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,
                                                  phAgreementHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID,
                                      unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
                                      ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle,
                                      void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithECC_(hSessionHandle, pucResponseID, uiResponseIDLength, pucResponsePublicKey,
                                        pucResponseTmpPublicKey, hAgreementHandle, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateAgreementDataAndKeyWithECC(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,
    unsigned int uiResponseIDLength, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
    ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateAgreementDataAndKeyWithECC_(
        hSessionHandle, uiISKIndex, uiKeyBits, pucResponseID, uiResponseIDLength, pucSponsorID, uiSponsorIDLength,
        pucSponsorPublicKey, pucSponsorTmpPublicKey, pucResponsePublicKey, pucResponseTmpPublicKey, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
                                                  ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
                                                  ECCCipher *pucEncDataOut) const {
  try {
    return sdf_.SDF_ExchangeDigitEnvelopeBaseOnECC_(hSessionHandle, uiKeyIndex, uiAlgID, pucPublicKey, pucEncDataIn,
                                                    pucEncDataOut);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
                                      unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int *puiKeyLength,
                                      void **phKeyHandle) const {
  try {
    return sdf_.SDF_GenerateKeyWithKEK_(hSessionHandle, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength,
                                        phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex,
                                    unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const {
  try {
    return sdf_.SDF_ImportKeyWithKEK_(hSessionHandle, uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength,
                             void **phKeyHandle) const {
  try {
    return sdf_.SDF_ImportKey_(hSessionHandle, pucKey, uiKeyLength, phKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle) const {
  try {
    return sdf_.SDF_DestroyKey_(hSessionHandle, hKeyHandle);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey,
                                                  unsigned char *pucDataInput, unsigned int uiInputLength,
                                                  unsigned char *pucDataOutput, unsigned int *puiOutputLength) const {
  try {
    return sdf_.SDF_ExternalPublicKeyOperation_RSA_(hSessionHandle, pucPublicKey, pucDataInput, uiInputLength,
                                                    pucDataOutput, puiOutputLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                  unsigned char *pucDataInput, unsigned int uiInputLength,
                                                  unsigned char *pucDataOutput, unsigned int *puiOutputLength) const {
  try {
    return sdf_.SDF_InternalPublicKeyOperation_RSA_(hSessionHandle, uiKeyIndex, pucDataInput, uiInputLength,
                                                    pucDataOutput, puiOutputLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                   unsigned char *pucDataInput, unsigned int uiInputLength,
                                                   unsigned char *pucDataOutput, unsigned int *puiOutputLength) const {
  try {
    return sdf_.SDF_InternalPrivateKeyOperation_RSA_(hSessionHandle, uiKeyIndex, pucDataInput, uiInputLength,
                                                     pucDataOutput, puiOutputLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey,
                                                   unsigned char *pucDataInput, unsigned int uiInputLength,
                                                   unsigned char *pucDataOutput, unsigned int *puiOutputLength) const {
  try {
    return sdf_.SDF_ExternalPrivateKeyOperation_RSA_(hSessionHandle, pucPrivateKey, pucDataInput, uiInputLength,
                                                     pucDataOutput, puiOutputLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                                    unsigned char *pucData, unsigned int uiDataLength,
                                    ECCSignature *pucSignature) const {
  try {
    return sdf_.SDF_ExternalSign_ECC_(hSessionHandle, uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                      unsigned char *pucDataInput, unsigned int uiInputLength,
                                      ECCSignature *pucSignature) const {
  try {
    return sdf_.SDF_ExternalVerify_ECC_(hSessionHandle, uiAlgID, pucPublicKey, pucDataInput, uiInputLength,
                                        pucSignature);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
                                    unsigned int uiDataLength, ECCSignature *pucSignature) const {
  try {
    return sdf_.SDF_InternalSign_ECC_(hSessionHandle, uiISKIndex, pucData, uiDataLength, pucSignature);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,
                                      unsigned int uiDataLength, ECCSignature *pucSignature) const {
  try {
    return sdf_.SDF_InternalVerify_ECC_(hSessionHandle, uiIPKIndex, pucData, uiDataLength, pucSignature);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                       unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData) const {
  try {
    return sdf_.SDF_ExternalEncrypt_ECC_(hSessionHandle, uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                                       ECCCipher *pucEncData, unsigned char *pucData,
                                       unsigned int *puiDataLength) const {
  try {
    return sdf_.SDF_ExternalDecrypt_ECC_(hSessionHandle, uiAlgID, pucPrivateKey, pucEncData, pucData, puiDataLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                           unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData,
                           unsigned int *puiEncDataLength) const {
  try {
    return sdf_.SDF_Encrypt_(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData,
                             puiEncDataLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                           unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData,
                           unsigned int *puiDataLength) const {
  try {
    return sdf_.SDF_Decrypt_(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData,
                             puiDataLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                                unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC,
                                unsigned int *puiMACLength) const {
  try {
    return sdf_.SDF_CalculateMAC_(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC,
                                  puiMACLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucID, unsigned int uiIDLength) const {
  try {
    return sdf_.SDF_HashInit_(hSessionHandle, uiAlgID, pucPublicKey, pucID, uiIDLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) const {
  try {
    return sdf_.SDF_HashUpdate_(hSessionHandle, pucData, uiDataLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength) const {
  try {
    return sdf_.SDF_HashFinal_(hSessionHandle, pucHash, puiHashLength);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName,
                              unsigned int uiNameLen, /* max 128-byte */
                              unsigned int uiFileSize) const {
  try {
    return sdf_.SDF_CreateFile_(hSessionHandle, pucFileName, uiNameLen, uiFileSize);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
                            unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer) const {
  try {
    return sdf_.SDF_ReadFile_(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
                             unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer) const {
  try {
    return sdf_.SDF_WriteFile_(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen) const {
  try {
    return sdf_.SDF_DeleteFile_(hSessionHandle, pucFileName, uiNameLen);
  } catch (...) {
    return SDR_NOTSUPPORT;
  }
}

int Connector::SVS_ExportCert(void *hSessionHandle, const char *certId, uint8_t *certData,
                              uint32_t *certDataLen) const {
  return -1;
}

int Connector::SVS_ParseCert(void *hSessionHandle, int certType, const uint8_t *certData, uint32_t certDataLen,
                             uint8_t *certInfo, uint32_t *certInfoLen) const {
  return -1;
}

int Connector::SVS_ValidateCert(void *hSessionHandle, const uint8_t *certData, uint32_t certDataLen, bool ocsp,
                                int *state) const {
  return -1;
}

int Connector::SVS_SignData(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                            const uint8_t *data, uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                                    const uint8_t *data, uint32_t dataLen, const uint8_t *signData,
                                    uint32_t signDataLen, int verifyLevel) const {
  return -1;
}

int Connector::SVS_SignDataInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_SignDataUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                  uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                  uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_SignDataFinal(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                                 const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                                 uint32_t *signDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedDataInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                        uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedDataUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                          uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                          uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedDataFinal(void *hSessionHandle, int method, int type, const uint8_t *certData,
                                         uint32_t certDataLen, const uint8_t *hashMediantData,
                                         uint32_t hashMediantDataLen, const uint8_t *signData, uint32_t signDataLen,
                                         int verifyLevel) const {
  return -1;
}

int Connector::SVS_SignMessage(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                               const uint8_t *data, uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen,
                               bool isHashFlag, bool isOriginalText, bool isCertificateChain, bool isCrl,
                               bool sAuthenticationAttributes) const {
  return -1;
}

int Connector::SVS_VerifySignedMessage(void *hSessionHandle, const uint8_t *data, uint32_t dataLen,
                                       const uint8_t *signData, uint32_t signDataLen, bool isHashFlag,
                                       bool isOriginalText, bool isCertificateChain, bool isCrl,
                                       bool sAuthenticationAttributes) const {
  return -1;
}

int Connector::SVS_SignMessageInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                   uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_SignMessageUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                     uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                     uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_SignMessageFinal(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex,
                                    const char *password, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                    uint8_t *signData, uint32_t *signDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedMessageInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                           uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedMessageUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                             uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                             uint8_t *hashData, uint32_t *hashDataLen) const {
  return -1;
}

int Connector::SVS_VerifySignedMessageFinal(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                            uint32_t hashMediantDataLen, const uint8_t *signData,
                                            uint32_t signDataLen) const {
  return -1;
}

SGD_UINT32 Connector::STF_InitEnvironment(void **phTSHandle) const {
  return stf_.STF_InitEnvironment_ ? stf_.STF_InitEnvironment_(phTSHandle) : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_ClearEnvironment(void *hTSHandle) const {
  return stf_.STF_ClearEnvironment_ ? stf_.STF_ClearEnvironment_(hTSHandle) : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_CreateTSRequest(void *hTSHandle, SGD_UINT8 *pucInData, SGD_UINT32 uiInDataLength,
                                          SGD_UINT32 uiReqType, SGD_UINT8 *pucTSExt, SGD_UINT32 uiTSExtLength,
                                          SGD_UINT32 uiHashAlgID, SGD_UINT8 *pucTSRequest,
                                          SGD_UINT32 *puiTSRequestLength) const {
  return stf_.STF_CreateTSRequest_
             ? stf_.STF_CreateTSRequest_(hTSHandle, pucInData, uiInDataLength, uiReqType, pucTSExt, uiTSExtLength,
                                         uiHashAlgID, pucTSRequest, puiTSRequestLength)
             : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_CreateTSResponse(void *hTSHandle, SGD_UINT8 *pucTSRequest, SGD_UINT32 uiTSRequestLength,
                                           SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSResponse,
                                           SGD_UINT32 *puiTSResponseLength) const {
  return stf_.STF_CreateTSResponse_ ? stf_.STF_CreateTSResponse_(hTSHandle, pucTSRequest, uiTSRequestLength,
                                                                 uiSignatureAlgID, pucTSResponse, puiTSResponseLength)
                                    : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_VerifyTSValidity(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                                           SGD_UINT32 uiHashAlgID, SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSCert,
                                           SGD_UINT32 uiTSCertLength) const {
  return stf_.STF_VerifyTSValidity_
             ? stf_.STF_VerifyTSValidity_(hTSHandle, pucTSResponse, uiTSResponseLength, uiHashAlgID, uiSignatureAlgID,
                                          pucTSCert, uiTSCertLength)
             : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_GetTSInfo(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                                    SGD_UINT8 *pucIssuerName, SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                                    SGD_UINT32 *puiTimeLength) const {
  return stf_.STF_GetTSInfo_ ? stf_.STF_GetTSInfo_(hTSHandle, pucTSResponse, uiTSResponseLength, pucIssuerName,
                                                   puiIssuerNameLength, pucTime, puiTimeLength)
                             : STF_TS_NOT_SUPPORT;
}

SGD_UINT32 Connector::STF_GetTSDetail(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                                      SGD_UINT32 uiItemNumber, SGD_UINT8 *pucItemValue,
                                      SGD_UINT32 *puiItemValueLength) const {
  return stf_.STF_GetTSDetail_ ? stf_.STF_GetTSDetail_(hTSHandle, pucTSResponse, uiTSResponseLength, uiItemNumber,
                                                       pucItemValue, puiItemValueLength)
                               : STF_TS_NOT_SUPPORT;
}

}  // namespace hsmc