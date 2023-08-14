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

#include "session_impl.h"

#include <absl/strings/str_format.h>

#include <utility>

#include "connector.h"
#include "utils/uuid.h"

namespace hsmc {
namespace dean {

SessionImpl::SessionImpl(hsmc::Connector::Ptr connector)
    : hsmc::SessionImpl(std::move(connector)), hSession_(nullptr) {
}

SessionImpl::~SessionImpl() = default;

void SessionImpl::open() {
  if (hSession_ == nullptr) {
    int rc = connector_->SDF_OpenSession(connector_->getDeviceHandle(), &hSession_);
    if (SDR_OK != rc) {
      throw SdfExcuteException(absl::StrFormat("Fail to open %s device session", connector_->getName().c_str()), rc);
    }

    id_ = connector_->getName() + "-" + hsmc::util::generate_uuid(16);
  }
}

void SessionImpl::close() {
  if (hSession_ != nullptr) {
    int rc = connector_->SDF_CloseSession(hSession_);
    if (SDR_OK != rc) {
      throw SdfExcuteException(absl::StrFormat("Fail to close %s device session", connector_->getName().c_str()), rc);
    }
    hSession_ = nullptr;
  }
}

bool SessionImpl::isGood(int *errcode, bool *dev_reopen) const {
  if (nullptr == hSession_) {
    return false;
  } else {
    DEVICEINFO di;
    return SDR_OK == connector_->SDF_GetDeviceInfo(hSession_, &di);
  }
}

void *SessionImpl::getSessionHandle() const {
  return hSession_;
}

std::string SessionImpl::getId() const {
  return id_;
}

int SessionImpl::processKeyHandle(void *keyHandle) const {
  auto connect = dynamic_cast<Connector *>(connector_.get());
  if (nullptr == connect) {
    throw SdfExcuteException(
        absl::StrFormat("Fail to dynamic_cast from hsmc::Connector to hsmc::dean::Connector"));
  }
  return connect->SDF_GetSesKey(hSession_, keyHandle);
}

int SessionImpl::SDF_ImportKey(unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const {
  int ret = connector_->SDF_ImportKey(hSession_, pucKey, uiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithKEK(unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
                                      unsigned int uiKeyLength, void **phKeyHandle) const {
  int ret = connector_->SDF_ImportKeyWithKEK(hSession_, uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithKEK(unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
                                        unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const {
  int ret =
      connector_->SDF_GenerateKeyWithKEK(hSession_, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithIPK_RSA(unsigned int uiIPKIndex, unsigned int uiKeyBits, unsigned char *pucKey,
                                            unsigned int *puiKeyLength, void **phKeyHandle) const {
  int ret = connector_->SDF_GenerateKeyWithIPK_RSA(hSession_, uiIPKIndex, uiKeyBits, pucKey, puiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithEPK_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                            unsigned char *pucKey, unsigned int *puiKeyLength,
                                            void **phKeyHandle) const {
  int ret =
      connector_->SDF_GenerateKeyWithEPK_RSA(hSession_, uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithISK_RSA(unsigned int uiISKIndex, unsigned char *pucKey, unsigned int uiKeyLength,
                                          void **phKeyHandle) const {
  int ret = connector_->SDF_ImportKeyWithISK_RSA(hSession_, uiISKIndex, pucKey, uiKeyLength, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithIPK_ECC(unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey,
                                            void **phKeyHandle) const {
  int ret = connector_->SDF_GenerateKeyWithIPK_ECC(hSession_, uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_GenerateKeyWithEPK_ECC(unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                            ECCCipher *pucKey, void **phKeyHandle) const {
  int ret = connector_->SDF_GenerateKeyWithEPK_ECC(hSession_, uiKeyBits, uiAlgID, pucPublicKey, pucKey, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

int SessionImpl::SDF_ImportKeyWithISK_ECC(unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const {
  int ret = connector_->SDF_ImportKeyWithISK_ECC(hSession_, uiISKIndex, pucKey, phKeyHandle);
  if (ret != SDR_OK) {
    return ret;
  }
  return processKeyHandle(*phKeyHandle);
}

}  // namespace dean
}  // namespace hsmc