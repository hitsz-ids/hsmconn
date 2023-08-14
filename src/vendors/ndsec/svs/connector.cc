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

#include "hsmc/svs/ndsec/connector.h"

#include <absl/strings/str_format.h>

#include <cstdlib>
#include <fstream>
#include <memory>

#include "hsmc/connector.h"
#include "hsmc/exception.h"
#include "hsmc/svs/ndsec/session_impl.h"

namespace hsmc {
namespace svs {
namespace ndsec {

Connector::Connector(const std::string &nativeLibPath)
    : hsmc::Connector(nativeLibPath),
      hDevice_(nullptr),
      svs_open_device_(nullptr),
      svs_open_device_with_config_(nullptr),
      svs_close_device_(nullptr),
      svs_open_session_(nullptr),
      svs_close_session_(nullptr),
      svs_verify_signed_data_(nullptr),
      svs_generate_random_(nullptr),
      SDF_OpenDeviceWithConfig_(nullptr),
      SDF_CloseDevice_(nullptr),
      SDF_OpenSession_(nullptr),
      SDF_CloseSession_(nullptr),
      SDF_GetDeviceInfo_(nullptr) {
}

Connector::Connector() : Connector("") {
}

Connector::~Connector() = default;

hsmc::SessionImpl::Ptr Connector::createSession() {
  open();
  hsmc::SessionImpl::Ptr p(new SessionImpl(shared_from_this()));
  p->open();

  return p;
}

void Connector::open() {
  std::lock_guard<std::mutex> guard(this->mutex_);
  // 打开连接器
  hsmc::Connector::open();

  openDevice();
}

void Connector::close() {
  closeDevice();
  // 关闭连接器
  hsmc::Connector::close();
}

void Connector::openDevice() {
  int rc;

  if (isOpen()) return;

  std::stringstream data;
  std::ifstream file(getConfig());
  data << file.rdbuf();
  file.close();
  std::string dev_config = data.str();
  if (0 !=
      (rc = svs_open_device_with_config_(&hDevice_, (const unsigned char *)dev_config.c_str(), dev_config.length()))) {
    std::string errorMsg = absl::StrFormat("[%s] fail to execute SVS_OpenDeviceWithConfig", getName().c_str());

    throw SdfExcuteException(errorMsg, rc);
  }
}

void Connector::closeDevice() {
  int rc;
  if (hDevice_ != nullptr) {
    // 关闭设备
    if (0 != (rc = svs_close_device_(hDevice_))) {
      std::string errorMsg = absl::StrFormat("[%s] fail to execute SVS_CloseDevice", getName().c_str());

      throw SdfExcuteException(errorMsg, rc);
    }
    hDevice_ = nullptr;
  }
}

void Connector::reopen() {
}

void *Connector::getDeviceHandle() const {
  return hDevice_;
}

bool Connector::isOpen() const {
  return hDevice_ != nullptr;
}

void Connector::resolveSvsFuncs() {
  svs_open_device_ = resolveFunc<NDSEC_SVS_OpenDevice_t>("SVS_OpenDevice");
  svs_open_device_with_config_ = resolveFunc<NDSEC_SVS_OpenDeviceWithConfig_t>("SVS_OpenDeviceWithConfig");
  svs_close_device_ = resolveFunc<NDSEC_SVS_CloseDevice_t>("SVS_CloseDevice");
  svs_open_session_ = resolveFunc<NDSEC_SVS_OpenSession_t>("SVS_OpenSession");
  svs_close_session_ = resolveFunc<NDSEC_SVS_CloseSession_t>("SVS_CloseSession");
  svs_verify_signed_data_ = resolveFunc<NDSEC_SVS_VerifySignedData_t>("SVS_VerifySignedData");
  svs_generate_random_ = resolveFunc<NDSEC_SVS_GenerateRandom_t>("SVS_GenerateRandom");

  SDF_OpenDeviceWithConfig_ = resolveFunc<SDF_OpenDeviceWithConfig_t>("SDF_OpenDeviceWithConfig");
  SDF_CloseDevice_ = resolveFunc<hsmc::SDF_CloseDevice_t>("SDF_CloseDevice");
  SDF_OpenSession_ = resolveFunc<hsmc::SDF_OpenSession_t>("SDF_OpenSession");
  SDF_CloseSession_ = resolveFunc<hsmc::SDF_CloseSession_t>("SDF_CloseSession");
  SDF_GetDeviceInfo_ = resolveFunc<hsmc::SDF_GetDeviceInfo_t>("SDF_GetDeviceInfo");
}

int Connector::SVS_Open(void **p_handle) {
  return svs_open_session_(hDevice_, p_handle);
}

int Connector::SVS_Close(void *handle) {
  return svs_close_session_(handle);
}

int Connector::SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                                    const uint8_t *data, uint32_t dataLen, const uint8_t *signData,
                                    uint32_t signDataLen, int verifyLevel) const {
  if (!svs_verify_signed_data_) {
    return -1;
  }
  return svs_verify_signed_data_(hSessionHandle, type, certData, certDataLen, reinterpret_cast<const char *>(data),
                                 dataLen, reinterpret_cast<const char *>(signData), signDataLen, verifyLevel);
}

int Connector::SVS_GenerateRandom(void *hSessionHandle, int length, uint8_t *randomData) const {
  if (!svs_generate_random_) {
    return -1;
  }
  return svs_generate_random_(hSessionHandle, length, randomData);
}

int Connector::SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo) const {
  std::stringstream data;
  std::ifstream file(getConfig());
  data << file.rdbuf();
  file.close();
  std::string dev_config = data.str();

  int rc = 0;
  void *deviceHandle = nullptr;
  void *sessionHandle = nullptr;
  if (SDR_OK !=
      (rc = SDF_OpenDeviceWithConfig_(&deviceHandle, reinterpret_cast<const unsigned char *>(dev_config.c_str()),
                                      dev_config.length()))) {
    std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDeviceWithConfig", getName().c_str());
    throw SdfExcuteException(errorMsg, rc);
  }

  if (SDR_OK != (rc = SDF_OpenSession_(deviceHandle, &sessionHandle))) {
    std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenSession", getName().c_str());
    SDF_CloseDevice_(deviceHandle);
    throw SdfExcuteException(errorMsg, rc);
  }

  rc = SDF_GetDeviceInfo_(sessionHandle, pstDeviceInfo);
  SDF_CloseSession_(sessionHandle);
  SDF_CloseDevice_(deviceHandle);
  return rc;
}

}  // namespace ndsec
}  // namespace svs
}  // namespace hsmc