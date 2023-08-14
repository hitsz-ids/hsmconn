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

#include "connector.h"

#include <absl/strings/str_format.h>

#include <cstdlib>
#include <fstream>
#include <memory>

#include "hsmc/exception.h"
#include "session_impl.h"

namespace hsmc {
namespace tss {
namespace ndsec {

Connector::Connector(const std::string &nativeLibPath)
    : hsmc::Connector(nativeLibPath),
      STF_OpenDeviceWithConfig_(nullptr),
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

  STF_OpenDeviceWithConfig_ = resolveFunc<STF_OpenDeviceWithConfig_t>("STF_OpenDeviceWithConfig");
  SDF_OpenDeviceWithConfig_ = resolveFunc<SDF_OpenDeviceWithConfig_t>("SDF_OpenDeviceWithConfig");
  SDF_CloseDevice_ = resolveFunc<hsmc::SDF_CloseDevice_t>("SDF_CloseDevice");
  SDF_OpenSession_ = resolveFunc<hsmc::SDF_OpenSession_t>("SDF_OpenSession");
  SDF_CloseSession_ = resolveFunc<hsmc::SDF_CloseSession_t>("SDF_CloseSession");
  SDF_GetDeviceInfo_ = resolveFunc<hsmc::SDF_GetDeviceInfo_t>("SDF_GetDeviceInfo");
}

void Connector::close() {
  // 关闭连接器
  hsmc::Connector::close();
}

void Connector::reopen() {
}

/// SVS设备没有device handle
void *Connector::getDeviceHandle() const {
  return nullptr;
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
}  // namespace tss
}  // namespace hsmc