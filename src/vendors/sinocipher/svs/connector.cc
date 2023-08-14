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

#include "hsmc/svs/sinocipher/connector.h"

#include <absl/strings/str_format.h>

#include <cstdlib>
#include <memory>

#include "hsmc/connector.h"
#include "hsmc/exception.h"
#include "hsmc/svs/sinocipher/session_impl.h"

namespace hsmc {
namespace svs {
namespace sinocipher {

Connector::Connector(const std::string &nativeLibPath)
    : hsmc::Connector(nativeLibPath),
      svs_connect_(nullptr),
      svs_disconnect_(nullptr),
      svs_verify_signed_data_(nullptr),
      svs_random_(nullptr) {
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

void Connector::resolveSvsFuncs() {
  svs_connect_ = resolveFunc<SINOCIPHER_SVS_Connect_t>("SVS_Connect");
  svs_disconnect_ = resolveFunc<SINOCIPHER_SVS_Disconnect_t>("SVS_Disconnect");
  svs_verify_signed_data_ = resolveFunc<SINOCIPHER_SVS_VerifySignedData_t>("SVS_VerifySignedData");
  svs_random_ = resolveFunc<SINOCIPHER_SVS_Random_t>("SVS_Random");
}

int Connector::SVS_Open(void **p_handle) {
  return svs_connect_(p_handle, ip_.c_str(), port_);
}

int Connector::SVS_Close(void *handle) {
  return svs_disconnect_(handle);
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

int Connector::SVS_Random(void *hSessionHandle, int length, uint8_t *randomData) const {
  if (!svs_random_) {
    return -1;
  }
  return svs_random_(hSessionHandle, length, (char *)randomData);
}

}  // namespace sinocipher
}  // namespace svs
}  // namespace hsmc