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
#include <stdlib.h>

#include <memory>

#include "hsmc/connector.h"
#include "hsmc/exception.h"
#include "session_impl.h"

namespace hsmc {
namespace svs {
namespace fisec {

Connector::Connector(const std::string &nativeLibPath) : hsmc::Connector(nativeLibPath) {
}

Connector::Connector() = default;

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

// SVS_UINT32 FM_SVS_OpenDevice (void **SVSHandle, SVS_UINT8 *ip ,SVS_UINT32 port);
void Connector::resolveSvsFuncs() {
  svs_connect_ = resolveFunc<FISEC_SVS_Connect_t>("FM_SVS_OpenDevice");
  svs_disconnect_ = resolveFunc<FISEC_SVS_Disconnect_t>("FM_SVS_CloseDevice");
}

int Connector::SVS_Open(void **p_handle) {
  return svs_connect_(p_handle, (uint8_t *)ip_.c_str(), port_);
}

int Connector::SVS_Close(void *handle) {
  return svs_disconnect_(handle);
}

}  // namespace fisec
}  // namespace svs
}  // namespace hsmc