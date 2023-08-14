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

#include <memory>

#include "hsmc/exception.h"
#include "session_impl.h"

namespace hsmc {
namespace fisec {

Connector::Connector(const std::string &nativeLibPath) : hsmc::Connector(nativeLibPath), hDevice_(nullptr) {
}

Connector::Connector() : hDevice_(nullptr) {
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
  if (isOpen()) return;

  // 打开连接器
  hsmc::Connector::open();

  // 打开设备
  int rc = SDF_OpenDevice(&hDevice_);
  if (SDR_OK != rc) {
    std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDevice", getName().c_str());

    throw SdfExcuteException(errorMsg, rc);
  }
}

void Connector::close() {
  if (hDevice_ != nullptr) {
    // 关闭设备
    int rc = SDF_CloseDevice(hDevice_);
    if (SDR_OK != rc) {
      std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDevice", getName().c_str());
      throw SdfExcuteException(errorMsg, rc);
    }

    hDevice_ = nullptr;
  }

  // 关闭连接器
  hsmc::Connector::close();
}

void Connector::reopen() {
}

}  // namespace fisec
}  // namespace hsmc