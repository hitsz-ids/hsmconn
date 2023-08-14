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
#include <memory>

#include "hsmc/exception.h"
#include "session_impl.h"

namespace hsmc {
namespace tss {
namespace infosec {

Connector::Connector(const std::string &nativeLibPath) : hsmc::Connector(nativeLibPath) {
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

void *Connector::getDeviceHandle() const {
  return nullptr;
}

}  // namespace infosec
}  // namespace tss
}  // namespace hsmc