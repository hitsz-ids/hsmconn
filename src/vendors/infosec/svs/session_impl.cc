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

#include "hsmc/svs/infosec/session_impl.h"

#include <absl/strings/str_format.h>

#include <utility>

#include "hsmc/svs/infosec/connector.h"
#include "utils/uuid.h"

namespace hsmc {
namespace svs {
namespace infosec {

SessionImpl::SessionImpl(hsmc::Connector::Ptr connector)
    : hsmc::SessionImpl(std::move(connector)), hSession_(nullptr) {
}

SessionImpl::~SessionImpl() = default;

void SessionImpl::open() {
  if (hSession_ == nullptr) {
    int rc = connector_->SVS_Open(&hSession_);
    if (0 != rc) {
      throw SdfExcuteException(absl::StrFormat("Fail to open %s device session", connector_->getName().c_str()), rc);
    }

    id_ = connector_->getName() + "-" + hsmc::util::generate_uuid(16);
  }
}

void SessionImpl::close() {
  if (hSession_ != nullptr) {
    int rc = connector_->SVS_Close(hSession_);
    if (0 != rc) {
      throw SdfExcuteException(absl::StrFormat("Fail to close %s device session", connector_->getName().c_str()), rc);
    }
    hSession_ = nullptr;
  }
}

// 文档显示随机数为本地生成，待验证以及待修改
bool SessionImpl::isGood(int *errcode, bool *dev_reopen) const {
  uint8_t randomData[6] = {0};
  if (nullptr == hSession_) {
    return false;
  }
  auto connect = dynamic_cast<Connector *>(connector_.get());
  if (nullptr == connect) {
    throw SdfExcuteException(
        absl::StrFormat("Fail to dynamic_cast from hsmc::Connector to hsmc::svs::infosec::Connector"));
  }
  return 0 == connect->INS_GenRandom(hSession_, randomData, 6);
}

void *SessionImpl::getSessionHandle() const {
  return hSession_;
}

std::string SessionImpl::getId() const {
  return id_;
}

int SessionImpl::INS_GenRandom(uint8_t *randomData, int length) const {
  auto connect = dynamic_cast<Connector *>(connector_.get());
  if (nullptr == connect) {
    throw SdfExcuteException(
        absl::StrFormat("Fail to dynamic_cast from hsmc::Connector to hsmc::svs::infosec::Connector"));
  }
  return connect->INS_GenRandom(getSessionHandle(), randomData, length);
}

}  // namespace infosec
}  // namespace svs
}  // namespace hsmc