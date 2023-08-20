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
#include "connector.h"
#include "utils/uuid.h"
#include <absl/strings/str_format.h>
#include "hsmc/exception.h"
#include "utils/log_internal.h"

namespace hsmc {
namespace ndsec {

SessionImpl::SessionImpl(::hsmc::Connector::Ptr connector)
    : ::hsmc::SessionImpl(connector), hSession_(nullptr) {
}

SessionImpl::~SessionImpl() = default;

void SessionImpl::open() {
  if (hSession_ == nullptr) {
    Logger()->debug("ndsec: enter SDF_OpenSession");
    int rc = connector_->SDF_OpenSession(connector_->getDeviceHandle(), &hSession_);
    if (SDR_OK != rc) {
      connector_->reopen();

      rc = connector_->SDF_OpenSession(connector_->getDeviceHandle(), &hSession_);
      if (SDR_OK != rc) {
        throw SdfExcuteException(absl::StrFormat("Fail to open %s device session",
                                                 connector_->getName().c_str()), rc);
      }
    }

    Logger()->debug("ndsec: leave SDF_OpenSession");

    id_ = connector_->getName() + "-" + ::hsmc::util::generate_uuid(16);
  }
}

void SessionImpl::close() {
  if (hSession_ != nullptr) {
    int rc = connector_->SDF_CloseSession(hSession_);
    if (SDR_OK != rc) {
      throw SdfExcuteException(absl::StrFormat("Fail to close %s device session",
                                               connector_->getName().c_str()), rc);
    }
    hSession_ = nullptr;
  }
}

bool SessionImpl::isGood(int *errcode, bool *recover) const {
  if (nullptr == hSession_) {
    return false;
  } else {
    DEVICEINFO di;
    int rc = connector_->SDF_GetDeviceInfo(hSession_, &di);
    if (errcode != nullptr) {
      *errcode = rc;
    }
    if (recover != nullptr && 0xdead0000 == static_cast<unsigned int>(rc)) {
      *recover = true;
    }
    // 兼容在客户端实现SDF_GetDeviceInfo
    uint8_t randomData[6] = {0};
    rc = connector_->SDF_GenerateRandom(hSession_, 6, randomData);
    return SDR_OK == rc;
  }
}

void *SessionImpl::getSessionHandle() const {
  return hSession_;
}

std::string SessionImpl::getId() const {
  return id_;
}

}
}
