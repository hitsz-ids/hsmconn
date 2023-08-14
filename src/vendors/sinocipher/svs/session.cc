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

#include "hsmc/svs/sinocipher/session.h"

#include <absl/strings/str_format.h>

#include <iostream>
#include <utility>

#include "hsmc/pooled_session_impl.h"
#include "utils/uuid.h"

namespace hsmc {
namespace svs {
namespace sinocipher {

Session::Session(const ::hsmc::Session &baseSession) : ::hsmc::Session(baseSession) {
}

Session::~Session() = default;

int Session::SVS_Random(
    int length,
    uint8_t *randomData) const {

  auto pool_impl = std::dynamic_pointer_cast<::hsmc::PooledSessionImpl>(pImpl_);
  if (!pool_impl) {
    throw SdfExcuteException(absl::StrFormat(
        "Fail to dynamic_cast from hsmc::SessionImpl to hsmc::PooledSessionImpl"));
  }

  auto impl = std::dynamic_pointer_cast<::hsmc::svs::sinocipher::SessionImpl>(pool_impl->impl());
  if (!impl) {
    throw SdfExcuteException(absl::StrFormat(
        "Fail to dynamic_cast from hsmc::SessionImpl to hsmc::svs::sinocipher::SessionImpl"));
  }

  return impl->SVS_Random(length, randomData);
}

}
}
}