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

#pragma once
#include <mutex>

#include "hsmc/connector.h"
#include "hsmc/session.h"

namespace hsmc {
namespace ndsec {

/// 九维数安密码机会话实现
class SessionImpl : public hsmc::SessionImpl {
 public:
  explicit SessionImpl(hsmc::Connector::Ptr connector);

  ~SessionImpl();

  void open() override;

  void close() override;

  void *getSessionHandle() const override;

  bool isGood(int *errcode, bool *recover) const override;

  std::string getId() const override;

 private:
  sdf_handle_t hSession_;
  std::string id_;
};

}  // namespace ndsec
}  // namespace hsmc
