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
namespace svs {
namespace fisec {

/// FISEC 签名验签会话实现
class SessionImpl : public hsmc::SessionImpl {
 public:
  /// 会话构造函数
  explicit SessionImpl(hsmc::Connector::Ptr connector);

  /// 会话析构函数
  ~SessionImpl();

  /// 打开会话
  void open() override;

  /// 关闭会话
  void close() override;

  /// 获取session 句柄
  void *getSessionHandle() const override;

  /// 检查会话是否正常
  bool isGood(int *errcode, bool *dev_reopen) const override;

  /// 获取id
  /// \return
  std::string getId() const override;

 private:
  void *hSession_;
  std::string id_;
};

}
}
}
