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

#include <string>

#include "hsmc/connector.h"
#include "hsmc/session_impl.h"

namespace hsmc {
namespace tss {
namespace sinocipher {

/// 厂商连接器定义: sinocipher
///
class Connector : public hsmc::Connector {
 public:
  /// 创建连接器
  explicit Connector(const std::string &nativeLibPath);

  /// 创建连接器
  Connector();

  /// 销毁连接器
  ~Connector() override;

  /// 打开连接器
  void open() override;

  /// 关闭连接器
  void close() override;

  void reopen() override;

  /// 创建会话
  hsmc::SessionImpl::Ptr createSession() override;

  bool isOpen() const override;

  void *getDeviceHandle() const override;

  using STF_InitEnvironment_Ex_t = SGD_UINT32 (*)(void **phTSHandle, SGD_UINT8 *pucConfigPath);
  STF_InitEnvironment_Ex_t STF_InitEnvironment_Ex_;

 private:

};


///
/// inlines
///

inline bool Connector::isOpen() const {
  return true;
}

}
}
}
