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
namespace svs {
namespace fisec {

/// 厂商HSM连接器定义: FISEC
///
class Connector : public hsmc::Connector {
 public:
  /// 创建连接器
  Connector(const std::string &nativeLibPath);

  /// 创建连接器
  Connector();

  /// 销毁连接器
  ~Connector();

  /// 打开连接器
  void open() override;

  /// 关闭连接器
  void close() override;

  void reopen() override;

  /// 创建会话
  hsmc::SessionImpl::Ptr createSession() override;

  bool isOpen() const override;

  void *getDeviceHandle() const override;

  void resolveSvsFuncs() override;

  int SVS_Open(void **p_handle) override;

  int SVS_Close(void *handle) override;

  /// 业务接口

 private:
  using FISEC_SVS_Connect_t = uint32_t (*)(void **, uint8_t *, uint32_t);
  using FISEC_SVS_Disconnect_t = uint32_t (*)(void *);

  FISEC_SVS_Connect_t svs_connect_;
  FISEC_SVS_Disconnect_t svs_disconnect_;

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
