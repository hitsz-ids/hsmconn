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

#include <atomic>
#include <string>
#include <thread>

#include "hsmc/connector.h"
#include "hsmc/session_impl.h"

namespace hsmc {
namespace ndsec {

/// 九维数安密码机适配
class Connector : public hsmc::Connector {
 public:
  /// 扩展函数，设置设备配置文件
  /// \param pcDeviceConfig 设备配置路径
  /// \return 0成功，其他失败
  using sdf_set_config_file_t = sdf_return_t (*)(const char *pcDeviceConfig);

  /// 扩展的SDF函数
  /// \param phDeviceHandle 设备句柄
  /// \param pcDeviceConfig 设备配置路径
  /// \param pcDeviceConfigLength 设备配置路径长度
  /// \return 0成功，其他失败
  using SDF_OpenDeviceWithConfig_t = int (*)(void **phDeviceHandle, const unsigned char *pcDeviceConfig,
                                             unsigned int pcDeviceConfigLength);

 public:
  explicit Connector(const std::string &nativeLibPath);

  Connector();

  ~Connector() override;

  void open() override;

  void close() override;

  void reopen() override;

  hsmc::SessionImpl::Ptr createSession() override;

  void *getDeviceHandle() const override;

  bool isOpen() const override;

  void recover() override;

 private:
  void openDevice();
  void closeDevice();

  sdf_handle_t hDevice_;
  sdf_set_config_file_t sdf_set_config_file_;
  SDF_OpenDeviceWithConfig_t SDF_OpenDeviceWithConfig_;

  std::thread keepalive_;
  std::atomic_bool keeplive_stopflag_;
};

///
/// inlines
///
inline void *Connector::getDeviceHandle() const {
  return hDevice_;
}

inline bool Connector::isOpen() const {
  return hDevice_ != nullptr;
}

}  // namespace ndsec
}  // namespace hsmc
