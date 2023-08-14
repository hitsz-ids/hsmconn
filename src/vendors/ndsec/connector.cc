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

#include <fstream>
#include <memory>
#include <thread>

#include "hsmc/exception.h"
#include "session_impl.h"
#include "utils/log_internal.h"

namespace hsmc {
namespace ndsec {

Connector::Connector(const std::string &nativeLibPath)
    : hsmc::Connector(nativeLibPath),
      hDevice_(nullptr),
      sdf_set_config_file_(nullptr),
      SDF_OpenDeviceWithConfig_(nullptr),
      keeplive_stopflag_(false) {
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

  openDevice();
}

void Connector::close() {
  closeDevice();

  // 关闭连接器
  hsmc::Connector::close();
}

void Connector::openDevice() {
  int rc;

  if (isOpen()) return;

  // PCI-E密码卡
  if (isPCIE()) {
    if (SDR_OK != (rc = SDF_OpenDevice(&hDevice_))) {
      std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDevice for PCI-E", getName().c_str());

      throw SdfExcuteException(errorMsg, rc);
    }

    return;
  }

  // 读取配置文件
  std::stringstream data;
  std::ifstream file(getConfig());
  data << file.rdbuf();
  file.close();

  std::string dev_config = data.str();
  // 设备配置文件
  try {
    // 老版本使用sdf_set_config_file加载配置
    sdf_set_config_file_ = resolveFunc<Connector::sdf_set_config_file_t>("sdf_set_config_file");
    if (SDR_OK != (rc = sdf_set_config_file_(dev_config.c_str()))) {
      std::string errorMsg = absl::StrFormat("[%s] fail to execute sdf_set_config_file", getName().c_str());

      throw SdfExcuteException(errorMsg, rc);
    }
  } catch (PropertyNotSupportedException &ex) {
    // 新版本使用SDF_OpenDeviceWithConfig加载配置
    Logger()->warn("sdf_set_config_file not resolved, try to resolve SDF_OpenDeviceWithConfig");
    SDF_OpenDeviceWithConfig_ = resolveFunc<SDF_OpenDeviceWithConfig_t>("SDF_OpenDeviceWithConfig");
  } catch (LibraryLoadException &ex) {
    throw ex;
  }

  // 新版的客户端使用SDF_OpenDeviceWithConfig打开设备
  if (SDF_OpenDeviceWithConfig_ != nullptr) {
    if (SDR_OK != (rc = SDF_OpenDeviceWithConfig_(
                       &hDevice_, reinterpret_cast<const unsigned char *>(dev_config.c_str()), dev_config.length()))) {
      std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDeviceWithConfig", getName().c_str());

      throw SdfExcuteException(errorMsg, rc);
    }
  }
  // 旧版客户端使用SDF_OpenDevice打开设备
  else if (SDR_OK != (rc = SDF_OpenDevice(&hDevice_))) {
    std::string errorMsg = absl::StrFormat("[%s] fail to execute SDF_OpenDevice", getName().c_str());

    throw SdfExcuteException(errorMsg, rc);
  }

  // 老版本需要开启心跳检测
  if (SDF_OpenDeviceWithConfig_ == nullptr) {
    keeplive_stopflag_ = false;

    // 开启当前device的心跳检测
    keepalive_ = std::thread([&]() {
      Logger()->info("ndsec: enter device keeplive thread");

      hsmc::SessionImpl::Ptr p(new SessionImpl(shared_from_this()));
      p->open();
      int cnt = 0;
      while (!keeplive_stopflag_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (cnt++ > 60) {
          p->isGood();
          cnt = 0;

          Logger()->debug("ndsec: sending keepalive...");
        }
      }
      p->close();

      Logger()->info("ndsec: leave device keeplive thread");
    });
  }
}

void Connector::closeDevice() {
  if (hDevice_ != nullptr) {
    if (!isPCIE()) {
      // 等待device的心跳线程结束
      if (SDF_OpenDeviceWithConfig_ == nullptr) {
        keeplive_stopflag_ = true;
        keepalive_.join();
      }
    }

    // 关闭设备
    int rc = SDF_CloseDevice(hDevice_);
    if (SDR_OK != rc) {
      // std::string errorMsg = absl::StrFormat(
      //	"[%s] fail to execute SDF_CloseDevice", getName().c_str());

      // throw SdfExcuteException(errorMsg, rc);
    }

    hDevice_ = nullptr;
  }
}

void Connector::reopen() {
  closeDevice();
  openDevice();
}

void Connector::recover() {
  close();
}

}  // namespace ndsec
}  // namespace hsmc