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
#include "sdf_funcs.h"

namespace hsmc {
namespace svs {
namespace ndsec {

/// 厂商连接器定义: ndsec
///
class Connector : public hsmc::Connector {
 public:
  explicit Connector(const std::string &nativeLibPath);

  Connector();

  ~Connector() override;

  void open() override;

  void close() override;

  void reopen() override;

  hsmc::SessionImpl::Ptr createSession() override;

  bool isOpen() const override;

  void *getDeviceHandle() const override;

  void resolveSvsFuncs() override;

  int SVS_Open(void **p_handle) override;

  int SVS_Close(void *handle) override;

  int SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                           const uint8_t *data, uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen,
                           int verifyLevel) const override;

  int SVS_GenerateRandom(void *hSessionHandle, int length, uint8_t *randomData) const;

  int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo) const override;

 private:
  void *hDevice_;
  void openDevice();
  void closeDevice();

  using NDSEC_SVS_OpenDevice_t = int (*)(void **);
  using NDSEC_SVS_OpenDeviceWithConfig_t = int (*)(void **, const unsigned char *, int);
  using NDSEC_SVS_CloseDevice_t = int (*)(void *);
  using NDSEC_SVS_OpenSession_t = int (*)(void *, void **);
  using NDSEC_SVS_CloseSession_t = int (*)(void *);
  using NDSEC_SVS_VerifySignedData_t = int (*)(void *, int, const unsigned char *, int, const char *, int, const char *,
                                               int, int);
  using NDSEC_SVS_GenerateRandom_t = int (*)(void *, int, unsigned char *);

  NDSEC_SVS_OpenDevice_t svs_open_device_;
  NDSEC_SVS_OpenDeviceWithConfig_t svs_open_device_with_config_;
  NDSEC_SVS_CloseDevice_t svs_close_device_;
  NDSEC_SVS_OpenSession_t svs_open_session_;
  NDSEC_SVS_CloseSession_t svs_close_session_;
  NDSEC_SVS_VerifySignedData_t svs_verify_signed_data_;
  NDSEC_SVS_GenerateRandom_t svs_generate_random_;

  using SDF_OpenDeviceWithConfig_t = int (*)(void **phDeviceHandle, const unsigned char *pcDeviceConfig,
                                             unsigned int pcDeviceConfigLength);
  SDF_OpenDeviceWithConfig_t SDF_OpenDeviceWithConfig_;
  hsmc::SDF_CloseDevice_t SDF_CloseDevice_;
  hsmc::SDF_OpenSession_t SDF_OpenSession_;
  hsmc::SDF_CloseSession_t SDF_CloseSession_;
  hsmc::SDF_GetDeviceInfo_t SDF_GetDeviceInfo_;
};

}  // namespace ndsec
}  // namespace svs
}  // namespace hsmc
