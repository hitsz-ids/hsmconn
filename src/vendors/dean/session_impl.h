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
namespace dean {

/// dean 密码机会话实现
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

  int SDF_ImportKey(unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const override;
  int SDF_ImportKeyWithKEK(unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
                           unsigned int uiKeyLength, void **phKeyHandle) const override;
  int SDF_GenerateKeyWithKEK(unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
                             unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const override;

  int SDF_GenerateKeyWithIPK_RSA(unsigned int uiIPKIndex, unsigned int uiKeyBits, unsigned char *pucKey,
                                 unsigned int *puiKeyLength, void **phKeyHandle) const override;
  int SDF_GenerateKeyWithEPK_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pucKey,
                                 unsigned int *puiKeyLength, void **phKeyHandle) const override;
  int SDF_ImportKeyWithISK_RSA(unsigned int uiISKIndex, unsigned char *pucKey, unsigned int uiKeyLength,
                               void **phKeyHandle) const override;
  int SDF_GenerateKeyWithIPK_ECC(unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey,
                                 void **phKeyHandle) const override;
  int SDF_GenerateKeyWithEPK_ECC(unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                 ECCCipher *pucKey, void **phKeyHandle) const override;
  int SDF_ImportKeyWithISK_ECC(unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const override;

 private:
  int processKeyHandle(void *keyHandle) const;

 private:
  sdf_handle_t hSession_;
  std::string id_;
};

}  // namespace dean
}  // namespace hsm
