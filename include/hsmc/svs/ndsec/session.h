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

#include "hsmc/session.h"

namespace hsmc {
namespace svs {
namespace ndsec {

/// 九维数安签名验签服务器扩展接口定义
class HSMC_API Session : public hsmc::Session {
 public:
  /// 构造函数
  /// \param baseSession 父会话对象
  explicit Session(const ::hsmc::Session &baseSession);
  ~Session() override;

  /// 扩展函数：生成随机数
  /// \param length 长度
  /// \param randomData 接收随机数的内存地址
  /// \return 成功返回0，失败则返回错误码
  int SVS_GenerateRandom(int length, uint8_t *randomData) const;
};

}  // namespace ndsec
}  // namespace svs
}  // namespace hsmc

