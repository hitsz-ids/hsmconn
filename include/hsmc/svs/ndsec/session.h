#pragma once

#include "hsmc/session.h"
#include "hsmc/svs/ndsec/session_impl.h"

namespace hsmc {
namespace svs {
namespace ndsec {

class HSMC_API Session : public hsmc::Session {
 public:
  explicit Session(const ::hsmc::Session &baseSession);
  ~Session() override;

  /// 扩展函数：生成随机数
  int SVS_GenerateRandom(int length, uint8_t *randomData) const;
};

}  // namespace ndsec
}  // namespace svs
}  // namespace hsmc

