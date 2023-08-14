#pragma once

#include "hsmc/connector.h"
#include "hsmc/session_impl.h"

namespace hsmc {
namespace svs {
namespace ndsec {

/// ndsec 签名验签会话实现
class SessionImpl : public hsmc::SessionImpl {
 public:
  explicit SessionImpl(hsmc::Connector::Ptr connector);

  ~SessionImpl();

  void open() override;

  void close() override;

  void *getSessionHandle() const override;

  bool isGood(int *errcode, bool *dev_reopen) const override;

  std::string getId() const override;

  int SVS_GenerateRandom(int length, uint8_t *randomData) const;

 private:
  void *hSession_;
  std::string id_;
};

}  // namespace ndsec
}  // namespace svs
}  // namespace hsmc
