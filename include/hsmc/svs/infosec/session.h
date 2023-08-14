#pragma once

#include "hsmc/session.h"
#include "hsmc/svs/infosec/session_impl.h"

namespace hsmc {
namespace svs {
namespace infosec {

class HSMC_API Session : public hsmc::Session {
 public:
  explicit Session(const hsmc::Session &baseSession);
  /// Session destructor
  ~Session() override;

  int INS_GenRandom(uint8_t *randomData, int length) const;
};

}  // namespace infosec
}  // namespace svs
}  // namespace hsmc

