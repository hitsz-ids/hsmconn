#pragma once

#include <memory>
#include <mutex>

#include "hsmc/session.h"
#include "hsmc/svs/sinocipher/connector.h"
#include "hsmc/svs/sinocipher/session_impl.h"

namespace hsmc {
namespace svs {
namespace sinocipher {

class HSMC_API Session : public hsmc::Session {
 public:
  explicit Session(const hsmc::Session &baseSession);
  /// Session destructor
  ~Session() override;

  int SVS_Random(int length, uint8_t *randomData) const;
};

}  // namespace sinocipher
}  // namespace svs
}  // namespace hsmc
