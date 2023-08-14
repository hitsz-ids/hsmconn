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

#include "uuid.h"
#include <sstream>
#include <string>
#include "absl/random/random.h"

namespace hsmc {
namespace util {

absl::BitGen bitgen_;

std::string generate_uuid(unsigned int len) {
  std::stringstream ss;

  for (auto i = 0; i < len; i++) {
    const auto rc = absl::Uniform(bitgen_, 0, 256);
    std::stringstream hexstream;
    hexstream << std::hex << rc;
    auto hex = hexstream.str();
    ss << (hex.length() < 2 ? '0' + hex : hex);
  }
  return ss.str();
}

}
}