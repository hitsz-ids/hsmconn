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

#include "gtest/gtest.h"
#include "hsmc/hsmc.h"
#include "utils/uuid.h"

#if ENABLE_OPENTELEMETRY_API
// implemented in metric.cc
void initMetrics(); 
#endif

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " [yaml configure file]" << std::endl;
    return -1;
  }

  ::hsmc::SessionFactory::instance().init(argv[1]);
  std::cout << "Version: " << ::hsmc::SessionFactory::instance().getVersion() << std::endl;

#if ENABLE_OPENTELEMETRY_API
  //initMetrics();
#endif

  int rc = RUN_ALL_TESTS();

  // NDSec HSM 资源释放存在bug，必须手动显式调用SessionPool::shutdown来释放资源
  ::hsmc::SessionPool::instance().shutdown();
  ::hsmc::SessionFactory::instance().shutdown();
  return rc;
}

