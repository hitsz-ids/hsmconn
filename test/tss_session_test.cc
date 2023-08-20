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

#include <absl/strings/escaping.h>
#include <absl/memory/memory.h>
#include "gtest/gtest.h"
#include "hsmc/connector.h"
#include "hsmc/session_factory.h"
#include "hsmc/session_pool.h"
#include "hsmc/exception.h"

TEST(TSSSessionTest, GetSession) {
  auto session = ::hsmc::SessionPool::instance().get(hsmc::ConnectorType::CT_TSS);

  EXPECT_TRUE(session.isGood());
}

TEST(TSSSessionTest, GetDevSnByNdsecTssNode1) {
  auto session = ::hsmc::SessionPool::instance().getByConnector("ndsec-tss_node1");
  DeviceInfo_st di = {0};
  int rc = session.SDF_GetDeviceInfo(&di);
  EXPECT_EQ(rc, 0);
  std::string SN((const char *)di.DeviceSerial, 16);
  std::cout << "The SN of ndsec-tss_node1 is: " << SN << std::endl;
}

TEST(TSSSessionTest, AutoTS) {
  auto session = ::hsmc::SessionPool::instance().get(hsmc::ConnectorType::CT_TSS);

  std::string plain_text = "123";
  unsigned int ts_request_len = 256;
  auto ts_request = absl::make_unique<uint8_t[]>(ts_request_len);
  int result = session.STF_CreateTSRequest((unsigned char *)plain_text.c_str(), plain_text.length(), 0, nullptr, 0,
                                           SGD_SM3, ts_request.get(), &ts_request_len);
  EXPECT_EQ(0, result);
  std::cout << "ts_request_len: " << ts_request_len << std::endl;
  std::string str_ts_request((const char *)ts_request.get(), ts_request_len);
  std::cout << "b64_ts_request: " << absl::Base64Escape(str_ts_request) << std::endl;

  unsigned int ts_response_len = 3072;
  auto ts_response = absl::make_unique<uint8_t[]>(ts_response_len);
  result =
      session.STF_CreateTSResponse(ts_request.get(), ts_request_len, SGD_SM3_SM2, ts_response.get(), &ts_response_len);
  EXPECT_EQ(0, result);
  std::cout << "ts_response_len: " << ts_response_len << std::endl;
  std::string str_ts_response((const char *)ts_response.get(), ts_response_len);
  std::cout << "b64_ts_response: " << absl::Base64Escape(str_ts_response) << std::endl;

  result = session.STF_VerifyTSValidity(ts_response.get(), ts_response_len, SGD_SM3, SGD_SM3_SM2, nullptr, 0);
  EXPECT_EQ(0, result);

  unsigned char issuer_name[256] = {0};
  unsigned int issuer_name_len = sizeof(issuer_name);
  unsigned char time_data[256] = {0};
  unsigned int time_data_len = sizeof(time_data);
  result = session.STF_GetTSInfo(ts_response.get(), ts_response_len, issuer_name, &issuer_name_len, time_data,
                                 &time_data_len);
  EXPECT_EQ(0, result);
  std::cout << "issuer_name: " << issuer_name << std::endl;
  std::cout << "time_data: " << time_data << std::endl;

  // 解析时间戳详细信息时分配内存：STF_CERT_OF_TSSERVER/2048;STF_CERTCHAIN_OF_TSSERVER/4096;其余256
  unsigned int cert_data_len = 2048;
  auto cert_data = absl::make_unique<uint8_t[]>(cert_data_len);
  result = session.STF_GetTSDetail(ts_response.get(), ts_response_len, STF_CERT_OF_TSSERVER, cert_data.get(),
                                   &cert_data_len);
  EXPECT_EQ(0, result);
  std::cout << "tss_cert_len: " << cert_data_len << std::endl;
  std::string str_tss_cert((const char *)cert_data.get(), cert_data_len);
  std::cout << "bs_tss_cert: " << absl::Base64Escape(str_tss_cert) << std::endl;

  unsigned int time_of_stamp_len = 256;
  auto time_of_stamp = absl::make_unique<uint8_t[]>(time_of_stamp_len);
  result = session.STF_GetTSDetail(ts_response.get(), ts_response_len, STF_TIME_OF_STAMP, time_of_stamp.get(),
                                   &time_of_stamp_len);
  EXPECT_EQ(0, result);
  std::cout << "time_of_stamp: " << time_of_stamp.get() << std::endl;
}
