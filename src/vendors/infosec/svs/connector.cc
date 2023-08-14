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

#include "hsmc/svs/infosec/connector.h"

#include <absl/strings/str_format.h>

#include <cstdlib>
#include <iostream>
#include <memory>

#include "hsmc/connector.h"
#include "hsmc/exception.h"
#include "hsmc/svs/infosec/session_impl.h"

namespace hsmc {
namespace svs {
namespace infosec {

Connector::Connector(const std::string &nativeLibPath)
    : hsmc::Connector(nativeLibPath),
      conn_to_netsign_(nullptr),
      disc_from_netsign_(nullptr),
      ins_genrandom_(nullptr),
      ins_rawverify_(nullptr),
      ins_raw_afterwards_verify_(nullptr),
      upload_cert_(nullptr),
      delete_cert_(nullptr),
      get_cert_info_(nullptr),
      check_cert_chain_(nullptr),
      check_cert_crl_(nullptr),
      raw_verify_simple_(nullptr) {
}

Connector::Connector() : Connector("") {
}

Connector::~Connector() = default;

hsmc::SessionImpl::Ptr Connector::createSession() {
  open();
  hsmc::SessionImpl::Ptr p(new SessionImpl(shared_from_this()));
  p->open();

  return p;
}

void Connector::open() {
  std::lock_guard<std::mutex> guard(this->mutex_);
  // 打开连接器
  hsmc::Connector::open();
}

void Connector::close() {
  // 关闭连接器
  hsmc::Connector::close();
}

void Connector::reopen() {
}

/// SVS设备没有device handle
void *Connector::getDeviceHandle() const {
  return nullptr;
}

void Connector::resolveSvsFuncs() {
  conn_to_netsign_ = resolveFunc<INFOSEC_CONNTONETSIGN_t>("ConnToNetSign");
  disc_from_netsign_ = resolveFunc<INFOSEC_DISCFROMNETSIGN_t>("DiscFromNetSign");
  ins_genrandom_ = resolveFunc<INFOSEC_INS_GENRANDOM_t>("INS_GenRandom");
  ins_rawverify_ = resolveFunc<INFOSEC_INS_RAWVERIFY_t>("INS_RAWVerify");
  ins_raw_afterwards_verify_ = resolveFunc<INFOSEC_INS_RAWAFTERWARDSVERIFY_t>("INS_RAWAfterwardsVerify");
  upload_cert_ = resolveFunc<INFOSEC_UPLOADCERT_t>("UploadCert");
  delete_cert_ = resolveFunc<INFOSEC_DELETECERT_t>("DeleteCert");
  get_cert_info_ = resolveFunc<INFOSEC_GETCERTINFO_t>("GetCertInfo");
  check_cert_chain_ = resolveFunc<INFOSEC_CHECKCERTCHAIN_t>("CheckCertChain");
  check_cert_crl_ = resolveFunc<INFOSEC_CHECKCERTCRL_t>("CheckCertCRL");
  raw_verify_simple_ = resolveFunc<INFOSEC_RAWVERIFYSIMPLE_t>("RawVerifySimple");
}

int Connector::SVS_Open(void **p_handle) {
  int handle = 0;
  int ret = conn_to_netsign_((char *)ip_.c_str(), port_, (char *)password_.c_str(), &handle);
  if (0 == ret) {
    *p_handle = reinterpret_cast<void *>(new int(handle));
  }
  return ret;
}

int Connector::SVS_Close(void *handle) {
  int ret = disc_from_netsign_(*(reinterpret_cast<int *>(handle)));
  delete reinterpret_cast<int *>(handle);
  return ret;
}

int Connector::SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                                    const uint8_t *data, uint32_t dataLen, const uint8_t *signData,
                                    uint32_t signDataLen, int verifyLevel) const {
  int ret = 0;
  std::string certDN;
  if (!get_cert_info_ || !upload_cert_ || !raw_verify_simple_ || !delete_cert_ || !check_cert_chain_ ||
      !check_cert_crl_) {
    return -1;
  }

  if (hsmc::CertType::CERTDATA == type) {
    CERTINFO certInfo;
    ret = get_cert_info_(const_cast<unsigned char *>(certData), certDataLen, &certInfo, nullptr);
    if (ret != 0) {
      return ret;
    }
    certDN.assign(certInfo.subject, strlen(certInfo.subject));

    ret = upload_cert_(*(reinterpret_cast<int *>(hSessionHandle)), const_cast<unsigned char *>(certData), certDataLen);
    if (ret != 0) {
      return ret;
    }
  } else if (hsmc::CertType::CERTID == type) {
    certDN.assign((const char *)certData, certDataLen);
  } else {
    return -2;
  }

  ret = raw_verify_simple_(*(reinterpret_cast<int *>(hSessionHandle)), const_cast<unsigned char *>(data), dataLen,
                           (char *)certDN.c_str(), const_cast<unsigned char *>(signData), signDataLen, 0, nullptr);
  if (ret != 0) {
    if (hsmc::CertType::CERTDATA == type) {
      delete_cert_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
    }
    return ret;
  }

  // 检查有效期
  // todo
  if (hsmc::VerifyCertLevel::VERIFYTIME == verifyLevel) {
    if (hsmc::CertType::CERTDATA == type) {
      delete_cert_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
    }
    return ret;
  }

  ret = check_cert_chain_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
  if (ret != 0 || hsmc::VerifyCertLevel::VERIFYCHAIN == verifyLevel) {
    if (hsmc::CertType::CERTDATA == type) {
      delete_cert_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
    }
    return ret;
  }

  ret = check_cert_crl_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
  if (hsmc::CertType::CERTDATA == type) {
    delete_cert_(*(reinterpret_cast<int *>(hSessionHandle)), (char *)certDN.c_str());
  }
  return ret;
}

int Connector::INS_GenRandom(void *hSessionHandle, uint8_t *randomData, int length) const {
  if (!ins_genrandom_) {
    return -1;
  }
  return ins_genrandom_(*(reinterpret_cast<int *>(hSessionHandle)), randomData, length);
}

}  // namespace infosec
}  // namespace svs
}  // namespace hsmc