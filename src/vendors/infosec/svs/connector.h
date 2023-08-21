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

#include <string>

#include "hsmc/connector.h"
#include "hsmc/session_impl.h"

namespace hsmc {
namespace svs {
namespace infosec {

/// 厂商连接器定义: infosec
///
class Connector : public hsmc::Connector {
 public:
  /// 创建连接器
  explicit Connector(const std::string &nativeLibPath);

  /// 创建连接器
  Connector();

  /// 销毁连接器
  ~Connector() override;

  /// 打开连接器
  void open() override;

  /// 关闭连接器
  void close() override;

  void reopen() override;

  /// 创建会话
  hsmc::SessionImpl::Ptr createSession() override;

  bool isOpen() const override;

  void *getDeviceHandle() const override;

  void resolveSvsFuncs() override;

  int SVS_Open(void **p_handle) override;

  int SVS_Close(void *handle) override;

  /// 业务接口

  /// 验证签名数据
  /// \param hSessionHandle
  /// \param type 签名验证方式，1:使用证书;3:DN
  /// \param certData
  /// \param certDataLen
  /// \param data
  /// \param dataLen
  /// \param signData
  /// \param signDataLen
  /// \param verifyLevel 证书验证级别
  /// \return
  int SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                           const uint8_t *data, uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen,
                           int verifyLevel) const override;

  // 产生随机数
  int INS_GenRandom(void *hSessionHandle, uint8_t *randomData, int length) const;

 private:
  /*注意： CERTINFO的 char[]类型成员不保证是以\0结尾的字符串， 例如当证书序列号长度为40字节时候，
 CERTINFO::serialNumber 内容为40个有效字节的字符串，但是非 \0结束*/
  typedef struct result_param {
    char issuer[256];         /* 颁发者DN*/
    char serialNumber[40];    /* 证书序列号*/
    char subject[256];        /* 证书主题*/
    char notBefore[20];       /* 证书有效期的起始时间*/
    char notAfter[20];        /* 证书有效期的终止时间*/
    char signresult[1024];    /* 签名结果*/
    unsigned char cert[2048]; /* 证书Der编码*/
    int certLen;              /* 证书Der编码长度*/
  } CERTINFO;

  typedef struct cert_info_ext {
    char Version[8];
    char SignAlg[16];
    char HashAlg[16];
    char PubKey[1024];
    int PubKeyLen;
  } CERTINFOEXT;

  using INFOSEC_CONNTONETSIGN_t = int (*)(char *, int, char *, int *);
  using INFOSEC_DISCFROMNETSIGN_t = int (*)(int);
  using INFOSEC_INS_GENRANDOM_t = int (*)(int, unsigned char *, int);
  using INFOSEC_INS_RAWVERIFY_t = int (*)(int, unsigned char *, int, unsigned char *, int, char *, unsigned char *, int,
                                          CERTINFO *);
  using INFOSEC_INS_RAWAFTERWARDSVERIFY_t = int (*)(int, unsigned char *, int, unsigned char *, int, char *,
                                                    unsigned char *, int, CERTINFO *);
  using INFOSEC_UPLOADCERT_t = int (*)(int, unsigned char *, int);
  using INFOSEC_DELETECERT_t = int (*)(int, char *);
  using INFOSEC_GETCERTINFO_t = int (*)(unsigned char *, int, CERTINFO *, CERTINFOEXT *);
  using INFOSEC_CHECKCERTCHAIN_t = int (*)(int, char *);
  using INFOSEC_CHECKCERTCRL_t = int (*)(int, char *);
  using INFOSEC_RAWVERIFYSIMPLE_t = int (*)(int, unsigned char *, int, char *, unsigned char *, int, int, CERTINFO *);

  INFOSEC_CONNTONETSIGN_t conn_to_netsign_;
  INFOSEC_DISCFROMNETSIGN_t disc_from_netsign_;
  INFOSEC_INS_GENRANDOM_t ins_genrandom_;
  INFOSEC_INS_RAWVERIFY_t ins_rawverify_;
  INFOSEC_INS_RAWAFTERWARDSVERIFY_t ins_raw_afterwards_verify_;
  INFOSEC_UPLOADCERT_t upload_cert_;
  INFOSEC_DELETECERT_t delete_cert_;
  INFOSEC_GETCERTINFO_t get_cert_info_;
  INFOSEC_CHECKCERTCHAIN_t check_cert_chain_;
  INFOSEC_CHECKCERTCRL_t check_cert_crl_;
  INFOSEC_RAWVERIFYSIMPLE_t raw_verify_simple_;
};

///
/// inlines
///

inline bool Connector::isOpen() const {
  return true;
}

}  // namespace infosec
}  // namespace svs
}  // namespace hsmc
