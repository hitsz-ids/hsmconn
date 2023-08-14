#pragma once

#include <string>

#include "hsmc/connector.h"
#include "hsmc/session_impl.h"

namespace hsmc {
namespace svs {
namespace sinocipher {

/// 厂商连接器定义: sinocipher
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
  /// \param type
  /// \param certData
  /// \param certDataLen
  /// \param data
  /// \param dataLen
  /// \param signData
  /// \param signDataLen
  /// \param verifyLevel
  /// \return
  int SVS_VerifySignedData(
      void *hSessionHandle,
      int type,
      const uint8_t *certData,
      uint32_t certDataLen,
      const uint8_t *data,
      uint32_t dataLen,
      const uint8_t *signData,
      uint32_t signDataLen,
      int verifyLevel) const override;

  // 产生随机数
  int SVS_Random(
      void *hSessionHandle,
      int length,
      uint8_t *randomData) const;

 private:
  using SINOCIPHER_SVS_Connect_t = int (*)(void **, const char *, unsigned int);
  using SINOCIPHER_SVS_Disconnect_t = uint32_t (*)(void *);
  using SINOCIPHER_SVS_VerifySignedData_t = int (*)(void *,
                                                    int,
                                                    const unsigned char *,
                                                    int,
                                                    const char *,
                                                    int,
                                                    const char *,
                                                    int,
                                                    int);
  using SINOCIPHER_SVS_Random_t = int (*)(void *, int, char *);

  SINOCIPHER_SVS_Connect_t svs_connect_;
  SINOCIPHER_SVS_Disconnect_t svs_disconnect_;
  SINOCIPHER_SVS_VerifySignedData_t svs_verify_signed_data_;
  SINOCIPHER_SVS_Random_t svs_random_;

};


///
/// inlines
///

inline bool Connector::isOpen() const {
  return true;
}

}
}
}

