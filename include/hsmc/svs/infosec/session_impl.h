#pragma once

#include <mutex>

#include "hsmc/connector.h"
#include "hsmc/session.h"

namespace hsmc {
namespace svs {
namespace infosec {

/// infosec 签名验签会话实现
class SessionImpl : public hsmc::SessionImpl {
 public:
  /// 会话构造函数
  explicit SessionImpl(hsmc::Connector::Ptr connector);

  /// 会话析构函数
  ~SessionImpl();

  /// 打开会话
  void open() override;

  /// 关闭会话
  void close() override;

  /// 获取session 句柄
  void *getSessionHandle() const override;

  /// 检查会话是否正常
  bool isGood(int *errcode, bool *dev_reopen) const override;

  /// 获取id
  /// \return
  std::string getId() const override;

  int INS_GenRandom(uint8_t *randomData, int length) const;

 private:
  void *hSession_;
  std::string id_;
};

}  // namespace infosec
}  // namespace svs
}  // namespace hsmc
