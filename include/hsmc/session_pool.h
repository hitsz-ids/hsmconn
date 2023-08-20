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

#include <atomic>
#include <mutex>
#include <thread>
#include <utility>
#ifdef ABSEIL_FLAT_HASH_MAP
#include "absl/container/flat_hash_map.h"
#else
#include <unordered_map>
#endif

#include "pooled_session_holder.h"
#include "pooled_session_impl.h"
#include "session.h"
#include "session_factory.h"

namespace hsmc {

/// `SessionPool`维护了服务器密码机、签名验签服务器、时间戳服务器三种设备当前可用的`Session`对象缓存池。
/// 并提供了从`SessionPool`中获取不同设备类型或设备节点的会话对象
class HSMC_API SessionPool final {
 public:
  static const int DEFAULT_MAX_SESSION;

  /// SessionPool构造函数
  /// \param minSessions 最小的session数量，默认为1
  /// \param maxSessions 最大的session数量，默认为DEFAULT_MAX_SESSION
  explicit SessionPool(int minSessions = 1, int maxSessions = DEFAULT_MAX_SESSION);

  /// SessionPool构造函数
  /// \param factory SessionFactory对象
  /// \param minSessions 最小的session数量，默认为1
  /// \param maxSessions 最大的session数量，默认为DEFAULT_MAX_SESSION
  explicit SessionPool(SessionFactory &factory, int minSessions = 1, int maxSessions = DEFAULT_MAX_SESSION);

  SessionPool(const SessionPool &) = delete;
  SessionPool(SessionPool &&) = delete;
  SessionPool &operator=(const SessionPool &) = delete;
  SessionPool &operator=(SessionPool &&) = delete;

  /// SessionPool析构函数
  ~SessionPool();

  /// 获取连接池获取会话。从pool中获取的session对象在析构时自动重新进入pool，pool在回收该session时，
  /// 通过session->isGood来检查session可用，不可用的session会自动被清理，其session id也将失效。
  /// \param id 会话ID，若不存在该id的session时，将抛出NotFoundException异常。
  /// \return 成功则返回session，失败则抛出异常
  Session get(const std::string &id);

  /// 获取指定连接器密码机的session，所有连接器可以使用SessionFactory::getConnectorNames获取。
  /// \param connector 连接器名称
  /// \return 成功则返回session，失败则抛出异常
  Session getByConnector(const std::string &connector);

  /// 从给定连接器集合中随机选择并返回该连接器的session
  /// \param connSet 连接器名字集合
  /// \return 成功则返回session，失败则抛出异常
  Session getByConnectorSet(const std::vector<std::string> &connSet);

  /// 获取连接池获取会话。从pool中获取的session对象在析构时自动重新进入pool，pool在回收该session时，
  /// 通过session->isGood来检查session可用，不可用的session会自动被清理。
  /// \param conntype 设备类型，默认为ConnectorType::CT_HSM（服务器密码机）
  /// \return 成功则返回session，失败则抛出异常
  Session get(ConnectorType conntype = ConnectorType::CT_HSM);

  /// 获取SessionPool全局单例
  /// \return 返回SessionPool全局单例
  static SessionPool &instance();

  /// 获取连接池的最大容量
  /// \return 返回连接池的最大容量
  size_t capacity() const;

  /// 获取连接池活动的会话数量
  /// \return 返回连接池活动的会话数量
  size_t used() const;

  /// 获取连接池空闲的会话数量
  /// \return 返回连接池空闲的会话数量
  size_t idle() const;

  /// 关闭连接池并释放所有资源
  void shutdown();

  /// 设置是否开启pooling，默认开启。若pooling关闭则每个session即用即销毁
  /// \param pooling 当为false则关闭pooling
  void setPooling(bool pooling);

  /// 设置定期检查空闲会话的检查周期，单位为秒
  /// \param interval 定期检查空闲会话的检查周期，单位为秒
  void setKeepaliveInterval(int interval);

  /// 设置连接池最大的会话数
  /// \param maxSessions 连接池最大的会话数
  void setMaxSessions(int maxSessions);

  /// 获取创建会话的工厂对象
  SessionFactory &getFactory();

 public:
  /// 存放PooledSessionHolder对象指针的容器
#ifdef ABSEIL_FLAT_HASH_MAP
  using container = absl::flat_hash_map<std::string, PooledSessionHolder::Ptr>;
#else
  using container = std::unordered_map<std::string, PooledSessionHolder::Ptr>;
#endif

  /// 继承container，并重载了insert和erase方法
  class SessionMap : public container {
   public:
    /// 清除闲置时间会话
    void purge_idle();

    /// 获取指定设备节点的会话
    PooledSessionHolder::Ptr next(const std::string &connector);

    /// 重载erase方法
    void erase(container::iterator it);

    /// 重载insert方法
    std::pair<container::iterator, bool> insert(container::value_type &&pair);

   private:
    /// sessions group by connector
    using session_list = std::pair<uint64_t, std::list<PooledSessionHolder::Ptr>>;
    using session_list_ptr = std::shared_ptr<session_list>;
#ifdef ABSEIL_FLAT_HASH_MAP
    using container_internal = absl::flat_hash_map<std::string, session_list_ptr>;
#else
    using container_internal = std::unordered_map<std::string, session_list_ptr>;
#endif
    container_internal connectors_;
  };

 protected:
  void purgeDeadSessions();
  void putBack(const PooledSessionHolder::Ptr &pHolder);
  void discard(const PooledSessionHolder::Ptr &pHolder);
  void closeAll(SessionMap &sessionMap);
  void limitCheck();
  void shutdownCheck();
  void incrementSessions(int num);
  PooledSessionHolder::Ptr newSession(const std::string &name);
  PooledSessionHolder::Ptr nextSession(SessionMap *container, const std::string &name);

 private:
  SessionFactory &factory_;
  int minSessions_;
  int maxSessions_;
  int nSessions_;
  std::atomic_bool shutdown_;
  std::atomic_bool pooling_;

  std::atomic_bool th_keepalive_stop_;
  std::atomic<int> th_keepalive_interval_;
  std::atomic_uint64_t randomSeed_;

  SessionMap hsmIdleSessions_;
  SessionMap svsIdleSessions_;
  SessionMap tsIdleSessions_;
  mutable std::recursive_mutex mutex_;
  std::thread th_keepalive_;

  friend class PooledSessionImpl;
};

}  // namespace hsmc
