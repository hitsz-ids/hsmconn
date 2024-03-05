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

#include <mutex>
#include <vector>
#include <atomic>
#include <unordered_map>
#include "connector.h"
#include "session.h"

namespace hsmc {

/// `SessionFactory`维护了服务器密码机、签名验签服务器、时间戳服务器三种设备的设备资源池信息，
/// 并通过创建不同设备节点的`Connector`对象实现对该节点的接口调用。由于`SessionFactory`在
/// 内存中缓存了每个设备节点的`Connector`对象（以密码机为例，一个密码机`Connector`对象映射到一
/// 个已打开的设备句柄），并通过该`Connector`对象打开对应设备的一个`Session`会话。
class HSMC_API SessionFactory final {
 public:

  /// SessionFactory构造函数
  SessionFactory();

  /// SessionFactory析构函数
  ~SessionFactory();

  SessionFactory(const SessionFactory &) = delete;             // copy constructor
  SessionFactory(SessionFactory &&) = delete;                  // move constructor
  SessionFactory &operator=(const SessionFactory &) = delete;  // copy assign
  SessionFactory &operator=(SessionFactory &&) = delete;       // move assign

  /// deprecated: 会话工厂单例
  static SessionFactory &instance();

  /// 获取版本号
  /// todo: 未来版本将移除该接口
  /// \return 版本号
  std::string getVersion();

  /// 默认从环境变量HSMC_CONFIG中读取配置文件路径
  void init();

  /// 读取YAML配置文件config，解析不同厂商密码机的配置及连接器。
  /// 若配置文件未包含以上必要配置，则抛出SystemException异常。
  /// 解析YAML采用了yaml-cpp的库，当文件不存在是则抛出yaml-cpp的BadFile异常。
  /// \param config 配置文件路径
  void init(const std::string &config);

  /// 添加指定供应商的密码设备的连接器
  /// \param conn 连接器实例智能指针
  void add(Connector::Ptr conn);

  /// 根据密码设备节点名称创建对应的会话
  /// \param name 设备节点名称格式：供应商名称-密码机实例名称，例如：emu-node1
  /// \return 指定密码设备节点的会话对象
  Session create(const std::string &name);

  /// 获取当前注册的所有密码设备节点名称，名称格式：供应商-密码设备名称
  /// \param conntype 类型，默认为CT_MAX，返回所有类型实例
  /// \return 供应商密码设备节点名称的数组
  std::vector<std::string> getConnectorNames(ConnectorType conntype = ConnectorType::CT_MAX) const;

  /// 获取当前注册的所有密码设备节点的连接器实例
  /// \param conntype 类型，默认为CT_MAX，返回所有类型实例
  /// \return 供应商密码设备节点连接器对象的数组
  std::vector<Connector::Ptr> getConnectors(ConnectorType conntype = ConnectorType::CT_MAX) const;

  /// 根据指定设备节点名称的连接器实例
  /// \param name 设备名称
  /// \return 设备节点连接器对象
  Connector::Ptr getConnector(const std::string &name) const;

  /// 获取设备节点的状态
  /// \param name 设备节点的名称
  /// \return 设备节点的状态，正常返回true，否则返回false
  bool getConnectorStatus(const std::string &name);

  /// 设置设备连接器新的权重
  /// \param conn 设备连接器对象
  /// \param weight 权重值
  void setConnectorWeight(const Connector::Ptr &conn, int weight);

  /// 释放资源
  void shutdown();

  /// 重置指定的设备连接器
  /// \param name 设备节点名称
  void reset(const std::string &name);

  /// 创建设备连接器
  /// \param name 设备节点名称
  /// \param ct   设备类型，默认为CT_HSM服务器密码机
  /// \return 设备连接器对象
  Connector::Ptr createConnector(const std::string &name, ConnectorType ct = ConnectorType::CT_HSM);

  /// 设备连接器容器类型
  using ConnectorArray = std::vector<Connector::Ptr>;

  /// 设备连接器的权重表
  class ConnectorRoundTable {
   public:
    ConnectorRoundTable();
    size_t choiceIndex;
    mutable std::recursive_mutex mutex_;
    std::vector<uint16_t> connector_round_table;
  };

  ConnectorRoundTable hsm_connector_round_table;
  ConnectorRoundTable svs_connector_round_table;
  ConnectorRoundTable ts_connector_round_table;

  /// 初始化设备的权重表
  void initWeightRoundTable();

  /// 获取指定设备类型的下一个被调度的设备名称
  /// \param ct 设备类型
  /// \return 设备名称
  std::string getWeightRoundConnectorName(ConnectorType ct);

  /// 更新指定设备的权重表
  std::vector<uint16_t> updateWeightRoundTable(ConnectorType ct);

 private:
  using Connectors = std::unordered_map<std::string, Connector::Ptr>;
  Connectors connectors_;

  ConnectorArray hsm_connectors_;
  ConnectorArray svs_connectors_;
  ConnectorArray ts_connectors_;

  std::atomic<bool> shutdown_;
  std::atomic<bool> inited_;
  int weight_sum_[static_cast<int>(ConnectorType::CT_MAX)];

  mutable std::recursive_mutex mutex_;

  static const char *HSMC_CONFIG_ENV_NAME;
};

}  // namespace hsmc
