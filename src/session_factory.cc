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

#include "hsmc/session_factory.h"

#include <absl/strings/str_format.h>
#include <vendors/fisec/connector.h>
#include <vendors/fisec/svs/connector.h>

#include <iostream>

#include "hsmc/exception.h"
#include "hsmc/svs/infosec/connector.h"
#include "hsmc/svs/ndsec/connector.h"
#include "hsmc/svs/sinocipher/connector.h"
#include "utils/log_internal.h"
#include "vendors/bjca/connector.h"
#include "vendors/dean/connector.h"
#include "vendors/emu/connector.h"
#include "vendors/infosec/tss/connector.h"
#include "vendors/ndsec/connector.h"
#include "vendors/ndsec/tss/connector.h"
#include "vendors/sansec/connector.h"
#include "vendors/sinocipher/connector.h"
#include "vendors/sinocipher/tss/connector.h"
#include "version.h"
#include "yaml-cpp/yaml.h"

namespace hsmc {

const char *SessionFactory::HSMC_CONFIG_ENV_NAME = "HSMC_CONFIG";

SessionFactory::SessionFactory() : shutdown_(false), inited_(false), weight_sum_{0} {
}

SessionFactory::~SessionFactory() {
  try {
    shutdown();
  } catch (hsmc::Exception &ex) {
    std::cerr << "SessionFactory shutdown failure, " << ex.what() << std::endl;
  } catch (...) {
    std::cerr << "SessionFactory shutdown failure" << std::endl;
  }
}

SessionFactory &SessionFactory::instance() {
  static SessionFactory sf;
  return sf;
}

std::string SessionFactory::getVersion() {
  return absl::StrFormat("%d.%d.%d", hsmc_VERSION_MAJOR, hsmc_VERSION_MINOR, hsmc_VERSION_PATCH);
}

void SessionFactory::add(Connector::Ptr conn) {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  auto name = conn->getName();
  auto it = connectors_.find(name);
  // std::cout << "SessionFactory add name=" << name << " size=" << connectors_.size() << std::endl;
  if (connectors_.end() != it) {
    throw SystemException(absl::StrFormat("connector `%s` already exist size=%d", name.c_str(), connectors_.size()));
  }
  connectors_.insert(std::make_pair(name, conn));
  ConnectorType ct = conn->getConnectorType();
  if (ConnectorType::CT_HSM == ct) {
    hsm_connectors_.push_back(conn);
  } else if (ConnectorType::CT_SVS == ct) {
    svs_connectors_.push_back(conn);
  } else if (ConnectorType::CT_TSS == ct) {
    ts_connectors_.push_back(conn);
  } else {
    throw SystemException("unexpected connector type");
  }

  weight_sum_[static_cast<int>(ct)] += conn->getWeight();
}

Session SessionFactory::create(const std::string &name) {
  Connector::Ptr conn;
  {
    std::lock_guard<std::recursive_mutex> guard(this->mutex_);
    auto it = connectors_.find(name);
    if (connectors_.end() == it) {
      throw NotFoundException(absl::StrFormat("connector `%s` not found", name.c_str()));
    }
    conn = it->second;
  }
  return Session(conn->createSession());
}

void SessionFactory::init() {
  char *env_config = getenv(HSMC_CONFIG_ENV_NAME);
  if (nullptr == env_config) {
    throw SystemException(absl::StrFormat("Env name `%s` not set", HSMC_CONFIG_ENV_NAME));
  }

  init(env_config);
}

void SessionFactory::init(const std::string &configfile) {
  if (inited_.exchange(true)) return;

  // parse listen config
  YAML::Node config = YAML::LoadFile(configfile);

  if (!config) {
    throw SystemException(absl::StrFormat("invalid config file: %s", configfile.c_str()));
  }

  // parse backends config
  YAML::Node backends = config["backends"];
  if (!backends) {
    throw SystemException(absl::StrFormat("no `backends` configured in %s", configfile.c_str()));
  }

  YAML::Node hsm_vendors = backends["hsm"];
  if (hsm_vendors) {
    for (auto vendor : hsm_vendors) {
      YAML::const_iterator it = vendor.begin();
      std::string vendorName = it->first.as<std::string>();

      YAML::Node att = it->second;
      YAML::Node conn = att["connector"];

      if (!conn) {
        throw SystemException(
            absl::StrFormat("no `connector` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }
      std::string vendorConnector = conn.as<std::string>();

      YAML::Node nodes = att["nodes"];
      if (!nodes) {
        throw SystemException(
            absl::StrFormat("no `nodes` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }

      for (auto &&node : nodes) {
        std::string nodeName = node["name"].as<std::string>();
        std::string nodeConfig = node["config"].as<std::string>();

        auto connector = createConnector(vendorName);

        if (connector == nullptr) {
          throw SystemException(absl::StrFormat("vendor connector `%s` not supported", vendorName.c_str()));
        }

        std::string name = vendorName;
        name += "-";
        name += nodeName;

        connector->setName(name);
        connector->setConfig(nodeConfig);
        connector->setLibrary(vendorConnector);

        if (node["pooling"]) {
          auto pooling = node["pooling"].as<bool>();
          connector->setPooling(pooling);
        }

        if (node["pcie"]) {
          auto pcie = node["pcie"].as<bool>();
          connector->setPCIE(pcie);
        }

        if (node["weight"]) {
          auto weight = node["weight"].as<uint16_t>();
          connector->setWeight(weight);
        }

        if (node["heartbeat_interval"]) {
          auto interval = node["heartbeat_interval"].as<int>();
          connector->setHeartbeatInterval(interval);
        }

        if (node["idle_timeout"]) {
          auto timeout = node["idle_timeout"].as<int>();
          connector->setIdleTimeout(timeout);
        }

        connector->setConnectorType(hsmc::ConnectorType::CT_HSM);
        add(connector);
      }
    }
  }

  YAML::Node svs_vendors = backends["svs"];
  if (svs_vendors) {
    for (auto vendor : svs_vendors) {
      YAML::const_iterator it = vendor.begin();
      std::string vendorName = it->first.as<std::string>();

      YAML::Node att = it->second;
      YAML::Node conn = att["connector"];

      if (!conn) {
        throw SystemException(
            absl::StrFormat("no `connector` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }
      std::string vendorConnector = conn.as<std::string>();

      YAML::Node nodes = att["nodes"];
      if (!nodes) {
        throw SystemException(
            absl::StrFormat("no `nodes` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }

      for (auto &&node : nodes) {
        std::string nodeName = node["name"].as<std::string>();
        std::string nodeConfig = node["config"].as<std::string>();

        auto connector = createConnector(vendorName, ConnectorType::CT_SVS);

        if (connector == nullptr) {
          throw SystemException(absl::StrFormat("vendor connector `%s` not supported", vendorName.c_str()));
        }

        std::string name = vendorName;
        name += "-";
        name += nodeName;

        connector->setName(name);
        connector->setConfig(nodeConfig);
        connector->setLibrary(vendorConnector);

        if (node["pooling"]) {
          auto pooling = node["pooling"].as<bool>();
          connector->setPooling(pooling);
        }

        if (node["ip"]) {
          auto ip = node["ip"].as<std::string>();
          connector->SVS_SetIp(ip);
        }

        if (node["port"]) {
          auto port = node["port"].as<uint16_t>();
          connector->SVS_SetPort(port);
        }

        if (node["password"]) {
          auto password = node["password"].as<std::string>();
          connector->SVS_SetPassword(password);
        }

        if (nodes["weight"]) {
          auto weight = nodes["weight"].as<uint16_t>();
          connector->setWeight(weight);
        }

        if (node["heartbeat_interval"]) {
          auto interval = node["heartbeat_interval"].as<int>();
          connector->setHeartbeatInterval(interval);
        }

        if (node["idle_timeout"]) {
          auto timeout = node["idle_timeout"].as<int>();
          connector->setIdleTimeout(timeout);
        }

        connector->setConnectorType(hsmc::ConnectorType::CT_SVS);
        add(connector);
      }
    }
  }

  YAML::Node tss_vendors = backends["tss"];
  if (tss_vendors) {
    for (auto vendor : tss_vendors) {
      YAML::const_iterator it = vendor.begin();
      std::string vendorName = it->first.as<std::string>();

      YAML::Node att = it->second;
      YAML::Node conn = att["connector"];

      if (!conn) {
        throw SystemException(
            absl::StrFormat("no `connector` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }
      std::string vendorConnector = conn.as<std::string>();

      YAML::Node nodes = att["nodes"];
      if (!nodes) {
        throw SystemException(
            absl::StrFormat("no `nodes` configured under `%s` in %s", vendorName.c_str(), configfile.c_str()));
      }

      for (auto &&node : nodes) {
        std::string nodeName = node["name"].as<std::string>();
        std::string nodeConfig = node["config"].as<std::string>();

        auto connector = createConnector(vendorName, ConnectorType::CT_TSS);

        if (connector == nullptr) {
          throw SystemException(absl::StrFormat("vendor connector `%s` not supported", vendorName.c_str()));
        }

        std::string name = vendorName;
        name += "-";
        name += nodeName;

        connector->setName(name);
        connector->setConfig(nodeConfig);
        connector->setLibrary(vendorConnector);

        if (node["pooling"]) {
          auto pooling = node["pooling"].as<bool>();
          connector->setPooling(pooling);
        }

        if (nodes["weight"]) {
          auto weight = nodes["weight"].as<uint16_t>();
          connector->setWeight(weight);
        }

        if (node["heartbeat_interval"]) {
          auto interval = node["heartbeat_interval"].as<int>();
          connector->setHeartbeatInterval(interval);
        }

        if (node["idle_timeout"]) {
          auto timeout = node["idle_timeout"].as<int>();
          connector->setIdleTimeout(timeout);
        }

        connector->setConnectorType(hsmc::ConnectorType::CT_TSS);
        add(connector);
      }
    }
  }
}

Connector::Ptr SessionFactory::createConnector(const std::string &name, ConnectorType ct) {
  Connector::Ptr connector;
  if (ConnectorType::CT_HSM == ct) {
    if (name == "bjca") {
      connector = std::make_shared<hsmc::bjca::Connector>();
    } else if (name == "ndsec") {
      connector = std::make_shared<hsmc::ndsec::Connector>();
    } else if (name == "emu") {
      connector = std::make_shared<hsmc::emu::Connector>();
    } else if (name == "fisec") {
      connector = std::make_shared<hsmc::fisec::Connector>();
    } else if (name == "sinocipher") {
      connector = std::make_shared<hsmc::sinocipher::Connector>();
    } else if (name == "dean") {
      connector = std::make_shared<hsmc::dean::Connector>();
    } else if (name == "sansec") {
      connector = std::make_shared<hsmc::sansec::Connector>();
    }
  } else if (ConnectorType::CT_SVS == ct) {
    if (name == "fisec") {
      connector = std::make_shared<hsmc::svs::fisec::Connector>();
    } else if (name == "sinocipher") {
      connector = std::make_shared<hsmc::svs::sinocipher::Connector>();
    } else if (name == "ndsec") {
      connector = std::make_shared<hsmc::svs::ndsec::Connector>();
    } else if (name == "infosec") {
      connector = std::make_shared<hsmc::svs::infosec::Connector>();
    }
  } else if (ConnectorType::CT_TSS == ct) {
    if (name == "sinocipher") {
      connector = std::make_shared<hsmc::tss::sinocipher::Connector>();
    } else if (name == "ndsec") {
      connector = std::make_shared<hsmc::tss::ndsec::Connector>();
    } else if (name == "infosec") {
      connector = std::make_shared<hsmc::tss::infosec::Connector>();
    }
  }

  return connector;
}

std::vector<std::string> SessionFactory::getConnectorNames(ConnectorType conntype) const {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);

  std::vector<std::string> names;
  for (auto &it : connectors_) {
    if (ConnectorType::CT_MAX == conntype || it.second->getConnectorType() == conntype) {
      names.push_back(it.first);
    }
  }
  return names;
}

std::vector<Connector::Ptr> SessionFactory::getConnectors(ConnectorType conntype) const {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  std::vector<Connector::Ptr> connectors;
  for (auto &it : connectors_) {
    if (ConnectorType::CT_MAX == conntype || it.second->getConnectorType() == conntype) {
      connectors.push_back(it.second);
    }
  }
  return connectors;
}

Connector::Ptr SessionFactory::getConnector(const std::string &name) const {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  auto it = connectors_.find(name);
  if (it != connectors_.end()) {
    return it->second;
  }
  return nullptr;
}

void SessionFactory::setConnectorWeight(const Connector::Ptr &conn, int weight) {
  if (!conn) return;

  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  weight_sum_[static_cast<int>(conn->getConnectorType())] += (weight - conn->getWeight());
  conn->setWeight(weight);
}

void SessionFactory::shutdown() {
  if (shutdown_.exchange(true)) return;
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  for (const auto &it : connectors_) {
    it.second->close();
  }
  connectors_.clear();
}

void SessionFactory::reset(const std::string &name) {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  auto it = connectors_.find(name);
  if (it != connectors_.end()) {
    it->second->close();
  }
}

void SessionFactory::initWeightRoundTable() {
  hsm_connector_round_table.connector_round_table = updateWeightRoundTable(ConnectorType::CT_HSM);
  svs_connector_round_table.connector_round_table = updateWeightRoundTable(ConnectorType::CT_SVS);
  ts_connector_round_table.connector_round_table = updateWeightRoundTable(ConnectorType::CT_TSS);
}

std::vector<uint16_t> SessionFactory::updateWeightRoundTable(ConnectorType ct) {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  std::vector<uint16_t> connector_round;
  std::vector<int> weight_current_array;
  ConnectorArray *conns = nullptr;
  if (ConnectorType::CT_HSM == ct) {
    conns = &hsm_connectors_;
  } else if (ConnectorType::CT_SVS == ct) {
    conns = &svs_connectors_;
  } else if (ConnectorType::CT_TSS == ct) {
    conns = &ts_connectors_;
  }
  if (conns != nullptr) {
    connector_round.resize(this->weight_sum_[static_cast<int>(ct)]);
    weight_current_array.resize(conns->size());
    for (int n = 0; n < this->weight_sum_[static_cast<int>(ct)]; n++) {
      int maxSub;
      for (int m = 0; m < conns->size(); m++) {
        weight_current_array[m] += (*conns)[m]->getWeight();
        if (m == 0 || (*conns)[m]->getWeight() > weight_current_array[maxSub]) {
          maxSub = m;
        }
      }
      weight_current_array[maxSub] -= this->weight_sum_[static_cast<int>(ct)];
      connector_round[n] = maxSub;
    }
  }
  return connector_round;
}

std::string SessionFactory::getWeightRoundConnectorName(ConnectorType ct) {
  ConnectorRoundTable *crtable;
  ConnectorArray *conns = nullptr;
  if (ConnectorType::CT_HSM == ct) {
    conns = &hsm_connectors_;
    crtable = &hsm_connector_round_table;
  } else if (ConnectorType::CT_SVS == ct) {
    conns = &svs_connectors_;
    crtable = &svs_connector_round_table;
  } else if (ConnectorType::CT_TSS == ct) {
    conns = &ts_connectors_;
    crtable = &ts_connector_round_table;
  }
  if (crtable != nullptr) {
    std::lock_guard<std::recursive_mutex> guard(crtable->mutex_);
    if (crtable->choiceIndex < crtable->connector_round_table.size()) {
      size_t index = crtable->connector_round_table[crtable->choiceIndex];
      if (index < conns->size()) {
        std::string conname = (*conns)[index]->getName();
        if (++crtable->choiceIndex == crtable->connector_round_table.size()) {
          crtable->choiceIndex = 0;
        }
        return conname;
      }
    }
  }
  return nullptr;
}

bool SessionFactory::getConnectorStatus(const std::string &name) {
  if (!inited_.load()) {
    Logger()->error("getConnectorStatus return false because of not initializing");
    return false;
  }

  std::shared_ptr<Session> sessionPtr = nullptr;
  try {
    auto session = create(name);
    sessionPtr = std::make_shared<Session>(session);
  } catch (hsmc::Exception &ex) {
    Logger()->error("getConnectorStatus return false because of exception:{}", ex.what());
    return false;
  } catch (std::bad_alloc &ex) {
    Logger()->error("getConnectorStatus return false because of exception:{}", ex.what());
    return false;
  }

  bool status = sessionPtr->isGood();
  sessionPtr->close();
  return status;
}

}  // namespace hsmc
