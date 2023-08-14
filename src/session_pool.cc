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

#include "hsmc/session_pool.h"

#include <absl/strings/str_format.h>

#include <iostream>
#include <set>

#include "hsmc/session_factory.h"
#include "hsmc/exception.h"
#include "utils/log_internal.h"

namespace hsmc {

using container = SessionPool::container;

void SessionPool::SessionMap::erase(container::iterator it) {
  // delete from the list
  auto connName = it->second->session()->getConnector()->getName();
  auto cit = connectors_.find(connName);
  if (connectors_.end() != cit) {
    cit->second->second.erase(it->second->getIterator());
    cit->second->first--;
  }
  // delete from the map
  container::erase(it);
}

std::pair<container::iterator, bool> SessionPool::SessionMap::insert(container::value_type &&pair) {
  // append to the list
  auto connName = pair.second->session()->getConnector()->getName();
  auto cit = connectors_.find(connName);
  if (connectors_.end() == cit) {
    auto result = connectors_.insert(
        std::make_pair(connName, std::make_shared<session_list>(0, std::list<PooledSessionHolder::Ptr>())));
    if (result.second) {
      cit = result.first;
    }
  }
  cit->second->second.emplace_front(pair.second);
  cit->second->first++;
  pair.second->setIterator(cit->second->second.begin());
  // append to the map
  return container::insert(pair);
}

void SessionPool::SessionMap::purge_idle() {
  for (auto p : connectors_) {
    int timeout = -1;
    for (auto rit = p.second->second.rbegin(); rit != p.second->second.rend(); rit++) {
      auto c = *rit;
      if (timeout < 0) {
        // timeout为0时，则不检查
        if ((timeout = c->session()->getConnector()->getIdleTimeout()) <= 0) break;
      }

      // 当前session未超时则跳出
      if (c->idle() < timeout * 1000) {
        break;
      }

      // 清理当前超时session
      container::erase(c->session()->getId());
      p.second->second.erase(c->getIterator());
      p.second->first--;
      c->owner().discard(c);
    }
  }
}

PooledSessionHolder::Ptr SessionPool::SessionMap::next(const std::string &connector) {
  auto cit = connectors_.find(connector);
  if (connectors_.end() != cit) {
    auto it = cit->second->second.begin();
    if (it != cit->second->second.end()) {
      auto c = *it;
      container::erase(c->session()->getId());
      cit->second->second.pop_front();
      cit->second->first--;
      return c;
    }
  }
  return nullptr;
}

const int SessionPool::DEFAULT_MAX_SESSION = 1024;

SessionPool &SessionPool::instance() {
  static SessionPool sp(SessionFactory::instance());
  return sp;
}

SessionPool::SessionPool(int minSessions, int maxSessions)
    : SessionPool(SessionFactory::instance(), minSessions, maxSessions) {
}

SessionPool::SessionPool(SessionFactory &factory, int minSessions, int maxSessions)
    : factory_(factory),
      minSessions_(minSessions),
      maxSessions_(maxSessions),
      nSessions_(0),
      shutdown_(false),
      pooling_(true),
      th_keepalive_stop_(false),
      th_keepalive_interval_(3000),
      randomSeed_(0) {
  factory_.initWeightRoundTable();
  th_keepalive_ = std::thread([&, this]() {
    // SessionPool初始化时开启一个线程，定期调用purgeDeadSessions以关闭失效session
    int cnt = 0;
    while (!this->th_keepalive_stop_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      if ((++cnt) * 50 >= this->th_keepalive_interval_) {
        auto idle = this->idle();
        auto used = this->used();
        auto start = std::chrono::steady_clock::now();
        this->purgeDeadSessions();
        auto end = std::chrono::steady_clock::now();
        auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        // 记录执行一次清理空闲session耗时大于 3s 的事件
        if (dur.count() >= 3000) {
          Logger()->error(
              "purgeDeadSession consuming {} ms; before purge: {} idle sessions, {} used sessions; after purge: {} "
              "idle sessions, {} used sessions",
              dur.count(), idle, used, this->idle(), this->used());
        }
        cnt = 0;
      }
    }
  });
}

SessionPool::~SessionPool() {
  try {
    shutdown();
  } catch (hsmc::Exception &ex) {
    std::cerr << "SessionPool shutdown failure, " << ex.what() << std::endl;
  } catch (...) {
    std::cerr << "SessionPool shutdown failure" << std::endl;
  }
}

void SessionPool::setPooling(bool pooling) {
  pooling_ = pooling;
}

void SessionPool::setKeepaliveInterval(int interval) {
  th_keepalive_interval_ = interval;
}

void SessionPool::setMaxSessions(int maxSessions) {
  maxSessions_ = maxSessions;
}

void SessionPool::incrementSessions(int num) {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  nSessions_ += num;
}

void SessionPool::limitCheck() {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  if (nSessions_ >= maxSessions_) {
    throw PoolOverflowException(
        absl::StrFormat("too many sessions, %d sessions exist, maximum %d allowed", nSessions_, maxSessions_));
  }
}

void SessionPool::shutdownCheck() {
  if (shutdown_) {
    throw InvalidAccessException("Session pool has been shut down.");
  }
}

PooledSessionHolder::Ptr SessionPool::newSession(const std::string &name) {
  limitCheck();
  auto s = factory_.create(name);
  auto sessholder = std::make_shared<PooledSessionHolder>(*this, s.impl());
  incrementSessions(1);
  return sessholder;
}

PooledSessionHolder::Ptr SessionPool::nextSession(SessionMap *container, const std::string &name) {
  while (container->size()) {
    auto c = container->next(name);
    if (!c) {
      return nullptr;
    }

    // if idle time less than heartbeat, return session
    auto interval = c->session()->getConnector()->getHeartbeatInterval();
    if (interval == 0 || c->idle() < interval * 1000) return c;
    // perform heartbeat check before return the session
    int errcode = 0;
    bool recover = false;
    if (c->session()->isGood(&errcode, &recover)) {
      // session is ok
      return c;
    }

    // discard the bad session
    c->owner().discard(c);

    // if recover flag detected, recover the connector
    if (recover) {
      auto conn = c->session()->getConnector();
      auto name = conn->getName();
      while ((c = container->next(name)) != nullptr) {
        c->owner().discard(c);
      }
      conn->recover();
    }
  }

  return nullptr;
}

Session SessionPool::get(const std::string &id) {
  Logger()->debug("get session by id: {}", id);

  shutdownCheck();

  PooledSessionHolder::Ptr pHolder;
  std::vector<SessionMap *> maps = {&hsmIdleSessions_, &svsIdleSessions_, &tsIdleSessions_};
  {
    for (auto idle_sessions : maps) {
      std::lock_guard<std::recursive_mutex> guard(this->mutex_);
      // 根据id查询
      auto it = idle_sessions->find(id);
      if (idle_sessions->end() == it) {
        continue;
      }
      pHolder = it->second;
      idle_sessions->erase(it);
      break;
    }
  }

  if (!pHolder) {
    throw NotFoundException(absl::StrFormat("fail to get a valid session %s", id.c_str()));
  }

  auto impl = std::make_shared<PooledSessionImpl>(pHolder);
  Logger()->debug("get session by id, return {}", impl->getId());

  return Session(impl);
}

Session SessionPool::get(ConnectorType conntype) {
  Logger()->debug("get session by connector type: {}", fmt::underlying(conntype));

  shutdownCheck();

  SessionMap *idle_sessions;
  if (ConnectorType::CT_HSM == conntype) {
    idle_sessions = &hsmIdleSessions_;
  } else if (ConnectorType::CT_SVS == conntype) {
    idle_sessions = &svsIdleSessions_;
  } else if (ConnectorType::CT_TSS == conntype) {
    idle_sessions = &tsIdleSessions_;
  } else {
    throw SystemException(absl::StrFormat("conntype `%d` not valid", conntype));
  }

  PooledSessionHolder::Ptr pHolder;
  std::string connector = factory_.getWeightRoundConnectorName(conntype);
  {
    std::lock_guard<std::recursive_mutex> guard(this->mutex_);
    pHolder = nextSession(idle_sessions, connector);
  }

  if (!pHolder) {
    if ((pHolder = newSession(connector)) == nullptr) {
      throw SdfExcuteException(absl::StrFormat("fail to create session with connector name: %s", connector.c_str()));
    }
  }

  auto impl = std::make_shared<PooledSessionImpl>(pHolder);
  Logger()->debug("get session by type, return {}", impl->getId());

  return Session(impl);
}

Session SessionPool::getByConnector(const std::string &connector) {
  Logger()->debug("get session by connector name: {}", connector);

  shutdownCheck();

  PooledSessionHolder::Ptr pHolder;
  std::vector<SessionMap *> maps = {&hsmIdleSessions_, &svsIdleSessions_, &tsIdleSessions_};
  {
    for (auto idle_sessions : maps) {
      std::lock_guard<std::recursive_mutex> guard(this->mutex_);
      pHolder = nextSession(idle_sessions, connector);
      if (pHolder) break;
    }
  }

  if (!pHolder) {
    if ((pHolder = newSession(connector)) == nullptr) {
      throw SdfExcuteException(absl::StrFormat("fail to create session with connector name: %s", connector.c_str()));
    }
  }

  auto impl = std::make_shared<PooledSessionImpl>(pHolder);
  Logger()->debug("get session by name, returned {}", impl->getId());

  return Session(impl);
}

Session SessionPool::getByConnectorSet(const std::vector<std::string> &connSet) {
  shutdownCheck();

  int setSize = connSet.size();
  if (0 == setSize) {
    throw NullValueException(absl::StrFormat("connector set is null"));
  }

  int index = 0;
  for (int i = 0; i < setSize - 1; i++) {
    try {
      index = randomSeed_.fetch_add(1) % setSize;
      return getByConnector(connSet[index]);
    } catch (Exception ex) {
      Logger()->error("fail to get session from {}", connSet[index]);
      continue;
    }
  }

  index = randomSeed_.fetch_add(1) % setSize;
  return getByConnector(connSet[index]);
}

void SessionPool::putBack(const PooledSessionHolder::Ptr &pHolder) {
  if (shutdown_) return;

  auto sid = pHolder->session()->getId();
  Logger()->debug("putting back session, {}", sid);

  try {
    if (pooling_ && pHolder->session()->getConnector()->isPooling()) {
      Logger()->debug("session recycled, {}", sid);
      pHolder->access();

      SessionMap *idle_sessions;
      auto conntype = pHolder->session()->getConnector()->getConnectorType();
      if (ConnectorType::CT_HSM == conntype) {
        idle_sessions = &hsmIdleSessions_;
      } else if (ConnectorType::CT_SVS == conntype) {
        idle_sessions = &svsIdleSessions_;
      } else if (ConnectorType::CT_TSS == conntype) {
        idle_sessions = &tsIdleSessions_;
      } else {
        throw SystemException(absl::StrFormat("recycled session conntype `%d` not valid", conntype));
      }

      std::lock_guard<std::recursive_mutex> guard(this->mutex_);
      idle_sessions->insert(std::make_pair(sid, pHolder));
    } else {
      discard(pHolder);
    }
  } catch (std::exception &e) {
    discard(pHolder);
    throw e;
  }
}

void SessionPool::discard(const PooledSessionHolder::Ptr &pHolder) {
  pHolder->session()->close();
  incrementSessions(-1);
}

void SessionPool::purgeDeadSessions() {
  if (shutdown_) return;

  std::vector<SessionMap *> all_sessions = {&hsmIdleSessions_, &svsIdleSessions_, &tsIdleSessions_};
  for (auto idle_sessions : all_sessions) {
    std::lock_guard<std::recursive_mutex> guard(this->mutex_);
    idle_sessions->purge_idle();
  }
}

void SessionPool::shutdown() {
  if (shutdown_.exchange(true)) return;

  th_keepalive_stop_ = true;
  th_keepalive_.join();
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  std::vector<SessionMap *> maps = {&hsmIdleSessions_, &svsIdleSessions_, &tsIdleSessions_};
  for (auto idle_sessions : maps) {
    closeAll(*idle_sessions);
  }
}

void SessionPool::closeAll(SessionMap &sessionMap) {
  auto it = sessionMap.begin();
  while (it != sessionMap.end()) {
    try {
      it->second->session()->close();
    } catch (...) {
    }
    sessionMap.erase(it++);
    if (nSessions_ > 0) {
      --nSessions_;
    }
  }
}

int SessionPool::capacity() const {
  return maxSessions_;
}

int SessionPool::used() const {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  return nSessions_ - idle();
}

int SessionPool::idle() const {
  std::lock_guard<std::recursive_mutex> guard(this->mutex_);
  return hsmIdleSessions_.size() + svsIdleSessions_.size() + tsIdleSessions_.size();
}

SessionFactory &SessionPool::getFactory() {
  return factory_;
}

}  // namespace hsmc