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

// 为能够从外部访问到sessionpool的private成员hsmIdleSessions_
#define private public

#include <chrono>
#include <vector>

#include "hsmc/hsmc.h"

TEST(SessionPoolTest, DefaultConstructor) {
  hsmc::SessionPool pool0_;
  hsmc::SessionPool pool1_;

  {
    auto s0 = pool1_.get();
    auto s1 = pool1_.get();
  }

  EXPECT_EQ(0, pool0_.idle());
  EXPECT_EQ(0, pool0_.used());
  EXPECT_EQ(hsmc::SessionPool::DEFAULT_MAX_SESSION, pool0_.capacity());

  EXPECT_EQ(2, pool1_.idle());
  EXPECT_EQ(0, pool1_.used());

  auto s2 = pool1_.get();
  EXPECT_EQ(1, pool1_.idle());
  EXPECT_EQ(1, pool1_.used());

  auto s3 = pool1_.get();
  EXPECT_EQ(0, pool1_.idle());
  EXPECT_EQ(2, pool1_.used());
}
#if 0
TEST(SessionPoolTest, MaxSession_getbyconntype) {
  // 创建DEFAULT_MAX_SESSION个session，期望不抛异常
  hsmc::SessionPool pool1;
  EXPECT_EQ(pool1.used(), 0);
  EXPECT_EQ(pool1.idle(), 0);
  try {
    std::vector<hsmc::Session> sessions;
    for (int i = 0; i < hsmc::SessionPool::DEFAULT_MAX_SESSION; ++i) {
      sessions.emplace_back(pool1.get());
    }

    EXPECT_EQ(pool1.used(), hsmc::SessionPool::DEFAULT_MAX_SESSION);
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  EXPECT_EQ(pool1.idle(), hsmc::SessionPool::DEFAULT_MAX_SESSION);

  // 创建 DEFAULT_MAX_SESSION + 1 个session，期望抛hsmc::PoolOverflowException异常
  bool throwPoolOverflowException = false;
  hsmc::SessionPool pool2;
  EXPECT_EQ(pool2.used(), 0);
  EXPECT_EQ(pool2.idle(), 0);
  try {
    std::vector<hsmc::Session> sessions;
    for (int i = 0; i < hsmc::SessionPool::DEFAULT_MAX_SESSION + 1; ++i) {
      sessions.emplace_back(pool1.get());
    }
  } catch (hsmc::PoolOverflowException &ex) {
    throwPoolOverflowException = true;
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  // 期望抛出了hsmc::PoolOverflowException异常
  EXPECT_TRUE(throwPoolOverflowException);
}

TEST(SessionPoolTest, MaxSession_getbyconnector) {
  // 创建DEFAULT_MAX_SESSION个session，期望不抛异常
  hsmc::SessionPool pool1;
  EXPECT_EQ(pool1.used(), 0);
  EXPECT_EQ(pool1.idle(), 0);
  try {
    auto names = hsmc::SessionFactory::instance().getConnectorNames();
    auto onename = names[0];

    std::vector<hsmc::Session> sessions;
    for (int i = 0; i < hsmc::SessionPool::DEFAULT_MAX_SESSION; ++i) {
      sessions.emplace_back(pool1.getByConnector(onename));
    }

    EXPECT_EQ(pool1.used(), hsmc::SessionPool::DEFAULT_MAX_SESSION);
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  EXPECT_EQ(pool1.idle(), hsmc::SessionPool::DEFAULT_MAX_SESSION);

  // 创建 DEFAULT_MAX_SESSION + 1 个session，期望抛hsmc::PoolOverflowException异常
  bool throwPoolOverflowException = false;
  hsmc::SessionPool pool2;
  EXPECT_EQ(pool2.used(), 0);
  EXPECT_EQ(pool2.idle(), 0);
  try {
    auto names = hsmc::SessionFactory::instance().getConnectorNames();
    auto onename = names[0];

    std::vector<hsmc::Session> sessions;
    for (int i = 0; i < hsmc::SessionPool::DEFAULT_MAX_SESSION + 1; ++i) {
      sessions.emplace_back(pool1.getByConnector(onename));
    }
  } catch (hsmc::PoolOverflowException &ex) {
    throwPoolOverflowException = true;
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  // 期望抛出了hsmc::PoolOverflowException异常
  EXPECT_TRUE(throwPoolOverflowException);
}

TEST(SessionPoolTest, CheckHeartbeat) {
  const int IDLE_SESSIONS = 64;          // 池内空闲session数量
  const int CLOSE_SESSIONS = 10;         // 主动关闭（失效）sesison数量
  const int HEART_INTERVAL = 3;          // session健康检查间隔（s）

  hsmc::SessionPool pool;
  auto hsmconnectors = pool.getFactory().getConnectors();
  for (auto conn : hsmconnectors) {
    conn->setHeartbeatInterval(HEART_INTERVAL); // 设置实例的心跳检查间隔
  }

  // pool内生成IDLE_SESSIONS个空闲session
  std::vector<hsmc::Session> sessions;
  for (auto i = sessions.size(); i < IDLE_SESSIONS; ++i) {
    auto session = pool.get();
    sessions.emplace_back(session);
  }
  sessions.clear();
  EXPECT_EQ(pool.idle(), IDLE_SESSIONS);

  srand(time(NULL));
  // 直接访问pool的hsmIdleSessions_，随机使其中的CLOSE_SESSIONS个空闲session失效
  int waittoclose = CLOSE_SESSIONS;
  while (waittoclose) {
    auto idle_sessions = pool.hsmIdleSessions_;

    auto offset = rand() % idle_sessions.size();

    auto it = std::next(idle_sessions.begin(), offset);
    if (!it->second->session()->isGood()) {
      continue;
    }
    it->second->session()->close();
    --waittoclose;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(HEART_INTERVAL * 1000));
  while (sessions.size() < IDLE_SESSIONS) {
    auto session = pool.get();
    // 获取的session均有效
    EXPECT_TRUE(session.isGood());
    sessions.emplace_back(session);
  }
  sessions.clear();

  // sessionpool空闲线程应该为IDLE_SESSIONS个
  EXPECT_EQ(pool.idle(), IDLE_SESSIONS);
}

TEST(SessionPoolTest, CheckIdleSessions) {
  const int IDLE_SESSIONS = 64;         // 池内空闲session数量
  const int IDLE_TIMEOUT_SESSIONS = 10; // 超时的sesison数量
  const int IDLE_TIMEOUT = 3;           // session超时时间，单位秒

  hsmc::SessionPool pool;
  pool.set_th_keepalive_interval(100);  // 每100ms轮询一次

  auto hsmconnectors = pool.getFactory().getConnectors();
  for (auto conn : hsmconnectors) {
    conn->setIdleTimeout(IDLE_TIMEOUT); // 设置实例的闲置超时
  }

  // pool内生成IDLE_SESSIONS个空闲session
  std::vector<hsmc::Session> sessions;
  for (auto i = sessions.size(); i < IDLE_SESSIONS; ++i) {
    auto session = pool.get();
    sessions.emplace_back(session);
  }
  sessions.clear();
  EXPECT_EQ(pool.idle(), IDLE_SESSIONS);

  for (int i = 0; i < IDLE_SESSIONS - IDLE_TIMEOUT_SESSIONS; i++) {
    auto session = pool.get();
    sessions.emplace_back(session);
  }

  // sleep IDLE_TIMEOUT时间，使的所有session超时
  std::this_thread::sleep_for(std::chrono::milliseconds((IDLE_TIMEOUT + 1) * 1000));

  // 返回pool中
  sessions.clear();
  { 
    auto session = pool.get();
  }
  EXPECT_EQ(pool.idle(), IDLE_SESSIONS - IDLE_TIMEOUT_SESSIONS);

  // sleep IDLE_TIMEOUT时间，使的所有session超时
  std::this_thread::sleep_for(std::chrono::milliseconds((IDLE_TIMEOUT + 1) * 1000));

  // sessionpool空闲线程应该为0个
  { 
    auto session = pool.get();
  }
  EXPECT_EQ(pool.idle(), 1);
}

TEST(SessionPoolTest, SetMaxSessions) {
  const int MAX_SESSIONS = 1024 * 2;

  hsmc::SessionPool pool;
  pool.set_maxSessions(MAX_SESSIONS);
  std::vector<hsmc::Session> sessions;

  EXPECT_EQ(pool.used(), 0);
  EXPECT_EQ(pool.idle(), 0);
  // 创建 MAX_SESSIONS 个session，期望不抛异常
  try {
    for (int i = 0; i < MAX_SESSIONS; ++i) {
      sessions.emplace_back(pool.get());
    }

    EXPECT_EQ(pool.used(), MAX_SESSIONS);
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  EXPECT_EQ(pool.used(), MAX_SESSIONS);

  // 创建第 MAX_SESSIONS + 1 个session，期望抛hsmc::PoolOverflowException异常
  bool throwPoolOverflowException = false;
  try {
    sessions.emplace_back(pool.get());
  } catch (hsmc::PoolOverflowException &ex) {
    throwPoolOverflowException = true;
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  // 期望抛出了hsmc::PoolOverflowException异常
  EXPECT_TRUE(throwPoolOverflowException);
}

TEST(SessionPoolTest, CreateSessionWithWeight) {
  const int SESSION_COUNT = 1000;
  // 计算所有connector的权重和
  int weight_sum = 0;
  auto connectors = hsmc::SessionFactory::instance().getConnectors(hsmc::ConnectorType::CT_HSM);
  for (auto &conn : connectors) {
      weight_sum += conn->getWeight();
  }

  std::vector<std::shared_ptr<hsmc::SessionImpl>> sessionCached;

  // 随机选择connector
  absl::BitGen bitgen_;
  auto selectedConnector = connectors[absl::Uniform<int>(bitgen_, 0, connectors.size())];

  int sessionCount = 0;
  for (int i = 0; i < SESSION_COUNT; i++) {
    auto sess = hsmc::SessionPool::instance().get();
    sessionCached.push_back(sess.impl());
    if (sess.getConnectorName() == selectedConnector->getName()) {
      ++sessionCount;
    }
  }
  sessionCached.clear();

  double weightPercent = (double)selectedConnector->getWeight() / weight_sum;
  double sessionPercent = (double)sessionCount / SESSION_COUNT;
  //误差在5%以内
  EXPECT_LT(sessionPercent, weightPercent + 0.05);
  EXPECT_GT(sessionPercent, weightPercent - 0.05);
}

TEST(SessionPoolTest, GetSessionWithWeight) {
  // 计算所有connector的权重和
  int weight_sum = 0;
  auto connectors = hsmc::SessionFactory::instance().getConnectors(hsmc::ConnectorType::CT_HSM);
  for (auto &conn : connectors) {
    weight_sum += conn->getWeight();
  }

  // 随机选择其中一个connector
  absl::BitGen bitgen_;
  auto selectedConnector = connectors[absl::Uniform<int>(bitgen_, 0, connectors.size())];

  // 计算该connector的权重占比
  double weightPercent = (double)selectedConnector->getWeight() / weight_sum;

  hsmc::SessionPool pool;
  std::vector<hsmc::Session> sessions;

  EXPECT_EQ(pool.used(), 0);
  EXPECT_EQ(pool.idle(), 0);
  try {
    for (int i = 0; i < pool.capacity(); ++i) {
      sessions.emplace_back(pool.get());
    }

    EXPECT_EQ(pool.used(), pool.capacity());
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  // 释放session并返回到pool
  sessions.clear();

  // 从pool中获取固定个数的session，并计算获取session是否符合权重比例
  const int ROUND = 10;
  const int fetchCount[ROUND] = {10, 50, 100, 200, 300, 400, 500, 600, 700, 800};
  for (int i = 0; i < ROUND; i++) {
    const int COUNT = fetchCount[i];

    int sessionCount = 0;
    for (int j = 0; j < COUNT; j++) {
      sessions.emplace_back(pool.get());
      if (sessions.back().getConnectorName() == selectedConnector->getName()) {
        ++sessionCount;
      }
    }
    sessions.clear();

    double sessionPercent = (double)sessionCount/COUNT;
    //误差在20%以内
    EXPECT_LT(sessionPercent, weightPercent + 0.2);
    EXPECT_GT(sessionPercent, weightPercent - 0.2);
  }
}

/*
TEST(SessionPoolTest, PerformanceMeasure) {
  const int MAX_SESSIONS = 1024 * 10;

  hsmc::SessionPool pool;
  pool.setMaxSessions(MAX_SESSIONS);
  std::vector<hsmc::Session> sessions;

  EXPECT_EQ(pool.used(), 0);
  EXPECT_EQ(pool.idle(), 0);
  // 创建 MAX_SESSIONS 个session，期望不抛异常
  try {
    for (int i = 0; i < MAX_SESSIONS; ++i) {
      sessions.push_back(pool.get());
    }

    EXPECT_EQ(pool.used(), MAX_SESSIONS);
  } catch (std::exception &ex) {
    EXPECT_TRUE(false);
  }
  EXPECT_EQ(pool.used(), MAX_SESSIONS);

  auto t0 = std::chrono::steady_clock::now();
  sessions.clear();
  for (int i = 0; i < MAX_SESSIONS / 2; ++i) {
    sessions.push_back(pool.get());
  }

  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - t0);

  std::cout << "duration is " << duration.count() << std::endl;
}
*/

#endif