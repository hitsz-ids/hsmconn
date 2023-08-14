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

#include <list>
#include <mutex>

#include "session_impl.h"

namespace hsmc {

class SessionPool;

class HSMC_API PooledSessionHolder {
 public:
  using Ptr = std::shared_ptr<PooledSessionHolder>;
  using LinkedIterator = std::list<Ptr>::iterator;

  PooledSessionHolder(SessionPool &owner, SessionImpl::Ptr pSessionImpl);

  virtual ~PooledSessionHolder();

  /// 获取被代理的SessionImpl对象
  /// \return 被代理的SessionImpl对象
  SessionImpl::Ptr session();

  /// 获取所属的SessionPool对象
  /// \return 所属的SessionPool对象
  SessionPool &owner();

  /// 更新最后访问时间
  void access();

  /// 获取空闲的毫秒数
  int idle();

 private:
  LinkedIterator getIterator();
  void setIterator(LinkedIterator it);
  friend class SessionPool;

 private:
  SessionPool &owner_;
  SessionImpl::Ptr pImpl_;
  std::chrono::time_point<std::chrono::steady_clock> lastUpdate_;
  std::mutex mux_;
  LinkedIterator it_; // store in linked list container
};

//
// inlines
//
inline SessionImpl::Ptr PooledSessionHolder::session() {
  return pImpl_;
}

inline SessionPool &PooledSessionHolder::owner() {
  return owner_;
}

inline void PooledSessionHolder::access() {
  std::lock_guard<std::mutex> guard(this->mux_);
  lastUpdate_ = std::chrono::steady_clock::now();
}

inline int PooledSessionHolder::idle() {
  std::lock_guard<std::mutex> guard(this->mux_);
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - lastUpdate_);
  return duration.count();
}

inline PooledSessionHolder::LinkedIterator PooledSessionHolder::getIterator() {
  return it_;
}

inline void PooledSessionHolder::setIterator(PooledSessionHolder::LinkedIterator it) {
  it_ = it;
}

}
