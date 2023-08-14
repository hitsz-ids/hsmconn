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

#include <memory>
#include <list>
#include <string>
#include <atomic>
#include <utility>
#include <mutex>
#include "absl/memory/memory.h"
#include <openssl/evp.h>

namespace hsmc {
namespace emu {

struct Session;
struct Device;

using DevicePtr = std::shared_ptr<Device>;
using DeviceWeakPtr = std::weak_ptr<Device>;
using SessionPtr = std::shared_ptr<Session>;
using SessionWeakPtr = std::weak_ptr<Session>;

using DeviceHandle = void *;
using SessionHandle = void *;
using KeyHandle = void *;

struct Device {
  explicit Device(std::string id);
  void eraseSession(const SessionPtr &sessPtr);
  std::string devid_;
  std::list<SessionPtr> sessions_;
  std::mutex mutex_;
  std::atomic_int seq_;
};

struct Session {
  struct Key {
    explicit Key(unsigned char *buf, int size) : size_(size), kek_(-1) {
      buf_ = absl::make_unique<uint8_t[]>(size);
      memcpy(buf_.get(), buf, size);
    }
    int size_;
    std::unique_ptr<uint8_t[]> buf_;
    // kek_索引号，如果为-1表示为明文key
    int kek_;
  };

  using KeyPtr = std::shared_ptr<Session::Key>;

  explicit Session(std::string sessionId, const DevicePtr &dev)
      : sid_(std::move(sessionId)), device_(dev), mdCtx_(nullptr) {
  }

  void eraseKey(KeyHandle handle) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto it = keys_.begin(); it != keys_.end(); it++) {
      if (handle == it->get()) {
        keys_.erase(it);
        break;
      }
    }
  }

  bool findKey(KeyHandle handle, KeyPtr *key) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto &it : keys_) {
      if (handle == it.get()) {
        *key = it;
        return true;
      }
    }
    return false;
  }

  std::string sid_;
  DeviceWeakPtr device_;
  std::list<KeyPtr> keys_;
  std::mutex mutex_;
  EVP_MD_CTX *mdCtx_;
  std::list<SessionPtr>::iterator it_; // position in session list
};

Device::Device(std::string id) : devid_(std::move(id)), seq_{0} {
}

void Device::eraseSession(const SessionPtr &sessPtr) {
  std::lock_guard<std::mutex> lk(mutex_);
  sessions_.erase(sessPtr->it_);
}

}
}
