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
#include <unordered_map>
#include "absl/memory/memory.h"

namespace hsmc {
namespace emu {

struct Session;
struct Device;

using DevicePtr = std::shared_ptr<Device>;
using DeviceWeakPtr = std::weak_ptr<Device>;
using SessionPtr = std::shared_ptr<Session>;

using DeviceHandle = void *;
using SessionHandle = void *;
using KeyHandle = void *;

class Session {
 public:
  class Key {
   public:
    explicit Key(unsigned char *buf, int size, int index = -1) : size_(size), key_index_(index) {
      buf_ = absl::make_unique<uint8_t[]>(size);
      memcpy(buf_.get(), buf, size);
    }
    uint8_t* buf() const {
      return buf_.get();
    }
    int size() const {
      return size_;
    }
    int index() const {
      return key_index_;
    }
   private:
    int size_;
    std::unique_ptr<uint8_t[]> buf_;
    int key_index_; // kek索引号，如果为-1表示为明文key
  };

  using KeyPtr = std::shared_ptr<Session::Key>;
  using UserDataPtr = void *;
  using UserDataFreeFunc = void (*)(UserDataPtr userdata);
  using SessionPos = std::list<SessionPtr>::iterator;

  explicit Session(std::string sessionId, const DevicePtr &dev, UserDataPtr userdata = nullptr, UserDataFreeFunc func = nullptr)
      : sid_(std::move(sessionId)), device_(dev), userdata_(userdata), user_data_free_func_(func) {
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
        if (key != nullptr) {
          *key = it;
        }
        return true;
      }
    }
    return false;
  }

  void addKey(const KeyPtr& key) {
    std::lock_guard<std::mutex> lk(mutex_);
    keys_.push_back(key);
  }

  void resetUserdata(UserDataPtr new_userdata = nullptr, UserDataFreeFunc new_free_func = nullptr) {
    if (userdata_ != nullptr && user_data_free_func_ != nullptr) {
      user_data_free_func_(userdata_);
      userdata_ = nullptr;
    }
    userdata_ = new_userdata;
    user_data_free_func_ = new_free_func;
  }

  UserDataPtr getUserdata() {
    return userdata_;
  }

  DevicePtr getDevice() {
    return device_.lock();
  }

  SessionPos getPos() {
    return pos_;
  }

  void setPos(const SessionPos& pos) {
    pos_ = pos;
  }

 private:
  std::string sid_;
  DeviceWeakPtr device_;
  std::list<KeyPtr> keys_;
  std::mutex mutex_;
  SessionPos pos_; // position in session list
  UserDataPtr userdata_;
  UserDataFreeFunc user_data_free_func_;
};

class Device {
 public:
  explicit Device(std::string id) : id_(std::move(id)), seq_{0} {}

  void eraseSession(const SessionPtr &sess_ptr) {
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_.erase(sess_ptr->getPos());
  }
  void addSession(const SessionPtr &sess_ptr) {
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_.push_front(sess_ptr);
    sess_ptr->setPos(sessions_.begin());
  }
  SessionPtr frontSession() {
    std::lock_guard<std::mutex> lk(mutex_);
    return sessions_.empty() ? nullptr : sessions_.front();
  }
  std::string getId() {
    return id_;
  }
  int postIncSeq() {
    int seq = seq_++;
    return seq;
  }

 private:
  std::string id_;
  std::list<SessionPtr> sessions_;
  std::mutex mutex_;
  std::atomic_int seq_;
};

class DevicePool {
 public:
  void add(const DevicePtr& dev) {
    std::lock_guard<std::mutex> lk(mutex_);
    devices_.push_back(dev);
  }

  DevicePtr find(DeviceHandle handle, bool erased_from_pool = false) {
    DevicePtr dev = nullptr;
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto it = devices_.begin(); it != devices_.end(); ++it) {
      if (it->get() == handle) {
        dev = *it;
        if (erased_from_pool) {
          devices_.erase(it);
        }
        break;
      }
    }
    return dev;
  }

 private:
  // member variables
  std::list<DevicePtr> devices_;
  std::mutex mutex_;
};

class SessionPool {
 public:
  void add(const SessionPtr &sess_ptr) {
    std::lock_guard<std::mutex> lk(mutex_);
    sessions_.insert({sess_ptr.get(), sess_ptr});
  }

  bool erase(SessionHandle handle) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_.find(handle);
    if (it == sessions_.end()) {
      return false;
    }
    auto dev = it->second->getDevice();
    if (dev) {
      dev->eraseSession(it->second);
    }
    it->second->resetUserdata();
    sessions_.erase(it);
    return true;
  }

  void eraseFromDevice(const DevicePtr &dev_ptr) {
    SessionPtr sess;
    while ((sess = dev_ptr->frontSession()) != nullptr) {
      erase(sess.get());
    }
  }

  SessionPtr find(SessionHandle handle) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_.find(handle);
    return it == sessions_.end() ? nullptr : it->second;
  }

 private:
  // member variables
  std::unordered_map<SessionHandle, SessionPtr> sessions_;
  std::mutex mutex_;
};

}
}
