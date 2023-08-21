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

#include <chrono>
#include <utility>
#include <functional>
#include "exception.h"

namespace hsmc {

/// 对设备接口调用的监控接口类
template<typename R>
class Instrument {
 public:
  virtual ~Instrument() = default;

  /// 进入设备的调动函数接口
  /// \param fn 调用的函数名
  virtual void enter(const std::string& fn) = 0;

  /// 离开设备的调动函数接口
  /// \param fn 调用的函数名
  /// \param result 调用的结果
  virtual void leave(const std::string& fn, R result) = 0;

  /// 调用设备的函数耗时接口
  /// \param fn 调用的函数名
  /// \param macroseconds 耗时，单位微秒
  virtual void elapsed(const std::string& fn, uint64_t macroseconds) = 0;
};

template<typename R>
class InstrumentDuration {
 public:
  explicit InstrumentDuration(std::string fn, Instrument<R> *instrument)
      : fn(std::move(fn)), ins(instrument), start_(std::chrono::steady_clock::now()) {
  }

  ~InstrumentDuration() {
    auto end_ = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_ - start_);
    if (ins) ins->elapsed(fn, duration.count());
  }

 private:
  std::chrono::steady_clock::time_point start_;
  Instrument<R> *ins;
  const std::string fn;
};

/// 对函数调用进行监控的包装类
template<class F>
class FuncInstrumentedWrapper;
template<class R, class... Args>
class FuncInstrumentedWrapper<R(Args...)> {
 public:
  using FuncType = std::function<R(Args...)>;
  using InstrumentType = Instrument<R>;

  FuncInstrumentedWrapper()
      : FuncInstrumentedWrapper("", nullptr, nullptr) {}

  FuncInstrumentedWrapper(const char* fn, FuncType func, InstrumentType *ins)
      : fn_(fn), f(func), ins(ins) {}

  FuncInstrumentedWrapper &operator=(const FuncType &func) {
    this->f = func;
    return *this;
  }

  R operator()(Args... args) const {
    if (f) {
      InstrumentDuration<R> id(fn_, ins);
      if (ins) ins->enter(fn_);
      auto ret = f(std::forward<Args>(args)...);
      if (ins) ins->leave(fn_, ret);
      return ret;
    }
    throw NullPointerException("null function pointer");
  }

 private:
  FuncType f;
  InstrumentType *ins;
  const char* fn_;
};

#define DECLARE_INSTRUMENTED_FUNCTYPE(name) \
  using name = FuncInstrumentedWrapper<std::remove_pointer<name##_t>::type>;

#define DECLARE_INSTRUMENTED_FUNCTYPE2(name, functype) \
  using name = FuncInstrumentedWrapper<functype>;

}
