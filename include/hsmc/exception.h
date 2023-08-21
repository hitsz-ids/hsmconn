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

#include "base.h"
#include <stdexcept>
#include <string>

namespace hsmc {

/// 异常的基类
class HSMC_API Exception : public std::exception {
 public:
  /// 构造函数
  explicit Exception(const std::string &msg, int code = 0) noexcept(noexcept(std::runtime_error(msg)))
      : code_(code), err_(msg) {}

  /// 返回异常的名称
  /// \return 名称
  virtual const char *name() const noexcept;

  /// 返回异常的具体原因
  /// \return 原因
  const char *what() const noexcept override;

  /// 返回异常的错误码
  /// \return 错误码
  int code() const noexcept;

 private:
  // 异常的错误码
  const int code_;

  // 错误消息由err_来保存
  std::runtime_error err_;
};


//
// inlines
//

inline int Exception::code() const noexcept {
  return code_;
}

inline const char *Exception::what() const noexcept {
  return err_.what();
}

inline const char *Exception::name() const noexcept {
  return "Exception";
}

#define HSMC_DECLARE_EXCEPTION_CODE(API, CLS, BASE, CODE)                                            \
    class API CLS: public BASE                                                                       \
    {                                                                                                \
    public:                                                                                          \
        explicit CLS(const std::string& msg, int code = CODE);                                       \
        const char* name() const noexcept override;                                                  \
    };

#define HSMC_DECLARE_EXCEPTION(API, CLS, BASE)                                                       \
    HSMC_DECLARE_EXCEPTION_CODE(API, CLS, BASE, 0)

#define HSMC_IMPLEMENT_EXCEPTION(CLS, BASE, NAME)                                                    \
    CLS::CLS(const std::string& msg, int code) noexcept(noexcept(std::runtime_error(msg)))           \
      : BASE(msg, code)                                                                              \
    {                                                                                                \
    }                                                                                                \
    const char* CLS::name() const noexcept                                                           \
    {                                                                                                \
        return NAME;                                                                                 \
    }                                                                                                \


//
// Standard exception classes
//
HSMC_DECLARE_EXCEPTION(HSMC_API, LogicException, Exception)
HSMC_DECLARE_EXCEPTION(HSMC_API, AssertionViolationException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, NullPointerException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, NullValueException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, BugcheckException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, InvalidArgumentException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, NotImplementedException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, RangeException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, IllegalStateException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, InvalidAccessException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, SignalException, LogicException)
HSMC_DECLARE_EXCEPTION(HSMC_API, UnhandledException, LogicException)

HSMC_DECLARE_EXCEPTION(HSMC_API, RuntimeException, Exception)
HSMC_DECLARE_EXCEPTION(HSMC_API, NotFoundException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, ExistsException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, TimeoutException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, SystemException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, RegularExpressionException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, LibraryLoadException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, LibraryAlreadyLoadedException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, NoThreadAvailableException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, PropertyNotSupportedException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, PoolOverflowException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, NoPermissionException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, OutOfMemoryException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, DataException, RuntimeException)

HSMC_DECLARE_EXCEPTION(HSMC_API, DataFormatException, DataException)
HSMC_DECLARE_EXCEPTION(HSMC_API, SyntaxException, DataException)
HSMC_DECLARE_EXCEPTION(HSMC_API, CircularReferenceException, DataException)
HSMC_DECLARE_EXCEPTION(HSMC_API, PathSyntaxException, SyntaxException)
HSMC_DECLARE_EXCEPTION(HSMC_API, IOException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, ProtocolException, IOException)
HSMC_DECLARE_EXCEPTION(HSMC_API, FileException, IOException)
HSMC_DECLARE_EXCEPTION(HSMC_API, FileExistsException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, FileNotFoundException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, PathNotFoundException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, FileReadOnlyException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, FileAccessDeniedException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, CreateFileException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, OpenFileException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, WriteFileException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, ReadFileException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, DirectoryNotEmptyException, FileException)
HSMC_DECLARE_EXCEPTION(HSMC_API, UnknownURISchemeException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, TooManyURIRedirectsException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, URISyntaxException, SyntaxException)

HSMC_DECLARE_EXCEPTION(HSMC_API, ApplicationException, Exception)
HSMC_DECLARE_EXCEPTION(HSMC_API, BadCastException, RuntimeException)
HSMC_DECLARE_EXCEPTION(HSMC_API, SdfExcuteException, RuntimeException)

}
