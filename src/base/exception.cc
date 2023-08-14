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

#include "hsmc/exception.h"

namespace hsmc {

HSMC_IMPLEMENT_EXCEPTION(LogicException, Exception, "Logic exception")
HSMC_IMPLEMENT_EXCEPTION(AssertionViolationException, LogicException, "Assertion violation")
HSMC_IMPLEMENT_EXCEPTION(NullPointerException, LogicException, "Null pointer")
HSMC_IMPLEMENT_EXCEPTION(NullValueException, LogicException, "Null value")
HSMC_IMPLEMENT_EXCEPTION(BugcheckException, LogicException, "Bugcheck")
HSMC_IMPLEMENT_EXCEPTION(InvalidArgumentException, LogicException, "Invalid argument")
HSMC_IMPLEMENT_EXCEPTION(NotImplementedException, LogicException, "Not implemented")
HSMC_IMPLEMENT_EXCEPTION(RangeException, LogicException, "Out of range")
HSMC_IMPLEMENT_EXCEPTION(IllegalStateException, LogicException, "Illegal state")
HSMC_IMPLEMENT_EXCEPTION(InvalidAccessException, LogicException, "Invalid access")
HSMC_IMPLEMENT_EXCEPTION(SignalException, LogicException, "Signal received")
HSMC_IMPLEMENT_EXCEPTION(UnhandledException, LogicException, "Unhandled exception")

HSMC_IMPLEMENT_EXCEPTION(RuntimeException, Exception, "Runtime exception")
HSMC_IMPLEMENT_EXCEPTION(NotFoundException, RuntimeException, "Not found")
HSMC_IMPLEMENT_EXCEPTION(ExistsException, RuntimeException, "Exists")
HSMC_IMPLEMENT_EXCEPTION(TimeoutException, RuntimeException, "Timeout")
HSMC_IMPLEMENT_EXCEPTION(SystemException, RuntimeException, "System exception")
HSMC_IMPLEMENT_EXCEPTION(RegularExpressionException, RuntimeException, "Error in regular expression")
HSMC_IMPLEMENT_EXCEPTION(LibraryLoadException, RuntimeException, "Cannot load library")
HSMC_IMPLEMENT_EXCEPTION(LibraryAlreadyLoadedException, RuntimeException, "Library already loaded")
HSMC_IMPLEMENT_EXCEPTION(NoThreadAvailableException, RuntimeException, "No thread available")
HSMC_IMPLEMENT_EXCEPTION(PropertyNotSupportedException, RuntimeException, "Property not supported")
HSMC_IMPLEMENT_EXCEPTION(PoolOverflowException, RuntimeException, "Pool overflow")
HSMC_IMPLEMENT_EXCEPTION(NoPermissionException, RuntimeException, "No permission")
HSMC_IMPLEMENT_EXCEPTION(OutOfMemoryException, RuntimeException, "Out of memory")
HSMC_IMPLEMENT_EXCEPTION(DataException, RuntimeException, "Data error")

HSMC_IMPLEMENT_EXCEPTION(DataFormatException, DataException, "Bad data format")
HSMC_IMPLEMENT_EXCEPTION(SyntaxException, DataException, "Syntax error")
HSMC_IMPLEMENT_EXCEPTION(CircularReferenceException, DataException, "Circular reference")
HSMC_IMPLEMENT_EXCEPTION(PathSyntaxException, SyntaxException, "Bad path syntax")
HSMC_IMPLEMENT_EXCEPTION(IOException, RuntimeException, "I/O error")
HSMC_IMPLEMENT_EXCEPTION(ProtocolException, IOException, "Protocol error")
HSMC_IMPLEMENT_EXCEPTION(FileException, IOException, "File access error")
HSMC_IMPLEMENT_EXCEPTION(FileExistsException, FileException, "File exists")
HSMC_IMPLEMENT_EXCEPTION(FileNotFoundException, FileException, "File not found")
HSMC_IMPLEMENT_EXCEPTION(PathNotFoundException, FileException, "Path not found")
HSMC_IMPLEMENT_EXCEPTION(FileReadOnlyException, FileException, "File is read-only")
HSMC_IMPLEMENT_EXCEPTION(FileAccessDeniedException, FileException, "Access to file denied")
HSMC_IMPLEMENT_EXCEPTION(CreateFileException, FileException, "Cannot create file")
HSMC_IMPLEMENT_EXCEPTION(OpenFileException, FileException, "Cannot open file")
HSMC_IMPLEMENT_EXCEPTION(WriteFileException, FileException, "Cannot write file")
HSMC_IMPLEMENT_EXCEPTION(ReadFileException, FileException, "Cannot read file")
HSMC_IMPLEMENT_EXCEPTION(DirectoryNotEmptyException, FileException, "Directory not empty")
HSMC_IMPLEMENT_EXCEPTION(UnknownURISchemeException, RuntimeException, "Unknown URI scheme")
HSMC_IMPLEMENT_EXCEPTION(TooManyURIRedirectsException, RuntimeException, "Too many URI redirects")
HSMC_IMPLEMENT_EXCEPTION(URISyntaxException, SyntaxException, "Bad URI syntax")

HSMC_IMPLEMENT_EXCEPTION(ApplicationException, Exception, "Application exception")
HSMC_IMPLEMENT_EXCEPTION(BadCastException, RuntimeException, "Bad cast exception")
HSMC_IMPLEMENT_EXCEPTION(SdfExcuteException, RuntimeException, "SDF execution exception")

}