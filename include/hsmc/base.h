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

#if !defined(HSMC_API)
#if !defined(HSMC_NO_GCC_API_ATTRIBUTE) && defined (__GNUC__) && (__GNUC__ >= 4)
#define HSMC_API __attribute__ ((visibility ("default")))
#else
#define HSMC_API
#endif
#endif

#if (defined(_WIN32) || defined(_WIN32_WCE)) && defined(HSMC_DLL)
#if defined(HSMC_EXPORTS)
#define HSMC_API __declspec(dllexport)
#else
#define HSMC_API __declspec(dllimport)
#endif
#endif

