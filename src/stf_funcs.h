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

#include "hsmc/base.h"
#include "hsmc/stf.h"

namespace hsmc {

using STF_InitEnvironment_t = \
  SGD_UINT32 (*)(void **phTSHandle);

using STF_ClearEnvironment_t = \
  SGD_UINT32 (*)(void *hTSHandle);

using STF_CreateTSRequest_t = \
  SGD_UINT32 (*)(void *hTSHandle,
                 SGD_UINT8 *pucInData,
                 SGD_UINT32 uiInDataLength,
                 SGD_UINT32 uiReqType,
                 SGD_UINT8 *pucTSExt,
                 SGD_UINT32 uiTSExtLength,
                 SGD_UINT32 uiHashAlgID,
                 SGD_UINT8 *pucTSRequest,
                 SGD_UINT32 *puiTSRequestLength);

using STF_CreateTSResponse_t = \
  SGD_UINT32 (*)(void *hTSHandle,
                 SGD_UINT8 *pucTSRequest,
                 SGD_UINT32 uiTSRequestLength,
                 SGD_UINT32 uiSignatureAlgID,
                 SGD_UINT8 *pucTSResponse,
                 SGD_UINT32 *puiTSResponseLength);

using STF_VerifyTSValidity_t = \
  SGD_UINT32 (*)(void *hTSHandle,
                 SGD_UINT8 *pucTSResponse,
                 SGD_UINT32 uiTSResponseLength,
                 SGD_UINT32 uiHashAlgID,
                 SGD_UINT32 uiSignatureAlgID,
                 SGD_UINT8 *pucTSCert,
                 SGD_UINT32 uiTSCertLength);

using STF_GetTSInfo_t = \
  SGD_UINT32 (*)(void *hTSHandle,
                 SGD_UINT8 *pucTSResponse,
                 SGD_UINT32 uiTSResponseLength,
                 SGD_UINT8 *pucIssuerName,
                 SGD_UINT32 *puiIssuerNameLength,
                 SGD_UINT8 *pucTime,
                 SGD_UINT32 *puiTimeLength);

using STF_GetTSDetail_t = \
  SGD_UINT32 (*)(void *hTSHandle,
                 SGD_UINT8 *pucTSResponse,
                 SGD_UINT32 uiTSResponseLength,
                 SGD_UINT32 uiItemNumber,
                 SGD_UINT8 *pucItemValue,
                 SGD_UINT32 *puiItemValueLength);

class HSMC_API STFFuncs {
 public:
  STFFuncs() = default;
  STF_InitEnvironment_t STF_InitEnvironment_;
  STF_ClearEnvironment_t STF_ClearEnvironment_;
  STF_CreateTSRequest_t STF_CreateTSRequest_;
  STF_CreateTSResponse_t STF_CreateTSResponse_;
  STF_VerifyTSValidity_t STF_VerifyTSValidity_;
  STF_GetTSInfo_t STF_GetTSInfo_;
  STF_GetTSDetail_t STF_GetTSDetail_;
};

}
