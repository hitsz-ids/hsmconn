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

#ifdef __cplusplus
extern "C" {
#endif

/*常量标识*/
#define SGD_TRUE           0x00000001
#define SGD_FALSE          0x00000000

/* 签名算法定义 */
#define SGD_SHA1_RSA       0x00010002
#define SGD_SHA256_RSA     0x00010004
#define SGD_SM3_SM2        0x00020201

/* Hash算法定义 */
#define SGD_SM3            0x00000001
#define SGD_SHA1           0x00000002
#define SGD_SHA256         0x00000004

/* 时间戳服务接口常量定义 */
#define STF_TIME_OF_STAMP                    0x00000001 //签发时间
#define STF_CN_OF_TSSIGNER                   0x00000002 //签发者的通用名
#define STF_ORIGINAL_DATA                    0x00000003 //时间戳请求的原始信息
#define STF_CERT_OF_TSSERVER                 0x00000004 //时间戳服务器的证书
#define STF_CERTCHAIN_OF_TSSERVER            0x00000005 //时间戳服务器的证书链
#define STF_SOURCE_OF_TIME                   0x00000006 //时间源的来源
#define STF_TIME_PRECISION                   0x00000007 //时间精度
#define STF_RESPONSE_TYPE                    0x00000008 //响应方式
#define STF_SUBJECT_COUNTRY_OF_TSSIGNER      0x00000009 //签发者国家
#define STF_SUBJECT_ORGNIZATION_OF_TSSIGNER  0x0000000A //签发者组织
#define STF_SUBJECT_CITY_OF_TSSIGNER         0x0000000B //签发者城市
#define STF_SUBJECT_EMAIL_OF_TSSIGNER        0x0000000C //签发者联系用电子信箱
//0x0000000D-0x000000FF //为其他标识保留

/*数据类型*/
typedef char SGD_CHAR;
typedef char SGD_INT8;
typedef short SGD_INT16;
typedef int SGD_INT32;
typedef long long SGD_INT64;
typedef unsigned char SGD_UCHAR;
typedef unsigned char SGD_UINT8;
typedef unsigned short SGD_UINT16;
typedef unsigned int SGD_UINT32;
typedef unsigned long long SGD_UINT64;
typedef unsigned int SGD_RV;
typedef void *SGD_OBJ;
typedef int SGD_BOOL;
typedef void *SGD_HANDLE;


/*错误代码标识*/
#define STF_TS_OK                            0          //正常返回
#define STF_TS_ERROR_BASE                    0x04000000
#define STF_TS_INDATA_TOOLONG                0x04000001 //输入的用户信息超出规定范围
#define STF_TS_NOT_ENOUGH_MEMORY             0x04000002 //分配给tsrequest的内存空间不够
#define STF_TS_SERVER_ERROR                  0x04000003 //找不到服务器或超时响应
#define STF_TS_MALFORMAT                     0x04000004 //时间戳格式错误
#define STF_TS_INVALID_ITEM                  0x04000005 //输人项目编号无效
#define STF_TS_INVALID_SIGNATURE             0x04000006 //签名无效
#define STF_TS_INVALID_ALG                   0x04000007 //申请使用了不支持的算法:
#define STF_TS_INVALID_REQUEST               0x04000008 //非法的申请
#define STF_TS_INVALID_DATAFORMAT            0x04000009 //数据格式错误
#define STF_TS_TIME_NOT_AVAILABLE            0x0400000A //TSA的可信时间源出现问题
#define STF_TS_UNACCEPTED_POLICY             0x0400000B //不支持申请消息中声明的策略
#define STF_TS_UNACCEPTED_EXTENSION          0x0400000C //申请消息中包括了不支持的扩展
#define STF_TS_ADDINFO_NOT_AVAILBLE          0x0400000D //有不理解或不可用的附加信息
#define STF_TS_SYSTEM_FAILURE                0x0400000E //系统内部错误
//0x04000010-0x040000FF //预留
#define STF_TS_NOT_SUPPORT                   0x040000FF //方法不支持

#ifdef __cplusplus
}
#endif
