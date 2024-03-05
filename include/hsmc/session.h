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
#include <mutex>

#include "session_impl.h"

namespace hsmc {

// 证书数据；证书序列号；证书ID(DN)
enum CertType { CERTDATA = 1, CERTSN, CERTID };
// 验证有效期；验证有效期和证书链；验证有效期、证书链以及黑名单
enum VerifyCertLevel { VERIFYTIME = 0, VERIFYCHAIN, VERIFYCRL };

/// Session对象以面向对象形式封装了SDF、SVS、STF接口函数，Session对象在其内部维护了代理
/// 实际`SessionImpl`对象的指针，并将对SDF、SVS、STF的接口调用委托给`SessionImpl`对象
/// 来执行。
class HSMC_API Session {
 public:
  /// Session构造函数
  /// \param impl 代理的`SessionImpl`对象
  explicit Session(SessionImpl::Ptr impl);

  /// Session拷贝构造函数
  /// \param other 另一个Session对象
  Session(const Session &other);

  /// Session拷贝赋值函数
  /// \param other 另一个Session对象
  Session(Session &&other) noexcept;

  /// Session拷贝赋值函数
  /// \param other 另一个Session对象
  Session &operator=(Session &&other) noexcept;

  /// Session析构函数
  virtual ~Session();

  /// 打开会话
  virtual void open();

  /// 关闭会话
  virtual void close();

  /// 检查当前会话是否可用
  /// \return 可用返回true，否则返回false
  virtual bool isGood() const;

  /// 获取会话底层的句柄
  /// \return 会话底层的句柄
  virtual void *getSessionHandle() const;

  /// 获取会话的唯一标识
  /// \return 会话的唯一标识
  std::string getId() const;

  /// 获取会话所属的设备节点名称
  /// \return 设备节点名称
  std::string getConnectorName() const;

  /// 获取会话所代理的实际对象
  /// \return 会话所代理的实际对象
  SessionImpl::Ptr impl();

  /// 获取密码设备能力描述
  /// \param pstDeviceInfo 设备能力描述信息，内容及格式见设备信息定义
  /// \return 成功返回0，失败返回错误代码
  int SDF_GetDeviceInfo(DEVICEINFO *pstDeviceInfo) const;

  /// 获取指定长度的随机数
  /// \param uiLength 欲获取的随机数长度
  /// \param pucRandom 缓冲区指针，用于存放获取的随机数
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateRandom(unsigned int uiLength, unsigned char *pucRandom) const;

  /// 获取密码设备内部存储的指定索引私钥的使用权
  /// \param uiKeyIndex 密码设备存储私钥的索引值
  /// \param pucPassword 使用私钥权限的标识码
  /// \param uiPwdLength 私钥访问控制码长度，不少于 8 字节
  /// \return 成功返回0，失败返回错误代码
  int SDF_GetPrivateKeyAccessRight(unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength) const;

  /// 释放密码设备存储的指定索引私钥的使用授权
  /// \param uiKeyIndex 密码设备存储私钥索引值
  /// \return 成功返回0，失败返回错误代码
  int SDF_ReleasePrivateKeyAccessRight(unsigned int uiKeyIndex) const;

  /// 导出密码设备内部存储的指定索引位置的签名公钥
  /// \param uiKeyIndex 密码设备存储的 RSA 密钥对索引值
  /// \param pucPublicKey RSA 公钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExportSignPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const;

  /// 导出密码设备内部存储的指定索引位置的加密公钥
  /// \param uiKeyIndex 密码设备存储的 RSA 密钥对索引值
  /// \param pucPublicKey RSA 公钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExportEncPublicKey_RSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) const;

  /// 请求密码设备产生指定模长的 RSA 密钥对
  /// \param uiKeyBits 指定密钥模长
  /// \param pucPublicKey RSA 公钥结构
  /// \param pucPrivateKey RSA 私钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyPair_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                              RSArefPrivateKey *pucPrivateKey) const;

  /// 生成会话密钥并用指定索引的内部加密公钥加密输出，同时返回密钥句柄
  /// 公钥加密数据时填充方式按照 PKCS#v1.5 的要求进行
  ///
  /// \param[in] uiIPKIndex 密码设备内部存储公钥的索引值
  /// \param[in] uiKeyBits 指定产生的会话密钥长度
  /// \param[out] pucKey 缓冲区指针，用于存放返回的密钥密文
  /// \param[out] puiKeyLength 返回的密钥密文长度
  /// \param[out] phKeyHandle 返回密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithIPK_RSA(unsigned int uiIPKIndex, unsigned int uiKeyBits, unsigned char *pucKey,
                                 unsigned int *puiKeyLength, void **phKeyHandle) const;

  /// 生成会话密钥并用外部加密公钥加密输出，同时返回密钥句柄
  /// \param[in] uiKeyBits 指定产生的会话密钥长度
  /// \param[in] pucPublicKey 输入的外部RSAg公钥结构
  /// \param[out] pucKey 缓冲区指针，用于存放返回的密钥密文
  /// \param[out] puiKeyLength 返回的密钥密文长度
  /// \param[out] phKeyHandle 返回密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithEPK_RSA(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pucKey,
                                 unsigned int *puiKeyLength, void **phKeyHandle) const;

  /// 导入会话密钥并用内部RSA私钥解密，同时返回密钥句柄
  /// \param[in] uiISKIndex 密码设备内部存储加密私钥的索引值，对应于加密时的公钥
  /// \param[in] pucKey 缓冲区指针，用于存放输入的密钥密文
  /// \param[in] uiKeyLength 输入的密钥密文长度
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_ImportKeyWithISK_RSA(unsigned int uiISKIndex, unsigned char *pucKey, unsigned int uiKeyLength,
                               void **phKeyHandle) const;

  /// 将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
  /// \param[in] uiKeyIndex 密码设备存储的内部 RSA 密钥对索引值
  /// \param[in] pucPublicKey 外部 RSA 公钥结构
  /// \param[in] pucDEInput 缓冲区指针，用于存放输入的会话密钥密文
  /// \param[out] uiDELength 输入的会话密钥密文长度
  /// \param[out] pucDEOutput 缓冲区指针，用于存放输出的会话密钥密文
  /// \param[out] puiDELength 输出的会话密钥密文长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExchangeDigitEnvelopeBaseOnRSA(unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
                                         unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput,
                                         unsigned int *puiDELength) const;

  /// 导出密码设备内部存储的指定索引位置的签名公钥
  /// \param[in] uiKeyIndex 密码设备存储的 ECC 密钥对索引值
  /// \param[out] pucPublicKey ECC 公钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExportSignPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const;

  /// 导出密码设备内部存储的指定索引位置的加密公钥
  /// \param[in] uiKeyIndex 密码设备存储的 ECC 密钥对索引值
  /// \param[out] pucPublicKey ECC 公钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExportEncPublicKey_ECC(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) const;

  /// 请求密码设备产生指定类型和模长的 ECC 密钥对
  /// \param[in] uiAlgID 指定算法标识
  /// \param[in] uiKeyBits 指定密钥长度
  /// \param[out] pucPublicKey ECC 公钥结构
  /// \param[out] pucPrivateKey ECC 私钥结构
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyPair_ECC(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey,
                              ECCrefPrivateKey *pucPrivateKey) const;

  /// 生成会话密钥并用指定索引的内部 ECC 加密公钥加密输出，同时返回密钥句柄。
  /// \param[in] uiIPKIndex 密码设备内部存储公钥的索引值
  /// \param[in] uiKeyBits 指定产生的会话密钥长度
  /// \param[out] pucKey 缓冲区指针，用于存放返回的密钥密文
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithIPK_ECC(unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey,
                                 void **phKeyHandle) const;

  /// 生成会话密钥并用外部 ECC 公钥加密输出，同时返回密钥句柄
  /// \param[in] uiKeyBits 指定产生的会话密钥长度
  /// \param[in] uiAlgID 外部 ECC 公钥的算法标识
  /// \param[in] pucPublicKey 输入的外部 ECC 公钥结构
  /// \param[out] pucKey 缓冲区指针，用于存放返回的密钥密文
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithEPK_ECC(unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                 ECCCipher *pucKey, void **phKeyHandle) const;

  /// 导入会话密钥并用内部 ECC 加密私钥解密，同时返回密钥句柄
  /// \param[in] uiISKIndex 密码设备内部存储加密私钥的索引值，对应于加密时的公钥
  /// \param[in] pucKey 缓冲区指针，用于存放输入的密钥密文
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_ImportKeyWithISK_ECC(unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle) const;

  /// 使用 ECC 密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的 ECC
  /// 公钥、临时 ECC 密钥对的公钥及协商句柄
  /// \param[in] uiISKIndex 密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
  /// \param[in] uiKeyBits 要求协商的密钥长度
  /// \param[in] pucSponsorID 参与密钥协商的发起方ID值
  /// \param[in] uiSponsorIDLength 发起方ID长度
  /// \param[out] pucSponsorPublicKey 返回的发起方ECC公钥结构
  /// \param[out] pucSponsorTmpPublicKey 返回的发起方临时 ECC 公钥结构
  /// \param[out] phAgreementHandle 返回的协商句柄，用于计算协商密钥
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateAgreementDataWithECC(unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,
                                       unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
                                       ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle) const;

  /// 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数 计算会话密钥，同时返
  /// 回会话密钥句柄
  /// \param[in] pucResponseID 外部输入的响应方 ID 值
  /// \param[in] uiResponseIDLength 外部输入的响应方 ID 长度
  /// \param[in] pucResponsePublicKey 外部输入的响应方 ECC 公钥结构
  /// \param[in] pucResponseTmpPublicKey 外部输入的响应方临时 ECC 公钥结构
  /// \param[in] hAgreementHandle 协商句柄，用于计算协商密钥
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithECC(unsigned char *pucResponseID, unsigned int uiResponseIDLength,
                             ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
                             void *hAgreementHandle, void **phKeyHandle) const;

  /// 使用 ECC 密钥协商算法，产生协商参数并计算会话密钥，同时返回产生的协商参数和密钥
  /// 句柄
  /// \param[in] uiISKIndex 密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
  /// \param[in] uiKeyBits 协商后要求输出的密钥长度
  /// \param[in] pucResponseID 响应方 ID 值
  /// \param[in] uiResponseIDLength 响应方ID长度
  /// \param[in] pucSponsorID 发起方ID值
  /// \param[in] uiSponsorIDLength 发起方ID长度
  /// \param[in] pucSponsorPublicKey 外部输入的发起方ECC公钥结构
  /// \param[in] pucSponsorTmpPublicKey 外部输入的发起方临时 ECC 公钥结构
  /// \param[out] pucResponsePublicKey 返回的响应方 ECC 公钥结构
  /// \param[out] pucResponseTmpPublicKey 返回的响应方临时 ECC 公钥结构
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateAgreementDataAndKeyWithECC(unsigned int uiISKIndex, unsigned int uiKeyBits,
                                             unsigned char *pucResponseID, unsigned int uiResponseIDLength,
                                             unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                             ECCrefPublicKey *pucSponsorPublicKey,
                                             ECCrefPublicKey *pucSponsorTmpPublicKey,
                                             ECCrefPublicKey *pucResponsePublicKey,
                                             ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) const;

  /// 将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密， 可用于数字信封转换
  /// \param[in] uiKeyIndex 密码设备存储的 ECC 密钥对索引值
  /// \param[in] uiAlgID 外部 ECC 公钥的算法标识
  /// \param[in] pucPublicKey 外部 ECC 公钥结构
  /// \param[in] pucEncDataIn 缓冲区指针，用于存放输入的会话密钥密文
  /// \param[out] pucEncDataOut 缓冲区指针，用于存放输出的会话密钥密文
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExchangeDigitEnvelopeBaseOnECC(unsigned int uiKeyIndex, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                         ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut) const;

  /// 生成会话密钥并用密钥加密密钥加密输出，同时返回密钥句柄
  /// \param[in] uiKeyBits 指定产生的会话密钥长度
  /// \param[in] uiAlgID 算法标识，指定对称加密算法
  /// \param[in] uiKEKIndex 密码设备内部存储密钥加密密钥的索引值
  /// \param[out] pucKey 缓冲区指针，用于存放返回的密钥密文
  /// \param[out] puiKeyLength 返回的密钥密文长度
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_GenerateKeyWithKEK(unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
                             unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const;

  /// 导入会话密钥并用密钥加密密钥解密，同时返回会话密钥句柄
  /// \param[in] uiAlgID 算法标识，指定对称加密算法
  /// \param[in] uiKEKIndex 密码设备内部存储密钥加密密钥的索引值
  /// \param[in] pucKey 缓冲区指针，用于存放输入的密钥密文
  /// \param[in] uiKeyLength 输入密钥密文长度
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_ImportKeyWithKEK(unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
                           unsigned int uiKeyLength, void **phKeyHandle) const;

  /// 导入明文会话密钥，同时返回密钥句柄
  /// 部分厂商HSM并不支持该操作，如BJCA
  ///
  /// \param[in] pucKey 缓冲区指针，用于存放输入的密钥明文
  /// \param[in] uiKeyLength 输入的密钥明文长度
  /// \param[out] phKeyHandle 返回的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_ImportKey(unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const;

  /// 销毁会话密钥，并释放为密钥句柄分配的内存等资源。
  /// \param[in] hKeyHandle 输入的密钥句柄
  /// \return 成功返回0，失败返回错误代码
  int SDF_DestroyKey(void *hKeyHandle) const;

  /// 指定使用外部公钥对数据进行运算
  /// 数据格式由应用层封装。
  ///
  /// \param[in] pucPublicKey 外部RSA公钥结构
  /// \param[in] pucDataInput 缓冲区指针，用于存放输入的数据
  /// \param[in] uiInputLength 输入的数据长度
  /// \param[out] pucDataOutput 缓冲区指针，用于存放输出的数据
  /// \param[out] puiOutputLength 输出的数据长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalPublicKeyOperation_RSA(RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
                                         unsigned int uiInputLength, unsigned char *pucDataOutput,
                                         unsigned int *puiOutputLength) const;

  /// 使用内部指定索引的公钥对数据进行运算
  /// 索引范围仅限于内部签名密钥对，数据格式由应用层封装
  /// \param[in] uiKeyIndex 密码设备内部存储公钥的索引值
  /// \param[in] pucDataInput 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiInputLength 输入的数据长度
  /// \param[out] pucDataOutput 缓冲区指针，用于存放输出的数据
  /// \param[out] puiOutputLength 输出的数据长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_InternalPublicKeyOperation_RSA(unsigned int uiKeyIndex, unsigned char *pucDataInput,
                                         unsigned int uiInputLength, unsigned char *pucDataOutput,
                                         unsigned int *puiOutputLength) const;

  /// 使用内部指定索引的私钥对数据进行运算
  /// 索引范围仅限于内部签名密钥对，数据格式由应用层封装
  ///
  /// \param[in] uiKeyIndex 密码设备内部存储私钥的索引值
  /// \param[in] pucDataInput 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiInputLength 输入的数据长度
  /// \param[out] pucDataOutput 缓冲区指针，用于存放输出的数据
  /// \param[out] puiOutputLength 输出的数据长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_InternalPrivateKeyOperation_RSA(unsigned int uiKeyIndex, unsigned char *pucDataInput,
                                          unsigned int uiInputLength, unsigned char *pucDataOutput,
                                          unsigned int *puiOutputLength) const;

  /// 使用外部私钥对数据进行运算
  /// 部分厂商HSM不支持该操作
  ///
  /// \param[in] pucPrivateKey 外部RSA私钥结构
  /// \param[in] pucDataInput 缓冲区指针，用于存放输入的数据
  /// \param[in] uiInputLength 输入的数据长度
  /// \param[out] pucDataOutput 缓冲区指针，用于存放输出的数据
  /// \param[out] puiOutputLength 输出的数据长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalPrivateKeyOperation_RSA(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
                                          unsigned int uiInputLength, unsigned char *pucDataOutput,
                                          unsigned int *puiOutputLength) const;

  /// 使用外部ECC私钥对数据进行签名运算
  /// 输入数据为待签名数据的杂凑值，当使用SM2算法时，该输入数据为待签名数据经过SM2签名预处理的结果
  /// \param[in] uiAlgID 算法标识，指定使用的ECC算法
  /// \param[in] pucPrivateKey 外部ECC私钥结构
  /// \param[in] pucData 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiDataLength 输入的数据长度
  /// \param[out] pucSignature 缓冲区指针，用于存放输出的签名值数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalSign_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucData,
                           unsigned int uiDataLength, ECCSignature *pucSignature) const;

  /// 使用外部 ECC 公钥对 ECC 签名值进行验证运算
  /// \param[in] uiAlgID 算法标识，指定使用的ECC算法
  /// \param[in] pucPublicKey 外部ECC公钥结构
  /// \param[in] pucDataInput 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiInputLength 输入的数据长度
  /// \param[in] pucSignature 缓冲区指针，用于存放输入的签名值数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalVerify_ECC(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucDataInput,
                             unsigned int uiInputLength, ECCSignature *pucSignature) const;

  /// 使用内部 ECC 私钥对数据进行签名运算
  /// \param[in] uiISKIndex 密码设备内部存储的ECC签名私钥的索引值
  /// \param[in] pucData 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiDataLength 输入的数据长度
  /// \param[out] pucSignature 缓冲区指针，用于存放输出的签名值数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_InternalSign_ECC(unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
                           ECCSignature *pucSignature) const;

  /// 使用内部 ECC 公钥对 ECC 签名值进行验证运算
  /// \param[in] uiIPKIndex 密码设备内部存储的ECC签名公钥的索引值
  /// \param[in] pucData 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiDataLength 输入的数据长度
  /// \param[in] pucSignature 缓冲区指针，用于存放输入的签名值数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_InternalVerify_ECC(unsigned int uiIPKIndex, unsigned char *pucData, unsigned int uiDataLength,
                             ECCSignature *pucSignature) const;

  /// 使用外部 ECC 公钥对数据进行加密运算
  /// \param[in] uiAlgID 算法标识，指定使用的ECC算法
  /// \param[in] pucPublicKey 外部ECC公钥结构
  /// \param[in] pucData 缓冲区指针，用于存放外部输入的数据
  /// \param[in] uiDataLength 输入的数据长度
  /// \param[out] pucEncData 缓冲区指针，用于存放输出的数据密文
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalEncrypt_ECC(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucData,
                              unsigned int uiDataLength, ECCCipher *pucEncData) const;

  /// 使用外部ECC 私钥对数据进行解密运算
  /// BJCA密码机不支持该操作
  /// \param[in] uiAlgID 算法标识，指定使用的ECC算法
  /// \param[in] pucPrivateKey 外部ECC私钥结构
  /// \param[in] pucEncData 缓冲区指针，用于存放输入的数据密文
  /// \param[out] pucData 缓冲区指针，用于存放输出的数据明文
  /// \param[out] puiDataLength 输出的数据明文长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_ExternalDecrypt_ECC(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData,
                              unsigned char *pucData, unsigned int *puiDataLength) const;

  /// 使用指定的密钥句柄和 IV 对数据进行对称加密运算
  /// 此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
  /// \param[in] hKeyHandle 指定的密钥句柄
  /// \param[in] uiAlgID 算法标识，指定对称加密算法
  /// \param[in,out] pucIV 缓冲区指针，用于存放输入和返回的IV数据
  /// \param[in] pucData 缓冲区指针，用于存放输入的数据明文
  /// \param[in] uiDataLength 输入的数据明文长度
  /// \param[out] pucEncData 缓冲区指针，用于存放输出的数据密文
  /// \param[out] puiEncDataLength 输出的数据密文长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_Encrypt(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
                  unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) const;

  /// 使用指定的密钥句柄和 IV 对数据进行对称解密运算
  /// 此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
  /// \param[in] hKeyHandle 指定的密钥句柄
  /// \param[in] uiAlgID 算法标识，指定对称加密算法
  /// \param[in,out] pucIV 缓冲区指针，用于存放输入和返回的IV数据
  /// \param[in] pucEncData 缓冲区指针，用于存放输入的数据密文
  /// \param[in] uiEncDataLength 输入的数据密文长度
  /// \param[out] pucData 缓冲区指针，用于存放输出的数据明文
  /// \param[out] puiDataLength 输出的数据明文长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_Decrypt(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
                  unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength) const;

  /// 使用指定的密钥句柄和 IV 对数据进行 MAC 运算
  /// 此函数不对数据进行分包处理，分包数据 MAC 运算由 IV 控制最后的 MAC 值
  /// \param[in] hKeyHandle 指定的密钥句柄
  /// \param[in] uiAlgID 算法标识，指定MAC加密算法
  /// \param[in,out] pucIV 缓冲区指针，用于存放输入和返回的IV数据
  /// \param[in] pucData 缓冲区指针，用于存放输入的数据明文
  /// \param[in] uiDataLength 输入的数据明文长度
  /// \param[out] pucMAC 缓冲区指针，用于存放输出的MAC值
  /// \param[out] puiMACLength 输出的MAC值长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_CalculateMAC(void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
                       unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength) const;

  /// 三步式数据杂凑运算第一步
  /// uiIDLength 非零且 uiAlgID 为 SGD_SM3 时，函数执行 SM2 的预处理 1 操作
  /// \param uiAlgID 指定杂凑算法标识
  /// \param pucPublicKey 签名者公钥。当 uiAlgID 为 SGD_SM3 时有效
  /// \param pucID 签名者公钥 ID 值，当 uiAlgID 为 SGD_SM3 时有效
  /// \param uiIDLength 签名者 ID 的长度，当 uiAlgID 为 SGD_SM3 时有效
  /// \return 成功返回0，失败返回错误代码
  int SDF_HashInit(unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID,
                   unsigned int uiIDLength) const;

  /// 三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
  /// \param pucData 缓冲区指针，用于存放输入的数据明文
  /// \param uiDataLength 输入的数据明文长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_HashUpdate(unsigned char *pucData, unsigned int uiDataLength) const;

  /// 三步式数据杂凑运算第三步，杂凑运算结束返回杂凑值数据并清除中间数据
  /// \param pucHash 缓冲区指针，用于存放输出的杂凑数据
  /// \param puiHashLength 返回的杂凑数据长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_HashFinal(unsigned char *pucHash, unsigned int *puiHashLength) const;

  /// 密码设备内部创建用于存储用户数据的文件
  /// \param pucFileName 缓冲区指针，用于存放输入的文件名，最大长度 128 字节
  /// \param uiNameLen 文件名长度
  /// \param uiFileSize 文件所占存储空间的长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_CreateFile(unsigned char *pucFileName, unsigned int uiNameLen, /* max 128-byte */
                     unsigned int uiFileSize) const;

  /// 读取密码设备内部存储用户数据的文件的内容
  /// \param[in] pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
  /// \param[in] uiNameLen 文件名长度
  /// \param[in] uiOffset 指定读取文件时的偏移值
  /// \param[in,out] puiFileLength 入参时指定读取文件内容的长度；出参时返回实际读取文件内容的长度
  /// \param[out] pucBuffer 缓冲区指针，用于存放读取的文件数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_ReadFile(unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
                   unsigned int *puiFileLength, unsigned char *pucBuffer) const;

  /// 向密码设备内部存储用户数据的文件中写入内容
  /// \param[in] pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
  /// \param[in] uiNameLen 文件名长度
  /// \param[in] uiOffset 指定写入文件时的偏移值
  /// \param[in] uiFileLength 指定写入文件内容的长度
  /// \param[in] pucBuffer 缓冲区指针，用于存放输入的写文件数据
  /// \return 成功返回0，失败返回错误代码
  int SDF_WriteFile(unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
                    unsigned int uiFileLength, unsigned char *pucBuffer) const;

  /// 删除指定文件名的密码设备内部存储用户数据的文件
  /// \param[in] pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
  /// \param[in] uiNameLen 文件名长度
  /// \return 成功返回0，失败返回错误代码
  int SDF_DeleteFile(unsigned char *pucFileName, unsigned int uiNameLen) const;

  /// 导出证书
  /// \param[in] certId 证书标识
  /// \param[out] certData 证书数据
  /// \param[in,out] certDataLen 为证书数据分配内存大小以及返回证书数据实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_ExportCert(const char *certId, uint8_t *certData, uint32_t *certDataLen) const;

  /// 解析证书
  /// \param[in] certType 证书解析项标识
  /// \param[in] certData 待解析证书数据
  /// \param[in] certDataLen 待解析证书数据长度
  /// \param[out] certInfo 解析出来的证书项值
  /// \param[in,out] certInfoLen 为证书项分配的内存大小以及返回证书项实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_ParseCert(int certType, const uint8_t *certData, uint32_t certDataLen, uint8_t *certInfo,
                    uint32_t *certInfoLen) const;

  /// 验证证书有效性
  /// \param[in] certData 待验证证书有效性的数字证书
  /// \param[in] certDataLen 待验证证书数据长度
  /// \param[in] ocsp 是否获取证书ocsp状态，默认值为FALSE
  /// \param[out] state 返回证书OCSP状态标识
  /// \return 成功返回0，失败返回错误代码
  int SVS_ValidateCert(const uint8_t *certData, uint32_t certDataLen, bool ocsp, int *state) const;

  /// 单包数字签名
  /// \param[in] method 签名算法类型
  /// \param[in] signPrivateKeyIndex 签名者私钥索引
  /// \param[in] password 签名者私钥权限标识码
  /// \param[in] data 待签名数据原文
  /// \param[in] dataLen 原文长度
  /// \param[out] signData 签名值
  /// \param[in,out] signDataLen 为签名值分配的内存大小以及返回签名值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignData(int method, uint32_t signPrivateKeyIndex, const char *password, const uint8_t *data,
                   uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen) const;

  /// 单包验证数字签名
  /// \param type 签名验证方式，1:使用证书; 2: 使用证书序列号;3:使用证书名
  /// \param certData 证书数据
  /// \param certDataLen 证书数据长度
  /// \param data 待验签数据原文
  /// \param dataLen 待验签数据原文长度
  /// \param signData 签名值
  /// \param signDataLen 签名值长度
  /// \param verifyLevel 证书验证级别。
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedData(int type, const uint8_t *certData, uint32_t certDataLen, const uint8_t *data,
                           uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen, int verifyLevel) const;

  /// 多包数据签名初始化
  /// \param[in] method 签名算法类型
  /// \param[in] data 待签名数据原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配的内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignDataInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                       uint32_t *hashDataLen) const;

  /// 多包数据签名更新
  /// \param[in] method 签名算法类型
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] data 待签名数据原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 输出杂凑值中间值
  /// \param[in,out] hashDataLen 为杂凑值中间值分配的内存大小以及返回杂凑值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignDataUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen, const uint8_t *data,
                         uint32_t dataLen, uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包数据签名结束
  /// \param[in] method 签名算法类型
  /// \param[in] signPrivateKeyIndex 签名者私钥索引值
  /// \param[in] password 签名者私钥权限标识码
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[out] signData 签名值
  /// \param[in,out] signDataLen 为签名值分配的内存大小以及返回签名值的实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignDataFinal(int method, uint32_t signPrivateKeyIndex, const char *password, const uint8_t *hashMediantData,
                        uint32_t hashMediantDataLen, uint8_t *signData, uint32_t *signDataLen) const;

  /// 多包数据签名验签初始化
  /// \param[in] method 签名算法类型
  /// \param[in] data 待验签数据原文
  /// \param[in] dataLen 待验签数据原文长度
  /// \param[out] hashData 输出杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedDataInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                               uint32_t *hashDataLen) const;

  /// 多包数据签名验签更新
  /// \param[in] method 签名算法类型
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] data 待验签数据原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 输出杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配的内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedDataUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                 const uint8_t *data, uint32_t dataLen, uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包数据签名验签结束
  /// \param[in] method 签名算法类型
  /// \param[in] type 签名验证方式，1：使用证书，2：使用证书序列号
  /// \param[in] certData 证书数据/证书序列号
  /// \param[in] certDataLen 证书数据长度/证书序列号长度
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] signData 签名值
  /// \param[in] signDataLen 签名值长度
  /// \param[in] verifyLevel 证书验证级别，0：验证有效期，1：验证有效期和证书链；2：验证有效期，证书链以及CRL
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedDataFinal(int method, int type, const uint8_t *certData, uint32_t certDataLen,
                                const uint8_t *hashMediantData, uint32_t hashMediantDataLen, const uint8_t *signData,
                                uint32_t signDataLen, int verifyLevel) const;

  /// 单包消息签名
  /// \param[in] method 签名算法类型
  /// \param[in] signPrivateKeyIndex 签名者私钥索引值
  /// \param[in] password 签名者私钥权限标识码
  /// \param[in] data 待签名原文
  /// \param[in] dataLen 待签名原文长度
  /// \param[out] signData 签名值
  /// \param[in,out] signDataLen 为签名值分配的内存大小以及返回签名值实际大小
  /// \param[in] isHashFlag 待签名原文是否已哈希
  /// \param[in] isOriginalText 是否附加原文选项
  /// \param[in] isCertificateChain 是否附加证书链选项
  /// \param[in] isCrl 是否附加黑名单选项
  /// \param[in] isAuthenticationAttributes 是否附加鉴别属性选项
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignMessage(int method, uint32_t signPrivateKeyIndex, const char *password, const uint8_t *data,
                      uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen, bool isHashFlag, bool isOriginalText,
                      bool isCertificateChain, bool isCrl, bool isAuthenticationAttributes) const;

  /// 单包验证消息签名
  /// \param[in] data 待验签原文
  /// \param[in] dataLen 待验签原文长度
  /// \param[in] signData 签名值
  /// \param[in] signDataLen 签名值长度
  /// \param[in] isHashFlag 待验签原文是否已哈希
  /// \param[in] isOriginalText 是否附加原文选项
  /// \param[in] isCertificateChain 是否附加证书链选项
  /// \param[in] isCrl 是否附加黑名单选项
  /// \param[in] isAuthenticationAttributes 是否附加鉴别属性选项
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedMessage(const uint8_t *data, uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen,
                              bool isHashFlag, bool isOriginalText, bool isCertificateChain, bool isCrl,
                              bool isAuthenticationAttributes) const;

  /// 多包消息签名初始化
  /// \param[in] method 签名算法类型
  /// \param[in] data 待签名原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配的内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignMessageInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                          uint32_t *hashDataLen) const;

  /// 多包消息签名更新
  /// \param[in] method 签名算法类型
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] data 待签名原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 输出杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignMessageUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                            const uint8_t *data, uint32_t dataLen, uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包消息签名结束
  /// \param[in] method 签名算法类型
  /// \param[in] signPrivateKeyIndex 签名者私钥索引值
  /// \param[in] password 签名者私钥权限标识码
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[out] signData 签名值
  /// \param[in,out] signDataLen 为签名值分配的内存大小以及返回签名值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_SignMessageFinal(int method, uint32_t signPrivateKeyIndex, const char *password,
                           const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                           uint32_t *signDataLen) const;

  /// 多包消息签名验签初始化
  /// \param[in] method 签名算法标识
  /// \param[in] data 待验签原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedMessageInit(int method, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                  uint32_t *hashDataLen) const;

  /// 多包消息签名验签更新
  /// \param[in] method 签名算法类型
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] data 待验签原文
  /// \param[in] dataLen 原文长度
  /// \param[out] hashData 杂凑中间值
  /// \param[in,out] hashDataLen 为杂凑中间值分配内存大小以及返回杂凑中间值实际大小
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedMessageUpdate(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                    const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                    uint32_t *hashDataLen) const;

  /// 多包消息签名验签结束
  /// \param[in] method 签名算法类型
  /// \param[in] hashMediantData 杂凑中间值
  /// \param[in] hashMediantDataLen 杂凑中间值长度
  /// \param[in] signData 签名值
  /// \param[in] signDataLen 签名值长度
  /// \return 成功返回0，失败返回错误代码
  int SVS_VerifySignedMessageFinal(int method, const uint8_t *hashMediantData, uint32_t hashMediantDataLen,
                                   const uint8_t *signData, uint32_t signDataLen) const;

  /// 生成时间戳请求
  /// \param[in] pucInData 需要加盖时间戳的用户信息
  /// \param[in] uiInDataLength 用户信息的长度
  /// \param[in] uiReqType 请求的时间戳服务类型，0：时间戳响应应该包含时间戳服务器的证书，1：不包含
  /// \param[in] pucTSExt 时间戳请求包的其他扩展，DER编码格式
  /// \param[in] uiTSExtLength 时间戳请求包扩展的长度
  /// \param[in] uiHashAlgID 密码杂凑算法标识
  /// \param[out] pucTSRequest 时间戳请求
  /// \param[in,out] puiTSRequestLength 为时间戳请求分配的内存大小以及返回时间戳请求实际大小
  /// \return 成功返回0，失败返回错误代码
  SGD_UINT32 STF_CreateTSRequest(SGD_UINT8 *pucInData, SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                                 SGD_UINT8 *pucTSExt, SGD_UINT32 uiTSExtLength, SGD_UINT32 uiHashAlgID,
                                 SGD_UINT8 *pucTSRequest, SGD_UINT32 *puiTSRequestLength) const;

  /// 根据时间戳请求包获取时间戳响应包
  /// \param[in] pucTSRequest 时间戳请求
  /// \param[in] uiTSRequestLength 时间戳请求的长度
  /// \param[in] uiSignatureAlgID 签名算法标识
  /// \param[out] pucTSResponse 时间戳响应
  /// \param[in,out] puiTSResponseLength 为时间戳响应分配的内存大小以及返回时间戳响应实际大小
  /// \return 成功返回0，失败返回错误代码
  SGD_UINT32 STF_CreateTSResponse(SGD_UINT8 *pucTSRequest, SGD_UINT32 uiTSRequestLength, SGD_UINT32 uiSignatureAlgID,
                                  SGD_UINT8 *pucTSResponse, SGD_UINT32 *puiTSResponseLength) const;

  /// 验证时间戳响应是否有效
  /// 对于时间戳响应中包含证书时，优先使用指定证书pucTSCert进行验证
  /// \param[in] pucTSResponse 获取的时间戳响应
  /// \param[in] uiTSResponseLength 时间戳响应的长度
  /// \param[in] uiHashAlgID 密码杂凑算法标识
  /// \param[in] uiSignatureAlgID 签名算法标识
  /// \param[in] pucTSCert TSA的证书，DER编码格式
  /// \param[in] uiTSCertLength TSA证书的长度
  /// \return 成功返回0，失败返回错误代码
  SGD_UINT32 STF_VerifyTSValidity(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength, SGD_UINT32 uiHashAlgID,
                                  SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSCert, SGD_UINT32 uiTSCertLength) const;

  /// 获取时间戳主要信息
  /// \param[in] pucTSResponse 获取的时间戳响应
  /// \param[in] uiTSResponseLength 时间戳响应的长度
  /// \param[out] pucIssuerName TSA的通用名
  /// \param[in,out] puiIssuerNameLength 为TSA通用名分配内存大小以及返回实际大小
  /// \param[out] pucTime 时间戳标注的时间值
  /// \param[in,out] puiTimeLength 为时间戳标注的时间值分配内存以及返回实际大小
  /// \return 成功返回0，失败返回错误代码
  SGD_UINT32 STF_GetTSInfo(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength, SGD_UINT8 *pucIssuerName,
                           SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime, SGD_UINT32 *puiTimeLength) const;

  /// 解析时间戳详情信息
  /// \param[in] pucTSResponse 获取的时间戳响应
  /// \param[in] uiTSResponseLength 时间戳响应的长度
  /// \param[in] uiItemNumber 指定获取时间戳详细信息的项目编号
  /// \param[out] pucItemValue 解析得到的时间戳相关信息
  /// \param[in,out] puiItemValueLength 为时间戳相关信息分配的内存大小以及返回实际大小
  /// \return 成功返回0，失败返回错误代码
  SGD_UINT32 STF_GetTSDetail(SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength, SGD_UINT32 uiItemNumber,
                             SGD_UINT8 *pucItemValue, SGD_UINT32 *puiItemValueLength) const;

 protected:
  SessionImpl::Ptr pImpl_;
};

}  // namespace hsmc
