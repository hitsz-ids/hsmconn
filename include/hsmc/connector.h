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

#include <dlfcn.h>

#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

#include "exception.h"
#include "sdf_funcs.h"
#include "stf_funcs.h"

#ifdef ENABLE_OPENTELEMETRY_API
#include <opentelemetry/metrics/provider.h>
#endif

namespace hsmc {

class SessionImpl;

/// 密码设备枚举类型
enum class ConnectorType {
  /// 服务器密码机
  CT_HSM,

  /// 签名验签服务器
  CT_SVS,

  /// 时间戳服务器
  CT_TSS,

  CT_MAX };

/// `Connector`接口类对密码设备打开或连接进行了抽象定义，`Connector`定义了`open`和`close`的虚拟方法，在具体实现上`open`方法
/// 负责动态加载密码设备的客户端连接动态库，并解析客户端动态库中导出的函数方法，实现对该密码设备的打开操作及后续方法的调
/// 用。
/// 实现`Connector`的子类，需要根据设备类型实现`open`和`close`函数。以密码机为例，open函数在实现上需要调用SDF_OpenDevice
/// 方法打开密码机设备，close函数在实现上需要调用SDF_CloseDevice方法关闭密码机设备。
/// `Connector`定义了`createSession`纯虚函数，子类必须实现`createSession`函数。同样以密码机为例，在打开密码机设备后，需要
/// 根据设备句柄创建会话，因此`createSession`函数需要调用SDF_OpenSession方法创建会话。
class HSMC_API Connector : public std::enable_shared_from_this<Connector>, public Instrument<int> {
 public:
  /// Connector的智能指针类型定义
  using Ptr = std::shared_ptr<Connector>;

  /// Connector的构造函数，需要传入密码设备的动态库路径
  /// \param nativeLibPath 访问密码设备的客户端动态库路径
  explicit Connector(const std::string &nativeLibPath);

  /// Connector的构造函数，不需要传入密码设备的动态库路径
  Connector();

  /// Connector的析构函数
  virtual ~Connector();

  /// 获取设备连接器名称
  /// \return 设备连接器名称
  std::string getName() const;

  /// 设置设备连接器名称
  /// \param name 设备连接器名称
  void setName(const std::string &name);

  /// 打开设备连接器，子类需要重载该方法并根据设备类型实现具体的打开方法
  virtual void open();

  /// 关闭设备连接器，子类需要重载该方法并根据设备类型实现具体的关闭方法
  virtual void close();

  /// 重新打开设备连接器，当设备调用出现异常时，部分厂商设备必须重新打开设备才能继续使用
  /// 子类需要重载该方法并根据设备类型实现具体的重新打开方法
  virtual void reopen() = 0;

  /// 恢复设备连接器，当设备调用出现异常时，部分厂商设备必须恢复设备才能继续使用
  virtual void recover();

  /// 创建会话，子类需要重载该方法并根据设备类型实现具体的创建会话方法
  /// \return 设备会话对象指针
  virtual std::shared_ptr<SessionImpl> createSession() = 0;

  /// 获取设备连接器的句柄
  /// \return 设备连接器的句柄
  virtual void *getDeviceHandle() const = 0;

  /// 判断设备是否已打开
  /// \return 设备已打开返回true，否则返回false
  virtual bool isOpen() const = 0;

  /// 设置访问设备的配置文件
  /// \param configfile 配置文件路径
  void setConfig(const std::string &configfile);

  /// 获取访问设备的配置文件
  /// \return 配置文件路径
  std::string getConfig() const;

  /// 设置访问设备的客户端动态库路径
  /// \param library 客户端动态库路径
  void setLibrary(const std::string &library);

  /// 获取访问设备的客户端动态库路径
  /// \return 客户端动态库路径
  std::string getLibrary() const;

  /// 设备会话是否开启池化管理，默认开启池化
  /// \return 开启返回true，否则返回false
  bool isPooling() const;

  /// 设置设备会话是否开启池化管理
  /// \param pooling 开启池化管理设置为true，否则设置为false
  void setPooling(bool pooling);

  /// 设备是否为PCI-E密码卡模块
  /// \return 是PCI-E密码卡模块返回true，否则返回false
  bool isPCIE() const;

  /// 设置设备是否为PCI-E密码卡模块
  /// \param pcie 是PCI-E密码卡模块设置为true，否则设置为false
  void setPCIE(bool pcie);

  /// 当前设备的连接器类型，当前主要分为HSM、SVS、TSS三种类型
  /// \return 当前设备的连接器类型
  ConnectorType getConnectorType() const;

  /// 设置当前设备的连接器类型
  /// \param conntype 当前设备的连接器类型
  void setConnectorType(ConnectorType conntype);

  /// 实现Instrument的监控接口，进入函数调用
  /// \param fn 函数名称
  void enter(const std::string& fn);

  /// 实现Instrument的监控接口，离开函数调用
  /// \param fn 函数名称
  /// \param result 函数调用结果
  void leave(const std::string& fn, int result);

  /// 实现Instrument的监控接口，函数调用耗时
  /// \param fn 函数名称
  /// \param macroseconds 函数调用耗时，单位微秒
  void elapsed(const std::string& fn, uint64_t macroseconds);

  /// 打开签名验签服务器设备
  /// \param handle 返回的签名验签服务器设备句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SVS_Open(void **handle);

  /// 关闭签名验签服务器设备
  /// \param handle 签名验签服务器设备句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SVS_Close(void *handle);

  /// 设置签名验签服务器设备的IP
  /// \param ip 签名验签服务器设备的IP
  void SVS_SetIp(const std::string &ip);

  /// 设置签名验签服务器设备的端口
  /// \param port 签名验签服务器设备的端口
  void SVS_SetPort(uint16_t port);

  /// 设置签名验签服务器设备的密码
  /// \param password 签名验签服务器设备的密码
  void SVS_SetPassword(const std::string &password);

  /// 获取设备的权重值，默认权重值为10
  /// \return 设备的权重值
  int getWeight();

  /// 设置设备的权重值，当权重为0时，该节点将不被调度参与计算
  /// \param weight 设备的权重值
  void setWeight(int weight);

  /// 获取设备会话心跳检查间隔，单位秒
  /// \return 心跳间隔时长
  int getHeartbeatInterval() const;

  /// 设置设备会话心跳检查时长，单位秒
  /// \param interval 心跳间隔时长
  void setHeartbeatInterval(int interval);

  /// 获取设备会话闲置超时时长，单位秒
  /// \return 闲置超时时长
  int getIdleTimeout() const;

  /// 设置设备会话闲置超时时长，单位秒
  /// \param timeout 闲置超时时长
  void setIdleTimeout(int timeout);

 public:

  /// 打开密码机设备
  /// \param phDeviceHandle 返回的密码机设备句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SDF_OpenDevice(void **phDeviceHandle);

  /// 关闭密码机设备
  /// \param hDeviceHandle 密码机设备句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SDF_CloseDevice(void *hDeviceHandle);

  /// 打开密码机设备会话
  /// \param hDeviceHandle 密码机设备句柄
  /// \param phSessionHandle 返回的密码机设备会话句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

  /// 关闭密码机设备会话
  /// \param hSessionHandle 密码机设备会话句柄
  /// \return 成功返回0，否则返回错误码
  virtual int SDF_CloseSession(void *hSessionHandle);

  /// 获取密码机设备信息
  /// \param hSessionHandle 密码机设备会话句柄
  /// \param pstDeviceInfo 返回的密码机设备信息
  /// \return 成功返回0，否则返回错误码
  virtual int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo) const;

  /// SDF_GenerateRandom
  /// \param uiLength
  /// \param pucRandom
  /// \return
  virtual int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom) const;

  /// SDF_GetPrivateKeyAccessRight
  /// \param uiKeyIndex
  /// \param pucPassword
  /// \param uiPwdLength
  /// \return
  virtual int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword,
                                           unsigned int uiPwdLength) const;

  /// SDF_ReleasePrivateKeyAccessRight
  /// \param uiKeyIndex
  /// \return
  virtual int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex) const;

  /// SDF_ExportSignPublicKey_RSA
  /// \param uiKeyIndex
  /// \param pucPublicKey
  /// \return
  virtual int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                          RSArefPublicKey *pucPublicKey) const;

  /// SDF_ExportEncPublicKey_RSA
  /// \param uiKeyIndex
  /// \param pucPublicKey
  /// \return
  virtual int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                         RSArefPublicKey *pucPublicKey) const;

  /// SDF_GenerateKeyPair_RSA
  /// \param uiKeyBits
  /// \param pucPublicKey
  /// \param pucPrivateKey
  /// \return
  virtual int SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                      RSArefPrivateKey *pucPrivateKey) const;

  /// SDF_GenerateKeyWithIPK_RSA
  /// \param uiIPKIndex
  /// \param uiKeyBits
  /// \param pucKey
  /// \param puiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
                                         unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const;

  /// SDF_GenerateKeyWithEPK_RSA
  /// \param uiKeyBits
  /// \param pucPublicKey
  /// \param pucKey
  /// \param puiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                                         unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) const;

  /// SDF_ImportKeyWithISK_RSA
  /// \param uiISKIndex
  /// \param pucKey
  /// \param uiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey,
                                       unsigned int uiKeyLength, void **phKeyHandle) const;

  /// SDF_ExchangeDigitEnvelopeBaseOnRSA
  /// \param uiKeyIndex
  /// \param pucPublicKey
  /// \param pucDEInput
  /// \param uiDELength
  /// \param pucDEOutput
  /// \param puiDELength
  /// \return
  virtual int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                 RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput,
                                                 unsigned int uiDELength, unsigned char *pucDEOutput,
                                                 unsigned int *puiDELength) const;

  /// SDF_ExportSignPublicKey_ECC
  /// \param uiKeyIndex
  /// \param pucPublicKey
  /// \return
  virtual int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                          ECCrefPublicKey *pucPublicKey) const;

  /// SDF_ExportEncPublicKey_ECC
  /// \param uiKeyIndex
  /// \param pucPublicKey
  /// \return
  virtual int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                         ECCrefPublicKey *pucPublicKey) const;

  /// SDF_GenerateKeyPair_ECC
  /// \param uiAlgID
  /// \param uiKeyBits
  /// \param pucPublicKey
  /// \param pucPrivateKey
  /// \return
  virtual int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,
                                      ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey) const;

  /// SDF_GenerateKeyWithIPK_ECC
  /// \param uiIPKIndex
  /// \param uiKeyBits
  /// \param pucKey
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
                                         ECCCipher *pucKey, void **phKeyHandle) const;

  /// SDF_GenerateKeyWithEPK_ECC
  /// \param uiKeyBits
  /// \param uiAlgID
  /// \param pucPublicKey
  /// \param pucKey
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
                                         ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle) const;

  /// SDF_ImportKeyWithISK_ECC
  /// \param uiISKIndex
  /// \param pucKey
  /// \param phKeyHandle
  /// \return
  virtual int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey,
                                       void **phKeyHandle) const;

  /// SDF_GenerateAgreementDataWithECC
  /// \param uiISKIndex
  /// \param uiKeyBits
  /// \param pucSponsorID
  /// \param uiSponsorIDLength
  /// \param pucSponsorPublicKey
  /// \param pucSponsorTmpPublicKey
  /// \param phAgreementHandle
  /// \return
  virtual int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
                                               unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                               ECCrefPublicKey *pucSponsorPublicKey,
                                               ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle) const;

  /// SDF_GenerateKeyWithECC
  /// \param pucResponseID
  /// \param uiResponseIDLength
  /// \param pucResponsePublicKey
  /// \param pucResponseTmpPublicKey
  /// \param hAgreementHandle
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID,
                                     unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
                                     ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle,
                                     void **phKeyHandle) const;

  /// SDF_GenerateAgreementDataAndKeyWithECC
  /// \param uiISKIndex
  /// \param uiKeyBits
  /// \param pucResponseID
  /// \param uiResponseIDLength
  /// \param pucSponsorID
  /// \param uiSponsorIDLength
  /// \param pucSponsorPublicKey
  /// \param pucSponsorTmpPublicKey
  /// \param pucResponsePublicKey
  /// \param pucResponseTmpPublicKey
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateAgreementDataAndKeyWithECC(
      void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,
      unsigned int uiResponseIDLength, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
      ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
      ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle) const;

  /// SDF_ExchangeDigitEnvelopeBaseOnECC
  /// \param uiKeyIndex
  /// \param uiAlgID
  /// \param pucPublicKey
  /// \param pucEncDataIn
  /// \param pucEncDataOut
  /// \return
  virtual int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
                                                 ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
                                                 ECCCipher *pucEncDataOut) const;

  /// SDF_GenerateKeyWithKEK
  /// \param uiKeyBits
  /// \param uiAlgID
  /// \param uiKEKIndex
  /// \param pucKey
  /// \param puiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
                                     unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int *puiKeyLength,
                                     void **phKeyHandle) const;

  /// SDF_ImportKeyWithKEK
  /// \param uiAlgID
  /// \param uiKEKIndex
  /// \param pucKey
  /// \param uiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex,
                                   unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle) const;

  /// SDF_ImportKey
  /// \param pucKey
  /// \param uiKeyLength
  /// \param phKeyHandle
  /// \return
  virtual int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength,
                            void **phKeyHandle) const;

  /// SDF_DestroyKey
  /// \param hKeyHandle
  /// \return
  virtual int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle) const;

  /// SDF_ExternalPublicKeyOperation_RSA
  /// \param pucPublicKey
  /// \param pucDataInput
  /// \param uiInputLength
  /// \param pucDataOutput
  /// \param puiOutputLength
  /// \return
  virtual int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey,
                                                 unsigned char *pucDataInput, unsigned int uiInputLength,
                                                 unsigned char *pucDataOutput, unsigned int *puiOutputLength) const;

  /// SDF_InternalPublicKeyOperation_RSA
  /// \param uiKeyIndex
  /// \param pucDataInput
  /// \param uiInputLength
  /// \param pucDataOutput
  /// \param puiOutputLength
  /// \return
  virtual int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                 unsigned char *pucDataInput, unsigned int uiInputLength,
                                                 unsigned char *pucDataOutput, unsigned int *puiOutputLength) const;

  /// SDF_InternalPrivateKeyOperation_RSA
  /// \param uiKeyIndex
  /// \param pucDataInput
  /// \param uiInputLength
  /// \param pucDataOutput
  /// \param puiOutputLength
  /// \return
  virtual int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex,
                                                  unsigned char *pucDataInput, unsigned int uiInputLength,
                                                  unsigned char *pucDataOutput, unsigned int *puiOutputLength) const;

  /// SDF_ExternalPrivateKeyOperation_RSA
  /// \param pucPrivateKey
  /// \param pucDataInput
  /// \param uiInputLength
  /// \param pucDataOutput
  /// \param puiOutputLength
  /// \return
  virtual int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey,
                                                  unsigned char *pucDataInput, unsigned int uiInputLength,
                                                  unsigned char *pucDataOutput, unsigned int *puiOutputLength) const;

  /// SDF_ExternalSign_ECC
  /// \param uiAlgID
  /// \param pucPrivateKey
  /// \param pucData
  /// \param uiDataLength
  /// \param pucSignature
  /// \return
  virtual int SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                                   unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature) const;

  /// SDF_ExternalVerify_ECC
  /// \param uiAlgID
  /// \param pucPublicKey
  /// \param pucDataInput
  /// \param uiInputLength
  /// \param pucSignature
  /// \return
  virtual int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                     unsigned char *pucDataInput, unsigned int uiInputLength,
                                     ECCSignature *pucSignature) const;

  /// SDF_InternalSign_ECC
  /// \param uiISKIndex
  /// \param pucData
  /// \param uiDataLength
  /// \param pucSignature
  /// \return
  virtual int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
                                   unsigned int uiDataLength, ECCSignature *pucSignature) const;

  /// SDF_InternalVerify_ECC
  /// \param uiIPKIndex
  /// \param pucData
  /// \param uiDataLength
  /// \param pucSignature
  /// \return
  virtual int SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,
                                     unsigned int uiDataLength, ECCSignature *pucSignature) const;

  /// SDF_ExternalEncrypt_ECC
  /// \param uiAlgID
  /// \param pucPublicKey
  /// \param pucData
  /// \param uiDataLength
  /// \param pucEncData
  /// \return
  virtual int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                                      unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData) const;

  /// SDF_ExternalDecrypt_ECC
  /// \param uiAlgID
  /// \param pucPrivateKey
  /// \param pucEncData
  /// \param pucData
  /// \param puiDataLength
  /// \return
  virtual int SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                                      ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength) const;

  /// SDF_Encrypt
  /// \param hKeyHandle
  /// \param uiAlgID
  /// \param pucIV
  /// \param pucData
  /// \param uiDataLength
  /// \param pucEncData
  /// \param puiEncDataLength
  /// \return
  virtual int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                          unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData,
                          unsigned int *puiEncDataLength) const;

  /// SDF_Decrypt
  /// \param hKeyHandle
  /// \param uiAlgID
  /// \param pucIV
  /// \param pucEncData
  /// \param uiEncDataLength
  /// \param pucData
  /// \param puiDataLength
  /// \return
  virtual int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                          unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData,
                          unsigned int *puiDataLength) const;

  /// SDF_CalculateMAC
  /// \param hKeyHandle
  /// \param uiAlgID
  /// \param pucIV
  /// \param pucData
  /// \param uiDataLength
  /// \param pucMAC
  /// \param puiMACLength
  /// \return
  virtual int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                               unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC,
                               unsigned int *puiMACLength) const;

  /// SDF_HashInit
  /// \param uiAlgID
  /// \param pucPublicKey
  /// \param pucID
  /// \param uiIDLength
  /// \return
  virtual int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucID, unsigned int uiIDLength) const;

  /// SDF_HashUpdate
  /// \param pucData
  /// \param uiDataLength
  /// \return
  virtual int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) const;

  /// SDF_HashFinal
  /// \param pucHash
  /// \param puiHashLength
  /// \return
  virtual int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength) const;

  /// SDF_CreateFile
  /// \param pucFileName
  /// \param uiNameLen
  /// \param uiFileSize
  /// \return
  virtual int SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName,
                             unsigned int uiNameLen, /* max 128-byte */
                             unsigned int uiFileSize) const;

  /// SDF_ReadFile
  /// \param pucFileName
  /// \param uiNameLen
  /// \param uiOffset
  /// \param puiFileLength
  /// \param pucBuffer
  /// \return
  virtual int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
                           unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer) const;

  /// SDF_WriteFile
  /// \param pucFileName
  /// \param uiNameLen
  /// \param uiOffset
  /// \param uiFileLength
  /// \param pucBuffer
  /// \return
  virtual int SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
                            unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer) const;

  /// SDF_DeleteFile
  /// \param pucFileName
  /// \param uiNameLen
  /// \return
  virtual int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen) const;

 public:
  ///
  /// 签名验签服务器抽象接口定义
  ///

  /// 导出证书
  /// \param hSessionHandle
  /// \param certId
  /// \param certData
  /// \param certDataLen
  /// \return
  virtual int SVS_ExportCert(void *hSessionHandle, const char *certId, uint8_t *certData, uint32_t *certDataLen) const;

  /// 解析证书
  /// \param hSessionHandle
  /// \param certType
  /// \param certData
  /// \param certDataLen
  /// \param certInfo
  /// \param certInfoLen
  /// \return
  int SVS_ParseCert(void *hSessionHandle, int certType, const uint8_t *certData, uint32_t certDataLen,
                    uint8_t *certInfo, uint32_t *certInfoLen) const;

  /// 验证证书有效性
  /// \param hSessionHandle
  /// \param certData
  /// \param certDataLen
  /// \param ocsp
  /// \param state
  /// \return
  virtual int SVS_ValidateCert(void *hSessionHandle, const uint8_t *certData, uint32_t certDataLen, bool ocsp,
                               int *state) const;

  /// 单包数字签名
  /// \param hSessionHandle
  /// \param method
  /// \param signPrivateKeyIndex
  /// \param password
  /// \param data
  /// \param dataLen
  /// \param signData
  /// \param signDataLen
  /// \return
  virtual int SVS_SignData(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                           const uint8_t *data, uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen) const;

  /// 单包验证数字签名
  /// \param hSessionHandle 会话句柄
  /// \param type 签名验证方式，1:使用证书; 2: 使用证书序列号;3:使用证书名
  /// \param certData 证书数据
  /// \param certDataLen 证书数据长度
  /// \param data 待验签数据原文
  /// \param dataLen 待验签数据原文长度
  /// \param signData 签名值
  /// \param signDataLen 签名值长度
  /// \param verifyLevel 证书验证级别。
  /// \return
  virtual int SVS_VerifySignedData(void *hSessionHandle, int type, const uint8_t *certData, uint32_t certDataLen,
                                   const uint8_t *data, uint32_t dataLen, const uint8_t *signData, uint32_t signDataLen,
                                   int verifyLevel) const;

  /// 多包数据签名初始化
  /// \param hSessionHandle
  /// \param method
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_SignDataInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                               uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包数据签名更新
  /// \param hSessionHandle
  /// \param method
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_SignDataUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                 uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen, uint8_t *hashData,
                                 uint32_t *hashDataLen) const;

  /// 多包数据签名结束
  /// \param hSessionHandle
  /// \param method
  /// \param signPrivateKeyIndex
  /// \param password
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param signData
  /// \param signDataLen
  /// \return
  virtual int SVS_SignDataFinal(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                                const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                                uint32_t *signDataLen) const;

  /// 多包数据签名验签初始化
  /// \param hSessionHandle
  /// \param method
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_VerifySignedDataInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                       uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包数据签名验签更新
  /// \param hSessonHandle
  /// \param method
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_VerifySignedDataUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                         uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                         uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包数据签名验签结束
  /// \param hSessionHandle
  /// \param method
  /// \param type
  /// \param certData
  /// \param certDataLen
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param signData
  /// \param signDataLen
  /// \param verifyLevel
  /// \return
  virtual int SVS_VerifySignedDataFinal(void *hSessionHandle, int method, int type, const uint8_t *certData,
                                        uint32_t certDataLen, const uint8_t *hashMediantData,
                                        uint32_t hashMediantDataLen, const uint8_t *signData, uint32_t signDataLen,
                                        int verifyLevel) const;

  /// 单包消息签名
  /// \param hSessionHandle
  /// \param method
  /// \param signPrivateKeyIndex
  /// \param password
  /// \param data
  /// \param dataLen
  /// \param signData
  /// \param signDataLen
  /// \param isHashFlag
  /// \param isOriginalText
  /// \param isCertificateChain
  /// \param isCrl
  /// \param sAuthenticationAttributes
  /// \return
  virtual int SVS_SignMessage(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                              const uint8_t *data, uint32_t dataLen, uint8_t *signData, uint32_t *signDataLen,
                              bool isHashFlag, bool isOriginalText, bool isCertificateChain, bool isCrl,
                              bool sAuthenticationAttributes) const;

  /// 单包验证消息签名
  /// \param hSessionHandle
  /// \param data
  /// \param dataLen
  /// \param signData
  /// \param signDataLen
  /// \param isHashFlag
  /// \param isOriginalText
  /// \param isCertificateChain
  /// \param isCrl
  /// \param sAuthenticationAttributes
  /// \return
  virtual int SVS_VerifySignedMessage(void *hSessionHandle, const uint8_t *data, uint32_t dataLen,
                                      const uint8_t *signData, uint32_t signDataLen, bool isHashFlag,
                                      bool isOriginalText, bool isCertificateChain, bool isCrl,
                                      bool sAuthenticationAttributes) const;

  /// 多包消息签名初始化
  /// \param hSessionHandle
  /// \param method
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_SignMessageInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                  uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包消息签名更新
  /// \param hSessionHandle
  /// \param method
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_SignMessageUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                    uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                    uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包消息签名结束
  /// \param hSessionHandle
  /// \param method
  /// \param signPrivateKeyIndex
  /// \param password
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param signData
  /// \param signDataLen
  /// \return
  virtual int SVS_SignMessageFinal(void *hSessionHandle, int method, uint32_t signPrivateKeyIndex, const char *password,
                                   const uint8_t *hashMediantData, uint32_t hashMediantDataLen, uint8_t *signData,
                                   uint32_t *signDataLen) const;

  /// 多包消息签名验签初始化
  /// \param hSessionHandle
  /// \param method
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_VerifySignedMessageInit(void *hSessionHandle, int method, const uint8_t *data, uint32_t dataLen,
                                          uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包消息签名验签更新
  /// \param hSessonHandle
  /// \param method
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param data
  /// \param dataLen
  /// \param hashData
  /// \param hashDataLen
  /// \return
  virtual int SVS_VerifySignedMessageUpdate(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                            uint32_t hashMediantDataLen, const uint8_t *data, uint32_t dataLen,
                                            uint8_t *hashData, uint32_t *hashDataLen) const;

  /// 多包消息签名验签结束
  /// \param hSessionHandle
  /// \param method
  /// \param type
  /// \param certData
  /// \param certDataLen
  /// \param hashMediantData
  /// \param hashMediantDataLen
  /// \param signData
  /// \param signDataLen
  /// \param verifyLevel
  /// \return
  virtual int SVS_VerifySignedMessageFinal(void *hSessionHandle, int method, const uint8_t *hashMediantData,
                                           uint32_t hashMediantDataLen, const uint8_t *signData,
                                           uint32_t signDataLen) const;

 public:
  ///
  /// 时间戳服务器抽象接口定义
  ///

  /// 初始化时间戳环境句柄
  /// \param phTSHandle 时间戳环境句柄指针
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_InitEnvironment(void **phTSHandle) const;

  /// 清除时间戳环境句柄
  /// \param hTSHandle
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_ClearEnvironment(void *hTSHandle) const;

  /// 生成时间戳请求
  /// \param hTSHandle
  /// \param pucInData
  /// \param uiInDataLength
  /// \param uiReqType
  /// \param pucTSExt
  /// \param uiTSExtLength
  /// \param uiHashAlgID
  /// \param pucTSRequest
  /// \param puiTSRequestLength
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_CreateTSRequest(void *hTSHandle, SGD_UINT8 *pucInData, SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                                 SGD_UINT8 *pucTSExt, SGD_UINT32 uiTSExtLength, SGD_UINT32 uiHashAlgID,
                                 SGD_UINT8 *pucTSRequest, SGD_UINT32 *puiTSRequestLength) const;

  /// 根据时间戳请求包获取时间戳响应包
  /// \param hTSHandle
  /// \param pucTSRequest
  /// \param uiTSRequestLength
  /// \param uiSignatureAlgID
  /// \param pucTSResponse
  /// \param puiTSResponseLength
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_CreateTSResponse(void *hTSHandle, SGD_UINT8 *pucTSRequest, SGD_UINT32 uiTSRequestLength,
                                  SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSResponse,
                                  SGD_UINT32 *puiTSResponseLength) const;

  /// 验证时间戳响应是否有效
  /// \param hTSHandle
  /// \param pucTSResponse
  /// \param uiTSResponseLength
  /// \param uiHashAlgID
  /// \param uiSignatureAlgID
  /// \param pucTSCert
  /// \param uiTSCertLength
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_VerifyTSValidity(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                                  SGD_UINT32 uiHashAlgID, SGD_UINT32 uiSignatureAlgID, SGD_UINT8 *pucTSCert,
                                  SGD_UINT32 uiTSCertLength) const;

  /// 获取时间戳主要信息
  /// \param hTSHandle
  /// \param pucTSResponse
  /// \param uiTSResponseLength
  /// \param pucIssuerName
  /// \param puiIssuerNameLength
  /// \param pucTime
  /// \param puiTimeLength
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_GetTSInfo(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                           SGD_UINT8 *pucIssuerName, SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                           SGD_UINT32 *puiTimeLength) const;

  /// 解析时间戳详情信息
  /// \param hTSHandle
  /// \param pucTSResponse
  /// \param uiTSResponseLength
  /// \param uiItemNumber
  /// \param pucItemValue
  /// \param puiItemValueLength
  /// \return 0 -- 执行成功， 非 0 -- 执行错误，详见错误码定义
  SGD_UINT32 STF_GetTSDetail(void *hTSHandle, SGD_UINT8 *pucTSResponse, SGD_UINT32 uiTSResponseLength,
                             SGD_UINT32 uiItemNumber, SGD_UINT8 *pucItemValue, SGD_UINT32 *puiItemValueLength) const;

 protected:
  /// 解析SDF函数，遵循《GMT 0018-2012 密码设备应用接口规范》
  virtual void resolveSdfFuncs();
  virtual void resolveSvsFuncs();
  /// 解析STF函数，遵循《GMT 0033-2014 时间戳接口规范》
  virtual void resolveStfFuncs();

  /// 从动态链接库解析函数
  template <typename T>
  T resolveFunc(const std::string &funcName) {
    if (this->hNativeLib_ == nullptr) {
      char msg[256];
      snprintf(msg, sizeof(msg), "Can't resolve func `%s`, library `%s` not loaded", funcName.c_str(),
               this->nativeLibPath_.c_str());

      throw LibraryLoadException(msg);
    }
    T func = reinterpret_cast<T>(dlsym(this->hNativeLib_, funcName.c_str()));
    const char *dlsym_error = dlerror();
    if (dlsym_error) {
      char msg[256];
      snprintf(msg, sizeof(msg), "Fail to resolve function symbol: %s, %s", funcName.c_str(), dlsym_error);
      throw PropertyNotSupportedException(msg);
    }
    return func;
  }

 private:
  /// HSM设备连接器动态链接库路径
  std::string nativeLibPath_;

  /// HSM设备连接器配置文件
  std::string configFile_;

  /// HSM设备连接器动态链接库句柄
  void *hNativeLib_;

  /// 连接器名称
  std::string name_;

  /// 是否开启池化
  bool pooling_;

  /// 是否PCI-E密码模块
  bool pcie_;

  /// 会话心跳检查间隔（秒）
  int heartbeat_interval_;

  /// 清除会话空闲超时（秒）
  int idle_timeout_;

  /// 类型
  ConnectorType connType_;

  /// SDF的函数集合对象
  SDFFuncs sdf_;

  /// STF的函数结合对象
  STFFuncs stf_;

#ifdef ENABLE_OPENTELEMETRY_API
  opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>> counter;
  opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<uint64_t>> histogram;
#endif

  int weight_;

 protected:
  /// SVS地址
  std::string ip_;

  /// SVS端口
  uint16_t port_;

  /// SVS访问密码
  std::string password_;

  /// 子类需要对open操作进行保护
  std::mutex mutex_;
};

#define INSTRUMENTED_FUNC_INITIALIZER(name) \
  {#name, resolveFunc<name##_t>(#name), this}

#define FUNC_INITIALIZER(name) \
  resolveFunc<name##_t>(#name)

}  // namespace hsmc
