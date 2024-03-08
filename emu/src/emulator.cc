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

#include <absl/strings/escaping.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>

#include "absl/strings/str_format.h"
#include "device.h"
#include "sdf.h"
#include "yaml-cpp/yaml.h"

#ifdef __cplusplus
extern "C" {
#endif

static void _init() __attribute__((constructor));
static void _fini() __attribute__((destructor));

hsmc::emu::DevicePool *g_devices = nullptr;
hsmc::emu::SessionPool *g_sessions = nullptr;
std::atomic_int g_seq(0);
std::atomic_bool g_initialized{false};
std::atomic_bool g_finalized{false};
YAML::Node *root = nullptr;

/* SDF_UserData 结构保存Session相关的用户数据 */
typedef struct SDF_UserData {
  EVP_MD_CTX *mdCtx;
} SDF_UserData_t;

static SDF_UserData_t* SDF_UserData_new() {
  auto* userdata = (SDF_UserData_t*)calloc(1,sizeof(SDF_UserData_t));
  if (!userdata) {
    return nullptr;
  }
  if (!(userdata->mdCtx = EVP_MD_CTX_new())) {
    free(userdata);
    return nullptr;
  }
  return userdata;
}

static void SDF_UserData_free(void *userdata) {
  if (userdata != nullptr) {
    auto *sdf_userdata = (SDF_UserData_t *)userdata;
    if (sdf_userdata->mdCtx != nullptr) {
      EVP_MD_CTX_free(sdf_userdata->mdCtx);
      sdf_userdata->mdCtx = nullptr;
    }
    free(userdata);
  }
}

void _init() {
  if (g_initialized.exchange(true)) {
    return;
  }
  g_devices = new hsmc::emu::DevicePool();
  g_sessions = new hsmc::emu::SessionPool();
}

void _fini() {
  if (g_finalized.exchange(true)) {
    return;
  }
  delete g_sessions;
  g_sessions = nullptr;
  delete g_devices;
  g_devices = nullptr;
}

int emu_init() {
  _init();

  auto configfile = getenv("HSM_EMULATOR_CONFIG");
  if (nullptr == configfile) {
    return SDR_NO_CONFIG;
  }

  if (root != nullptr) {
    delete root;
    root = nullptr;
  }
  try {
    root = new YAML::Node(YAML::LoadFile(configfile));
  } catch (YAML::BadFile &e) {
    return SDR_CONFIG_BAD;
  }

  return SDR_OK;
}

int emu_fini() {
  _fini();
  return SDR_OK;
}

static bool _query_session(hsmc::emu::SessionHandle handle,
                           hsmc::emu::SessionPtr *session = nullptr,
                           hsmc::emu::DevicePtr *dev = nullptr) {
  auto sessionPtr = g_sessions->find(handle);
  if (!sessionPtr) {
    return false;
  }

  auto device = sessionPtr->getDevice();
  if (!device) {
    return false;
  }

  if (session != nullptr) {
    *session = sessionPtr;
  }
  if (dev != nullptr) {
    *dev = device;
  }

  return true;
}

static int _get_kek(int kek_index, std::string &kek_value) {
  auto ki = std::to_string(kek_index);
  if (!(*root) || !(*root)["kek"] || !(*root)["kek"][ki]) {
    return SDR_KEYNOTEXIST;
  }

  auto kekstr = (*root)["kek"][ki].as<std::string>();
  if (!absl::Base64Unescape(kekstr, &kek_value)) {
    return SDR_KEYERR;
  }
  return SDR_OK;
}

static int _encrypt_with_kek(int kek_index,
                             unsigned char *inbuf,
                             int inlen,
                             unsigned char *outbuf,
                             int *outlen) {
  std::string kek_value;
  int rc = SDR_OK;
  int out_len = 0, total_len = 0;
  EVP_CIPHER_CTX *ctx = nullptr;

  if ((rc = _get_kek(kek_index, kek_value)) != 0) {
    goto cleanup;
  }

  /* 使用kek_value中的密钥，使用sm4 ecb算法对inbuf和inlen的数据进行加密 */
  if (nullptr == (ctx = EVP_CIPHER_CTX_new())) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }

  rc = SDR_SYMOPERR;
  if (!EVP_CipherInit(ctx,
                      EVP_sm4_ecb(),
                      reinterpret_cast<const unsigned char *>(kek_value.c_str()),
                      nullptr,
                      1)) {
    goto cleanup;
  }

  if (!EVP_CipherUpdate(ctx,
                        outbuf,
                        &out_len,
                        inbuf,
                        inlen)) {
    goto cleanup;
  }
  total_len += out_len;

  if (!EVP_CipherFinal(ctx,
                       outbuf + total_len,
                       &out_len)) {
    goto cleanup;
  }
  total_len += out_len;
  *outlen = total_len;
  rc = SDR_OK;

cleanup:
  if (nullptr != ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return rc;
}

static int _decrypt_with_kek(int kek_index,
                             unsigned char *inbuf,
                             int inlen,
                             unsigned char *outbuf,
                             int *outlen) {
  std::string kek_value;
  int rc = SDR_OK;
  int out_len, total_len = 0;
  EVP_CIPHER_CTX *ctx = nullptr;

  if ((rc = _get_kek(kek_index, kek_value)) != 0) {
    goto cleanup;
  }

  if (nullptr == (ctx = EVP_CIPHER_CTX_new())) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }

  rc = SDR_SYMOPERR;
  if (!EVP_CipherInit(ctx,
                      EVP_sm4_ecb(),
                      reinterpret_cast<const unsigned char *>(kek_value.c_str()),
                      nullptr,
                      0)) {
    goto cleanup;
  }
  if (!EVP_CipherUpdate(ctx,
                        outbuf,
                        &out_len,
                        inbuf,
                        inlen)) {
    goto cleanup;
  }
  total_len += out_len;
  if (!EVP_CipherFinal(ctx,
                       outbuf + total_len,
                       &out_len)) {
    goto cleanup;
  }
  total_len += out_len;
  *outlen = total_len;
  rc = SDR_OK;

cleanup:
  if (nullptr != ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return rc;
}

static int _symmetric_operation(unsigned char *key,
                                int padding,
                                unsigned int uiAlgID,
                                unsigned char *pucIV,
                                unsigned char *in,
                                unsigned int inLen,
                                unsigned char *out,
                                unsigned int *outLen,
                                int isEnc) {
  const EVP_CIPHER *cipher = nullptr;
  int rc = SDR_OK;
  unsigned int updateSize = 0;
  unsigned int finalSize = 0;
  EVP_CIPHER_CTX *cipherCtx = nullptr;
  int blockSize = 16;

  if (SGD_SM4_ECB == uiAlgID) {
    cipher = EVP_get_cipherbynid(NID_sm4_ecb);
  } else if (SGD_SM4_CBC == uiAlgID) {
    if (nullptr == pucIV) {
      return SDR_INARGERR;
    }
    cipher = EVP_get_cipherbynid(NID_sm4_cbc);
  } else {
    return SDR_ALGNOTSUPPORT;
  }

  cipherCtx = EVP_CIPHER_CTX_new();
  if (nullptr == cipherCtx) {
    return SDR_NOBUFFER;
  }
  if (!EVP_CipherInit(cipherCtx,
                      cipher,
                      key,
                      pucIV,
                      isEnc)) {
    rc = SDR_SYMOPERR;
    goto cleanup;
  }

  // OPENSSL 默认使用PKCS7_PADDING
  if (EVP_CIPH_NO_PADDING == padding) {
    EVP_CIPHER_CTX_set_padding(cipherCtx, 0);
  }

  updateSize = *outLen;
  if (!EVP_CipherUpdate(cipherCtx,
                        out,
                        (int *)&updateSize,
                        in,
                        inLen)) {
    rc = SDR_SYMOPERR;
    goto cleanup;
  }

  if (EVP_CIPH_NO_PADDING == padding) {
    if (updateSize != inLen) {
      rc = SDR_INARGERR;
    } else {
      *outLen = updateSize;
      rc = SDR_OK;
    }
    goto cleanup;
  }

  finalSize = *outLen - updateSize;
  if (!EVP_CipherFinal(cipherCtx,
                       out + updateSize,
                       (int *)&finalSize)) {
    rc = SDR_SYMOPERR;
    goto cleanup;
  }
  *outLen = updateSize + finalSize;

  rc = SDR_OK;
cleanup:
  if (SDR_OK == rc && SGD_SM4_CBC == uiAlgID) {
    if (isEnc) {
      memcpy(pucIV, out + *outLen - blockSize, blockSize);
    } else {
      memcpy(pucIV, in + inLen - blockSize, blockSize);
    }
  }
  if (cipherCtx) {
    EVP_CIPHER_CTX_free(cipherCtx);
    cipherCtx = nullptr;
  }

  return rc;
}

// ECCrefPublicKey中X,Y是GM0018标准长度，分配64，实际数据32
static int ECCrefPublicKey2EC_KEY(ECCrefPublicKey *pucPublicKey,
                                  EC_KEY **key) {
  int rc = SDR_OK;
  unsigned char *dPublicKey = nullptr;
  unsigned char *tmpPublicKey = nullptr;
  EC_KEY *eckey = nullptr;

  if (nullptr == pucPublicKey || nullptr == key) {
    return SDR_INARGERR;
  }

  tmpPublicKey = (unsigned char *)malloc(1 + 32 + 32);
  dPublicKey = tmpPublicKey;
  if (nullptr == dPublicKey) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }
  *dPublicKey = 04;
  memcpy(dPublicKey + 1,      pucPublicKey->x + 32, 32);
  memcpy(dPublicKey + 1 + 32, pucPublicKey->y + 32, 32);

  eckey = EC_KEY_new_by_curve_name(NID_sm2);
  if (nullptr == eckey) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }
  if (!o2i_ECPublicKey(&eckey,
                       (const unsigned char **)&dPublicKey,
                       1 + 32 + 32)) {
    unsigned long l;
    l = ERR_get_error();
    if (0 != l) {
      printf("\nOPENSSL ERROR: [%lu] %s\n", l, ERR_error_string(l, nullptr));
    }
    rc = SDR_KEYERR;
    goto cleanup;
  }

  *key = eckey;
cleanup:
  if (tmpPublicKey) {
    free(tmpPublicKey);
    tmpPublicKey = nullptr;
  }
  if (rc != SDR_OK && eckey) {
    EC_KEY_free(eckey);
    eckey = nullptr;
  }

  return rc;
}

static int _sm2_pretreatment_one(uint8_t *out,
                                 const EVP_MD *digest,
                                 const uint8_t *id,
                                 const size_t id_len,
                                 const EC_KEY *key) {
  int rc = 0;
  const EC_GROUP *group = EC_KEY_get0_group(key);
  BN_CTX *ctx = nullptr;
  EVP_MD_CTX *hash = nullptr;
  BIGNUM *p = nullptr;
  BIGNUM *a = nullptr;
  BIGNUM *b = nullptr;
  BIGNUM *xG = nullptr;
  BIGNUM *yG = nullptr;
  BIGNUM *xA = nullptr;
  BIGNUM *yA = nullptr;
  int p_bytes = 0;
  uint8_t *buf = nullptr;
  uint16_t entl = 0;
  uint8_t e_byte = 0;

  hash = EVP_MD_CTX_new();
  ctx = BN_CTX_new();
  if (hash == nullptr || ctx == nullptr) {
    goto cleanup;
  }

  p = BN_CTX_get(ctx);
  a = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  xG = BN_CTX_get(ctx);
  yG = BN_CTX_get(ctx);
  xA = BN_CTX_get(ctx);
  yA = BN_CTX_get(ctx);

  if (yA == nullptr) {
    goto cleanup;
  }

  if (!EVP_DigestInit(hash, digest)) {
    goto cleanup;
  }

  /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

  if (id_len >= (UINT16_MAX / 8)) {
    /* too large */
    goto cleanup;
  }

  entl = (uint16_t)(8 * id_len);

  e_byte = entl >> 8;
  if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
    goto cleanup;
  }
  e_byte = entl & 0xFF;
  if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
    goto cleanup;
  }

  if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
    goto cleanup;
  }

  if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
    goto cleanup;
  }

  p_bytes = BN_num_bytes(p);
  buf = (uint8_t *)OPENSSL_zalloc(p_bytes);
  if (buf == nullptr) {
    goto cleanup;
  }

  if (BN_bn2binpad(a, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || BN_bn2binpad(b, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || !EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), xG, yG, ctx)
      || BN_bn2binpad(xG, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || BN_bn2binpad(yG, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || !EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), xA, yA, ctx)
      || BN_bn2binpad(xA, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || BN_bn2binpad(yA, buf, p_bytes) < 0
      || !EVP_DigestUpdate(hash, buf, p_bytes)
      || !EVP_DigestFinal(hash, out, nullptr)) {
    goto cleanup;
  }

  rc = 1;

cleanup:
  OPENSSL_free(buf);
  BN_CTX_free(ctx);
  EVP_MD_CTX_free(hash);
  return rc;
}

int SDF_OpenDevice(void **phDeviceHandle) {
  auto emuName = absl::StrFormat("emu-%02d", g_seq++);
  auto dev = std::make_shared<hsmc::emu::Device>(emuName);
  if (phDeviceHandle != nullptr) {
    *phDeviceHandle = dev.get();
  } else {
    return SDR_OUTARGERR;
  }
  g_devices->add(dev);
  return SDR_OK;
}

int SDF_CloseDevice(void *hDeviceHandle) {
  if (hDeviceHandle == nullptr) {
    return SDR_INARGERR;
  }
  hsmc::emu::DevicePtr dev = g_devices->find(hDeviceHandle, true);
  if (!dev) {
    return SDR_INARGERR;
  }
  g_sessions->eraseFromDevice(dev);
  return SDR_OK;
}

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) {
  hsmc::emu::DevicePtr dev = g_devices->find(hDeviceHandle);
  if (!dev) {
    return SDR_INARGERR;
  }
  auto id = dev->getId();
  auto sessName = absl::StrFormat("%s/sess-%02d",
                                  id.c_str(),
                                  dev->postIncSeq());
  auto session = std::make_shared<hsmc::emu::Session>(sessName, dev);
  if (phSessionHandle != nullptr) {
    *phSessionHandle = session.get();
  } else {
    return SDR_OUTARGERR;
  }

  g_sessions->add(session);
  dev->addSession(session);
  return SDR_OK;
}

int SDF_CloseSession(void *hSessionHandle) {
  if (hSessionHandle == nullptr || !g_sessions->erase(hSessionHandle)) {
    return SDR_INARGERR;
  }

  return SDR_OK;
}

int SDF_GetDeviceInfo(void *hSessionHandle,
                      DEVICEINFO *pstDeviceInfo) {
  if (pstDeviceInfo == nullptr) {
    return SDR_OUTARGERR;
  }

  hsmc::emu::SessionPtr session;
  hsmc::emu::DevicePtr dev;
  if (!_query_session(hSessionHandle, &session, &dev)) {
    return SDR_OPENSESSION;
  }

  memset(pstDeviceInfo, 0, sizeof(DEVICEINFO));
  // 设备生产厂商名称
  memcpy(pstDeviceInfo->IssuerName, "HSMC", 4);
  // 设备型号
  memcpy(pstDeviceInfo->DeviceName, "HSM-EMU", 7);
  // 设备编号：日期(8bytes)+批次号(3bytes)+流水号(5bytes)
  memcpy(pstDeviceInfo->DeviceSerial, "2021122800100001", 16);
  // 密码设备内部软件的版本号
  pstDeviceInfo->DeviceVersion = 0x00010001;
  // 密码设备支持的接口规范版本号
  pstDeviceInfo->StandardVersion = 1;
  // 前四字节表示支持的算法，非对称算法按位或的结果
  // 后四字节表示算法最大模长，支持的模长按位或的结果
  pstDeviceInfo->AsymAlgAbility[0] = SGD_SM2_1 | SGD_SM2_2 | SGD_SM2_3;
  pstDeviceInfo->AsymAlgAbility[1] = ECCref_MAX_BITS;
  // 所有支持的对称算法标识按位或的结果
  pstDeviceInfo->SymAlgAbility = SGD_SM4_CBC | SGD_SM4_ECB;
  // 所有支持的杂凑算法标识按位或的结果
  pstDeviceInfo->HashAlgAbility = SGD_SM3;
  // 支持的最大文件存储空间(单位字节)
  pstDeviceInfo->BufferSize = 0;

  return SDR_OK;
}

int SDF_GenerateRandom(void *hSessionHandle,
                       unsigned int uiLength,
                       unsigned char *pucRandom) {
  if (pucRandom == nullptr) {
    return SDR_OUTARGERR;
  }

  if (!_query_session(hSessionHandle)) {
    return SDR_OPENSESSION;
  }

  time_t t = time(nullptr);
  t = t * uiLength;
  RAND_seed(&t, sizeof(time_t));

  if (!RAND_bytes(pucRandom, (int)uiLength)) {
    return SDR_RANDERR;
  }

  return SDR_OK;
}

int SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
                                 unsigned int uiKeyIndex,
                                 unsigned char *pucPassword,
                                 unsigned int uiPwdLength) {
  return SDR_NOTSUPPORT;
}

int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                     unsigned int uiKeyIndex) {
  return SDR_NOTSUPPORT;
}

int SDF_ExportSignPublicKey_RSA(void *hSessionHandle,
                                unsigned int uiKeyIndex,
                                RSArefPublicKey *pucPublicKey) {
  return SDR_NOTSUPPORT;
}

int SDF_ExportEncPublicKey_RSA(void *hSessionHandle,
                               unsigned int uiKeyIndex,
                               RSArefPublicKey *pucPublicKey) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyPair_RSA(void *hSessionHandle,
                            unsigned int uiKeyBits,
                            RSArefPublicKey *pucPublicKey,
                            RSArefPrivateKey *pucPrivateKey) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle,
                               unsigned int uiIPKIndex,
                               unsigned int uiKeyBits,
                               unsigned char *pucKey,
                               unsigned int *puiKeyLength,
                               void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle,
                               unsigned int uiKeyBits,
                               RSArefPublicKey *pucPublicKey,
                               unsigned char *pucKey,
                               unsigned int *puiKeyLength,
                               void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_ImportKeyWithISK_RSA(void *hSessionHandle,
                             unsigned int uiISKIndex,
                             unsigned char *pucKey,
                             unsigned int uiKeyLength,
                             void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       RSArefPublicKey *pucPublicKey,
                                       unsigned char *pucDEInput,
                                       unsigned int uiDELength,
                                       unsigned char *pucDEOutput,
                                       unsigned int *puiDELength) {
  return SDR_NOTSUPPORT;
}

int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
                                unsigned int uiKeyIndex,
                                ECCrefPublicKey *pucPublicKey) {
  return SDR_NOTSUPPORT;
}

int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
                               unsigned int uiKeyIndex,
                               ECCrefPublicKey *pucPublicKey) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyPair_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            unsigned int uiKeyBits,
                            ECCrefPublicKey *pucPublicKey,
                            ECCrefPrivateKey *pucPrivateKey) {
  int rc;
  BN_CTX *ctx = nullptr;
  BIGNUM *bn_d = nullptr, *bn_x = nullptr, *bn_y = nullptr;
  const BIGNUM *bn_order;
  EC_GROUP *group = nullptr;
  EC_POINT *ec_pt = nullptr;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle)) {
    goto cleanup;
  }

  rc = SDR_ALGNOTSUPPORT;
  // 当前算法标识支持SGD_SM2_1,SGD_SM2_3,并且二者产生的密钥对无区别
  if (uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_3) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (uiKeyBits != 256 || nullptr == pucPublicKey || nullptr == pucPrivateKey) {
    goto cleanup;
  }

  rc = SDR_NOBUFFER;
  if ( !(ctx = BN_CTX_secure_new()) ) {
    goto cleanup;
  }
  BN_CTX_start(ctx);
  bn_d = BN_CTX_get(ctx);
  bn_x = BN_CTX_get(ctx);
  bn_y = BN_CTX_get(ctx);
  if ( !bn_y ) {
    goto cleanup;
  }

  rc = SDR_KEYERR;
  if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
    goto cleanup;
  }
  if (!(bn_order = EC_GROUP_get0_order(group))) {
    goto cleanup;
  }
  if (!(ec_pt = EC_POINT_new(group))) {
    goto cleanup;
  }

  do {
    if (!BN_rand_range(bn_d, bn_order)) {
      goto cleanup;
    }
  } while (BN_is_zero(bn_d));

  if (!EC_POINT_mul(group, ec_pt, bn_d, nullptr, nullptr, ctx)) {
    goto cleanup;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(group,
                                            ec_pt,
                                            bn_x,
                                            bn_y,
                                            ctx)) {
    goto cleanup;
  }

  pucPrivateKey->bits = 256;
  memset(pucPrivateKey->K, 0, sizeof(pucPrivateKey->K));
  if (BN_bn2binpad(bn_d, pucPrivateKey->K + 32, 32) != 32) {
    goto cleanup;
  }
  pucPublicKey->bits = 256;
  memset(pucPublicKey->x, 0, sizeof(pucPublicKey->x));
  memset(pucPublicKey->y, 0, sizeof(pucPublicKey->y));
  if (BN_bn2binpad(bn_x,pucPublicKey->x + 32,32) != 32) {
    goto cleanup;
  }
  if (BN_bn2binpad(bn_y,pucPublicKey->y + 32,32) != 32) {
    goto cleanup;
  }

  rc = SDR_OK;

cleanup:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }

  if (group) {
    EC_GROUP_free(group);
  }

  if (ec_pt) {
    EC_POINT_free(ec_pt);
  }
  return rc;
}

int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,
                               unsigned int uiIPKIndex,
                               unsigned int uiKeyBits,
                               ECCCipher *pucKey,
                               void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,
                               unsigned int uiKeyBits,
                               unsigned int uiAlgID,
                               ECCrefPublicKey *pucPublicKey,
                               ECCCipher *pucKey,
                               void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
                             unsigned int uiISKIndex,
                             ECCCipher *pucKey,
                             void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateAgreementDataWithECC(void *hSessionHandle,
                                     unsigned int uiISKIndex,
                                     unsigned int uiKeyBits,
                                     unsigned char *pucSponsorID,
                                     unsigned int uiSponsorIDLength,
                                     ECCrefPublicKey *pucSponsorPublicKey,
                                     ECCrefPublicKey *pucSponsorTmpPublicKey,
                                     void **phAgreementHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithECC(void *hSessionHandle,
                           unsigned char *pucResponseID,
                           unsigned int uiResponseIDLength,
                           ECCrefPublicKey *pucResponsePublicKey,
                           ECCrefPublicKey *pucResponseTmpPublicKey,
                           void *hAgreementHandle,
                           void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle,
                                           unsigned int uiISKIndex,
                                           unsigned int uiKeyBits,
                                           unsigned char *pucResponseID,
                                           unsigned int uiResponseIDLength,
                                           unsigned char *pucSponsorID,
                                           unsigned int uiSponsorIDLength,
                                           ECCrefPublicKey *pucSponsorPublicKey,
                                           ECCrefPublicKey *pucSponsorTmpPublicKey,
                                           ECCrefPublicKey *pucResponsePublicKey,
                                           ECCrefPublicKey *pucResponseTmpPublicKey,
                                           void **phKeyHandle) {
  return SDR_NOTSUPPORT;
}

int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       unsigned int uiAlgID,
                                       ECCrefPublicKey *pucPublicKey,
                                       ECCCipher *pucEncDataIn,
                                       ECCCipher *pucEncDataOut) {
  return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithKEK(void *hSessionHandle,
                           unsigned int uiKeyBits,
                           unsigned int uiAlgID,
                           unsigned int uiKEKIndex,
                           unsigned char *pucKey,
                           unsigned int *puiKeyLength,
                           void **phKeyHandle) {
  int rc;
  unsigned char* key_plain = nullptr, *key_cipher = nullptr;
  size_t kp_len, kc_len;
  hsmc::emu::Session::KeyPtr key_ptr;
  hsmc::emu::SessionPtr session;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle, &session)) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (0 != (uiKeyBits % 8)) {
    goto cleanup;
  }

  kp_len = uiKeyBits / 8;
  if (!(key_plain = (unsigned char*)malloc(kp_len))) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }
  if (SDR_OK != (rc = SDF_GenerateRandom(hSessionHandle,
                                         kp_len,
                                         key_plain))) {
    goto cleanup;
  }
  kc_len = kp_len + 16;
  if (!(key_cipher = (unsigned char*)malloc(kc_len))) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }
  if (_encrypt_with_kek((int)uiKEKIndex,
                        key_plain,
                        (int)kp_len,
                        key_cipher,
                        (int*)&kc_len)) {
    rc = SDR_KEYERR;
    goto cleanup;
  }
  if (pucKey == nullptr || puiKeyLength == nullptr || *puiKeyLength < kc_len
      || phKeyHandle == nullptr) {
    rc = SDR_OUTARGERR;
    goto cleanup;
  }
  memcpy(pucKey, key_cipher, kc_len);
  *puiKeyLength = kc_len;

  key_ptr = std::make_shared<hsmc::emu::Session::Key>(
      key_plain, kp_len, uiKEKIndex);
  session->addKey(key_ptr);
  *phKeyHandle = key_ptr.get();
  
  rc = SDR_OK;

cleanup:
  if (key_plain) {
    free(key_plain);
  }
  if (key_cipher) {
    free(key_cipher);
  }
  return rc;
}

int SDF_ImportKeyWithKEK(void *hSessionHandle,
                         unsigned int uiAlgID,
                         unsigned int uiKEKIndex,
                         unsigned char *pucKey,
                         unsigned int uiKeyLength,
                         void **phKeyHandle) {
  int rc;
  unsigned char *key_plain = nullptr;
  int kp_len;
  hsmc::emu::Session::KeyPtr key_ptr;
  hsmc::emu::SessionPtr session;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle, &session)) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (!pucKey) {
    goto cleanup;
  }

  kp_len = (int)uiKeyLength;
  if (!(key_plain = (unsigned char*)malloc(kp_len))) {
    rc = SDR_NOBUFFER;
    goto cleanup;
  }
  if (_decrypt_with_kek(uiKEKIndex,
                        pucKey,
                        uiKeyLength,
                        key_plain,
                        &kp_len)) {
    rc = SDR_KEYERR;
    goto cleanup;
  }

  if (phKeyHandle == nullptr) {
    rc = SDR_OUTARGERR;
    goto cleanup;
  }
  key_ptr = std::make_shared<hsmc::emu::Session::Key>(
      key_plain, kp_len, uiKEKIndex);
  session->addKey(key_ptr);
  *phKeyHandle = key_ptr.get();
  
  rc = SDR_OK;

cleanup:
  if (key_plain) {
    free(key_plain);
  }
  return rc;
}

int SDF_ImportKey(void *hSessionHandle,
                  unsigned char *pucKey,
                  unsigned int uiKeyLength,
                  void **phKeyHandle) {
  if (pucKey == nullptr) {
    return SDR_INARGERR;
  }

  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  if (phKeyHandle == nullptr) {
    return SDR_OUTARGERR;
  }
  auto key_ptr = std::make_shared<hsmc::emu::Session::Key>(
      pucKey, uiKeyLength);
  session->addKey(key_ptr);
  *phKeyHandle = key_ptr.get();

  return SDR_OK;
}

int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle) {
  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  session->eraseKey(hKeyHandle);
  return SDR_OK;
}

int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,
                                       RSArefPublicKey *pucPublicKey,
                                       unsigned char *pucDataInput,
                                       unsigned int uiInputLength,
                                       unsigned char *pucDataOutput,
                                       unsigned int *puiOutputLength) {
  return SDR_NOTSUPPORT;
}

int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       unsigned char *pucDataInput,
                                       unsigned int uiInputLength,
                                       unsigned char *pucDataOutput,
                                       unsigned int *puiOutputLength) {
  return SDR_NOTSUPPORT;
}

int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                        unsigned int uiKeyIndex,
                                        unsigned char *pucDataInput,
                                        unsigned int uiInputLength,
                                        unsigned char *pucDataOutput,
                                        unsigned int *puiOutputLength) {
  return SDR_NOTSUPPORT;
}

int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                        RSArefPrivateKey *pucPrivateKey,
                                        unsigned char *pucDataInput,
                                        unsigned int uiInputLength,
                                        unsigned char *pucDataOutput,
                                        unsigned int *puiOutputLength) {
  return SDR_NOTSUPPORT;
}

int SDF_ExternalSign_ECC(void *hSessionHandle,
                         unsigned int uiAlgID,
                         ECCrefPrivateKey *pucPrivateKey,
                         unsigned char *pucData,
                         unsigned int uiDataLength,
                         ECCSignature *pucSignature) {
  int rc = SDR_OK;
  BN_CTX *ctx = nullptr;
  EC_GROUP *group = nullptr;
  BIGNUM *ck = nullptr;
  BIGNUM *bn_k = nullptr;
  BIGNUM *bn_x = nullptr;
  BIGNUM *bn_m = nullptr;
  BIGNUM *bn_one = nullptr;
  BIGNUM *bn_r = nullptr;
  BIGNUM *bn_s = nullptr;
  BIGNUM *bn_s1 = nullptr;
  BIGNUM *bn_s2 = nullptr;
  BIGNUM *bn_tmp = nullptr;
  BIGNUM *bn_d = nullptr;
  const BIGNUM *bn_order = nullptr;
  const EC_POINT *generator = nullptr;
  EC_POINT *k_G = nullptr;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle)) {
    goto cleanup;
  }

  rc = SDR_ALGNOTSUPPORT;
  if (uiAlgID != SGD_SM2_1) {
    goto cleanup;
  }

  /* check input parameters */
  rc = SDR_INARGERR;
  if (pucPrivateKey == nullptr || pucData == nullptr || pucSignature == nullptr
      || uiDataLength != 32 || pucPrivateKey->bits != 256) {
    goto cleanup;
  }

  rc = SDR_NOBUFFER;
  if (!(ctx = BN_CTX_secure_new())) {
    goto cleanup;
  }

  BN_CTX_start(ctx);
  bn_m = BN_CTX_get(ctx);
  bn_k = BN_CTX_get(ctx);
  bn_x = BN_CTX_get(ctx);
  bn_one = BN_CTX_get(ctx);
  bn_r = BN_CTX_get(ctx);
  bn_s = BN_CTX_get(ctx);
  bn_s1 = BN_CTX_get(ctx);
  bn_s2 = BN_CTX_get(ctx);
  bn_tmp = BN_CTX_get(ctx);
  bn_d = BN_CTX_get(ctx);
  // remember to check the return value of last BN_CTX_get call
  if (!bn_d) {
    goto cleanup;
  }

  if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
    goto cleanup;
  }

  if (!(k_G = EC_POINT_new(group))) {
    goto cleanup;
  }

  rc = SDR_SIGNERR;
  if (!(bn_order = EC_GROUP_get0_order(group))) {
    goto cleanup;
  }

  if (!(generator = EC_GROUP_get0_generator(group))) {
    goto cleanup;
  }

  if (!BN_one(bn_one)) {
    goto cleanup;
  }

  // data buffer to BIGNUM m
  if (!BN_bin2bn(pucData, (int)uiDataLength, bn_m)) {
    goto cleanup;
  }
  // private key buffer to BIGNUM d
  if (!BN_bin2bn(pucPrivateKey->K + 32, 32, bn_d)) {
    goto cleanup;
  }

  do {
    // generate random k
    if (!BN_rand_range(bn_k, bn_order)) {
      goto cleanup;
    }

    if (BN_is_zero(bn_k)) continue;
    /* calculate kG = k * G */
    if (!EC_POINT_mul(group, k_G, bn_k, nullptr, nullptr, ctx)) {
      goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group,
                                             k_G,
                                             bn_x,
                                             nullptr,
                                             ctx)) {
      goto cleanup;
    }

    if (!BN_mod_add(bn_r, bn_m, bn_x, bn_order, ctx)) {
      goto cleanup;
    }
    /* check r == 0 */
    if (BN_is_zero(bn_r)) continue;

    if (!BN_add(bn_tmp, bn_r, bn_k)) {
      goto cleanup;
    }
    /* check r + k == n */
    if (BN_cmp(bn_tmp, bn_order) == 0) continue;

    /* calculate bn_tmp = 1 + d */
    if (!BN_add(bn_tmp, bn_one, bn_d)) {
      goto cleanup;
    }
    /* calculate s1 = (1 + d) ^ -1 */
    if (!BN_mod_inverse(bn_s1, bn_tmp, bn_order, ctx)) {
      goto cleanup;
    }
    /* calculate bn_tmp = r * d */
    if (!BN_mul(bn_tmp, bn_r, bn_d, ctx)) {
      goto cleanup;
    }
    /* calculate s2 = k - r * d */
    if (!BN_mod_sub(bn_s2, bn_k, bn_tmp, bn_order, ctx)) {
      goto cleanup;
    }
    if (!BN_mod_mul(bn_s, bn_s1, bn_s2, bn_order, ctx)) {
      goto cleanup;
    }
  } while (BN_is_zero(bn_s));

  memset(pucSignature->r, 0, sizeof(pucSignature->r));
  memset(pucSignature->s, 0, sizeof(pucSignature->s));
  if (BN_bn2binpad(bn_r, pucSignature->r + 32, 32) != 32) {
    goto cleanup;
  }
  if (BN_bn2binpad(bn_s, pucSignature->s + 32, 32) != 32) {
    goto cleanup;
  }
  rc = SDR_OK;

cleanup:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (group) {
    EC_GROUP_free(group);
  }
  if (k_G) {
    EC_POINT_free(k_G);
  }
  return rc;
}

int SDF_ExternalVerify_ECC(void *hSessionHandle,
                           unsigned int uiAlgID,
                           ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucDataInput,
                           unsigned int uiInputLength,
                           ECCSignature *pucSignature) {
  int rc = SDR_OK;
  BN_CTX *ctx = nullptr;
  EC_GROUP *group = nullptr;
  BIGNUM *bn_pubkey_x = nullptr;
  BIGNUM *bn_pubkey_y = nullptr;
  BIGNUM *bn_r = nullptr;
  BIGNUM *bn_s = nullptr;
  BIGNUM *bn_t = nullptr;
  BIGNUM *bn_x = nullptr;
  BIGNUM *bn_y = nullptr;
  BIGNUM *bn_R = nullptr;
  BIGNUM *bn_e = nullptr;
  const BIGNUM *bn_order = nullptr;
  const EC_POINT *generator = nullptr;
  EC_POINT *ec_pubkey_pt = nullptr, *ec_pt1 = nullptr, *ec_pt2 = nullptr;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle)) {
    goto cleanup;
  }

  rc = SDR_ALGNOTSUPPORT;
  if (uiAlgID != SGD_SM2_1) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (!pucPublicKey || !pucDataInput || !pucSignature
      || uiInputLength != 32 || pucPublicKey->bits != 256) {
    goto cleanup;
  }

  rc = SDR_NOBUFFER;
  if (!(ctx = BN_CTX_new())) {
    goto cleanup;
  }
  BN_CTX_start(ctx);
  bn_pubkey_x = BN_CTX_get(ctx);
  bn_pubkey_y = BN_CTX_get(ctx);
  bn_r = BN_CTX_get(ctx);
  bn_s = BN_CTX_get(ctx);
  bn_t = BN_CTX_get(ctx);
  bn_x = BN_CTX_get(ctx);
  bn_y = BN_CTX_get(ctx);
  bn_R = BN_CTX_get(ctx);
  bn_e = BN_CTX_get(ctx);
  // remember to check the return value of last BN_CTX_get call
  if (!bn_e) {
    goto cleanup;
  }

  if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
  {
    goto cleanup;
  }

  if (!(ec_pubkey_pt = EC_POINT_new(group))) {
    goto cleanup;
  }

  if (!(ec_pt1 = EC_POINT_new(group))) {
    goto cleanup;
  }

  if (!(ec_pt2 = EC_POINT_new(group))) {
    goto cleanup;
  }

  rc = SDR_VERIFYERR;
  if (!(bn_order = EC_GROUP_get0_order(group))) {
    goto cleanup;
  }

  if (!(generator = EC_GROUP_get0_generator(group))) {
    goto cleanup;
  }

  if (!BN_bin2bn(pucDataInput, 32, bn_e)) {
    goto cleanup;
  }

  if (!BN_bin2bn(pucPublicKey->x + 32, 32, bn_pubkey_x)) {
    goto cleanup;
  }
  if (!BN_bin2bn(pucPublicKey->y + 32, 32, bn_pubkey_y)) {
    goto cleanup;
  }

  if (!BN_bin2bn(pucSignature->r + 32, 32, bn_r)) {
    goto cleanup;
  }
  if (!BN_bin2bn(pucSignature->s + 32, 32, bn_s)) {
    goto cleanup;
  }

  /* check r in [1, n-1 ]*/
  if (BN_is_zero(bn_r) || BN_cmp(bn_r, bn_order) >= 0) {
    goto cleanup;
  }
  /* check s in [1, n-1 ]*/
  if (BN_is_zero(bn_s) || BN_cmp(bn_s, bn_order) >= 0) {
    goto cleanup;
  }

  if (!BN_mod_add(bn_t, bn_r, bn_s, bn_order, ctx)) {
    goto cleanup;
  }
  if (BN_is_zero(bn_t)) {
    goto cleanup;
  }

  if (!EC_POINT_mul(group, ec_pt1, bn_s, nullptr, nullptr, ctx)) {
    goto cleanup;
  }

  if (!EC_POINT_set_affine_coordinates_GFp(group,
                                           ec_pubkey_pt,
                                           bn_pubkey_x,
                                           bn_pubkey_y,
                                           ctx)) {
    goto cleanup;
  }

  if (!EC_POINT_mul(group, ec_pt2, nullptr, ec_pubkey_pt, bn_t, ctx)) {
    goto cleanup;
  }

  if (!EC_POINT_add(group, ec_pt1, ec_pt1, ec_pt2, ctx)) {
    goto cleanup;
  }

  if (!EC_POINT_get_affine_coordinates_GFp(group,
                                           ec_pt1,
                                           bn_x,
                                           bn_y,
                                           ctx)) {
    goto cleanup;
  }

  if (!BN_mod_add(bn_R, bn_e, bn_x, bn_order, ctx)) {
    goto cleanup;
  }

  if (BN_cmp(bn_R, bn_r) != 0) {
    goto cleanup;
  }

  rc = SDR_OK;
cleanup:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (group) {
    EC_GROUP_free(group);
  }
  if (ec_pubkey_pt) {
    EC_POINT_free(ec_pubkey_pt);
  }
  if (ec_pt1) {
    EC_POINT_free(ec_pt1);
  }
  if (ec_pt2) {
    EC_POINT_free(ec_pt2);
  }
  return rc;
}

int SDF_InternalSign_ECC(void *hSessionHandle,
                         unsigned int uiISKIndex,
                         unsigned char *pucData,
                         unsigned int uiDataLength,
                         ECCSignature *pucSignature) {
  return SDR_NOTSUPPORT;
}

int SDF_InternalVerify_ECC(void *hSessionHandle,
                           unsigned int uiIPKIndex,
                           unsigned char *pucData,
                           unsigned int uiDataLength,
                           ECCSignature *pucSignature) {
  return SDR_NOTSUPPORT;
}

int SDF_ExternalEncrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucData,
                            unsigned int uiDataLength,
                            ECCCipher *pucEncData) {
  int rc = SDR_OK;
  unsigned char x2[32], y2[32], x2_y2[64];
  unsigned char *t = nullptr;
  BN_CTX *ctx = nullptr;
  BIGNUM *bn_k = nullptr, *bn_c1_x = nullptr, *bn_c1_y = nullptr;
  BIGNUM *bn_pub_key_x = nullptr, *bn_pub_key_y = nullptr;
  BIGNUM *bn_x2 = nullptr, *bn_y2 = nullptr;
  const BIGNUM *bn_order, *bn_cofactor;
  EC_GROUP *group = nullptr;
  const EC_POINT *generator;
  EC_POINT *pub_key_pt = nullptr, *c1_pt = nullptr, *s_pt = nullptr, *ec_pt = nullptr;
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx = nullptr;
  int i, flag;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle)) {
    goto cleanup;
  }

  rc = SDR_ALGNOTSUPPORT;
  if (uiAlgID != SGD_SM2_3) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (!pucPublicKey || !pucData || !pucEncData
      || pucPublicKey->bits != 256) {
    goto cleanup;
  }

  rc = SDR_NOBUFFER;
  if (!(ctx = BN_CTX_new())) {
    goto cleanup;
  }
  if (!(t = static_cast<unsigned char *>(malloc(uiDataLength)))) {
    goto cleanup;
  }
  BN_CTX_start(ctx);
  bn_k = BN_CTX_get(ctx);
  bn_c1_x = BN_CTX_get(ctx);
  bn_c1_y = BN_CTX_get(ctx);
  bn_pub_key_x = BN_CTX_get(ctx);
  bn_pub_key_y = BN_CTX_get(ctx);
  bn_x2 = BN_CTX_get(ctx);
  bn_y2 = BN_CTX_get(ctx);
  if ( !(bn_y2) ) {
    goto cleanup;
  }
  if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) ){
    goto cleanup;
  }

  if ( !(pub_key_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(c1_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(s_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(ec_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }

  if ( !(md_ctx = EVP_MD_CTX_new()) ) {
    goto cleanup;
  }

  rc = SDR_ENCDATAERR;
  if (!BN_bin2bn(pucPublicKey->x + 32, 32, bn_pub_key_x)) {
    goto cleanup;
  }
  if (!BN_bin2bn(pucPublicKey->y + 32, 32, bn_pub_key_y)) {
    goto cleanup;
  }
  if (!(bn_order = EC_GROUP_get0_order(group))) {
    goto cleanup;
  }
  if (!(bn_cofactor = EC_GROUP_get0_cofactor(group))) {
    goto cleanup;
  }
  if (!(generator = EC_GROUP_get0_generator(group))) {
    goto cleanup;
  }
  if (!(EC_POINT_set_affine_coordinates_GFp(group,
                                            pub_key_pt,
                                            bn_pub_key_x,
                                            bn_pub_key_y,
                                            ctx))) {
    goto cleanup;
  }
  /* 计算椭圆曲线点S=[h]*P */
  if (!(EC_POINT_mul(group, s_pt, nullptr, pub_key_pt, bn_cofactor, ctx))) {
    goto cleanup;
  }
  /* 若S是无穷远点，则报错并退出 */
  if (EC_POINT_is_at_infinity(group, s_pt)) {
    goto cleanup;
  }
  md = EVP_sm3();

  do {
    /* 用随机数发生器产生随机数k∈[1,n-1] */
    if (!BN_rand_range(bn_k, bn_order)) {
      goto cleanup;
    }
    if (BN_is_zero(bn_k)) continue;
    /* 计算椭圆曲线点C1=[k]G=(x1,y1) */
    if (!EC_POINT_mul(group, c1_pt, bn_k, nullptr, nullptr, ctx)) {
      goto cleanup;
    }
    /* 计算椭圆曲线点[k]P=(x2,y2) */
    if (!EC_POINT_mul(group, ec_pt, nullptr, pub_key_pt, bn_k, ctx)) {
      goto cleanup;
    }
    /* 将坐标x2、y2的数据类型转换为比特串 */
    if (!EC_POINT_get_affine_coordinates_GFp(group,
                                             ec_pt,
                                             bn_x2,
                                             bn_y2,
                                             ctx)) {
      goto cleanup;
    }
    if (BN_bn2binpad(bn_x2, x2, sizeof(x2)) != sizeof(x2)) {
      goto cleanup;
    }
    if (BN_bn2binpad(bn_y2, y2, sizeof(y2)) != sizeof(y2)) {
      goto cleanup;
    }
    /*计算t=KDF (x2 || y2, klen)，若t为全0比特串，则返回循环开头*/
    memcpy(x2_y2, x2, sizeof(x2));
    memcpy(x2_y2 + sizeof(x2), y2, sizeof(y2));
    if (!ECDH_KDF_X9_62(t,
                        uiDataLength,
                        x2_y2,
                        sizeof(x2_y2),
                        nullptr,
                        0,
                        md)) {
      goto cleanup;
    }
    flag = 1;
    for (i = 0; i < uiDataLength; i++) {
      if (t[i] != 0) {
        flag = 0;
        break;
      }
    }
  } while (flag);

  if (!EC_POINT_get_affine_coordinates_GFp(group,
                                           c1_pt,
                                           bn_c1_x,
                                           bn_c1_y,
                                           ctx)) {
    goto cleanup;
  }
  memset(pucEncData->x, 0, sizeof(pucEncData->x));
  memset(pucEncData->y, 0, sizeof(pucEncData->y));
  if (BN_bn2binpad(bn_c1_x, pucEncData->x + 32, 32) != 32) {
    goto cleanup;
  }
  if (BN_bn2binpad(bn_c1_y, pucEncData->y + 32, 32) != 32) {
    goto cleanup;
  }

  /*计算C3 = Hash(x2 || M || y2);*/
  if (!EVP_DigestInit_ex(md_ctx, md, nullptr)) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, x2, sizeof(x2))) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, pucData, uiDataLength)) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, y2, sizeof(y2))) {
    goto cleanup;
  }
  if (!EVP_DigestFinal_ex(md_ctx, pucEncData->M, nullptr)) {
    goto cleanup;
  }
  pucEncData->L = uiDataLength;
  /* 计算C2 = M | t */
  for (i = 0; i < pucEncData->L; i++) {
    pucEncData->C[i] = pucData[i] ^ t[i];
  }
  rc = SDR_OK;

cleanup:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (t) {
    free(t);
  }
  if (group) {
    EC_GROUP_free(group);
  }
  if (pub_key_pt) {
    EC_POINT_free(pub_key_pt);
  }
  if (c1_pt) {
    EC_POINT_free(c1_pt);
  }
  if (s_pt) {
    EC_POINT_free(s_pt);
  }
  if (ec_pt) {
    EC_POINT_free(ec_pt);
  }
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
  }
  return rc;
}

int SDF_ExternalDecrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData,
                            unsigned char *pucData,
                            unsigned int *puiDataLength) {
  int rc;
  unsigned char x2[32], y2[32];
  unsigned char x2_y2[64], digest[32];
  unsigned char *t = nullptr, *M = nullptr;
  BN_CTX *ctx = nullptr;
  BIGNUM *bn_d = nullptr, *bn_c1_x = nullptr, *bn_c1_y = nullptr;
  BIGNUM *bn_x2 = nullptr, *bn_y2 = nullptr;
  const BIGNUM *bn_cofactor;
  EC_GROUP *group = nullptr;
  EC_POINT *c1_pt = nullptr, *s_pt = nullptr, *ec_pt = nullptr;
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx = nullptr;
  int i, flag;

  rc = SDR_OPENSESSION;
  if (!_query_session(hSessionHandle)) {
    goto cleanup;
  }

  rc = SDR_ALGNOTSUPPORT;
  if (uiAlgID != SGD_SM2_3) {
    goto cleanup;
  }

  rc = SDR_INARGERR;
  if (!pucPrivateKey || !pucData || !pucEncData
      || !puiDataLength || pucPrivateKey->bits != 256) {
    goto cleanup;
  }

  rc = SDR_NOBUFFER;
  if ( !(ctx = BN_CTX_new()) ) {
    goto cleanup;
  }
  BN_CTX_start(ctx);
  bn_d = BN_CTX_get(ctx);
  bn_c1_x = BN_CTX_get(ctx);
  bn_c1_y = BN_CTX_get(ctx);
  bn_x2 = BN_CTX_get(ctx);
  bn_y2 = BN_CTX_get(ctx);
  if (!(bn_y2)) {
    goto cleanup;
  }
  if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) ) {
    goto cleanup;
  }
  if ( !(c1_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(s_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(ec_pt = EC_POINT_new(group)) ) {
    goto cleanup;
  }
  if ( !(md_ctx = EVP_MD_CTX_new()) ) {
    goto cleanup;
  }

  rc = SDR_ENCDATAERR;
  if ( !(BN_bin2bn(pucPrivateKey->K + 32, 32, bn_d)) ) {
    goto cleanup;
  }
  if ( !(BN_bin2bn(pucEncData->x + 32, 32, bn_c1_x)) ) {
    goto cleanup;
  }
  if ( !(BN_bin2bn(pucEncData->y + 32, 32, bn_c1_y)) ) {
    goto cleanup;
  }
  /* 验证C1是否满足椭圆曲线方程，若不满足则报错并退出 */
  if ( !(EC_POINT_set_affine_coordinates_GFp(group,
                                            c1_pt,
                                            bn_c1_x,
                                            bn_c1_y,
                                            ctx)) ) {
    goto cleanup;
  }
  if ( EC_POINT_is_on_curve(group, c1_pt, ctx) != 1 ) {
    goto cleanup;
  }

  if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) ) {
    goto cleanup;
  }
  /*计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出*/
  if ( !(EC_POINT_mul(group, s_pt, nullptr, c1_pt, bn_cofactor, ctx)) ) {
    goto cleanup;
  }
  if ( EC_POINT_is_at_infinity(group, s_pt) ) {
    goto cleanup;
  }

  /* 计算[dB]C1=(x2,y2) */
  if ( !(EC_POINT_mul(group, ec_pt, nullptr, c1_pt, bn_d, ctx)) ) {
    goto cleanup;
  }
  if ( !(EC_POINT_get_affine_coordinates_GFp(group,
                                            ec_pt,
                                            bn_x2,
                                            bn_y2,
                                            ctx)) ) {
    goto cleanup;
  }
  if ( BN_bn2binpad(bn_x2,x2,sizeof(x2)) != sizeof(x2) ) {
    goto cleanup;
  }
  if ( BN_bn2binpad(bn_y2,y2,sizeof(x2)) != sizeof(y2) ) {
    goto cleanup;
  }
  /*计算t=KDF (x2 || y2, klen)*/
  memcpy(x2_y2,              x2, sizeof(x2));
  memcpy(x2_y2 + sizeof(x2), y2, sizeof(y2));
  md = EVP_sm3();

  if ( !(t = (unsigned char *)malloc(pucEncData->L)) ) {
    goto cleanup;
  }
  if ( !(ECDH_KDF_X9_62(t,
                       pucEncData->L,
                       x2_y2,
                       sizeof(x2_y2),
                       nullptr,
                       0,
                       md)) ) {
    goto cleanup;
  }
  /*若t为全0比特串，则报错并退出*/
  flag = 1;
  for (i = 0; i < pucEncData->L; i++) {
    if ( t[i] != 0 ) {
      flag = 0;
      break;
    }
  }
  if (flag) {
    goto cleanup;
  }

  if ( !(M = (unsigned char *)malloc(pucEncData->L)) ) {
    goto cleanup;
  }
  /* 从C中取出比特串C2 计算M' = C2 ^ t */
  for (i = 0; i < pucEncData->L; i++) {
    M[i] = pucEncData->C[i] ^ t[i];
  }

  /* 计算C3 = Hash(x2 || M' || y2) */
  if (!EVP_DigestInit_ex(md_ctx, md, nullptr)) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, x2, sizeof(x2))) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, M, pucEncData->L)) {
    goto cleanup;
  }
  if (!EVP_DigestUpdate(md_ctx, y2, sizeof(y2))) {
    goto cleanup;
  }
  if (!EVP_DigestFinal_ex(md_ctx, digest, nullptr)) {
    goto cleanup;
  }

  if (memcmp(digest, pucEncData->M, sizeof(digest)) != 0) {
    goto cleanup;
  }
  if (*puiDataLength < pucEncData->L) {
    goto cleanup;
  }
  *puiDataLength = pucEncData->L;
  memcpy(pucData, M, *puiDataLength);
  rc = SDR_OK;

cleanup:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (group) {
    EC_GROUP_free(group);
  }
  if (c1_pt) {
    EC_POINT_free(c1_pt);
  }
  if (s_pt) {
    EC_POINT_free(s_pt);
  }
  if (ec_pt) {
    EC_POINT_free(ec_pt);
  }
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
  }
  if (t) {
    free(t);
  }
  if (M) {
    free(M);
  }
  return rc;
}

int SDF_Encrypt(void *hSessionHandle,
                void *hKeyHandle,
                unsigned int uiAlgID,
                unsigned char *pucIV,
                unsigned char *pucData,
                unsigned int uiDataLength,
                unsigned char *pucEncData,
                unsigned int *puiEncDataLength) {
  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  hsmc::emu::Session::KeyPtr key;
  if (!session->findKey(hKeyHandle, &key)) {
    return SDR_KEYNOTEXIST;
  }

  // 支持分组大小16byte
  if (uiDataLength % 16 != 0) {
    return SDR_INARGERR;
  }

  return _symmetric_operation(key->buf(),
                              EVP_CIPH_NO_PADDING,
                              uiAlgID, pucIV,
                              pucData,
                              uiDataLength,
                              pucEncData,
                              puiEncDataLength,
                              1);
}

int SDF_Decrypt(void *hSessionHandle,
                void *hKeyHandle,
                unsigned int uiAlgID,
                unsigned char *pucIV,
                unsigned char *pucEncData,
                unsigned int uiEncDataLength,
                unsigned char *pucData,
                unsigned int *puiDataLength) {
  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  hsmc::emu::Session::KeyPtr key;
  if (!session->findKey(hKeyHandle, &key)) {
    return SDR_KEYNOTEXIST;
  }

  // 支持分组大小16byte
  if (uiEncDataLength % 16 != 0) {
    return SDR_INARGERR;
  }

  return _symmetric_operation(key->buf(),
                              EVP_CIPH_NO_PADDING,
                              uiAlgID,
                              pucIV,
                              pucEncData,
                              uiEncDataLength,
                              pucData,
                              puiDataLength,
                              0);
}

int SDF_CalculateMAC(void *hSessionHandle,
                     void *hKeyHandle,
                     unsigned int uiAlgID,
                     unsigned char *pucIV,
                     unsigned char *pucData,
                     unsigned int uiDataLength,
                     unsigned char *pucMAC,
                     unsigned int *puiMACLength) {
  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  hsmc::emu::Session::KeyPtr key;
  if (!session->findKey(hKeyHandle, &key)) {
    return SDR_KEYNOTEXIST;
  }

  if (uiAlgID != SGD_SM4_MAC) {
    return SDR_ALGNOTSUPPORT;
  }

  if (nullptr == pucIV || nullptr == pucData || 0 == uiDataLength
      || uiDataLength % 16 != 0 || nullptr == pucMAC
      || *puiMACLength < 16) {
    return SDR_INARGERR;
  }

  auto encData = absl::make_unique<uint8_t[]>(uiDataLength);
  unsigned int encDataLen = uiDataLength;
  if (_symmetric_operation(key->buf(),
                           EVP_CIPH_NO_PADDING,
                           SGD_SM4_CBC,
                           pucIV,
                           pucData,
                           uiDataLength,
                           encData.get(),
                           &encDataLen,
                           1) != 0) {
    return SDR_SYMOPERR;
  }
  memcpy(pucMAC, pucIV, 16);
  *puiMACLength = 16;

  return SDR_OK;
}

int SDF_HashInit(void *hSessionHandle,
                 unsigned int uiAlgID,
                 ECCrefPublicKey *pucPublicKey,
                 unsigned char *pucID,
                 unsigned int uiIDLength) {
  int rc = 0;
  const EVP_MD *md = nullptr;
  int digestNid = 0;
  uint8_t *z = nullptr;
  EC_KEY *key = nullptr;

  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    return SDR_OPENSESSION;
  }

  if (SGD_SM3 != uiAlgID) {
    return SDR_ALGNOTSUPPORT;
  }
  digestNid = NID_sm3;

  SDF_UserData_t* userdata = SDF_UserData_new();
  if (nullptr == userdata) {
    rc = SDR_UNKNOWERR;
    goto cleanup;
  }
  session->resetUserdata(userdata, SDF_UserData_free);

  md = EVP_get_digestbynid(digestNid);
  if (nullptr == md) {
    rc = SDR_UNKNOWERR;
    goto cleanup;
  }
  if (EVP_DigestInit(((SDF_UserData_t*)session->getUserdata())->mdCtx,md) != 1) {
    rc = SDR_UNKNOWERR;
    goto cleanup;
  }

  if (SGD_SM3 == uiAlgID && uiIDLength > 0) {
    z = (uint8_t *)OPENSSL_zalloc(EVP_MD_size(md));
    if (nullptr == z) {
      rc = SDR_NOBUFFER;
      goto cleanup;
    }
    if (ECCrefPublicKey2EC_KEY(pucPublicKey, &key) != 0) {
      goto cleanup;
    }
    if (!_sm2_pretreatment_one(z, md, pucID, uiIDLength, key)) {
      rc = SDR_UNKNOWERR;
      goto cleanup;
    }
    if (EVP_DigestUpdate(((SDF_UserData_t*)session->getUserdata())->mdCtx,
                         z,
                         EVP_MD_size(md)) != 1) {
      rc = SDR_UNKNOWERR;
      goto cleanup;
    }
  }

  rc = SDR_OK;
cleanup:
  if (rc != 0) {
    session->resetUserdata();
  }
  if (z) {
    OPENSSL_free(z);
    z = nullptr;
  }
  if (key) {
    EC_KEY_free(key);
    key = nullptr;
  }

  return rc;
}

int SDF_HashUpdate(void *hSessionHandle,
                   unsigned char *pucData,
                   unsigned int uiDataLength) {
  int rc = 0;

  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    rc = SDR_OPENSESSION;
    goto cleanup;
  }

  if (!(SDF_UserData_t*)session->getUserdata()
       || nullptr == pucData || uiDataLength <= 0) {
    rc = SDR_INARGERR;
    goto cleanup;
  }

  if (EVP_DigestUpdate(((SDF_UserData_t*)session->getUserdata())->mdCtx,
                       pucData,
                       uiDataLength) != 1) {
    rc = SDR_UNKNOWERR;
  }

cleanup:
  if (rc != 0) {
    session->resetUserdata();
  }

  return rc;
}

int SDF_HashFinal(void *hSessionHandle,
                  unsigned char *pucHash,
                  unsigned int *puiHashLength) {
  int rc = 0;

  hsmc::emu::SessionPtr session;
  if (!_query_session(hSessionHandle, &session)) {
    rc = SDR_OPENSESSION;
    goto cleanup;
  }

  if (!(SDF_UserData_t*)session->getUserdata() || nullptr == pucHash) {
    rc = SDR_INARGERR;
    goto cleanup;
  }

  if (EVP_DigestFinal(((SDF_UserData_t*)session->getUserdata())->mdCtx,
                      pucHash,
                      puiHashLength) != 1) {
    rc = SDR_UNKNOWERR;
  }
cleanup:
  session->resetUserdata();
  return rc;
}

int SDF_CreateFile(void *hSessionHandle,
                   unsigned char *pucFileName,
                   unsigned int uiNameLen, /* max 128-byte */
                   unsigned int uiFileSize) {
  return SDR_NOTSUPPORT;
}

int SDF_ReadFile(void *hSessionHandle,
                 unsigned char *pucFileName,
                 unsigned int uiNameLen,
                 unsigned int uiOffset,
                 unsigned int *puiFileLength,
                 unsigned char *pucBuffer) {
  return SDR_NOTSUPPORT;
}

int SDF_WriteFile(void *hSessionHandle,
                  unsigned char *pucFileName,
                  unsigned int uiNameLen,
                  unsigned int uiOffset,
                  unsigned int uiFileLength,
                  unsigned char *pucBuffer) {
  return SDR_NOTSUPPORT;
}

int SDF_DeleteFile(void *hSessionHandle,
                   unsigned char *pucFileName,
                   unsigned int uiNameLen) {
  return SDR_NOTSUPPORT;
}

#ifdef __cplusplus
}
#endif
