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

#include <cstdlib>
#include <cstring>
#include "sdf.h"
#include "device.h"
#include <memory>
#include <unordered_map>
#include <mutex>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <absl/strings/escaping.h>
#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "yaml-cpp/yaml.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SM2_Cipher_st SM2_Cipher;
DECLARE_ASN1_FUNCTIONS(SM2_Cipher)
struct SM2_Cipher_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};
ASN1_SEQUENCE(SM2_Cipher) = {
    ASN1_SIMPLE(SM2_Cipher, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Cipher, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Cipher, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Cipher, C2, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(SM2_Cipher)
IMPLEMENT_ASN1_FUNCTIONS(SM2_Cipher)

static void _init() __attribute__((constructor));
static void _fini() __attribute__((destructor));

using DeviceList = std::list<hsmc::emu::DevicePtr>;
using SessionTable = std::unordered_map<hsmc::emu::SessionHandle, hsmc::emu::SessionPtr>;

DeviceList *g_devices = nullptr;
SessionTable *g_sessions = nullptr;
std::atomic_int g_seq(0);
std::mutex *g_device_mux = nullptr;
std::mutex *g_session_mux = nullptr;
std::atomic_bool g_initialized{false};
std::atomic_bool g_finalized{false};
YAML::Node *root = nullptr;

void _init() {
    if (g_initialized.exchange(true)) {
        return;
    }

    g_device_mux = new std::mutex();
    g_session_mux = new std::mutex();
    g_devices = new DeviceList();
    g_sessions = new SessionTable();
}

void _fini() {
    if (g_finalized.exchange(true)) {
        return;
    }
    delete g_sessions;
    g_sessions = nullptr;
    delete g_devices;
    g_devices = nullptr;
    delete g_device_mux;
    g_device_mux = nullptr;
    delete g_session_mux;
    g_session_mux = nullptr;
}

int emu_init() {
    _init();

    auto configfile = getenv("HSM_EMULATOR_CONFIG");
    if (nullptr == configfile) {
        return -1;
    }

    if (root != nullptr) {
        delete root;
        root = nullptr;
    }
    root = new YAML::Node(YAML::LoadFile(configfile));

    return 0;
}

int emu_fini() {
    _fini();
    return 0;
}

/// 查询session
/// \param session
/// \param dev
/// \return
static bool _query_session(hsmc::emu::SessionHandle handle,
                           hsmc::emu::SessionPtr *session = nullptr,
                           hsmc::emu::DevicePtr *dev = nullptr) {
    std::lock_guard<std::mutex> lk(*g_session_mux);
    auto it = g_sessions->find(handle);
    if (it == g_sessions->end()) {
        return false;
    }

    auto device = it->second->device_.lock();
    if (!device) {
        return false;
    }

    if (session != nullptr) {
        *session = it->second;
    }
    if (dev != nullptr) {
        *dev = device;
    }

    return true;
}

static int _get_kek(int kek_index, std::string &kek_value) {
    auto ki = std::to_string(kek_index);
    if (!(*root) || !(*root)["kek"] || !(*root)["kek"][ki]) {
        return 1;
    }

    auto kekstr = (*root)["kek"][ki].as<std::string>();
    if (!absl::Base64Unescape(kekstr, &kek_value)) {
        return 2;
    }
    return 0;
}

static int _encrypt_with_kek(int kek_index, unsigned char *inbuf, int inlen, unsigned char *outbuf, int *outlen) {
    std::string kek_value;
    int rc = 0;
    if ((rc = _get_kek(kek_index, kek_value) != 0)) {
        return rc;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_sm4_ecb(), reinterpret_cast<const unsigned char *>(kek_value.c_str()), nullptr, 1);

    int out_len, total_len = 0;
    EVP_CipherUpdate(ctx, outbuf, &out_len, inbuf, inlen);
    total_len += out_len;
    EVP_CipherFinal(ctx, outbuf + total_len, &out_len);
    total_len += out_len;

    *outlen = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int _decrypt_with_kek(int kek_index, unsigned char *inbuf, int inlen, unsigned char *outbuf, int *outlen) {
    std::string kek_value;
    int rc = 0;
    if ((rc = _get_kek(kek_index, kek_value) != 0)) {
        return rc;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_sm4_ecb(), reinterpret_cast<const unsigned char *>(kek_value.c_str()), nullptr, 0);

    int out_len, total_len = 0;
    EVP_CipherUpdate(ctx, outbuf, &out_len, inbuf, inlen);
    total_len += out_len;
    EVP_CipherFinal(ctx, outbuf + total_len, &out_len);
    total_len += out_len;

    *outlen = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int _symmetric_operation(unsigned char *key, int padding,
                                unsigned int uiAlgID, unsigned char *pucIV,
                                unsigned char *in, unsigned int inLen,
                                unsigned char *out, unsigned int *outLen, int isEnc) {
    const EVP_CIPHER *cipher = nullptr;
    int ret = 0;
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
        return SDR_UNKNOWERR;
    }
    if (EVP_CipherInit(cipherCtx, cipher, key, pucIV, isEnc) != 1) {
        ret = SDR_SYMOPERR;
        goto FREE;
    }

    // OPENSSL 默认使用PKCS7_PADDING
    if (EVP_CIPH_NO_PADDING == padding) {
        EVP_CIPHER_CTX_set_padding(cipherCtx, 0);
    }

    updateSize = *outLen;
    if (EVP_CipherUpdate(cipherCtx, out, (int*)&updateSize, in, inLen) != 1) {
        ret = SDR_SYMOPERR;
        goto FREE;
    }

    if (EVP_CIPH_NO_PADDING == padding) {
        if (updateSize != inLen) {
            ret = SDR_INARGERR;
        } else {
            *outLen = updateSize;
            ret = SDR_OK;
        }
        goto FREE;
    }

    finalSize = *outLen - updateSize;
    if (!EVP_CipherFinal(cipherCtx, out + updateSize, (int*)&finalSize)) {
        ret = SDR_SYMOPERR;
        goto FREE;
    }
    *outLen = updateSize + finalSize;

    ret = SDR_OK;
FREE:
    if (SDR_OK == ret && SGD_SM4_CBC == uiAlgID) {
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

    return ret;
}

// ECCrefPublicKey中X,Y是GM0018标准长度，分配64，实际数据32
static int ECCrefPublicKey2EC_KEY(ECCrefPublicKey *pucPublicKey, EC_KEY **key) {
    int ret = 0;
    unsigned char *dPublicKey = nullptr;
    unsigned char *tmpPublicKey = nullptr;
    EC_KEY *eckey = nullptr;

    if (nullptr == pucPublicKey || nullptr == key) {
        return SDR_INARGERR;
    }

    tmpPublicKey = (unsigned char *)malloc(1 + 32 + 32);
    dPublicKey = tmpPublicKey;
    if (nullptr == dPublicKey) {
        ret = SDR_NOBUFFER;
        goto FREE;
    }
    *dPublicKey = 04;
    memcpy(dPublicKey + 1, pucPublicKey->x + 32, 32);
    memcpy(dPublicKey + 1 + 32, pucPublicKey->y + 32, 32);

    eckey = EC_KEY_new_by_curve_name(NID_sm2);
    if (nullptr == eckey) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }
    if (!o2i_ECPublicKey(&eckey, (const unsigned char **)&dPublicKey, 1 + 32 + 32)) {
        unsigned long l;
        l = ERR_get_error();
        if (0 != l) {
            printf("\nOPENSSL ERROR: [%lu] %s\n", l, ERR_error_string(l, NULL));
        }
        ret = SDR_UNKNOWERR;
        goto FREE;
    }

    *key = eckey;
    ret = 0;
FREE:
    if(tmpPublicKey) {
        free(tmpPublicKey);
        tmpPublicKey = nullptr;
    }
    if (ret != 0 && eckey) {
        EC_KEY_free(eckey);
        eckey = nullptr;
    }

    return ret;
}

static int EC_KEY2ECCrefPublicKey(EC_KEY *key, ECCrefPublicKey **pucPublicKey) {
    ECCrefPublicKey *publicKey = nullptr;
    int ret = 0;
    unsigned char *dPublicKey = nullptr;
    int keyBytes = 0;

    if (nullptr == key || nullptr == pucPublicKey) {
        return SDR_INARGERR;
    }

    ret = i2o_ECPublicKey(key, &dPublicKey);
    if (65 == ret) {
        keyBytes = 32;
    } else if (129 == ret) {
        keyBytes = 64;
    } else {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }
    
    publicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    if (nullptr == publicKey) {
        ret = SDR_NOBUFFER;
        goto FREE;
    }
    memset(publicKey, 0, sizeof(ECCrefPublicKey));
    memcpy(publicKey->x + (64 - keyBytes), dPublicKey + 1, keyBytes);
	memcpy(publicKey->y + (64 - keyBytes), dPublicKey + 1 + keyBytes, keyBytes);
	publicKey->bits = keyBytes * 8;

    if (nullptr == *pucPublicKey) {
        *pucPublicKey = publicKey;
    } else {
        memcpy(*pucPublicKey, publicKey, sizeof(ECCrefPublicKey));
        free(publicKey);
        publicKey = nullptr;
    }
    ret = 0;
FREE:
    if (dPublicKey) {
        OPENSSL_free(dPublicKey);
        dPublicKey = nullptr;
    }

    return ret;
}

static int EC_KEY2ECCrefPrivateKey(EC_KEY *key, ECCrefPrivateKey **pucPrivateKey) {
    int keyBytes = 0;
    BIGNUM *privateKey = nullptr;
    ECCrefPrivateKey *eccPrivateKey = nullptr;

    if (nullptr == key || nullptr == pucPrivateKey) {
        return SDR_INARGERR;
    }

    privateKey = (BIGNUM*)EC_KEY_get0_private_key(key);

    eccPrivateKey = (ECCrefPrivateKey*)malloc(sizeof(ECCrefPrivateKey));
    if (nullptr == eccPrivateKey) {
        return SDR_NOBUFFER;
    }
    memset(eccPrivateKey, 0, sizeof(ECCrefPrivateKey));
    
    keyBytes = BN_num_bytes(privateKey);
    BN_bn2bin(privateKey, eccPrivateKey->K + 64 - keyBytes);
    eccPrivateKey->bits = (keyBytes + 32 - 1) / 32 * 32 * 8;

    if (nullptr == *pucPrivateKey) {
        *pucPrivateKey = eccPrivateKey;
    } else {
        memcpy(*pucPrivateKey, eccPrivateKey, sizeof(ECCrefPrivateKey));
        free(eccPrivateKey);
        eccPrivateKey = nullptr;
    }

    return 0;
}

static int _sm2_pretreatment_one(uint8_t *out, const EVP_MD *digest,
                                 const uint8_t *id, const size_t id_len, const EC_KEY *key) {
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
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == nullptr) {
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = (uint8_t *)OPENSSL_zalloc(p_bytes);
    if (buf == nullptr) {
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_GROUP_get0_generator(group),
                                            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_KEY_get0_public_key(key),
                                            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, nullptr)) {
        goto done;
    }

    rc = 1;

done:
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

    std::lock_guard<std::mutex> lk(*g_device_mux);
    g_devices->push_back(dev);

    return SDR_OK;
}

int SDF_CloseDevice(void *hDeviceHandle) {
    if (hDeviceHandle == nullptr) {
        return SDR_INARGERR;
    }

    hsmc::emu::DevicePtr dev;
    {
        std::lock_guard<std::mutex> lk(*g_device_mux);
        for (auto it = g_devices->begin(); it != g_devices->end(); ++it) {
            if (it->get() == hDeviceHandle) {
                dev = *it;
                g_devices->erase(it);
                break;
            }
        }
    }

    if (dev) {
        std::lock_guard<std::mutex> lk(*g_session_mux);
        for (auto &session : dev->sessions_) {
            auto session_handle = session.get();
            auto it = g_sessions->find(session_handle);
            if (it != g_sessions->end()) {
                g_sessions->erase(it);
            }
        }

        return SDR_OK;
    }

    return SDR_INARGERR;
}

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) {
    hsmc::emu::DevicePtr dev;
    {
        std::lock_guard<std::mutex> lk(*g_device_mux);
        for (auto &device : *g_devices) {
            if (device.get() == hDeviceHandle) {
                dev = device;
                break;
            }
        }
    }

    if (!dev) {
        return SDR_INARGERR;
    }

    auto sessName = absl::StrFormat("%s/sess-%02d", dev->devid_.c_str(), dev->seq_++);
    auto session = std::make_shared<hsmc::emu::Session>(sessName, dev);
    if (phSessionHandle != nullptr) {
        *phSessionHandle = session.get();
    } else {
        return SDR_OUTARGERR;
    }

    std::lock_guard<std::mutex> lk(*g_session_mux);
    g_sessions->insert({session.get(), session});
    dev->sessions_.push_front(session);
    session->it_ = dev->sessions_.begin();

    return SDR_OK;
}

int SDF_CloseSession(void *hSessionHandle) {
    if (hSessionHandle == nullptr) {
        return SDR_INARGERR;
    }

    std::lock_guard<std::mutex> lk(*g_session_mux);
    auto it = g_sessions->find(hSessionHandle);
    if (it == g_sessions->end()) {
        return SDR_INARGERR;
    }

    auto dev = it->second->device_.lock();
    if (dev) {
        dev->eraseSession(it->second);
    }

    if (it->second->mdCtx_) {
        EVP_MD_CTX_free(it->second->mdCtx_);
        it->second->mdCtx_ = nullptr;
    }
    g_sessions->erase(it);
    return SDR_OK;
}

int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo) {
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

int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom) {
    if (pucRandom == nullptr) {
        return SDR_OUTARGERR;
    }

    if (!_query_session(hSessionHandle)) {
        return SDR_OPENSESSION;
    }

    time_t t = time(nullptr);
    t = t * uiLength;
    RAND_seed(&t, sizeof(time_t));

    if (1 != RAND_bytes(pucRandom, uiLength)) {
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

int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex) {
    return SDR_NOTSUPPORT;
}

int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) {
    return SDR_NOTSUPPORT;
}

int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey) {
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

int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) {
    return SDR_NOTSUPPORT;
}

int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey) {
    return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyPair_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            unsigned int uiKeyBits,
                            ECCrefPublicKey *pucPublicKey,
                            ECCrefPrivateKey *pucPrivateKey) {
    EC_KEY *eckey = nullptr;
    int ret = 0;

    if (!_query_session(hSessionHandle)) {
        return SDR_OPENSESSION;
    }

    // 当前算法标识支持SGD_SM2_1,SGD_SM2_3,并且二者产生的密钥对无区别
    if (uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_3) {
        return SDR_ALGNOTSUPPORT;
    }
    // 当前密钥长度支持256bit,512bit暂不支持
    if (uiKeyBits != 256 || nullptr == pucPublicKey || nullptr == pucPrivateKey) {
        return SDR_INARGERR;
    }

    eckey = EC_KEY_new_by_curve_name(NID_sm2);
    if (nullptr == eckey) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }
    if (EC_KEY_generate_key(eckey) != 1) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }
    if (EC_KEY_check_key(eckey) != 1) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }

    ret = EC_KEY2ECCrefPublicKey(eckey, &pucPublicKey);
    if (ret != 0) {
        goto FREE; 
    }
    ret = EC_KEY2ECCrefPrivateKey(eckey, &pucPrivateKey);
    if (ret != 0) {
        goto FREE;
    }

    ret = 0;
FREE:
    if (eckey) {
        EC_KEY_free(eckey);
        eckey = nullptr;
    }
    return ret;
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

    unsigned int randomLength = uiKeyBits / 8;
    auto randomBuf = absl::make_unique<uint8_t[]>(randomLength);
    int rv = SDF_GenerateRandom(hSessionHandle, randomLength, randomBuf.get());
    if (SDR_OK != rv) {
        return rv;
    }

    hsmc::emu::SessionPtr session;
    if (!_query_session(hSessionHandle, &session)) {
        return SDR_OPENSESSION;
    }

    int keyCipherLength = randomLength + 16;
    auto keyCipherBuf = absl::make_unique<uint8_t[]>(keyCipherLength);

    if (_encrypt_with_kek(uiKEKIndex, randomBuf.get(), randomLength, keyCipherBuf.get(), &keyCipherLength)) {
        return SDR_KEYERR;
    }

    if (puiKeyLength == nullptr || *puiKeyLength < keyCipherLength) {
        if (puiKeyLength != nullptr) {
            *puiKeyLength = keyCipherLength;
        }
        return SDR_NOBUFFER;
    }

    auto key = std::make_shared<hsmc::emu::Session::Key>(randomBuf.get(), randomLength);
    key->kek_ = uiKEKIndex;
    session->keys_.push_back(key);

    if (pucKey != nullptr) {
        memcpy(pucKey, keyCipherBuf.get(), keyCipherLength);
        *puiKeyLength = keyCipherLength;
    }

    if (phKeyHandle != nullptr) {
        *phKeyHandle = key.get();
    }

    return SDR_OK;
}

int SDF_ImportKeyWithKEK(void *hSessionHandle,
                         unsigned int uiAlgID,
                         unsigned int uiKEKIndex,
                         unsigned char *pucKey,
                         unsigned int uiKeyLength,
                         void **phKeyHandle) {
    hsmc::emu::SessionPtr session;
    if (!_query_session(hSessionHandle, &session)) {
        return SDR_OPENSESSION;
    }

    int keyPlainLength = uiKeyLength;
    auto keyPlainBuf = absl::make_unique<uint8_t[]>(keyPlainLength);

    if (_decrypt_with_kek(uiKEKIndex, pucKey, uiKeyLength, keyPlainBuf.get(), &keyPlainLength)) {
        return SDR_KEYERR;
    }

    auto key = std::make_shared<hsmc::emu::Session::Key>(keyPlainBuf.get(), keyPlainLength);
    key->kek_ = uiKEKIndex;
    session->keys_.push_back(key);

    if (phKeyHandle != nullptr) {
        *phKeyHandle = key.get();
    }

    return SDR_OK;
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

    auto key = std::make_shared<hsmc::emu::Session::Key>(pucKey, uiKeyLength);
    session->keys_.push_back(key);

    if (phKeyHandle != nullptr) {
        *phKeyHandle = key.get();
    }

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

static int sm2_sign_setup(const EC_GROUP *ecgroup, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **rp) {
    BN_CTX *ctx = nullptr;
    BIGNUM *k = nullptr, *r = nullptr, *order = nullptr, *X = nullptr, *total = nullptr;
    EC_POINT *tmp_point = nullptr;
    int ret = 0;
    if (ctx_in == nullptr) {
        if ((ctx = BN_CTX_new()) == nullptr)
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            return 1;
    } else
        ctx = ctx_in;

    k = BN_new();
    r = BN_new();
    order = BN_new();
    X = BN_new();
    total = BN_new();
    if (!k || !r || !order || !X || !total) {
        ret = 1;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(ecgroup)) == nullptr) {
        ret = 1;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (!EC_GROUP_get_order(ecgroup, order, ctx)) {
        ret = 1;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }

    do {
        do {
            if (!BN_rand_range(k, order)) {
                ret = 1;
                //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
                goto err;
            }
        } while (BN_is_zero(k));

        if (!EC_POINT_mul(ecgroup, tmp_point, k, nullptr, nullptr, ctx)) {
            ret = 1;
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            goto err;
        }
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field) {
            if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, tmp_point, X, nullptr, ctx)) {
                ret = 1;
                //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
                goto err;
            }
        } else {
            ret = 1;
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            goto err;
        }
        if (!BN_nnmod(r, X, order, ctx)) {
            ret = 1;
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            goto err;
        }
        if (!BN_add(total, r, k)) {
            ret = 1;
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            goto err;
        }
    } while (BN_is_zero(r) || !BN_cmp(order, total));

    if (*rp != nullptr)
        BN_clear_free(*rp);
    if (*kp != nullptr)
        BN_clear_free(*kp);

    *rp = r;
    *kp = k;
err:
    if (0 != ret) {
        if (k != nullptr) BN_clear_free(k);
        if (r != nullptr) BN_clear_free(r);
    }
    if (!ctx_in) BN_CTX_free(ctx);
    if (order) BN_free(order);
    if (tmp_point) EC_POINT_free(tmp_point);
    if (X) BN_clear_free(X);
    if (total) BN_clear_free(total);
    return ret;
}

int SDF_ExternalSign_ECC(void *hSessionHandle,
                         unsigned int uiAlgID,
                         ECCrefPrivateKey *pucPrivateKey,
                         unsigned char *pucData,
                         unsigned int uiDataLength,
                         ECCSignature *pucSignature) {
    int ret = SDR_OK;
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *ck = nullptr;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k = nullptr;
    BIGNUM *x = nullptr;
    BIGNUM *m = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *privatekey = BN_new();
    int sigrlen = 0;
    int sigslen = 0;
    int bnsize = 0;
    EC_GROUP_get_order(ecgroup, order, ctx);

    if ((uiDataLength != 32) || (pucPrivateKey->bits != 256)) {
        //debug_printf("---[%s][L%d]---uiDataLength != 32--OR--pucPrivateKey->bits != 256--\n", __FUNCTION__, __LINE__);
        ret = SDR_NOTSUPPORT;
        goto err;
    }
    BN_bin2bn(pucData, uiDataLength, m);
    BN_bin2bn(pucPrivateKey->K + 32, 32, privatekey);

    do {
        if (0 != (ret = sm2_sign_setup(ecgroup, ctx, &k, &x))) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        ck = k;
        if (!BN_mod_add_quick(r, m, x, order)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        if (BN_is_zero(r))
            continue;
        BN_add(tmp, r, ck);
        if (BN_ucmp(tmp, order) == 0)
            continue;
        if (!BN_mod_mul(tmp, privatekey, r, order, ctx)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        if (!BN_mod_sub_quick(s, ck, tmp, order)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        BN_one(a);
        if (!BN_mod_add_quick(tmp, privatekey, a, order)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        if (!BN_mod_inverse(tmp, tmp, order, ctx)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        if (!BN_mod_mul(s, s, tmp, order, ctx)) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
            ret = SDR_NOTSUPPORT;
            goto err;
        }
        if (BN_is_zero(s) || BN_ucmp(r, order) >= 0 || BN_ucmp(s, order) >= 0) {
            //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        } else
            break;
    } while (1);

    //debug_printf("------[%s][L%d]---signature Success.--------\n", __FUNCTION__, __LINE__);
    //sigrlen = BN_bn2bin(r, pucSignature->r + 32);
    //sigslen = BN_bn2bin(s, pucSignature->s + 32);
    memset(pucSignature->r, 0, 64);
    bnsize = BN_num_bytes(r);
    BN_bn2bin(r, pucSignature->r + 32 + (32 - bnsize));
	memset(pucSignature->s, 0, 64);
	bnsize = BN_num_bytes(s);
    BN_bn2bin(s, pucSignature->s + 32 + (32 - bnsize));

    ret = SDR_OK;

err:
    if (ctx) BN_CTX_free(ctx);
    if (m) BN_clear_free(m);
    if (tmp) BN_clear_free(tmp);
    if (order) BN_clear_free(order);
    if (privatekey) BN_clear_free(privatekey);
    if (k) BN_clear_free(k);
    if (x) BN_clear_free(x);
    if (a) BN_clear_free(a);
    if (r) BN_clear_free(r);
    if (s) BN_clear_free(s);
    if (ecgroup) EC_GROUP_free(ecgroup);
    return ret;
}

int SDF_ExternalVerify_ECC(void *hSessionHandle,
                           unsigned int uiAlgID,
                           ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucDataInput,
                           unsigned int uiInputLength,
                           ECCSignature *pucSignature) {
    int ret = SDR_OK;
    BN_CTX *ctx = nullptr;
    BIGNUM *order, *R, *m, *X, *t, *x, *y, *r, *s;
    EC_POINT *point = nullptr;
    EC_GROUP *ECgroup = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_POINT *pub_key = EC_POINT_new(ECgroup);
    if ((uiInputLength != 32) || (pucPublicKey->bits != 256)) {
        ret = SDR_NOTSUPPORT;
        goto err;
    }
    x = BN_bin2bn(pucPublicKey->x + 32, 32, nullptr);
    y = BN_bin2bn(pucPublicKey->y + 32, 32, nullptr);
    EC_POINT_set_affine_coordinates_GFp(ECgroup, pub_key, x, y, ctx);
    r = BN_bin2bn(pucSignature->r + 32, 32, nullptr);
    s = BN_bin2bn(pucSignature->s + 32, 32, nullptr);
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(ECgroup, order, ctx)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (BN_is_zero(r) || BN_is_negative(r) ||
        BN_ucmp(r, order) >= 0 || BN_is_zero(s) ||
        BN_is_negative(s) || BN_ucmp(s, order) >= 0) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (!BN_mod_add_quick(t, s, r, order)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (BN_is_zero(t)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if ((point = EC_POINT_new(ECgroup)) == nullptr) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (!EC_POINT_mul(ECgroup, point, s, pub_key, t, ctx)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (!EC_POINT_get_affine_coordinates_GFp(ECgroup, point, X, nullptr, ctx)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }

    if (!BN_bin2bn(pucDataInput, uiInputLength, m)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (!BN_mod_add_quick(R, m, X, order)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----------\n", __FUNCTION__, __LINE__);
        goto err;
    }
    if (BN_ucmp(R, r)) {
        ret = SDR_NOTSUPPORT;
        //debug_printf("------[%s][L%d]-----Verify Faild------\n", __FUNCTION__, __LINE__);
    } else {
        ret = SDR_OK;
        //debug_printf("------[%s][L%d]-----Verify Success.------\n", __FUNCTION__, __LINE__);
    }

err:
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (ECgroup) EC_GROUP_free(ECgroup);
    if (point) EC_POINT_free(point);
    if (pub_key) EC_POINT_free(pub_key);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (r) BN_free(r);
    if (s) BN_free(s);

    return ret;
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
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecGroup = EC_GROUP_new_by_curve_name(NID_sm2);
    EVP_PKEY *setpkey = EVP_PKEY_new();
    EC_KEY *seteckey = EC_KEY_new();
    EC_KEY_set_group(seteckey, ecGroup);
    EC_POINT *setpubkey = EC_POINT_new(ecGroup);
    BN_zero(x);
    BN_zero(y);
    BN_bin2bn(pucPublicKey->x + 32, 32, x);
    BN_bin2bn(pucPublicKey->y + 32, 32, y);
    int ret = EC_POINT_set_affine_coordinates_GFp(ecGroup, setpubkey, x, y, ctx);
    ret = EC_KEY_set_public_key(seteckey, setpubkey);
    ret = EVP_PKEY_set1_EC_KEY(setpkey, seteckey);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_PKEY_set_alias_type(setpkey, EVP_PKEY_SM2);
#endif
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(setpkey, nullptr);
    ret = EVP_PKEY_encrypt_init(ectx);
    long unsigned int outbuflen = 0;
    EVP_PKEY_encrypt(ectx, nullptr, &outbuflen, (const unsigned char *)pucData, uiDataLength);
    unsigned char *outbuf = (unsigned char *)malloc(outbuflen);
    EVP_PKEY_encrypt(ectx, outbuf, &outbuflen, (const unsigned char *)pucData, uiDataLength);
    //dump_hex("encrypt result:", outbuf, outbuflen);
    const unsigned char *pencbuf = outbuf;
    struct SM2_Cipher_st *sm2_cipher_st = d2i_SM2_Cipher(nullptr, &pencbuf, outbuflen);
    memset(pucEncData->x, 0, 64);
    int bnsize = BN_num_bytes(sm2_cipher_st->C1x);
    BN_bn2bin(sm2_cipher_st->C1x, pucEncData->x + 32 + (32 - bnsize));
	memset(pucEncData->y, 0, 64);
	bnsize = BN_num_bytes(sm2_cipher_st->C1y);
    BN_bn2bin(sm2_cipher_st->C1y, pucEncData->y + 32 + (32 - bnsize));
    memcpy(pucEncData->M, (unsigned char *)ASN1_STRING_get0_data(sm2_cipher_st->C3), 32);
    pucEncData->L = ASN1_STRING_length(sm2_cipher_st->C2);
    memcpy(pucEncData->C, (unsigned char *)ASN1_STRING_get0_data(sm2_cipher_st->C2), pucEncData->L);

    free(outbuf);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(setpubkey);
    EVP_PKEY_free(setpkey);
    EC_KEY_free(seteckey);
    EVP_PKEY_CTX_free(ectx);
    SM2_Cipher_free(sm2_cipher_st);
    EC_GROUP_free(ecGroup);
    BN_CTX_free(ctx);

    return SDR_OK;
}

int SDF_ExternalDecrypt_ECC(void *hSessionHandle,
                            unsigned int uiAlgID,
                            ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData,
                            unsigned char *pucData,
                            unsigned int *puiDataLength) {
    EC_GROUP *ecGroup = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *prikey = BN_new();
    EVP_PKEY *setpkey = EVP_PKEY_new();
    EC_KEY *seteckey = EC_KEY_new();
    EC_KEY_set_group(seteckey, ecGroup);
    BN_bin2bn((unsigned char *)(pucPrivateKey->K + 32), 32, prikey);
    int ret = EC_KEY_set_private_key(seteckey, prikey);
    ret = EVP_PKEY_set1_EC_KEY(setpkey, seteckey);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    ret = EVP_PKEY_set_alias_type(setpkey, EVP_PKEY_SM2);
#endif
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(setpkey, nullptr);
    ret = EVP_PKEY_decrypt_init(ectx);
    struct SM2_Cipher_st *sm2_cipher_st = SM2_Cipher_new();
    BIGNUM *C1x, *C1y;
    C1x = BN_bin2bn((unsigned char *)(pucEncData->x + 32), 32, nullptr);
    C1y = BN_bin2bn((unsigned char *)(pucEncData->y + 32), 32, nullptr);

    BN_free(sm2_cipher_st->C1x);
    BN_free(sm2_cipher_st->C1y);

    sm2_cipher_st->C1x = C1x;
    sm2_cipher_st->C1y = C1y;
    ret = ASN1_OCTET_STRING_set(sm2_cipher_st->C3, pucEncData->M, 32);
    ret = ASN1_OCTET_STRING_set(sm2_cipher_st->C2, pucEncData->C, pucEncData->L);
    unsigned char *pciphertext_buf = nullptr;
    int ciphertext_len = i2d_SM2_Cipher(sm2_cipher_st, &pciphertext_buf);
    //dump_hex("decrypt src data:", pciphertext_buf, ciphertext_len);
    long unsigned int decreslen = *puiDataLength; //Must long int !!!
    ret = EVP_PKEY_decrypt(ectx, pucData, &decreslen, (const unsigned char *)pciphertext_buf, ciphertext_len);

    *puiDataLength = decreslen;

    SM2_Cipher_free(sm2_cipher_st);
    OPENSSL_free(pciphertext_buf);
    EVP_PKEY_free(setpkey);
    EC_KEY_free(seteckey);
    BN_free(prikey);
    EVP_PKEY_CTX_free(ectx);
    EC_GROUP_free(ecGroup);

    if (1 != ret) {
        return SDR_UNKNOWERR;
    }
    return SDR_OK;
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

    return _symmetric_operation(key->buf_.get(), EVP_CIPH_NO_PADDING,
                                uiAlgID, pucIV,
                                pucData, uiDataLength,
                                pucEncData, puiEncDataLength, 1);
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

    return _symmetric_operation(key->buf_.get(), EVP_CIPH_NO_PADDING,
                                uiAlgID, pucIV,
                                pucEncData, uiEncDataLength,
                                pucData, puiDataLength, 0);
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

    if (nullptr == pucIV ||
        nullptr == pucData || 0 == uiDataLength || uiDataLength % 16 != 0 ||
        nullptr == pucMAC || *puiMACLength < 16) {
        return  SDR_INARGERR; 
    }

    auto encData = absl::make_unique<uint8_t[]>(uiDataLength);
    unsigned int encDataLen = uiDataLength;
    if (_symmetric_operation(key->buf_.get(), EVP_CIPH_NO_PADDING,
                            SGD_SM4_CBC, pucIV,
                            pucData, uiDataLength,
                            encData.get(), &encDataLen, 1) != 0) {
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

    int ret = 0;
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

    if (session->mdCtx_) {
        EVP_MD_CTX_free(session->mdCtx_);
        session->mdCtx_ = nullptr;
    }
    session->mdCtx_ = EVP_MD_CTX_new();
    if (nullptr == session->mdCtx_) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }

    md = EVP_get_digestbynid(digestNid);
    if (nullptr == md) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }
    if (EVP_DigestInit(session->mdCtx_, md) != 1) {
        ret = SDR_UNKNOWERR;
        goto FREE;
    }

    if (SGD_SM3 == uiAlgID && uiIDLength > 0) {
        z = (uint8_t *)OPENSSL_zalloc(EVP_MD_size(md));
        if (nullptr == z) {
            ret = SDR_NOBUFFER;
            goto FREE;
        }
        if (ECCrefPublicKey2EC_KEY(pucPublicKey, &key) != 0) {
            goto FREE;
        }
        if (!_sm2_pretreatment_one(z, md, pucID, uiIDLength, key)) {
            ret = SDR_UNKNOWERR;
            goto FREE;
        }
        if (EVP_DigestUpdate(session->mdCtx_, z, EVP_MD_size(md)) != 1) {
            ret = SDR_UNKNOWERR;
            goto FREE;
        }
    }

    ret = SDR_OK;
FREE:
    if (ret != 0 && session->mdCtx_) {
        EVP_MD_CTX_free(session->mdCtx_);
        session->mdCtx_ = nullptr;
    }
    if (z) {
        OPENSSL_free(z);
        z = nullptr;
    }
    if (key) {
        EC_KEY_free(key);
        key = nullptr;
    }

    return ret;
}

int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength) {
    if (nullptr == pucData || uiDataLength <= 0) {
        return SDR_INARGERR;
    }

    hsmc::emu::SessionPtr session;
    if (!_query_session(hSessionHandle, &session)) {
        return SDR_OPENSESSION;
    }

    if (EVP_DigestUpdate(session->mdCtx_, pucData, uiDataLength) != 1) {
        return SDR_UNKNOWERR;
    }

    return SDR_OK;
}

int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength) {
    if (nullptr == pucHash) {
        return SDR_INARGERR;
    }

    hsmc::emu::SessionPtr session;
    if (!_query_session(hSessionHandle, &session)) {
        return SDR_OPENSESSION;
    }

    if (EVP_DigestFinal(session->mdCtx_, pucHash, puiHashLength) != 1) {
        return SDR_UNKNOWERR;
    }

    return SDR_OK;
}

int SDF_CreateFile(void *hSessionHandle,
                   unsigned char *pucFileName,
                   unsigned int uiNameLen,/* max 128-byte */
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

int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen) {
    return SDR_NOTSUPPORT;
}

#ifdef __cplusplus
}
#endif
