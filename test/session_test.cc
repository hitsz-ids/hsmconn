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

#include <thread>

#include "gtest/gtest.h"
#include "hsmc/hsmc.h"

TEST(SessionTest, GetSession) {
  auto session = ::hsmc::SessionPool::instance().get();

  EXPECT_TRUE(session.isGood());
}

TEST(SessionTest, NamespaceAliasTest) {
  auto session = ::hsmc::SessionPool::instance().get();

  EXPECT_TRUE(session.isGood());
}

/*
TEST(SessionTest, GetMutipleSession) {
        {
                std::vector<hsmc::Session> sessions;
                for (int i = 0; i < hsmc::SessionPool::instance().capacity(); i++) {
                        auto session = ::hsmc::SessionPool::instance().get();

                        sessions.push_back(session);

                        EXPECT_TRUE(session.isGood());
                }
        }
}
*/

TEST(SessionTest, GetSessionById) {
  std::string sid;
  {
    auto session = ::hsmc::SessionPool::instance().get();
    sid = session.getId();

    // session将自动回到pool中
  }

  try {
    auto session = ::hsmc::SessionPool::instance().get(sid);
    EXPECT_TRUE(session.isGood());
  } catch (hsmc::NotFoundException &ex) {
    // 不应该抛出NotFound异常
    EXPECT_TRUE(false);
  }

  try {
    auto session = ::hsmc::SessionPool::instance().get("a-fake-id");
    EXPECT_TRUE(session.isGood());
  } catch (hsmc::NotFoundException &ex) {
    // 应该抛出NotFound异常
    EXPECT_TRUE(true);
  } catch (std::exception &ex) {
    // 不应该抛出其它异常
    EXPECT_TRUE(false);
  }
}

TEST(SessionTest, GetSessionByConnector) {
  auto names = hsmc::SessionFactory::instance().getConnectorNames();

  for (auto it : names) {
    auto session = ::hsmc::SessionPool::instance().getByConnector(it);

    EXPECT_EQ(true, it == session.getConnectorName());
  }
}

TEST(SessionTest, CreateSessionWithFactory) {
  auto names = hsmc::SessionFactory::instance().getConnectorNames();

  for (const auto &it : names) {
    auto session = ::hsmc::SessionFactory::instance().create(it);

    EXPECT_TRUE(session.isGood());
  }
}

TEST(SessionTest, GetDeviceInfo) {
  auto session = ::hsmc::SessionPool::instance().get();

  EXPECT_TRUE(session.isGood());

  DeviceInfo_st di = {0};
  int rc = session.SDF_GetDeviceInfo(&di);

  EXPECT_EQ(rc, 0);
}

TEST(SessionTest, ImportKey) {
  auto session = ::hsmc::SessionPool::instance().get();

  unsigned char key[16] = {0};
  void *keyHandle;
  int rc = session.SDF_ImportKey(key, 16, &keyHandle);
  EXPECT_EQ(SDR_OK, rc);
  rc = session.SDF_DestroyKey(keyHandle);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, ImportKeyAndEncrypt) {
  try {
    auto session = ::hsmc::SessionPool::instance().get();

    unsigned char key[16] = {0};
    void *keyHandle;

    int rc = session.SDF_ImportKey(key, 16, &keyHandle);
    EXPECT_EQ(SDR_OK, rc);

    unsigned char iv[16] = {0};
    unsigned char plaintext[16] = {0};
    unsigned char ciphertext[32];
    unsigned int cipherbuflen = 32;
    rc = session.SDF_Encrypt(keyHandle, 0x401, iv, plaintext, 16, ciphertext, &cipherbuflen);
    EXPECT_EQ(SDR_OK, rc);
    rc = session.SDF_DestroyKey(keyHandle);
    EXPECT_EQ(SDR_OK, rc);
  } catch (hsmc::SdfExcuteException &ex) {
    std::cout << ex.what() << std::endl << std::flush;
    EXPECT_TRUE(false);
  }
}

TEST(SessionTest, EncryptPerformance_10MB) {
  auto session = ::hsmc::SessionPool::instance().get();

  unsigned char key[16] = {0};
  void *keyHandle;

  int rc = session.SDF_ImportKey(key, 16, &keyHandle);
  EXPECT_EQ(SDR_OK, rc);

  unsigned char iv[16] = {0};
  unsigned char plaintext[16 * 1024] = {0};
  unsigned char ciphertext[16 * 1024];
  unsigned int cipherbuflen = 16 * 1024;
  for (int i = 0; i < 10 * 1024 * 1024 / 16 / 1024; i++) {
    rc = session.SDF_Encrypt(keyHandle, 0x401, iv, plaintext, 16, ciphertext, &cipherbuflen);
    EXPECT_EQ(SDR_OK, rc);
  }
  rc = session.SDF_DestroyKey(keyHandle);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, GenerateDEKAndWrapWithKEK) {
  auto session = ::hsmc::SessionPool::instance().get();

  int uiKeyBits = 16;
  int keyIndex = 1;
  unsigned char keycipher[32];
  unsigned int cipherlen = 32;
  void *keyHandle;
  // 使用KEK保护生成的DEK，并返回DEK的句柄key handle
  int rc = session.SDF_GenerateKeyWithKEK(uiKeyBits * 8, SGD_SM4_ECB, keyIndex, keycipher, &cipherlen, &keyHandle);
  EXPECT_EQ(SDR_OK, rc);
  unsigned char plaintext[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned char ciphertext[32] = {0};
  unsigned int ciphertextlen = sizeof(ciphertext);
  rc = session.SDF_Encrypt(keyHandle, SGD_SM4_ECB, nullptr, plaintext, sizeof(plaintext), ciphertext, &ciphertextlen);
  EXPECT_EQ(SDR_OK, rc);
  rc = session.SDF_DestroyKey(keyHandle);
  EXPECT_EQ(SDR_OK, rc);

  // 导入密文DEK，并返回该DEK的句柄
  void *importKeyHandle;
  rc = session.SDF_ImportKeyWithKEK(SGD_SM4_ECB, keyIndex, keycipher, cipherlen, &importKeyHandle);
  EXPECT_EQ(SDR_OK, rc);
  unsigned char dectext[16] = {0};
  unsigned int dectextlen = sizeof(dectext);
  rc = session.SDF_Decrypt(importKeyHandle, SGD_SM4_ECB, nullptr, ciphertext, ciphertextlen, dectext, &dectextlen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(dectext, plaintext, dectextlen));
  rc = session.SDF_DestroyKey(importKeyHandle);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, GenerateRandom) {
  auto session = ::hsmc::SessionPool::instance().get();

  unsigned int uiRandLen = 0;
  unsigned char ucRandData[32] = {0};
  uiRandLen = 16;

  int rc = session.SDF_GenerateRandom(uiRandLen, ucRandData);

  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, ImportKeyAndEncrypt_SM4ECB) {
  auto session = ::hsmc::SessionPool::instance().get();

  // set key
  void *keyHandle;
  unsigned char key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  int rc = session.SDF_ImportKey(key, 16, &keyHandle);
  EXPECT_EQ(SDR_OK, rc);

  // sm4 enc
  unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
  unsigned char plaintext[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned char cipher_cor[16] = {0x98, 0x94, 0xc6, 0x29, 0xdb, 0x49, 0xef, 0xd2,
                                  0xe8, 0x26, 0x64, 0xa0, 0x58, 0xa7, 0x69, 0x77};
  unsigned char ciphertext[32] = {0};
  unsigned int cipherbuflen = sizeof(ciphertext);
  rc = session.SDF_Encrypt(keyHandle, SGD_SM4_ECB, iv, plaintext, sizeof(plaintext), ciphertext, &cipherbuflen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(ciphertext, cipher_cor, cipherbuflen));

  // sm4 dec
  unsigned char dectext[32] = {0};
  unsigned int decbuflen = sizeof(dectext);
  rc = session.SDF_Decrypt(keyHandle, SGD_SM4_ECB, iv, ciphertext, cipherbuflen, dectext, &decbuflen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(dectext, plaintext, decbuflen));

  rc = session.SDF_DestroyKey(keyHandle);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, ImportKeyAndEncrypt_SM4CBC) {
  auto session = ::hsmc::SessionPool::instance().get();

  // set key
  void *keyHandle;
  unsigned char key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  int rc = session.SDF_ImportKey(key, 16, &keyHandle);
  EXPECT_EQ(SDR_OK, rc);

  // sm4 enc
  unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
  unsigned char plaintext[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned char cipher_cor[16] = {0x9b, 0x4d, 0x67, 0x92, 0x65, 0x30, 0x5c, 0x47,
                                  0x01, 0x1e, 0x6d, 0x5c, 0xf1, 0x4c, 0x50, 0xf8};
  unsigned char sm4_iv[16] = {0};
  unsigned char ciphertext[32] = {0};
  unsigned int cipherbuflen = 32;
  memcpy(sm4_iv, iv, 16);
  rc = session.SDF_Encrypt(keyHandle, SGD_SM4_CBC, sm4_iv, plaintext, 16, ciphertext, &cipherbuflen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(ciphertext, cipher_cor, 16));

  // sm4 dec
  unsigned char dectext[32] = {0};
  unsigned int decbuflen = 32;
  memcpy(sm4_iv, iv, 16);
  rc = session.SDF_Decrypt(keyHandle, SGD_SM4_CBC, sm4_iv, ciphertext, cipherbuflen, dectext, &decbuflen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(dectext, plaintext, 16));

  rc = session.SDF_DestroyKey(keyHandle);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, HashInit_SM3) {
  auto session = ::hsmc::SessionPool::instance().get();

  unsigned char ucData[32] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned char hash_cor[32] = {0xad, 0x87, 0xd4, 0x15, 0x2b, 0x45, 0xc7, 0x2a, 0x1b, 0xe2, 0x1f,
                                0x53, 0x48, 0xe0, 0xb7, 0x79, 0xb2, 0x92, 0xf9, 0x83, 0x69, 0x89,
                                0xa6, 0xf5, 0x58, 0x6a, 0xae, 0xfa, 0x6a, 0x56, 0x9d, 0x7f};
  unsigned int uiDataLen = 16;
  unsigned char Outdata[32] = {0};
  unsigned int nOutlen = 32;

  int rc = session.SDF_HashInit(SGD_SM3, NULL, NULL, 0);
  EXPECT_EQ(SDR_OK, rc);

  rc = session.SDF_HashUpdate(ucData, uiDataLen);
  EXPECT_EQ(SDR_OK, rc);

  rc = session.SDF_HashFinal(Outdata, &nOutlen);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(Outdata, hash_cor, 32));
}

TEST(SessionTest, GenerateKeyPair_ECC) {
  auto session = ::hsmc::SessionPool::instance().get();

  ECCrefPublicKey stEccPub;
  ECCrefPrivateKey stEccPriv;
  unsigned int nAlgId = 0;
  unsigned int nKeyLen = 0;
  ECCCipher *pucKeyIn = NULL;
  unsigned int uiKeyBufferLen = 0;
  void *hSessionKey = NULL;
  nKeyLen = 256;
  nAlgId = SGD_SM2_3;
  int rc = session.SDF_GenerateKeyPair_ECC(nAlgId, nKeyLen, &stEccPub, &stEccPriv);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, ExternalEncDec_ECC) {
  auto session = ::hsmc::SessionPool::instance().get();

  ECCrefPublicKey stEccPub;
  ECCCipher *ucCipher = NULL;
  ECCrefPrivateKey stEccPriv;
  unsigned long ulCipherLen = 0;
  unsigned char ucData[32] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned int uiDataLen = 16;

  unsigned char pubkey_test[64] = {0xA2, 0xC0, 0x57, 0xAE, 0x2D, 0x89, 0x4C, 0xDD, 0x31, 0x2B, 0xA7, 0x1D, 0x05,
                                   0x22, 0x1D, 0x73, 0xC4, 0x2A, 0x68, 0xE4, 0x1D, 0x3B, 0x6E, 0x01, 0x7E, 0x3F,
                                   0x65, 0xED, 0x29, 0x20, 0x62, 0xA2, 0x18, 0x21, 0x5F, 0x8B, 0xF0, 0xAF, 0x80,
                                   0x91, 0x33, 0xE0, 0xFC, 0xB8, 0x75, 0xCD, 0x16, 0x84, 0x8D, 0x2F, 0x3C, 0xEB,
                                   0x58, 0x46, 0xA7, 0xA2, 0x40, 0xFB, 0x77, 0x23, 0xBF, 0x4B, 0xD0, 0x90};
  unsigned char prikey_test[32] = {0x24, 0x3E, 0x1E, 0x02, 0x77, 0xDB, 0xD2, 0xD7, 0x67, 0x21, 0xC9,
                                   0x1D, 0x0A, 0x39, 0xF1, 0x15, 0xA0, 0x20, 0x95, 0x76, 0xB0, 0x5D,
                                   0xCF, 0x8E, 0x45, 0xCD, 0x20, 0x2B, 0x9E, 0x0B, 0xFB, 0x37};

  int rc;
  stEccPub.bits = 256;
  memcpy(stEccPub.x + 32, pubkey_test, 32);
  memcpy(stEccPub.y + 32, pubkey_test + 32, 32);
  stEccPriv.bits = 256;
  memcpy(stEccPriv.K + 32, prikey_test, 32);

  // sm2 enc
  ulCipherLen = sizeof(ECCCipher) + uiDataLen * sizeof(unsigned char);
  ucCipher = (ECCCipher *)calloc(ulCipherLen, sizeof(unsigned char));
  if (ucCipher == NULL) {
    printf("calloc error\n");
    return;
  }
  rc = session.SDF_ExternalEncrypt_ECC(SGD_SM2_3, &stEccPub, ucData, uiDataLen, ucCipher);
  EXPECT_EQ(SDR_OK, rc);

  unsigned char dec[1024] = {0};
  unsigned int dec_len = sizeof(dec);
  rc = session.SDF_ExternalDecrypt_ECC(SGD_SM2_3, &stEccPriv, ucCipher, dec, &dec_len);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(ucData, dec, dec_len));

  unsigned char x[64] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x95, 0x69, 0x2a, 0x36, 0x47, 0x93,
                         0xcd, 0x82, 0x0d, 0xee, 0xba, 0xa5, 0xa8, 0x8b, 0xd5, 0xb5, 0x7a, 0x60, 0x94,
                         0x5a, 0xd0, 0x74, 0xc0, 0x0c, 0xe4, 0x85, 0xc0, 0xde, 0x71, 0xbe, 0x67};
  memcpy(ucCipher->x, x, 64);
  unsigned char y[64] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x26, 0x6e, 0x94, 0x21, 0x9c, 0xcd,
                         0x52, 0x61, 0x71, 0x38, 0x69, 0x70, 0x4c, 0x79, 0x75, 0xe8, 0x80, 0x28, 0x13,
                         0x74, 0xd9, 0x11, 0x74, 0x50, 0x7f, 0xce, 0x62, 0xd7, 0x53, 0xbc, 0x80};
  memcpy(ucCipher->y, y, 64);
  unsigned char m[32] = {0xbd, 0x5c, 0xd9, 0xc4, 0x29, 0x4d, 0xe2, 0x63, 0xf6, 0xdd, 0x17,
                         0x96, 0xb5, 0x51, 0xe1, 0x00, 0xab, 0x35, 0xb9, 0x08, 0x30, 0x79,
                         0x70, 0x01, 0x8a, 0x99, 0xc9, 0x14, 0x0b, 0xc9, 0x0e, 0xea};
  memcpy(ucCipher->M, m, 32);
  unsigned char c[16] = {0x1f, 0x4c, 0x6c, 0xcf, 0xfa, 0xf6, 0x41, 0x5a,
                         0xbf, 0x1f, 0xc3, 0xd2, 0x40, 0xaa, 0xda, 0xf2};
  memcpy(ucCipher->C, c, 16);

  dec_len = sizeof(dec);
  memset(dec, 0, dec_len);
  rc = session.SDF_ExternalDecrypt_ECC(SGD_SM2_3, &stEccPriv, ucCipher, dec, &dec_len);
  EXPECT_EQ(SDR_OK, rc);
  EXPECT_EQ(0, memcmp(ucData, dec, dec_len));
  free(ucCipher);
}

TEST(SessionTest, ExternalSigVer_ECC) {
  auto session = ::hsmc::SessionPool::instance().get();

  ECCrefPublicKey stEccPub;
  ECCrefPrivateKey stEccPriv;
  unsigned char ucData[32] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  unsigned int uiDataLen = 32;

  unsigned char pubkey_test[64] = {0xA2, 0xC0, 0x57, 0xAE, 0x2D, 0x89, 0x4C, 0xDD, 0x31, 0x2B, 0xA7, 0x1D, 0x05,
                                   0x22, 0x1D, 0x73, 0xC4, 0x2A, 0x68, 0xE4, 0x1D, 0x3B, 0x6E, 0x01, 0x7E, 0x3F,
                                   0x65, 0xED, 0x29, 0x20, 0x62, 0xA2, 0x18, 0x21, 0x5F, 0x8B, 0xF0, 0xAF, 0x80,
                                   0x91, 0x33, 0xE0, 0xFC, 0xB8, 0x75, 0xCD, 0x16, 0x84, 0x8D, 0x2F, 0x3C, 0xEB,
                                   0x58, 0x46, 0xA7, 0xA2, 0x40, 0xFB, 0x77, 0x23, 0xBF, 0x4B, 0xD0, 0x90};
  unsigned char prikey_test[32] = {0x24, 0x3E, 0x1E, 0x02, 0x77, 0xDB, 0xD2, 0xD7, 0x67, 0x21, 0xC9,
                                   0x1D, 0x0A, 0x39, 0xF1, 0x15, 0xA0, 0x20, 0x95, 0x76, 0xB0, 0x5D,
                                   0xCF, 0x8E, 0x45, 0xCD, 0x20, 0x2B, 0x9E, 0x0B, 0xFB, 0x37};

  stEccPub.bits = 256;
  memcpy(stEccPub.x + 32, pubkey_test, 32);
  memcpy(stEccPub.y + 32, pubkey_test + 32, 32);
  stEccPriv.bits = 256;
  memcpy(stEccPriv.K + 32, prikey_test, 32);

  // sm2 sign
  ECCSignature stSign;
  int rc = session.SDF_ExternalSign_ECC(SGD_SM2_1, &stEccPriv, ucData, uiDataLen, &stSign);
  EXPECT_EQ(SDR_OK, rc);

  // sm2 verify
  rc = session.SDF_ExternalVerify_ECC(SGD_SM2_1, &stEccPub, ucData, uiDataLen, &stSign);
  EXPECT_EQ(SDR_OK, rc);

  unsigned char r[64] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xd9, 0x90, 0xfe, 0xe4, 0x69, 0x2d,
                         0xb9, 0x8c, 0x68, 0x04, 0x4b, 0x29, 0x8c, 0x5d, 0x37, 0x6f, 0x03, 0x04, 0xe9,
                         0x5c, 0x05, 0xc4, 0x54, 0xca, 0xd7, 0x45, 0x01, 0x2b, 0xe0, 0x20, 0xb5};
  memcpy(stSign.r, r, 64);
  unsigned char s[64] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x24, 0x34, 0x72, 0x0a, 0xc3, 0x98,
                         0x4b, 0x0e, 0xbd, 0xc1, 0x23, 0xc6, 0x60, 0xc2, 0x6c, 0xb4, 0x64, 0x0e, 0xae,
                         0xea, 0xa3, 0x9b, 0xee, 0x8d, 0x01, 0x77, 0xb6, 0x26, 0x6d, 0xf5, 0xa5};
  memcpy(stSign.s, s, 64);
  rc = session.SDF_ExternalVerify_ECC(SGD_SM2_1, &stEccPub, ucData, uiDataLen, &stSign);
  EXPECT_EQ(SDR_OK, rc);
}

TEST(SessionTest, ConcurrencyTest) {
  hsmc::SessionPool pool;

  std::vector<std::thread> threads;
  for (int i = 0; i < 100; i++) {
    threads.emplace_back([&]() {
      auto session = pool.get();

      // set key
      void *keyHandle;
      unsigned char key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
      int rc = session.SDF_ImportKey(key, 16, &keyHandle);
      EXPECT_EQ(SDR_OK, rc);

      // sm4 enc
      unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
      unsigned char plaintext[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
      unsigned char cipher_cor[16] = {0x98, 0x94, 0xc6, 0x29, 0xdb, 0x49, 0xef, 0xd2,
                                      0xe8, 0x26, 0x64, 0xa0, 0x58, 0xa7, 0x69, 0x77};
      unsigned char ciphertext[32] = {0};
      unsigned int cipherbuflen = sizeof(ciphertext);
      rc = session.SDF_Encrypt(keyHandle, SGD_SM4_ECB, iv, plaintext, sizeof(plaintext), ciphertext, &cipherbuflen);
      EXPECT_EQ(SDR_OK, rc);
      EXPECT_EQ(0, memcmp(ciphertext, cipher_cor, cipherbuflen));

      // sm4 dec
      unsigned char dectext[32] = {0};
      unsigned int decbuflen = sizeof(dectext);
      rc = session.SDF_Decrypt(keyHandle, SGD_SM4_ECB, iv, ciphertext, cipherbuflen, dectext, &decbuflen);
      EXPECT_EQ(SDR_OK, rc);
      EXPECT_EQ(0, memcmp(dectext, plaintext, decbuflen));
      rc = session.SDF_DestroyKey(keyHandle);
      EXPECT_EQ(SDR_OK, rc);
    });
  }
  for (auto &t : threads) {
    t.join();
  }

  EXPECT_EQ(pool.used(), 0);
}

TEST(SessionTest, GetSessionByConnectorSet) {
  auto hsmNames = hsmc::SessionFactory::instance().getConnectorNames(hsmc::ConnectorType::CT_HSM);

  auto session = ::hsmc::SessionPool::instance().getByConnectorSet(hsmNames);
  EXPECT_TRUE(session.isGood());
}