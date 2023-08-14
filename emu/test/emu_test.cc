#include "gtest/gtest.h"
#include "sdf.h"
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"

class EmulatorTest : public testing::Test {
protected:
    void SetUp() override {
        emu_init();
    }

    void TearDown() override {
        //emu_fini();
    }
};

#if 1
TEST_F(EmulatorTest, SDF_OpenSession_10times) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    for (int i = 0; i < 10; i++) {
        void *session_handle = nullptr;
        rv = SDF_OpenSession(device_handle, &session_handle);
        EXPECT_EQ(rv, SDR_OK);

        rv = SDF_CloseSession(session_handle);
        EXPECT_EQ(rv, SDR_OK);
    }

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, SDF_GetDeviceInfo) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    DEVICEINFO info;
    rv = SDF_GetDeviceInfo(session_handle, &info);
    EXPECT_EQ(rv, SDR_OK);
    
    std::cout << "SDF_GetDeviceInfo: " << std::endl;
    std::cout << "IssuerName:" << info.IssuerName << std::endl;
    std::cout << "DeviceName:" << info.DeviceName << std::endl;
    std::cout << "DeviceSerial:" << info.DeviceSerial << std::endl;
    std::cout << "DeviceVersion:" << info.DeviceVersion << std::endl;
    std::cout << "StandardVersion:" << info.StandardVersion << std::endl;
    std::cout << "AsymAlgAbility[0]:" << info.AsymAlgAbility[0] << std::endl;
    std::cout << "AsymAlgAbility[1]:" << info.AsymAlgAbility[1] << std::endl;
    std::cout << "SymAlgAbility:" << info.SymAlgAbility << std::endl;
    std::cout << "HashAlgAbility:" << info.HashAlgAbility << std::endl;
    std::cout << "BufferSize:" << info.BufferSize << std::endl;

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, SDF_GenerateRandom) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned int randomLength = 16;
    auto randomBuf = absl::make_unique<uint8_t[]>(randomLength);
    rv = SDF_GenerateRandom(session_handle, randomLength, randomBuf.get());
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

#endif

TEST_F(EmulatorTest, SDF_GenerateKeyWithKEK) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned int keyLength = 32;
    auto keyBuf = absl::make_unique<uint8_t[]>(keyLength);
    void *keyHandle = nullptr;

    // 生成key
    rv = SDF_GenerateKeyWithKEK(session_handle, 128, SGD_SM4_ECB, 1, (unsigned char *)keyBuf.get(),
                                &keyLength, &keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    // 销毁生成的key
    rv = SDF_DestroyKey(session_handle, keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    // 导入key
    rv = SDF_ImportKeyWithKEK(session_handle, SGD_SM4_ECB, 1, keyBuf.get(), keyLength, &keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    // 销毁导入的key
    rv = SDF_DestroyKey(session_handle, keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, ImportKey_Encrypt_Decrypt_SM4_ECB) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *keyHandle = nullptr;
    unsigned char pucKey[16] = {0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4,
                                0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4};
    rv = SDF_ImportKey(session_handle, pucKey, sizeof(pucKey), &keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned char plain[16] = {0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4,
                               0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4};
    unsigned int plainLen = sizeof(plain);
    auto cipherBuf = absl::make_unique<uint8_t[]>(plainLen);
    unsigned cipherLen = plainLen;
    unsigned char expectResult[] = {0x36, 0x72, 0xfe, 0x3d, 0xd2, 0x5c, 0xd0, 0x85,
                                    0x04, 0x07, 0x22, 0x9a, 0xbc, 0x55, 0x81, 0xa8};
    rv = SDF_Encrypt(session_handle, keyHandle, SGD_SM4_ECB, NULL,
                     plain, plainLen, cipherBuf.get(), &cipherLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(cipherBuf.get(), expectResult, cipherLen));

    unsigned int decPlainLen = plainLen;
    auto decPlainBuf = absl::make_unique<uint8_t[]>(decPlainLen);
    rv = SDF_Decrypt(session_handle, keyHandle, SGD_SM4_ECB, NULL,
                     cipherBuf.get(), cipherLen, decPlainBuf.get(), &decPlainLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(plainLen, decPlainLen);
    EXPECT_EQ(0, memcmp(decPlainBuf.get(), plain, decPlainLen));

    rv = SDF_DestroyKey(session_handle, keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, ImportKey_Encrypt_Decrypt_SM4_CBC) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *keyHandle = nullptr;
    unsigned char pucKey[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    rv = SDF_ImportKey(session_handle, pucKey, sizeof(pucKey), &keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x00};
    unsigned char plain[32] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    unsigned int plainLen = sizeof(plain);
    auto cipherBuf = absl::make_unique<uint8_t[]>(plainLen);
    unsigned cipherLen = plainLen;
    unsigned char expectResult[] = {0x9b, 0x4d, 0x67, 0x92, 0x65, 0x30, 0x5c, 0x47,
                                    0x01, 0x1e, 0x6d, 0x5c, 0xf1, 0x4c, 0x50, 0xf8,
                                    0x96, 0x96, 0x2d, 0xfd, 0xe4, 0x1a, 0x96, 0xb4,
                                    0xd0, 0xf4, 0x92, 0x6b, 0xb1, 0x23, 0x8c, 0x6d};
    unsigned char expectIV[] = {0x96, 0x96, 0x2d, 0xfd, 0xe4, 0x1a, 0x96, 0xb4,
                                0xd0, 0xf4, 0x92, 0x6b, 0xb1, 0x23, 0x8c, 0x6d};
    unsigned char iv_init[16] = {0};
    memcpy(iv_init, iv, 16);
    rv = SDF_Encrypt(session_handle, keyHandle, SGD_SM4_CBC, iv,
                     plain, plainLen, cipherBuf.get(), &cipherLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(cipherBuf.get(), expectResult, cipherLen));
    EXPECT_EQ(0, memcmp(iv, expectIV, 16));

    unsigned int decPlainLen = plainLen;
    auto decPlainBuf = absl::make_unique<uint8_t[]>(decPlainLen);
    memcpy(iv, iv_init, 16);
    rv = SDF_Decrypt(session_handle, keyHandle, SGD_SM4_CBC, iv,
                     cipherBuf.get(), cipherLen, decPlainBuf.get(), &decPlainLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(plainLen, decPlainLen);
    EXPECT_EQ(0, memcmp(decPlainBuf.get(), plain, decPlainLen));
    EXPECT_EQ(0, memcmp(iv, expectIV, 16));

    rv = SDF_DestroyKey(session_handle, keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, SDF_Hash_Init_Update_Final) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned char message[16] = {0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4,
                                 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4};

    ECCrefPublicKey eccRefPubKey;
    eccRefPubKey.bits = 256;
    std::string x;
    std::string y;
    std::string b64X = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACJNf6Mjr9nTcAo6Xku+fTdMqafQOvbA8SqciM8S0hG/A==";
    std::string b64Y = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACtObvt4Dfbt5Z+XqOJYyDpDQg6gX72d5/KQxjdfs16aQ==";
    if (!absl::Base64Unescape(b64X, &x)) {
        EXPECT_EQ(1, SDR_OK);
    }
    if (!absl::Base64Unescape(b64Y, &y)) {
        EXPECT_EQ(1, SDR_OK);
    }
    memcpy(eccRefPubKey.x, x.c_str(), x.length());
    memcpy(eccRefPubKey.y, y.c_str(), y.length());
    std::string id = "1234567812345678";

    rv = SDF_HashInit(session_handle, SGD_SM3, &eccRefPubKey, (unsigned char *)id.c_str(), 16);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_HashUpdate(session_handle, message, sizeof(message));
    EXPECT_EQ(rv, SDR_OK);

    unsigned char sm3Hash[32] = {0};
    unsigned int sm3HashLen = 32;
    unsigned char expectResult[] =
        {0xda, 0x7b, 0x52, 0xe3, 0x54, 0xa8, 0xce, 0x84, 0x0f, 0xc2, 0x97, 0xd0, 0xad, 0x8a, 0x2b, 0xc8,
         0x12, 0x71, 0xeb, 0x49, 0xb2, 0xf9, 0x76, 0x35, 0x28, 0x41, 0x69, 0x7c, 0x87, 0x9b, 0x7c, 0x9d};
    rv = SDF_HashFinal(session_handle, sm3Hash, &sm3HashLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(sm3Hash, expectResult, 32));

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

//*********************************************/
// SM2 测试
//*********************************************/
TEST_F(EmulatorTest, SDF_ExternalEncDec_ECC) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    ECCrefPublicKey st_pub_key;
    ECCrefPrivateKey st_pri_key;
    unsigned long cipher_len = 0;
    unsigned char plain_data[16] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };
    unsigned int plain_len = 16;

    unsigned char pubkey_test[64] = {
        0xA2, 0xC0, 0x57, 0xAE, 0x2D, 0x89, 0x4C, 0xDD, 0x31, 0x2B, 0xA7, 0x1D, 0x05, 0x22, 0x1D, 0x73,
        0xC4, 0x2A, 0x68, 0xE4, 0x1D, 0x3B, 0x6E, 0x01, 0x7E, 0x3F, 0x65, 0xED, 0x29, 0x20, 0x62, 0xA2,
        0x18, 0x21, 0x5F, 0x8B, 0xF0, 0xAF, 0x80, 0x91, 0x33, 0xE0, 0xFC, 0xB8, 0x75, 0xCD, 0x16, 0x84,
        0x8D, 0x2F, 0x3C, 0xEB, 0x58, 0x46, 0xA7, 0xA2, 0x40, 0xFB, 0x77, 0x23, 0xBF, 0x4B, 0xD0, 0x90
    };
    unsigned char prikey_test[32] = {
        0x24, 0x3E, 0x1E, 0x02, 0x77, 0xDB, 0xD2, 0xD7, 0x67, 0x21, 0xC9, 0x1D, 0x0A, 0x39, 0xF1, 0x15,
        0xA0, 0x20, 0x95, 0x76, 0xB0, 0x5D, 0xCF, 0x8E, 0x45, 0xCD, 0x20, 0x2B, 0x9E, 0x0B, 0xFB, 0x37
    };

    memset((unsigned char *)&st_pub_key, 0, sizeof(ECCrefPublicKey));
    memset((unsigned char *)&st_pri_key, 0, sizeof(ECCrefPrivateKey));

    int rc;
    st_pub_key.bits = 256;
    printf("exportenc pub bits =%d\n", st_pub_key.bits);
    memcpy(st_pub_key.x + 32, pubkey_test, 32);
    memcpy(st_pub_key.y + 32, pubkey_test + 32, 32);
    st_pri_key.bits = 256;
    memcpy(st_pri_key.K + 32, prikey_test, 32);

    //sm2 enc
    cipher_len = sizeof(ECCCipher) + plain_len * sizeof(unsigned char);
    auto ucCipher = absl::make_unique<uint8_t[]>(cipher_len);

    rv = SDF_ExternalEncrypt_ECC(session_handle, SGD_SM2_3, &st_pub_key, plain_data,
                                 plain_len, reinterpret_cast<ECCCipher *>(ucCipher.get()));
    EXPECT_EQ(rv, SDR_OK);

    //sm2 dec
    unsigned char dec_data[112] = {0};
    unsigned int dec_len = sizeof(dec_data);
    rv = SDF_ExternalDecrypt_ECC(session_handle,
                                 SGD_SM2_3,
                                 &st_pri_key,
                                 reinterpret_cast<ECCCipher *>(ucCipher.get()),
                                 dec_data,
                                 &dec_len);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(dec_data, plain_data, dec_len));
}

TEST_F(EmulatorTest, SDF_ExternalSigVer_ECC) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    ECCrefPublicKey st_pub_key;
    ECCrefPrivateKey st_pri_key;
    unsigned char plain_data[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };
    unsigned int plain_len = 32;

    unsigned char pubkey_test[64] = {
        0xA2, 0xC0, 0x57, 0xAE, 0x2D, 0x89, 0x4C, 0xDD, 0x31, 0x2B, 0xA7, 0x1D, 0x05, 0x22, 0x1D, 0x73,
        0xC4, 0x2A, 0x68, 0xE4, 0x1D, 0x3B, 0x6E, 0x01, 0x7E, 0x3F, 0x65, 0xED, 0x29, 0x20, 0x62, 0xA2,
        0x18, 0x21, 0x5F, 0x8B, 0xF0, 0xAF, 0x80, 0x91, 0x33, 0xE0, 0xFC, 0xB8, 0x75, 0xCD, 0x16, 0x84,
        0x8D, 0x2F, 0x3C, 0xEB, 0x58, 0x46, 0xA7, 0xA2, 0x40, 0xFB, 0x77, 0x23, 0xBF, 0x4B, 0xD0, 0x90
    };
    unsigned char prikey_test[32] = {
        0x24, 0x3E, 0x1E, 0x02, 0x77, 0xDB, 0xD2, 0xD7, 0x67, 0x21, 0xC9, 0x1D, 0x0A, 0x39, 0xF1, 0x15,
        0xA0, 0x20, 0x95, 0x76, 0xB0, 0x5D, 0xCF, 0x8E, 0x45, 0xCD, 0x20, 0x2B, 0x9E, 0x0B, 0xFB, 0x37
    };
    ECCSignature st_sign;

    memset((unsigned char *)&st_pub_key, 0, sizeof(ECCrefPublicKey));
    memset((unsigned char *)&st_pri_key, 0, sizeof(ECCrefPrivateKey));
    memset((unsigned char *)&st_sign, 0, sizeof(ECCSignature));

    st_pub_key.bits = 256;
    memcpy(st_pub_key.x + 32, pubkey_test, 32);
    memcpy(st_pub_key.y + 32, pubkey_test + 32, 32);
    st_pri_key.bits = 256;
    memcpy(st_pri_key.K + 32, prikey_test, 32);

    //sm2 sign
    rv = SDF_ExternalSign_ECC(session_handle, SGD_SM2_1, &st_pri_key, plain_data, plain_len, &st_sign);
    EXPECT_EQ(rv, SDR_OK);

    //sm2 verify
    rv = SDF_ExternalVerify_ECC(session_handle, SGD_SM2_1, &st_pub_key, plain_data, plain_len, &st_sign);
    EXPECT_EQ(rv, SDR_OK);
}
//*********************************************/
// SM2 测试 end
//*********************************************/

TEST_F(EmulatorTest, SDF_GenerateKeyPair_ECC) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    ECCrefPublicKey eccPublicKey;
    ECCrefPrivateKey eccPrivateKey;
    rv = SDF_GenerateKeyPair_ECC(session_handle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
    EXPECT_EQ(rv, SDR_OK);

    unsigned char plain[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };
    ECCSignature sign;
    rv = SDF_ExternalSign_ECC(session_handle, SGD_SM2_1, &eccPrivateKey, plain, sizeof(plain), &sign);
    EXPECT_EQ(rv, SDR_OK);
    rv = SDF_ExternalVerify_ECC(session_handle, SGD_SM2_1, &eccPublicKey, plain, sizeof(plain), &sign);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}

TEST_F(EmulatorTest, SDF_CalculateMAC_SGD_SM4_MAC) {
    void *device_handle = nullptr;
    int rv = SDF_OpenDevice(&device_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *session_handle = nullptr;
    rv = SDF_OpenSession(device_handle, &session_handle);
    EXPECT_EQ(rv, SDR_OK);

    void *keyHandle = nullptr;
    unsigned char pucKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    rv = SDF_ImportKey(session_handle, pucKey, sizeof(pucKey), &keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char message[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    unsigned int messageLen = sizeof(message);
    auto macBuf = absl::make_unique<uint8_t[]>(messageLen);
    unsigned int macLen = messageLen;
    unsigned char expectResult[] = {0xdf, 0x4e, 0x4e, 0xfc, 0x6d, 0xbb, 0x1c, 0xfb,
                                    0x3c, 0xe8, 0xbb, 0x0c, 0x8b, 0x1e, 0x03, 0xb5};
    unsigned char iv_init[16] = {0};
    memcpy(iv_init, iv, 16);
    rv = SDF_CalculateMAC(session_handle, keyHandle, SGD_SM4_MAC, iv,
                     message, messageLen, macBuf.get(), &macLen);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(macBuf.get(), expectResult, macLen));
    EXPECT_EQ(0, memcmp(iv, expectResult, 16));

    unsigned char message2[32] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    unsigned int messageLen2 = sizeof(message2);
    auto macBuf2 = absl::make_unique<uint8_t[]>(messageLen2);
    unsigned int macLen2 = messageLen2;
    unsigned char expectResult2[] = {0x19, 0x4c, 0xb6, 0xe5, 0xd7, 0xbf, 0x8a, 0x10,
                                    0x3c, 0x62, 0x36, 0x83, 0xd9, 0xa0, 0x90, 0x21};
    memcpy(iv, iv_init, 16);
    rv = SDF_CalculateMAC(session_handle, keyHandle, SGD_SM4_MAC, iv,
                     message2, messageLen2, macBuf2.get(), &macLen2);
    EXPECT_EQ(rv, SDR_OK);
    EXPECT_EQ(0, memcmp(macBuf2.get(), expectResult2, macLen2));
    EXPECT_EQ(0, memcmp(iv, expectResult2, 16));

    rv = SDF_DestroyKey(session_handle, keyHandle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseSession(session_handle);
    EXPECT_EQ(rv, SDR_OK);

    rv = SDF_CloseDevice(device_handle);
    EXPECT_EQ(rv, SDR_OK);
}