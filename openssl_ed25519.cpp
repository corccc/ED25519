//
//  openssl_ed25519.cpp
//  OpenSSLTest
//
//  Created by iwall on 2020/9/25.
//  Copyright © 2020 cor. All rights reserved.
//
#include <string>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

void print_bytes(unsigned char *str, int strlen)
{
    for (int i = 0; i < strlen; i++) {
        printf("%02x", str[i]);
    }
    printf("\n");
}

void ed25519_gen_keypair(unsigned char *pub, unsigned int *pub_len,
                         unsigned char *pri, unsigned int *pri_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    *pub_len = i2d_PUBKEY(pkey, &pub);
    *pri_len = i2d_PrivateKey(pkey, &pri);
    PEM_write_PUBKEY(stdout, pkey);
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
fail:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (pkey)
        EVP_PKEY_free(pkey);
}

void ed25519_sign(const unsigned char *msg,    int msglen,
                  const unsigned char *prikey, unsigned int prikeylen,
                  unsigned char *sign,         unsigned int *signlen) {
    int ret = -1;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    d2i_PrivateKey(EVP_PKEY_ED25519, &pkey, &prikey, prikeylen);
    if (pkey == NULL) {
        ret = -1;
    }
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey);
    size_t message_len = msglen;
    EVP_DigestSign(md_ctx, sign, (size_t *)signlen, msg, message_len);
fail:
    if (eckey)
        EC_KEY_free(eckey);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);
}

int ed25519_verifySign(const unsigned char *msg,    int msglen,
                       const unsigned char *pubkey, unsigned int pubkeylen,
                       unsigned char *sign,         unsigned int signlen) {
    int ret = -1;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    d2i_PUBKEY(&pkey, &pubkey, pubkeylen);
    if (pkey == NULL) {
        ret = -1;
    }
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    
    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey);
    ret = EVP_DigestVerify(md_ctx, sign, signlen, msg, msglen);
fail:
    if (eckey)
        EC_KEY_free(eckey);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);
    return ret;
}

int main()
{
    const unsigned char message[] = {
        0x6E, 0x1B, 0x2C, 0x99, 0x43, 0x8A, 0xE6, 0x6A,
        0x35, 0x61, 0x02, 0xCE, 0xBF, 0x55, 0x77, 0xE7
    };
    unsigned char pub[256] = {0};
    unsigned int  publen = 256;
    
    unsigned char pri[256] = {0};
    unsigned int  prilen = 256;
    
    unsigned char sign[128] = {0};
    unsigned int  signlen = 128;
    
    ed25519_gen_keypair(pub, &publen, pri, &prilen);
    printf("public key: \n");
    print_bytes(pub, publen);
    
    printf("private key: \n");
    print_bytes(pri, prilen);
    
    ed25519_sign(message, sizeof(message), pri, prilen, sign, &signlen);
    printf("signature: \n");
    print_bytes(sign, signlen);
    
    int isSuccess = ed25519_verifySign(message, sizeof(message), pub, publen, sign, signlen);
    printf("verify signature res: %d\n", isSuccess);
    
    return 1;
}
