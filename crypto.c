#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#include "elink.h"
#include "server.h"
#include "log.h"

int _do_aes_cbc_crypt(unsigned char *in, int inlen, unsigned char **out, int *outlen, unsigned char *key, int do_encrypt)
{
	int tmplen = 0;
	unsigned char *buf = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	EVP_CIPHER_CTX ctx;

	// #if ENABLE_AES_DEBUG
	printf("%s from: \n", do_encrypt ? "encrypt" : "decrypt");
	log_mem(in, inlen);
	// #endif

	/* make sure key size == 16 */

	EVP_CIPHER_CTX_init(&ctx);

	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	buf = calloc(1, inlen + 1);

	if (!buf)
	{
		log("%s: %s malloc %d failed", __func__, do_encrypt ? "encrypt" : "decrypt", inlen + 1);
		return -1;
	}

	if (EVP_CipherUpdate(&ctx, buf, outlen, in, inlen) == 0)
	{
		log("aes_128_cbc %s failed: EVP_CipherUpdate", do_encrypt ? "encrypt" : "decrypt");
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}

	//printf("outlen = %d\n", *outlen);

	if (EVP_CipherFinal_ex(&ctx, buf + *outlen, &tmplen) == 0 && (tmplen > 0))
	{
		log("aes_128_cbc %s failed: EVP_CipherFinal_ex, tmplen %d", do_encrypt ? "encrypt" : "decrypt", tmplen);
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}

	//printf("tmplen = %d\n", tmplen);

	*out = buf;

	*outlen += tmplen;

	// #if ENABLE_AES_DEBUG
	printf("to: \n");
	log_mem(*out, *outlen);
	// #endif
	EVP_CIPHER_CTX_cleanup(&ctx);
	return *outlen;
}

int _do_aes_ecb_crypt(unsigned char *in, int inlen, unsigned char **out, int *outlen, unsigned char *key, int do_encrypt)
{
	int tmplen;
	unsigned char *buf = NULL;
	EVP_CIPHER_CTX ctx;

	// #if ENABLE_AES_DEBUG
	printf("from: \n");
	log_mem(in, inlen);
	// #endif
	EVP_CIPHER_CTX_init(&ctx);

	EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL, do_encrypt);

	if (do_encrypt)
		buf = malloc(inlen + AES_128_BLOCK_SIZE - inlen % AES_128_BLOCK_SIZE);
	else
		buf = malloc(inlen);

	if (!buf)
	{
		log("%s: %s malloc %d failed", __func__, do_encrypt ? "encrypt" : "decrypt", inlen);
		return -1;
	}

	if (EVP_CipherUpdate(&ctx, buf, outlen, in, inlen) == 0)
	{
		log("aes_128_ecb %s failed: EVP_CipherUpdate", do_encrypt ? "encrypt" : "decrypt");
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}

	//printf("outlen = %d\n", *outlen);

	if (EVP_CipherFinal_ex(&ctx, buf + *outlen, &tmplen) == 0 && (tmplen > 0))
	{
		log("aes_128_ecb %s failed: EVP_CipherFinal_ex, tmplen %d\n", do_encrypt ? "encrypt" : "decrypt", tmplen);
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}
}

int base64_encode(char *in_str, int in_len, char *out_str)
{
	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;
	size_t size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, in_str, in_len);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	memcpy(out_str, bptr->data, bptr->length);
	out_str[bptr->length] = '\0';
	size = bptr->length;

	BIO_free_all(bio);
	return size;
}

int base64_decode(char *in_str, int in_len, char *out_str)
{
	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;
	int counts;
	int size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(in_str, in_len);
	bio = BIO_push(b64, bio);

	size = BIO_read(bio, out_str, in_len);
	out_str[size] = '\0';

	BIO_free_all(bio);
	return size;
}