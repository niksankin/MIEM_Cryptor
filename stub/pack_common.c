#include <stdint.h>	//возможно от этого хедера лучше избавиться
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <linux/keyctl.h>
#include <unistd.h>
#include "aes.h"

#define PAGE_ALIGN(x) ((x + 0xfff)&~0xfff)
#define PAGE_ALIGN_DOWN(x) ((x) &~0xfff) 

void *memcpy(void *dest, void *src, size_t len){
	register size_t i;
	for(i=0;i<len;++i){
		((unsigned char *)dest)[i]=((unsigned char*)src)[i];
	}
	return dest;
}

static void write_dec(int v){
	char buffer[12]="";
	int i=0;
	unsigned int c=1000000000; /* 10**9 */
	unsigned int v2;
	if (v<0){
		buffer[i]='-';
		++i;
		v2 = (unsigned int)-v;
	} else {
		v2 = v;
	}
	while(c >= 1){
		int num = v2/c;
        v2 = v2 - c*num;
		buffer[i]= '0' + num;
		c = c/10;
		++i;
	}
	buffer[i]=0;
	write(1, buffer, i);
}

static void write_hex(unsigned int v){
	unsigned int c = 0xf0000000;
	char alphabet[]="0123456789abcdef";
	int i=0;
	char buffer[9]="";
	while(c > 0){
		buffer[i]=alphabet[(v & c) >> ((7-i)*4)];
		++i;
		c >>=4;
	}
	buffer[i]='\0';
	write(1,buffer,i);
}

#ifdef ARCH_AMD64
static void write_hex64(uint64_t v){
	uint64_t c = 0xf000000000000000;
	char alphabet[]="0123456789abcdef";
	int i=0;
	char buffer[17]="";
	while(c > 0){
		buffer[i]=alphabet[(v & c) >> ((15-i)*4)];
		++i;
		c >>=4;
	}
	buffer[i]='\0';
	write(1,buffer,i);
}
#endif

off_t strlen(char *s){
	register int i;
	for(i=0;s[i];++i)
		;
	return i;
}

void* memset(void *p, int val, size_t len){
	register size_t i;
	for(i=0;i<len;++i)
		((char *)p)[i]=val;
	return p;
}

int memcmp(const void *s1, const void *s2, size_t n){
	size_t i;
	for (i=0;i<n;++i){
		if(((uint8_t *)s1)[i] != ((uint8_t *)s2)[i]){
			return ((uint8_t *)s1)[i] < ((uint8_t *)s2)[i] ? -1:1;
		}
	}
	return 0;
}

char *strchr(const char *s, int c){
	int i;
	for(i=0;s[i]!='\0';++i)
		if(s[i] == c)
			return (char *)s + i;
	return NULL;
}

void encryptDecrypt(char *input, int size_inp, char *key, int size_key) {

	int i;
	for (i = 0; i < size_inp; i++) {
		input[i] = input[i] ^ key[i % (size_key / sizeof(char))];
	}
}

void *get_oep(char *oep_offset, char* stub_offset, char *stub_runtime, char* crypted_offset, int text_len){
	void *entry=oep_offset;
	void *stub = stub_offset;
	void *runtime = stub_runtime;
	char *crypted = crypted_offset;
	void *ret;
	uint32_t key_id;
	uint32_t iv_id;
	uint8_t key_data[16];
	uint8_t iv_data[16];
	uint32_t key_len;
	uint32_t iv_len;
	uint8_t crypted_text[text_len + (AES_BLOCKLEN - text_len % AES_BLOCKLEN)];

	entry = (char*)entry + ((char*)runtime - (char*)stub);
	crypted = crypted + ((char*)runtime - (char*)stub);

	char role[] = "user";
	char desc_key[] = "enc_key";
	char desc_iv[] = "iv";

	key_id = syscall(__NR_request_key, role, desc_key, NULL, KEY_SPEC_SESSION_KEYRING);

	iv_id = syscall(__NR_request_key, role, desc_iv, NULL, KEY_SPEC_SESSION_KEYRING);

	key_len = syscall(__NR_keyctl, KEYCTL_READ, key_id, key_data, sizeof(key_data));

	iv_len = syscall(__NR_keyctl, KEYCTL_READ, iv_id, iv_data, sizeof(iv_data));

	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key_data, iv_data);

	memcpy(crypted_text, crypted, text_len + (AES_BLOCKLEN - (int)(text_len % AES_BLOCKLEN)));

	AES_CBC_decrypt_buffer(&ctx, crypted_text, text_len + (AES_BLOCKLEN - (int)(text_len % AES_BLOCKLEN)));

	memcpy(entry, crypted_text, text_len);

	return entry;
}
