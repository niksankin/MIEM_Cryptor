/*
 * Copyright 2014 Aris Adamantiadis <aris@badcode.be>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* pack_common.c
 * This is where the packer payload executes
 */
#include <stdint.h>	//возможно от этого хедера лучше избавиться
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <linux/keyctl.h>
#include <unistd.h>
#include "aes.h"
#include <errno.h>

extern int errno;

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

static int myprintf(const char *format, ...){
	va_list ap;
	const char *s;
	const char *p;
	union {
		int intv;
		char *charv;
		unsigned int uintv;
		uint64_t uint64v;
	} param;

	va_start(ap, format);
	p=s=format;
	while(*p != 0){
		while(*p && *p != '%')
			++p;
		if(p!=s){
			write(1, s, p-s);
			s=p;
		}
		if(*p == '%'){
			switch(p[1]){
				case 's':
					param.charv = va_arg(ap, char *);
					write(1, param.charv, strlen(param.charv));
					break;
				case 'd':
					param.intv = va_arg(ap, int);
					write_dec(param.intv);
					break;
				case 'x':
					param.uintv = va_arg(ap, unsigned int);
					write_hex(param.uintv);
					break;
				case 'p':
#if defined(ARCH_X86) || defined(ARCH_ARM)
					param.uintv = va_arg(ap, unsigned int);
					write_hex(param.uintv);
					break;
#else
					param.uint64v = va_arg(ap, uint64_t);
					write_hex64(param.uint64v);
					break;
#endif
				case '\0':
					goto end;
			}
			p += 2;
			s=p;
		}
	}
end:
	va_end(ap);
	return 0;
}

static void clean_pages(/*some args*/){
	//здесь можно реализовать зачистку области памяти
}

static void decrypt(){
	//тут будет декрипт. Желательно, не использующий сторонние либы
}

void *get_oep(char *oep_offset, char* stub_offset, char *stub_runtime, char* crypted_offset, int text_len){
	void *entry=oep_offset;
	void *stub = stub_offset;
	void *runtime = stub_runtime;
	char *crypted = crypted_offset;
	void *ret;
	uint32_t key_id;
	uint32_t iv_id;
	uint8_t key_data[256];
	uint8_t iv_data[256];
	uint32_t key_len;
	uint32_t iv_len;
	uint8_t crypted_text[text_len + (AES_BLOCKLEN - text_len % AES_BLOCKLEN)];

	entry = (char*)entry + ((char*)runtime - (char*)stub);
	crypted = crypted + ((char*)runtime - (char*)stub);

	//const char lol[] = {'H','e','l','l','o','!','\n','\0'};

	//myprintf(lol);

	char role[] = "user";
	char desc_key[] = "enc_key";
	char desc_iv[] = "iv";

	key_id = syscall(__NR_request_key, role, desc_key, NULL, KEY_SPEC_USER_KEYRING);

	myprintf("%d", errno);

	iv_id = syscall(__NR_request_key, role, desc_iv, NULL, KEY_SPEC_USER_KEYRING);

	key_len = syscall(__NR_keyctl, KEYCTL_READ, key_id, key_data, sizeof(key_data));

	iv_len = syscall(__NR_keyctl, KEYCTL_READ, iv_id, iv_data, sizeof(iv_data));

	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key_data, iv_data);

	memcpy(crypted_text, crypted, text_len + (AES_BLOCKLEN - text_len % AES_BLOCKLEN));

	AES_CBC_decrypt_buffer(&ctx, crypted_text, text_len + (AES_BLOCKLEN - text_len % AES_BLOCKLEN));

	memcpy(entry, crypted_text, text_len);

	/*key_serial_t key;

	key = add_key(role, desc,
                            secret, sizeof(secret),
                            KEY_SPEC_SESSION_KEYRING);*/

	//здесь будет расшифровка и запись исходных секций на место.
	//после выполнения основной проги неплохо было бы зачистить память

	return entry;
}
