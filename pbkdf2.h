#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdint.h>

#ifndef __PBKDF2__
#define __PBKDF2__

typedef void(*PRF)(const uint8_t *keyPtr, size_t keyLen,
		const uint8_t *textPtr, size_t textLen,
		uint8_t *randomPtr);

void pbkdf2(PRF prf, size_t hLen,
	const void *passwordPtr, size_t passwordLen,
	const void *saltPtr, size_t saltLen,
	size_t iterationCount,
	void *dkPtr, size_t dkLen);

#endif /* __PBKDF2__ */