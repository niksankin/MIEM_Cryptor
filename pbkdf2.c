#include <string.h>
#include "stdlib.h"
#include "pbkdf2.h"

static void F(PRF prf, size_t hLen,
	const void *passwordPtr, size_t passwordLen,
	const void *saltPtr, size_t saltLen,
	size_t iterationCount,
	uint32_t blockNumber,
	void *dataPtr)
{
	uint8_t *inBlock, *outBlock, *resultBlockPtr;

	size_t blockSize = hLen > (saltLen + 4) ? hLen : saltLen + 4;

	outBlock = calloc(blockSize, sizeof(uint8_t));
	inBlock = calloc(blockSize, sizeof(uint8_t));
	
	memcpy(inBlock, saltPtr, saltLen);

	inBlock[saltLen + 0] = (uint8_t)(blockNumber >> 24);
	inBlock[saltLen + 1] = (uint8_t)(blockNumber >> 16);
	inBlock[saltLen + 2] = (uint8_t)(blockNumber >> 8);
	inBlock[saltLen + 3] = (uint8_t)(blockNumber);

	resultBlockPtr = (uint8_t*)dataPtr;
	prf(passwordPtr, passwordLen, inBlock, saltLen + 4, outBlock);
	memcpy(resultBlockPtr, outBlock, hLen);
	
	int lol = 1;

	for (size_t i = 2; i <= iterationCount; i++)
	{
		uint8_t *tempBlock;
		
		tempBlock = inBlock;
		inBlock = outBlock;
		outBlock = tempBlock;
		
		prf(passwordPtr, passwordLen, inBlock, hLen, outBlock);
		
		for (uint32_t byte = 0; byte < hLen; byte++)
			resultBlockPtr[byte] ^= outBlock[byte];
	}

	free(outBlock);
	free(inBlock);
}
void pbkdf2(PRF prf, size_t hLen,
	const void *passwordPtr, size_t passwordLen,
	const void *saltPtr, size_t saltLen,
	size_t iterationCount,
	void *dkPtr, size_t dkLen)
{
	size_t completeBlocks = dkLen / hLen;
	size_t partialBlockSize = dkLen % hLen;
	uint32_t blockNumber;
	uint8_t *dataPtr = (uint8_t*)dkPtr;
	uint8_t *blkBuffer = calloc(hLen, sizeof(uint8_t));

	completeBlocks = completeBlocks & UINT32_MAX;

	for (blockNumber = 1; blockNumber <= completeBlocks; blockNumber++)
	{
		F(prf, hLen, passwordPtr, passwordLen, saltPtr, saltLen,
			iterationCount, blockNumber, dataPtr);
		dataPtr += hLen;
	}

	if (partialBlockSize > 0)
	{
		F(prf, hLen, passwordPtr, passwordLen, saltPtr, saltLen,
			iterationCount, blockNumber, blkBuffer);
		memcpy(dataPtr, blkBuffer, partialBlockSize);
	}

	free(blkBuffer);
}