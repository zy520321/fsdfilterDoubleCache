#ifndef TC_HEADER_Crypto_Ripemd160
#define TC_HEADER_Crypto_Ripemd160

#if defined(__cplusplus)
extern "C"
{
#endif

#define RIPEMD160_BLOCK_LENGTH 64

typedef struct RMD160Context
{
	unsigned __int32 state[5];
#ifndef TC_NO_COMPILER_INT64
	unsigned __int64 count;
#else
	unsigned __int32 count;
#endif
	unsigned char buffer[RIPEMD160_BLOCK_LENGTH];
} RMD160_CTX;

void RMD160Init (RMD160_CTX *ctx);
void RMD160Transform (unsigned __int32 *state, const unsigned __int32 *data);
void RMD160Update (RMD160_CTX *ctx, const unsigned char *input, unsigned __int32 len);
void RMD160Final (unsigned char *digest, RMD160_CTX *ctx);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_Ripemd160
