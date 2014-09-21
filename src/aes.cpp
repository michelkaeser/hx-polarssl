#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <stdlib.h>
#include <polarssl/aes.h>

#include "hxpolarssl/aes.hpp"
#include "hxpolarssl/utils.hpp"

extern "C" {

DEFINE_KIND(k_aes_context);


value hx_aes_crypt_cbc(value context, value mode, value length, value iv, value input)
{
    val_check_aes_context(context);
    val_check(mode, int);

    s_bytes* _iv = bytes_fromHaxe(iv, alloc_int(AES_BLOCKSIZE));
    s_bytes* _in = bytes_fromHaxe(input, length);
    unsigned char output[_in->length];

    value val;
    int ret = aes_crypt_cbc(val_aes_context(context), val_int(mode), _in->length, (unsigned char*)_iv->data, _in->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, _in->length);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_aes_crypt_cbc, 5);


value hx_aes_crypt_ecb(value context, value mode, value input)
{
    val_check_aes_context(context);
    val_check(mode, int);

    s_bytes* bytes = bytes_fromHaxe(input, alloc_int(AES_BLOCKSIZE));
    unsigned char output[AES_BLOCKSIZE];

    value val;
    int ret = aes_crypt_ecb(val_aes_context(context), val_int(mode), bytes->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, AES_BLOCKSIZE);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_aes_crypt_ecb, 3);


value hx_aes_free(value context)
{
    val_check_aes_context(context);

    aes_free(val_aes_context(context));

    return alloc_null();
}
DEFINE_PRIM(hx_aes_free, 1);


value hx_aes_init(void)
{
    aes_context* context = malloc_aes_context();
    aes_init(context);

   value val = alloc_aes_context(context);
   val_gc(val, finalize_aes_context);

   return val;
}
DEFINE_PRIM(hx_aes_init, 0);


value hx_aes_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = aes_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_aes_self_test, 1);


value hx_aes_setkey_dec(value context, value key, value keylen)
{
    val_check_aes_context(context);

    const size_t size = val_int(keylen);
    s_bytes* _key     = bytes_fromHaxe(key, keylen /* *8 */);

    int ret = aes_setkey_dec(val_aes_context(context), _key->data, size);
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_aes_setkey_dec, 3);


value hx_aes_setkey_enc(value context, value key, value keylen)
{
    val_check_aes_context(context);

    const size_t size = val_int(keylen);
    s_bytes* _key     = bytes_fromHaxe(key, keylen /* *8 */);

    int ret = aes_setkey_enc(val_aes_context(context), _key->data, size);
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_aes_setkey_enc, 3);


void finalize_aes_context(value context)
{
    val_check_aes_context(context);

    if (context != NULL) {
        aes_context* _context = val_aes_context(context);
        aes_free(_context);
        _context = NULL;
    }
}

} // extern "C"
