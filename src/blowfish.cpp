#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <stdlib.h>
#include <polarssl/blowfish.h>

#include "hxpolarssl/blowfish.hpp"
#include "hxpolarssl/utils.hpp"

extern "C" {

DEFINE_KIND(k_blowfish_context);


value hx_blowfish_crypt_cbc(value context, value mode, value length, value iv, value input)
{
    val_check_blowfish_context(context);
    val_check(mode, int);

    s_bytes* _iv = bytes_fromHaxe(iv, alloc_int(BLOWFISH_BLOCKSIZE));
    s_bytes* _in = bytes_fromHaxe(input, length);
    unsigned char output[_in->length];

    value val;
    int ret = blowfish_crypt_cbc(val_blowfish_context(context), val_int(mode), _in->length, (unsigned char*)_iv->data, _in->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, _in->length);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_blowfish_crypt_cbc, 5);


value hx_blowfish_crypt_ecb(value context, value mode, value input)
{
    val_check_blowfish_context(context);
    val_check(mode, int);

    s_bytes* bytes = bytes_fromHaxe(input, alloc_int(BLOWFISH_BLOCKSIZE));
    unsigned char output[BLOWFISH_BLOCKSIZE];

    value val;
    int ret = blowfish_crypt_ecb(val_blowfish_context(context), val_int(mode), bytes->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, BLOWFISH_BLOCKSIZE);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_blowfish_crypt_ecb, 3);


value hx_blowfish_free(value context)
{
    val_check_blowfish_context(context);

    blowfish_free(val_blowfish_context(context));

    return alloc_null();
}
DEFINE_PRIM(hx_blowfish_free, 1);


value hx_blowfish_init(void)
{
    blowfish_context* context = malloc_blowfish_context();
    blowfish_init(context);

   value val = alloc_blowfish_context(context);
   val_gc(val, finalize_blowfish_context);

   return val;
}
DEFINE_PRIM(hx_blowfish_init, 0);


value hx_blowfish_setkey(value context, value key, value keysize)
{
    val_check_blowfish_context(context);

    s_bytes* bytes = bytes_fromHaxe(key, keysize);

    int ret = blowfish_setkey(val_blowfish_context(context), bytes->data, bytes->length);
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_blowfish_setkey, 3);


void finalize_blowfish_context(value context)
{
    val_check_blowfish_context(context);

    if (context != NULL) {
        blowfish_context* _context = val_blowfish_context(context);
        blowfish_free(_context);
        _context = NULL;
    }
}

} // extern "C"
