#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <stdlib.h>
#include <polarssl/xtea.h>

#include "hxpolarssl/xtea.hpp"
#include "hxpolarssl/utils.hpp"

extern "C" {

DEFINE_KIND(k_xtea_context);


value hx_xtea_crypt_cbc(value context, value mode, value length, value iv, value input)
{
    val_check_xtea_context(context);
    val_check(mode, int);

    s_bytes* _iv = bytes_fromHaxe(iv, alloc_int(8));
    s_bytes* _in = bytes_fromHaxe(input, length);
    unsigned char output[_in->length];

    value val;
    int ret = xtea_crypt_cbc(val_xtea_context(context), val_int(mode), _in->length, (unsigned char*)_iv->data, _in->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, _in->length);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_xtea_crypt_cbc, 5);


value hx_xtea_crypt_ecb(value context, value mode, value input)
{
    val_check_xtea_context(context);
    val_check(mode, int);

    s_bytes* bytes = bytes_fromHaxe(input, alloc_int(8));
    unsigned char output[8];

    value val;
    int ret = xtea_crypt_ecb(val_xtea_context(context), val_int(mode), bytes->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, 8);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_xtea_crypt_ecb, 3);


value hx_xtea_free(value context)
{
    val_check_xtea_context(context);

    xtea_free(val_xtea_context(context));

    return alloc_null();
}
DEFINE_PRIM(hx_xtea_free, 1);


value hx_xtea_init(void)
{
    xtea_context* context = malloc_xtea_context();
    xtea_init(context);

   value val = alloc_xtea_context(context);
   val_gc(val, finalize_xtea_context);

   return val;
}
DEFINE_PRIM(hx_xtea_init, 0);


value hx_xtea_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = xtea_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_xtea_self_test, 1);


value hx_xtea_setup(value context, value key)
{
    val_check_xtea_context(context);

    s_bytes* key_bytes = bytes_fromHaxe(key, alloc_int(16));
    xtea_setup(val_xtea_context(context), key_bytes->data);

    return alloc_null();
}
DEFINE_PRIM(hx_xtea_setup, 2);


void finalize_xtea_context(value context)
{
    val_check_xtea_context(context);

    if (context != NULL) {
        xtea_context* _context = val_xtea_context(context);
        xtea_free(_context);
        _context = NULL;
    }
}

} // extern "C"
