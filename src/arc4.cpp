#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <stdlib.h>
#include <polarssl/arc4.h>

#include "hxpolarssl/arc4.hpp"
#include "hxpolarssl/utils.hpp"

extern "C" {

DEFINE_KIND(k_arc4_context);


value hx_arc4_crypt(value context, value length, value input)
{
    val_arc4_context(context);

    const size_t size = val_int(length);
    s_bytes* bytes    = bytes_fromHaxe(input, length);

    value val;
    unsigned char output[size];
    int ret = arc4_crypt(val_arc4_context(context), size, bytes->data, output);
    if (ret == 0) {
        val = value_fromBytes(output, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_arc4_crypt, 3);


value hx_arc4_free(value context)
{
    val_check_arc4_context(context);

    arc4_free(val_arc4_context(context));

    return alloc_null();
}
DEFINE_PRIM(hx_arc4_free, 1);


value hx_arc4_init(void)
{
    arc4_context* context = malloc_arc4_context();
    arc4_init(context);

   value val = alloc_arc4_context(context);
   val_gc(val, finalize_arc4_context);

   return val;
}
DEFINE_PRIM(hx_arc4_init, 0);


value hx_arc4_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = arc4_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_arc4_self_test, 1);


value hx_arc4_setup(value context, value key, value keylen)
{
    val_check_arc4_context(context);

    s_bytes* bytes = bytes_fromHaxe(key, keylen);
    arc4_setup(val_arc4_context(context), bytes->data, bytes->length);

    return alloc_null();
}
DEFINE_PRIM(hx_arc4_setup, 3);


void finalize_arc4_context(value context)
{
    val_check_arc4_context(context);

    if (context != NULL) {
        arc4_context* _context = val_arc4_context(context);
        arc4_free(_context);
        _context = NULL;
    }
}

} // extern "C"
