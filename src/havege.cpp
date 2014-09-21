#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/havege.h>

#include "hxpolarssl/utils.hpp"
#include "hxpolarssl/havege.hpp"

extern "C" {

DEFINE_KIND(k_havege_state);


value hx_havege_free(value hs)
{
    val_check_havege_state(hs);

    havege_free(val_havege_state(hs));

    return alloc_null();
}
DEFINE_PRIM(hx_havege_free, 1);


value hx_havege_init(void)
{
    havege_state* hs = malloc_havege_state();
    havege_init(hs);

    value val = alloc_havege_state(hs);
    val_gc(val, finalize_havege_state);

    return val;
}
DEFINE_PRIM(hx_havege_init, 0);


value hx_havege_random(value hs, value length)
{
    val_check_havege_state(hs);
    val_check(length, int);

    const size_t size = val_int(length);
    unsigned char buffer[size];
    havege_random(val_havege_state(hs), buffer, size);

    return value_fromBytes(buffer, size);
}
DEFINE_PRIM(hx_havege_random, 2);


void finalize_havege_state(value hs)
{
    val_check_havege_state(hs);

    if (hs != NULL) {
        havege_state* _hs = val_havege_state(hs);
        havege_free(_hs);
        _hs = NULL;
    }
}

} // extern "C"
