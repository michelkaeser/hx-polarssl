#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/sha512.h>

#include "hxpolarssl/utils.hpp"
#include "hxpolarssl/sha512.hpp"

extern "C" {

value hx_sha512(value bytes, value length, value is384)
{
    val_check(is384, int);

    s_bytes* cbytes = bytes_fromHaxe(bytes, length);
    unsigned char sum[64];
    sha512(cbytes->data, cbytes->length, sum, val_int(is384));

    return value_fromBytes(sum, sizeof(sum));
}
DEFINE_PRIM(hx_sha512, 3);


value hx_sha512_file(value path, value is384)
{
    val_check(path, string);
    val_check(is384, int);

    value val;
    unsigned char sum[64];
    int ret = sha512_file(val_string(path), sum, val_int(is384));
    if (ret == 0) {
        val = value_fromBytes(sum, sizeof(sum));
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_sha512_file, 2);


value hx_sha512_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = sha512_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_sha512_self_test, 1);

} // extern "C"
