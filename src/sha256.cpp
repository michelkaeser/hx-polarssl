#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/sha256.h>

#include "hxpolarssl/utils.hpp"
#include "hxpolarssl/sha256.hpp"

extern "C" {

value hx_sha256(value bytes, value length, value is224)
{
    val_check(is224, int);

    s_bytes* cbytes = bytes_fromHaxe(bytes, length);
    unsigned char sum[32];
    sha256(cbytes->data, cbytes->length, sum, val_int(is224));

    return value_fromBytes(sum, sizeof(sum));
}
DEFINE_PRIM(hx_sha256, 3);


value hx_sha256_file(value path, value is224)
{
    val_check(path, string);
    val_check(is224, int);

    value val;
    unsigned char sum[32];
    int ret = sha256_file(val_string(path), sum, val_int(is224));
    if (ret == 0) {
        val = value_fromBytes(sum, sizeof(sum));
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_sha256_file, 2);


value hx_sha256_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = sha256_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_sha256_self_test, 1);

} // extern "C"
