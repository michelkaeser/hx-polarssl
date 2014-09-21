#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/sha1.h>

#include "hxpolarssl/utils.hpp"
#include "hxpolarssl/sha1.hpp"

extern "C" {

value hx_sha1(value bytes, value length)
{
    s_bytes* cbytes = bytes_fromHaxe(bytes, length);
    unsigned char sum[20];
    sha1(cbytes->data, cbytes->length, sum);

    return value_fromBytes(sum, sizeof(sum));
}
DEFINE_PRIM(hx_sha1, 2);


value hx_sha1_file(value path)
{
    val_check(path, string);

    value val;
    unsigned char sum[20];
    int ret = sha1_file(val_string(path), sum);
    if (ret == 0) {
        val = value_fromBytes(sum, sizeof(sum));
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_sha1_file, 1);


value hx_sha1_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = sha1_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_sha1_self_test, 1);

} // extern "C"
