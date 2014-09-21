#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/base64.h>

#include "hxpolarssl/utils.hpp"
#include "hxpolarssl/base64.hpp"

extern "C" {

value hx_base64_decode(value bytes, value length)
{
    s_bytes* cbytes = bytes_fromHaxe(bytes, length);

    value val;
    size_t dlen = 0;
    int ret = base64_decode(NULL, &dlen, cbytes->data, cbytes->length); // get required buffer length
    unsigned char decoded[dlen];
    ret = base64_decode(decoded, &dlen, cbytes->data, cbytes->length);
    if (ret == 0) {
        val = value_fromBytes(decoded, dlen);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_base64_decode, 2);


value hx_base64_encode(value bytes, value length)
{
    s_bytes* cbytes = bytes_fromHaxe(bytes, length);

    value val;
    size_t dlen = 0;
    int ret = base64_encode(NULL, &dlen, cbytes->data, cbytes->length); // get required buffer length
    unsigned char encoded[dlen];
    ret = base64_encode(encoded, &dlen, cbytes->data, cbytes->length);
    if (ret == 0) {
        val = value_fromBytes(encoded, dlen);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_base64_encode, 2);


value hx_base64_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = base64_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_base64_self_test, 1);

} // extern "C"
