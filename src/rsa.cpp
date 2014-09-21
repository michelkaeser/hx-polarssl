#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <stdlib.h>
#include <polarssl/md.h>
#include <polarssl/havege.h>
#include <polarssl/rsa.h>

#include "hxpolarssl/rsa.hpp"
#include "hxpolarssl/utils.hpp"

extern "C" {

DEFINE_KIND(k_rsa_context);


value hx_rsa_check_pubkey(value context)
{
    val_check_rsa_context(context);

    int ret = rsa_check_pubkey(val_rsa_context(context));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_rsa_check_pubkey, 1);


value hx_rsa_check_privkey(value context)
{
    val_check_rsa_context(context);

    int ret = rsa_check_privkey(val_rsa_context(context));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_rsa_check_privkey, 1);


// value hx_rsa_copy(value dest_context, value src_context)
// {
//     val_check_rsa_context(dest_context);
//     val_check_rsa_context(src_context);

//     int ret = rsa_copy(val_rsa_context(dest_context), val_rsa_context(src_context));
//     if (ret != 0) {
//         throw_err(ret);
//     }

//     return alloc_int(ret);
// }
// DEFINE_PRIM(hx_rsa_copy, 2);


// value hx_rsa_export_pubkey(value context)
// {
//     val_check_rsa_context(context);

//     rsa_context* _context  = val_rsa_context(context);
//     size_t datasize        = _context->len * 4;
//     size_t size            = datasize;
//     char* data             = (char*)malloc(datasize);
//     char* p                = data;

//     datasize -= strlen(data);
//     p        += strlen(data);

//     value val;
//     if (mpi_write_string(&_context->N, 16, p, &size) == 0 && (size + 1) <= datasize) {
//         p[size - 1] = ':';
//         p          += size;
//         datasize   -= size;
//         size        = datasize;
//         if (mpi_write_string(&_context->E, 16, p, &size) == 0) {
//             val = alloc_string(data);
//         } else {
//             free(data);
//             neko_error();
//             val = alloc_null();
//         }
//     } else {
//         free(data);
//         neko_error();
//         val = alloc_null();
//     }

//     return val;
// }
// DEFINE_PRIM(hx_rsa_export_pubkey, 1);


value hx_rsa_free(value context)
{
    val_check_rsa_context(context);

    rsa_free(val_rsa_context(context));

    return alloc_null();
}
DEFINE_PRIM(hx_rsa_free, 1);


value hx_rsa_gen_key(value context, value nbits, value exponent)
{
    val_check_rsa_context(context);
    val_check(nbits, int);
    val_check(exponent, int);

    havege_state state;
    havege_init(&state);
    int ret = rsa_gen_key(val_rsa_context(context), havege_random, &state, val_int(nbits), val_int(exponent));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_rsa_gen_key, 3);


value hx_rsa_get_D(value context)
{
    val_check_rsa_context(context);

    rsa_context* _context = val_rsa_context(context);
    const size_t size     = mpi_size(&(_context->D));
    unsigned char buffer[size];

    value val;
    int ret = mpi_write_binary(&(_context->D), buffer, size);
    if (ret == 0) {
        val = value_fromBytes(buffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_get_D, 1);


value hx_rsa_get_E(value context)
{
    val_check_rsa_context(context);

    rsa_context* _context = val_rsa_context(context);
    const size_t size     = mpi_size(&(_context->E));
    unsigned char buffer[size];

    value val;
    int ret = mpi_write_binary(&(_context->E), buffer, size);
    if (ret == 0) {
        val = value_fromBytes(buffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_get_E, 1);


value hx_rsa_get_N(value context)
{
    val_check_rsa_context(context);

    rsa_context* _context = val_rsa_context(context);
    const size_t size     = mpi_size(&(_context->N));
    unsigned char buffer[size];

    value val;
    int ret = mpi_write_binary(&(_context->N), buffer, size);
    if (ret == 0) {
        val = value_fromBytes(buffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_get_N, 1);


value hx_rsa_get_P(value context)
{
    val_check_rsa_context(context);

    rsa_context* _context = val_rsa_context(context);
    const size_t size     = mpi_size(&(_context->P));
    unsigned char buffer[size];

    value val;
    int ret = mpi_write_binary(&(_context->P), buffer, size);
    if (ret == 0) {
        val = value_fromBytes(buffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_get_P, 1);


value hx_rsa_get_Q(value context)
{
    val_check_rsa_context(context);

    rsa_context* _context = val_rsa_context(context);
    const size_t size     = mpi_size(&(_context->Q));
    unsigned char buffer[size];

    value val;
    int ret = mpi_write_binary(&(_context->Q), buffer, size);
    if (ret == 0) {
        val = value_fromBytes(buffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_get_Q, 1);


value hx_rsa_init(value padding, value hash_id)
{
    val_check(padding, int);
    val_check(hash_id, int);

    rsa_context* context = malloc_rsa_context();
    rsa_init(context, val_int(padding), val_int(hash_id));

    value val = alloc_rsa_context(context);
    val_gc(val, finalize_rsa_context);

    return val;
}
DEFINE_PRIM(hx_rsa_init, 2);


value hx_rsa_pkcs1_decrypt(value context, value mode, value input)
{
    val_check_rsa_context(context);
    val_check(mode, int);

    s_bytes* bytes        = bytes_fromHaxe(input, alloc_int(0));
    rsa_context* _context = val_rsa_context(context);
    const size_t bufsize  = (const size_t)((_context->N.n) * 8);
    unsigned char outbuffer[bufsize];
    size_t outlen;
    havege_state state;
    havege_init(&state);

    value val;
    int ret = rsa_pkcs1_decrypt(_context, havege_random, &state, val_int(mode), &outlen, bytes->data, outbuffer, bufsize);
    if (ret == 0) {
        val = value_fromBytes(outbuffer, outlen);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_pkcs1_decrypt, 3);


value hx_rsa_pkcs1_encrypt(value context, value mode, value input, value length)
{
    val_check_rsa_context(context);
    val_check(mode, int);

    s_bytes* bytes        = bytes_fromHaxe(input, length);
    rsa_context* _context = val_rsa_context(context);
    const size_t size     = (const size_t)((_context->N.n) * 8);
    unsigned char outbuffer[size];
    havege_state state;
    havege_init(&state);

    value val;
    int ret = rsa_pkcs1_encrypt(_context, havege_random, &state, val_int(mode), bytes->length, bytes->data, outbuffer);
    if (ret == 0) {
        val = value_fromBytes(outbuffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_pkcs1_encrypt, 4);


value hx_rsa_pkcs1_sign(value context, value mode, value md_alg, value hashlen, value hash)
{
    val_check_rsa_context(context);
    val_check(mode, int);
    val_check(md_alg, int);
    val_check(hashlen, int);

    s_bytes* bytes        = bytes_fromHaxe(hash, hashlen);
    rsa_context* _context = val_rsa_context(context);
    const size_t size     = (const size_t)((_context->N.n) * 8);
    unsigned char sigbuffer[size];
    havege_state state;
    havege_init(&state);

    value val;
    int ret = rsa_pkcs1_sign(_context, havege_random, &state, val_int(mode), (md_type_t)val_int(md_alg), /*(unsigned int)*/bytes->length, bytes->data, sigbuffer);
    if (ret == 0) {
        val = value_fromBytes(sigbuffer, size);
    } else {
        throw_err(ret);
        val = alloc_int(ret);
    }

    return val;
}
DEFINE_PRIM(hx_rsa_pkcs1_sign, 5);


value hx_rsa_pkcs1_verify(value context, value mode, value md_alg, value hashArr, value sig)
{
    val_check_rsa_context(context);
    val_check(mode, int);
    val_check(md_alg, int);
    val_check(hashArr, array);
    val_check(val_array_i(hashArr, 0), int);

    s_bytes* hash_bytes   = bytes_fromHaxe(val_array_i(hashArr, 1), val_array_i(hashArr, 0));
    s_bytes* sig_bytes    = bytes_fromHaxe(sig, alloc_int(0));
    rsa_context* _context = val_rsa_context(context);
    havege_state state;
    havege_init(&state);

    int ret = rsa_pkcs1_verify(_context, havege_random, &state, val_int(mode), (md_type_t)val_int(md_alg), /*(unsigned int)*/hash_bytes->length, hash_bytes->data, sig_bytes->data);
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_rsa_pkcs1_verify, 5);


value hx_rsa_self_test(value verbose)
{
    val_check(verbose, bool);

    int ret = rsa_self_test(val_bool(verbose));
    if (ret != 0) {
        throw_err(ret);
    }

    return alloc_int(ret);
}
DEFINE_PRIM(hx_rsa_self_test, 1);


value hx_rsa_set_padding(value context, value padding, value hash_id)
{
    val_check_rsa_context(context);
    val_check(padding, int);
    val_check(hash_id, int);

    rsa_set_padding(val_rsa_context(context), val_int(padding), val_int(hash_id));

    return alloc_null();
}
DEFINE_PRIM(hx_rsa_set_padding, 3);


void finalize_rsa_context(value context)
{
    val_check_rsa_context(context);

    if (context != NULL) {
        rsa_context* _context = val_rsa_context(context);
        rsa_free(_context);
        _context = NULL;
    }
}

} // extern "C"
