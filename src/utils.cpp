#define  IMPLEMENT_API
#define  NEKO_COMPATIBLE
#include <hx/CFFI.h>
#include <polarssl/error.h>

#include "hxpolarssl/utils.hpp"

extern "C" {

s_bytes* bytes_fromHaxe(const value bytes, const value length)
{
    val_check(length, int);

    s_bytes* cbytes = (s_bytes*)alloc_private(sizeof(s_bytes)); // TODO: use alloc
    cbytes->length = val_int(length);
    if (val_is_string(bytes)) { // Neko
        cbytes->data = (const unsigned char*)val_string(bytes);
    } else { // C++
        buffer buf   = val_to_buffer(bytes);
        cbytes->data = (const unsigned char*)buffer_data(buf);
    }

    return cbytes;
}


void throw_err(int errnum)
{
    char buffer[ERROR_BUFFER_SIZE];

    polarssl_strerror(errnum, buffer, ERROR_BUFFER_SIZE);
    val_throw(alloc_string(buffer));
}


value value_fromBytes(const unsigned char* bytes, const size_t length)
{
    buffer buf = alloc_buffer(NULL);
    buffer_append_sub(buf, (const char*)bytes, length);

    return buffer_val(buf);
}

} // extern "C"
