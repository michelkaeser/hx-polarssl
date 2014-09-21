#ifndef __HX_POLARSSL_UTILS_HPP
#define __HX_POLARSSL_UTILS_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_BUFFER_SIZE  256


/*
 * Internal structure used to represent Haxe's BytesData.
 */
typedef struct {
    size_t               length;
    const unsigned char* data;
} s_bytes;


/*
 * Converts Haxe's BytesData into a struct that is a bit like
 * C++ native bytes array.
 *
 * Example:
 *   s_bytes* bytes = bytes_fromHaxe(hx_bytes, length);
 */
s_bytes* bytes_fromHaxe(value bytes, value length);


/*
 * Raises a Neko exception for the given PolarSSL error code.
 *
 * Example:
 *   int ret = _hxpolarssl_operation(....);
 *   if (ret != 0) {
 *       throw_err(ret);
 *   }
 */
void throw_err(int errnum);


/*
 * Converts C bytes back to Haxe's BytesData.
 *
 * Example:
 *   value bytes = value_fromBytes(bytes->data, bytes->length);
 */
value value_fromBytes(const unsigned char* bytes, size_t length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_UTILS_HPP */
