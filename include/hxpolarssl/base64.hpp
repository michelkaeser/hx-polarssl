#ifndef __HX_POLARSSL_BASE64_HPP
#define __HX_POLARSSL_BASE64_HPP

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decodes the encoded bytes back to unencoded ones.
 *
 * See:
 *   https://polarssl.org/api/base64_8h.html
 *
 * Example:
 *   value decoded = hx_base64_decode(buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[haxe.io.BytesData] bytes  the bytes to decode
 *   value[Int]               length the number of bytes to decode
 *
 * Returns:
 *   value[haxe.io.BytesData] the decoded bytes
 *   or in case of an error [Int] the error code (and a Neko error is raised).
 */
value hx_base64_decode(value bytes, value length);


/*
 * Encodes the provided bytes.
 *
 * See:
 *   https://polarssl.org/api/base64_8h.html
 *
 * Example:
 *   value encoded = hx_base64_encode(buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[haxe.io.BytesData] bytes  the bytes to encode
 *   value[Int]               length the number of bytes to encode
 *
 * Returns:
 *   value[haxe.io.BytesData] the encoded bytes
 *   or in case of an error [Int] the error code (and a Neko error is raised).
 */
value hx_base64_encode(value bytes, value length);


/*
 * Runs various health checks to ensure the Base64 module works correctly.
 *
 * See:
 *   https://polarssl.org/api/base64_8h.html
 *
 * Example:
 *   value ret = hx_base64_self_test(alloc_bool(false));
 *   if (val_int(ret) == 0) {
 *       // everthing good
 *   }
 *
 * Parameters:
 *   value[Bool] verbose output debug information or not
 *
 * Returns:
 *   value[Int] the self test's return code (0 = OK).
 *     In case of an error, a Neko error is raised too.
 */
value hx_base64_self_test(value verbose);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_BASE64_HPP */
