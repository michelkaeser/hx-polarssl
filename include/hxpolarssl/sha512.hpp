#ifndef __HX_POLARSSL_SHA512_HPP
#define __HX_POLARSSL_SHA512_HPP

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates the SHA-512 sum of the input bytes.
 *
 * See:
 *   https://polarssl.org/api/sha512_8h.html
 *
 * Example:
 *   value sum = hx_sha512(buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[haxe.io.BytesData] bytes  the bytes to hash
 *   value[Int]               length the number of bytes to hash
 *   value[Bool]              is384  to use SHA-384 or not (SHA-512 is false)
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the input bytes
 */
value hx_sha512(value bytes, value length, value is384);


/*
 * Calculates the SHA-512 sum of the file specified by 'path'.
 *
 * See:
 *   https://polarssl.org/api/sha384_8h.html
 *
 * Example:
 *   value sum = hx_sha512_file(alloc_string("/some/path"));
 *
 * Parameters:
 *   value[String] path  the file path
 *   value[Bool]   is384 to use SHA-384 or not (SHA-512 is false)
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the file
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_sha512_file(value path, value is384);


/*
 * Runs various health checks to ensure the SHA-512 module works correctly.
 *
 * See:
 *   https://polarssl.org/api/sha512_8h.html
 *
 * Example:
 *   value ret = hx_sha512_self_test(alloc_bool(false));
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
value hx_sha512_self_test(value verbose);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_SHA256_HPP */
