#ifndef __HX_POLARSSL_RIPEMD160_HPP
#define __HX_POLARSSL_RIPEMD160_HPP

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates the RIPEMD-160 sum of the input bytes.
 *
 * See:
 *   https://polarssl.org/api/ripemd160_8h.html
 *
 * Example:
 *   value sum = hx_ripemd160(buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[haxe.io.BytesData] bytes  the bytes to hash
 *   value[Int]               length the number of bytes to hash
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the input bytes
 */
value hx_ripemd160(value bytes, value length);


/*
 * Calculates the RIPEMD-160 sum of the file specified by 'path'.
 *
 * See:
 *   https://polarssl.org/api/ripemd160_8h.html
 *
 * Example:
 *   value sum = hx_ripemd160_file(alloc_string("/some/path"));
 *
 * Parameters:
 *   value[String] path the file path
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the file
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_ripemd160_file(value path);


/*
 * Runs various health checks to ensure the RIPEMD-160 module works correctly.
 *
 * See:
 *   https://polarssl.org/api/md5_8h.html
 *
 * Example:
 *   value ret = hx_ripemd160_self_test(alloc_bool(false));
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
value hx_ripemd160_self_test(value verbose);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_RIPEMD160_HPP */
