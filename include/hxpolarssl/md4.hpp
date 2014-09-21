#ifndef __HX_POLARSSL_MD4_HPP
#define __HX_POLARSSL_MD4_HPP

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates the MD4 sum of the input bytes.
 *
 * See:
 *   https://polarssl.org/api/md4_8h.html
 *
 * Example:
 *   value sum = hx_md4(buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[haxe.io.BytesData] bytes  the bytes to hash
 *   value[Int]               length the number of bytes to hash
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the input bytes
 */
value hx_md4(value bytes, value length);


/*
 * Calculates the MD4 sum of the file specified by 'path'.
 *
 * See:
 *   https://polarssl.org/api/md4_8h.html
 *
 * Example:
 *   value sum = hx_md4_file(alloc_string("/some/path"));
 *
 * Parameters:
 *   value[String] path the file path
 *
 * Returns:
 *   value[haxe.io.BytesData] the hashsum of the file
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_md4_file(value path);


/*
 * Runs various health checks to ensure the MD4 module works correctly.
 *
 * See:
 *   https://polarssl.org/api/md2_8h.html
 *
 * Example:
 *   value ret = hx_md4_self_test(alloc_bool(false));
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
value hx_md4_self_test(value verbose);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_MD4_HPP */
