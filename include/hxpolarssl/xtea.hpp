#ifndef __HX_POLARSSL_XTEA_HPP
#define __HX_POLARSSL_XTEA_HPP

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_KIND(k_xtea_context);


#define alloc_xtea_context(v)      alloc_abstract(k_xtea_context, v)
#define malloc_xtea_context()      ((xtea_context*)alloc_private(sizeof(xtea_context)))
#define val_xtea_context(v)        ((xtea_context*)val_data(v))
#define val_check_xtea_context(v)  val_check_kind(v, k_xtea_context)
#define val_is_xtea_context(v)     val_is_kind(v, k_xtea_context)


/**
 * XTEA CBC cipher function.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   value enc = hx_xtea_crypt_cbc(alloc_xtea_context(xtea_context), alloc_int(XTEA_DECRYPT), buffer_size(buf), buffer_val(iv), buffer_val(buf));
 *
 * Parameters:
 *   value[k_xtea_context]    xtea_context the XTEA context to use
 *   value[Int]               mode         XTEA_ENCRYPT or XTEA_DECRYPT
 *   value[Int]               length       the number of input bytes (must be % 8 == 0)
 *   value[haxe.io.BytesData] iv           the initialization vector (.length == 8)
 *   value[haxe.io.BytesData] input        the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_xtea_crypt_cbc(value xtea_context, value mode, value length, value iv, value input);


/**
 * XTEA ECB cipher function.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   value enc = hx_xtea_crypt_ecb(alloc_xtea_context(xtea_context), alloc_int(XTEA_DECRYPT), buffer_val(buf));
 *
 * Parameters:
 *   value[k_xtea_context]    xtea_context the XTEA context to use
 *   value[Int]               mode         XTEA_ENCRYPT or XTEA_DECRYPT
 *   value[haxe.io.BytesData] input        the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_xtea_crypt_ecb(value xtea_context, value mode, value input);


/*
 * Frees the XTEA context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   hx_xtea_free(alloc_xtea_context(xtea_context));
 *
 * Parameters:
 *   value[k_xtea_context] xtea_context the XTEA context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_xtea_free(value xtea_context);


/*
 * Initializes and returns an XTEA context.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   value xtea_context = hx_xtea_init();
 *
 * Returns:
 *   value[k_xtea_context] the initialized XTEA context
 */
value hx_xtea_init(void);


/*
 * Runs various health checks to ensure the XTEA module works correctly.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   value ret = hx_xtea_self_test(alloc_bool(false));
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
value hx_xtea_self_test(value verbose);


/*
 * Setup the XTEA context so it can afterwards be used for de-/encryption.
 *
 * See:
 *   https://polarssl.org/api/xtea_8h.html
 *
 * Example:
 *   value xtea = hx_xtea_init();
 *   hx_xtrea_setup(xtea, buffer_val(key));
 *
 * Parameters:
 *   value[k_xtea_context]    xtea_context the XTEA context to setup
 *   value[haxe.io.BytesData] key          the secret key bytes (must be 16!)
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_xtea_setup(value xtea_context, value key);


/*
 * Finalizes the XTEA context by freeing associated memory.
 *
 * Example:
 *   finalize_xtea_context(alloc_xtea_context(xtea_context));
 *
 * Parameters:
 *   value[k_xtea_context] xtea_context the XTEA context to free
 */
void finalize_xtea_context(value xtea_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_XTEA_HPP */
