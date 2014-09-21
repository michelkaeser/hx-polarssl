#ifndef __HX_POLARSSL_CAMELLIA_HPP
#define __HX_POLARSSL_CAMELLIA_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define CAMELLIA_BLOCKSIZE  16


DECLARE_KIND(k_camellia_context);


#define alloc_camellia_context(v)      alloc_abstract(k_camellia_context, v)
#define malloc_camellia_context()      ((camellia_context*)alloc_private(sizeof(camellia_context)))
#define val_camellia_context(v)        ((camellia_context*)val_data(v))
#define val_check_camellia_context(v)  val_check_kind(v, k_camellia_context)
#define val_is_camellia_context(v)     val_is_kind(v, k_camellia_context)


/**
 * Camellia CBC cipher function.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value enc = hx_camellia_crypt_cbc(alloc_camellia_context(camellia_context), alloc_int(CAMELLIA_DECRYPT), buffer_size(buf), buffer_val(iv), buffer_val(buf));
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context to use
 *   value[Int]                mode             CAMELLIA_ENCRYPT or CAMELLIA_DECRYPT
 *   value[Int]                length           the number of input bytes (must be % CAMELLIA_BLOCKSIZE == 0)
 *   value[haxe.io.BytesData]  iv               the initialization vector (.length == CAMELLIA_BLOCKSIZE)
 *   value[haxe.io.BytesData]  input            the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_camellia_crypt_cbc(value camellia_context, value mode, value length, value iv, value input);


/**
 * Camellia ECB cipher function.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value enc = hx_camellia_crypt_ecb(alloc_camellia_context(camellia_context), alloc_int(CAMELLIA_DECRYPT), buffer_val(buf));
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context to use
 *   value[Int]                mode             CAMELLIA_ENCRYPT or CAMELLIA_DECRYPT
 *   value[haxe.io.BytesData]  input            the input block bytes (length must be 16)
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_camellia_crypt_ecb(value camellia_context, value mode, value input);


/*
 * Frees the Camellia context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   hx_camellia_free(alloc_camellia_context(camellia_context));
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_camellia_free(value camellia_context);


/*
 * Initializes and returns a Camellia context.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value camellia_context = hx_camellia_init();
 *
 * Returns:
 *   value[k_camellia_context] the initialized Camellia context
 */
value hx_camellia_init(void);


/*
 * Runs various health checks to ensure the Camellia module works correctly.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value ret = hx_camellia_self_test(alloc_bool(false));
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
value hx_camellia_self_test(value verbose);


/*
 * Sets the decryption key and internally generates the key schedule.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value cam = hx_camellia_init();
 *   hx_camellia_setkey_dec(cam, buffer_val(key), buffer_size(key) * 8);
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context for which the key should be set
 *   value[haxe.io.BytesData]  key              the key to set
 *   value[Int]                keylen           the key's length (in bits!)
 *
 * Returns:
 *   value[int] with 0 == OK and every other code meaning an error (which will also raise a Neko error).
 */
value hx_camellia_setkey_dec(value camellia_context, value key, value keylen);


/*
 * Sets the encryption key and internally generates the key schedule.
 *
 * See:
 *   https://polarssl.org/api/camellia_8h.html
 *
 * Example:
 *   value cam = hx_camellia_init();
 *   hx_camellia_setkey_enc(cam, buffer_val(key), buffer_size(key) * 8);
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context for which the key should be set
 *   value[haxe.io.BytesData]  key              the key to set
 *   value[Int]                keylen           the key's length (in bits!)
 *
 * Returns:
 *   value[int] with 0 == OK and every other code meaning an error (which will also raise a Neko error).
 */
value hx_camellia_setkey_enc(value camellia_context, value key, value keylen);


/*
 * Finalizes the Camellia context by freeing associated memory.
 *
 * Example:
 *   finalize_camellia_context(alloc_camellia_context(camellia_context));
 *
 * Parameters:
 *   value[k_camellia_context] camellia_context the Camellia context to free
 */
void finalize_camellia_context(value camellia_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_CAMELLIA_HPP */
