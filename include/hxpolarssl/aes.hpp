#ifndef __HX_POLARSSL_AES_HPP
#define __HX_POLARSSL_AES_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCKSIZE  16


DECLARE_KIND(k_aes_context);


#define alloc_aes_context(v)      alloc_abstract(k_aes_context, v)
#define malloc_aes_context()      ((aes_context*)alloc_private(sizeof(aes_context)))
#define val_aes_context(v)        ((aes_context*)val_data(v))
#define val_check_aes_context(v)  val_check_kind(v, k_aes_context)
#define val_is_aes_context(v)     val_is_kind(v, k_aes_context)


/**
 * AES CBC cipher function.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value enc = hx_aes_crypt_cbc(alloc_aes_context(aes_context), alloc_int(AES_DECRYPT), buffer_size(buf), buffer_val(iv), buffer_val(buf));
 *
 * Parameters:
 *   value[k_aes_context]     aes_context the AES context to use
 *   value[Int]               mode        AES_ENCRYPT or AES_DECRYPT
 *   value[Int]               length      the number of input bytes (must be % AES_BLOCKSIZE == 0)
 *   value[haxe.io.BytesData] iv          the initialization vector (.length == AES_BLOCKSIZE)
 *   value[haxe.io.BytesData] input       the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_aes_crypt_cbc(value aes_context, value mode, value length, value iv, value input);


/**
 * AES ECB cipher function.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value enc = hx_aes_crypt_ecb(alloc_aes_context(aes_context), alloc_int(aes_DECRYPT), buffer_val(buf));
 *
 * Parameters:
 *   value[k_aes_context]     aes_context the aes context to use
 *   value[Int]               mode        AES_ENCRYPT or AES_DECRYPT
 *   value[haxe.io.BytesData] input       the input block bytes (length must be 16)
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_aes_crypt_ecb(value aes_context, value mode, value input);


/*
 * Frees the AES context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   hx_aes_free(alloc_aes_context(aes_context));
 *
 * Parameters:
 *   value[k_aes_context] aes_context the AES context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_aes_free(value aes_context);


/*
 * Initializes and returns an AES context.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value aes_context = hx_aes_init();
 *
 * Returns:
 *   value[k_aes_context] the initialized AES context
 */
value hx_aes_init(void);


/*
 * Runs various health checks to ensure the AES module works correctly.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value ret = hx_aes_self_test(alloc_bool(false));
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
value hx_aes_self_test(value verbose);


/*
 * Sets the decryption key and internally generates the key schedule.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value aes = hx_aes_init();
 *   hx_aes_setkey_dec(aes, buffer_val(key), buffer_size(key) * 8);
 *
 * Parameters:
 *   value[k_aes_context]     aes_context the AES context for which the key should be set
 *   value[haxe.io.BytesData] key         the key to set
 *   value[Int]               keylen      the key's length (in bits!)
 *
 * Returns:
 *   value[int] with 0 == OK and every other code meaning an error (which will also raise a Neko error).
 */
value hx_aes_setkey_dec(value aes_context, value key, value keylen);


/*
 * Sets the encryption key and internally generates the key schedule.
 *
 * See:
 *   https://polarssl.org/api/aes_8h.html
 *
 * Example:
 *   value aes = hx_aes_init();
 *   hx_aes_setkey_enc(aes, buffer_val(key), buffer_size(key) * 8);
 *
 * Parameters:
 *   value[k_aes_context]     aes_context the AES context for which the key should be set
 *   value[haxe.io.BytesData] key         the key to set
 *   value[Int]               keylen      the key's length (in bits!)
 *
 * Returns:
 *   value[int] with 0 == OK and every other code meaning an error (which will also raise a Neko error).
 */
value hx_aes_setkey_enc(value aes_context, value key, value keylen);


/*
 * Finalizes the AES context by freeing associated memory.
 *
 * Example:
 *   finalize_aes_context(alloc_aes_context(aes_context));
 *
 * Parameters:
 *   value[k_aes_context] aes_context the AES context to free
 */
void finalize_aes_context(value aes_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_AES_HPP */
