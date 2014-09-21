#ifndef __HX_POLARSSL_BLOWFISH_HPP
#define __HX_POLARSSL_BLOWFISH_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define BLOWFISH_BLOCKSIZE  8 /* Blowfish uses 64 bit blocks */


DECLARE_KIND(k_blowfish_context);


#define alloc_blowfish_context(v)      alloc_abstract(k_blowfish_context, v)
#define malloc_blowfish_context()      ((blowfish_context*)alloc_private(sizeof(blowfish_context)))
#define val_blowfish_context(v)        ((blowfish_context*)val_data(v))
#define val_check_blowfish_context(v)  val_check_kind(v, k_blowfish_context)
#define val_is_blowfish_context(v)     val_is_kind(v, k_blowfish_context)


/**
 * Blowfish CBC cipher function.
 *
 * See:
 *   https://polarssl.org/api/blowfish_8h.html
 *
 * Example:
 *   value enc = hx_blowfish_crypt_cbc(alloc_blowfish_context(blowfish_context), alloc_int(BLOWFISH_DECRYPT), buffer_size(buf), buffer_val(iv), buffer_val(buf));
 *
 * Parameters:
 *   value[k_blowfish_context] blowfish_context the Blowfish context to use
 *   value[Int]                mode             BLOWFISH_ENCRYPT or BLOWFISH_DECRYPT
 *   value[Int]                length           the number of input bytes (must be % BLOWFISH_BLOCKSIZE == 0)
 *   value[haxe.io.BytesData]  iv               the initialization vector (.length == BLOWFISH_BLOCKSIZE)
 *   value[haxe.io.BytesData]  input            the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_blowfish_crypt_cbc(value blowfish_context, value mode, value length, value iv, value input);


/**
 * Blowfish ECB cipher function.
 *
 * See:
 *   https://polarssl.org/api/blowfish_8h.html
 *
 * Example:
 *   value enc = hx_blowfish_crypt_ecb(alloc_blowfish_context(blowfish_context), alloc_int(BLOWFISH_DECRYPT), buffer_val(buf));
 *
 * Parameters:
 *   value[k_blowfish_context] blowfish_context the Blowfish context to use
 *   value[Int]                mode             BLOWFISH_ENCRYPT or BLOWFISH_DECRYPT
 *   value[haxe.io.BytesData]  input            the input block bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted Bytes
 *   or in case of an error, its code [Int] (and a Neko error is raised).
 */
value hx_blowfish_crypt_ecb(value blowfish_context, value mode, value input);


/*
 * Frees the Blowfish context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/blowfish_8h.html
 *
 * Example:
 *   hx_blowfish_free(alloc_blowfish_context(blowfish_context));
 *
 * Parameters:
 *   value[k_blowfish_context] blowfish_context the Blowfish context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_blowfish_free(value blowfish_context);


/*
 * Initializes and returns a Blowfish context.
 *
 * See:
 *   https://polarssl.org/api/Blowfish_8h.html
 *
 * Example:
 *   value blowfish_context = hx_blowfish_init();
 *
 * Returns:
 *   value[k_blowfish_context] the initialized Blowfish context
 */
value hx_blowfish_init(void);


/*
 * Sets the Blowfish context's secret key.
 *
 * See:
 *   https://polarssl.org/api/blowfish_8h.html
 *
 * Example:
 *   value blowfish = hx_blowfish_init();
 *   hx_blowfish_setkey(blowfish, buffer_val(key), buffer_size(keysize) * 8);
 *
 * Parameters:
 *   value[k_blowfish_context] blowfish_context the context for which the key should be set
 *   value[haxe.io.BytesData]  key              the secret key in bytes
 *   value[Int]                keylen           the secret key's length in bits!
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_blowfish_setkey(value blowfish_context, value key, value keysize);


/*
 * Finalizes the Blowfish context by freeing associated memory.
 *
 * Example:
 *   finalize_blowfish_context(alloc_blowfish_context(blowfish_context));
 *
 * Parameters:
 *   value[k_blowfish_context] blowfish_context the Blowfish context to free
 */
void finalize_blowfish_context(value blowfish_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_BLOWFISH_HPP */
