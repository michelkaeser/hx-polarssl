#ifndef __HX_POLARSSL_ARC4_HPP
#define __HX_POLARSSL_ARC4_HPP

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_KIND(k_arc4_context);


#define alloc_arc4_context(v)      alloc_abstract(k_arc4_context, v)
#define malloc_arc4_context()      ((arc4_context*)alloc_private(sizeof(arc4_context)))
#define val_arc4_context(v)        ((arc4_context*)val_data(v))
#define val_check_arc4_context(v)  val_check_kind(v, k_arc4_context)
#define val_is_arc4_context(v)     val_is_kind(v, k_arc4_context)


/**
 * Runs the input bytes through the cipher function.
 *
 * See:
 *   https://polarssl.org/api/arc4_8h.html
 *
 * Example:
 *   value arc4 = hx_arc4_init();
 *   hx_arc4_setup(arc4, buffer_val(key), buffer_size(key));
 *   value enc  = hx_arc4_crypt(arc4, buffer_size(buf), buffer_val(buf));
 *   ...
 *   value arc4 = hx_arc4_init();
 *   hx_arc4_setup(arc4, buffer_val(key), buffer_size(key));
 *   value dec = hx_arc_crypt(arc4, buffer_size(enc), buffer_val(enc))
 *
 * Parameters:
 *   value[k_arc4_context]    arc4_context the ARCFOUR context with which to cipher
 *   value[Int]               length       the number of bytes to crypt
 *   value[haxe.io.BytesData] input        the bytes to crypt
 *
 * Returns:
 *   value[haxe.io.BytesData] the crypted bytes
 *   or the error code [Int] together with a raised Neko error.
 */
value hx_arc4_crypt(value arc4_context, value length, value input);


/*
 * Frees the ARCFOUR context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/arc4_8h.html
 *
 * Example:
 *   hx_arc4_free(alloc_arc4_context(arc4_context));
 *
 * Parameters:
 *   value[k_arc4_context] arc4_context the ARCFOUR context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_arc4_free(value arc4_context);


/*
 * Initializes and returns an ARCFOUD context.
 *
 * See:
 *   https://polarssl.org/api/arc4_8h.html
 *
 * Example:
 *   value arc4_context = hx_arc4_init();
 *
 * Returns:
 *   value[k_arc4_context] the initialized ARCFOUR context
 */
value hx_arc4_init(void);


/*
 * Runs various health checks to ensure the ARCFOUR module works correctly.
 *
 * See:
 *   https://polarssl.org/api/arc4_8h.html
 *
 * Example:
 *   value ret = hx_arc4_self_test(alloc_bool(false));
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
value hx_arc4_self_test(value verbose);


/**
 * Setup the ARC4 context (its S-Boxes etc).
 *
 * See:
 *   https://polarssl.org/api/arc4_8h.html
 *
 * Example:
 *   hx_arc4_setup(alloc_arc4_context(arc4_context), buffer_val(buf), buffer_size(buf));
 *
 * Parameters:
 *   value[k_arc4_context]    arc4_context ARCFOUR context pointer
 *   value[haxe.io.BytesData] key          the secret key bytes
 *   value[Int]               keylen       the secret key number of bytes
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_arc4_setup(value arc4_context, value key, value keylen);


/*
 * Finalizes the ARCFOUR context by freeing associated memory.
 *
 * Example:
 *   finalize_arc4_context(alloc_arc4_context(arc4_context));
 *
 * Parameters:
 *   value[k_arc4_context] arc4_context the ARCFOUR context to free
 */
void finalize_arc4_context(value arc4_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_ARC4_HPP */
