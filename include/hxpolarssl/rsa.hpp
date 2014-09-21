#ifndef __HX_POLARSSL_RSA_HPP
#define __HX_POLARSSL_RSA_HPP

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_KIND(k_rsa_context);


#define alloc_rsa_context(v)      alloc_abstract(k_rsa_context, v)
#define malloc_rsa_context()      ((rsa_context*)alloc_private(sizeof(rsa_context)))
#define val_rsa_context(v)        ((rsa_context*)val_data(v))
#define val_check_rsa_context(v)  val_check_kind(v, k_rsa_context)
#define val_is_rsa_context(v)     val_is_kind(v, k_rsa_context)


/*
 * Checks if the RSA context's public key is valid.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value ret = hx_rsa_check_pubkey(alloc_rsa_context(rsa_context));
 *   if (val_int(ret) == 0) {
 *       // everything good
 *   }
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context which's public key should be checked
 *
 * Returns:
 *   value[Int] the return code which is 0 == OK; other codes also raise a Neko error.
 */
value hx_rsa_check_pubkey(value rsa_context);


/*
 * Checks if the RSA context's private key is valid.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value ret = hx_rsa_check_privkey(alloc_rsa_context(rsa_context));
 *   if (val_int(ret) == 0) {
 *       // everything good
 *   }
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context which's private key should be checked
 *
 * Returns:
 *   value[Int] the return code which is 0 == OK; other codes also raise a Neko error.
 */
value hx_rsa_check_privkey(value rsa_context);


/*
 * Copy the components of the source RSA context to the destination context.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value ret = hx_rsa_copy(alloc_rsa_context(dest_context), alloc_rsa_context(src_context));
 *   if (val_int(ret) == 0) {
 *       // everything good
 *   }
 *
 * Parameters:
 *   value[k_rsa_context] dest_context the destination RSA context
 *   value[k_rsa_context] src_context  the source RSA context
 *
 * Returns:
 *   value[Int] the return code which is 0 == OK; other codes also raise a Neko error.
 */
//value hx_rsa_copy(value dest_context, value src_context);


/*
 * Returns the public key of the RSA keypair.
 *
 * Example:
 *   value key = hx_rsa_export_pubkey(alloc_rsa_context(rsa_context));
 */
//value hx_rsa_export_pubkey(value rsa_context);


/*
 * Frees the RSA context and all resources allocated for it.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   hx_rsa_free(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context to free
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_rsa_free(value rsa_context);


/*
 * Generates an RSA keypair of length 'nbits' with public n 'exponent'.
 *
 * Attn: The random number generator in use is PolarSSL's internal havege function.
 *       It is by default NOT compiled into the library, so make sure to uncomment the #define
 *       for that.
 *
 * TODO:
 *   - Allow passing a RNG function from Haxe?
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value ret = hx_rsa_gen_key(alloc_rsa_context(rsa_context), alloc_int(2048), alloc_int(65537));
 *   if (val_int(ret) == 0) {
 *       // everything good
 *   }
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which a keypair should be generated
 *   value[Int]           nbits       the length of the keys to generate (in bit)
 *   value[Int]           exponent    the public exponent
 *
 * Returns:
 *   value[Int] the return code which is 0 == OK; other codes also raise a Neko error.
 */
value hx_rsa_gen_key(value rsa_context, value nbits, value exponent);


/*
 * Returns the RSA context's private exponent.
 *
 * Example:
 *   value D = hx_rsa_get_D(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which the private exponent should be returned
 *
 * Returns:
 *   value[haxe.io.Bytes] the private exponent in bytes
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_rsa_get_D(value rsa_context);


/*
 * Returns the RSA context's public exponent.
 *
 * Example:
 *   value D = hx_rsa_get_D(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which the public exponent should be returned
 *
 * Returns:
 *   value[haxe.io.Bytes] the private exponent in bytes
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_rsa_get_E(value rsa_context);


/*
 * Returns the RSA context's public modulus.
 *
 * Example:
 *   value D = hx_rsa_get_D(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which the public modulus should be returned
 *
 * Returns:
 *   value[haxe.io.Bytes] the private exponent in bytes
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_rsa_get_N(value rsa_context);


/*
 * Returns the RSA context's 1st prime factor.
 *
 * Example:
 *   value D = hx_rsa_get_D(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which the prime factor should be returned
 *
 * Returns:
 *   value[haxe.io.Bytes] the private exponent in bytes
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_rsa_get_P(value rsa_context);


/*
 * Returns the RSA context's 2nd prime factor.
 *
 * Example:
 *   value D = hx_rsa_get_D(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context for which the prime factor should be returned
 *
 * Returns:
 *   value[haxe.io.Bytes] the private exponent in bytes
 *   or the error code [Int] (and a Neko error is raised).
 */
value hx_rsa_get_Q(value rsa_context);


/*
 * Initializes and returns an RSA context.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value rsa_context = hx_rsa_init(alloc_int(RSA_PKCS_V15), alloc_int(0));
 *
 * Parameters:
 *   value[Int] padding the padding scheme to use (PKCS_V15 (0) or PKCS_V21 (1))
 *   value[Int] hash_id the hash to use (only applies if padding is PKCS_V21)
 *
 * Returns:
 *   value[k_rsa_context] the initialized RSA context
 */
value hx_rsa_init(value padding, value hash_id);


/*
 * Decrypts the encrypted input bytes using the specified RSA mode (RSA_PUBLIC or RSA_PRIVATE).
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   val context = alloc_rsa_context(rsa_context);
 *   val enc = hx_rsa_pkcs1_encrypt(context, alloc_int(RSA_PUBLIC), buffer_val(input), buffer_size(length));
 *   val dec = hx_rsa_pkcs1_decrypt(context, alloc_int(RSA_PRIVATE), enc);
 *
 * Parameters:
 *   value[k_rsa_context]     rsa_context the RSA context to decrypt in
 *   value[Int]               mode        the mode in which should be decrypted (e.g. RSA_PRIVATE (1))
 *   value[haxe.io.BytesData] input       the input bytes to decrypt
 *
 * Returns:
 *   value[haxe.io.BytesData] the decrypted bytes
 *   or the error code [Int] together with a raised Neko error.
 */
value hx_rsa_pkcs1_decrypt(value rsa_context, value mode, value input);


/*
 * Encrypts the input bytes of length 'length' using the specified mode.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   val enc = hx_rsa_pkcs1_encrypt(alloc_rsa_context(rsa_context), alloc_int(RSA_PUBLIC), buffer_val(input), buffer_size(length));
 *
 * Parameters:
 *   value[k_rsa_context]     rsa_context the RSA context to encrypt in
 *   value[Int]               mode        the mode in which should be encrypted (e.g. RSA_PRIVATE (1))
 *   value[haxe.io.BytesData] input       the input bytes to encrypt
 *   value[Int]               length      the number of bytes to encrypt
 *
 * Returns:
 *   value[haxe.io.BytesData] the encrypted bytes
 *   or the error code [Int] together with a raised Neko error.
 */
value hx_rsa_pkcs1_encrypt(value rsa_context, value mode, value input, value length);


/*
 * Performs a PKCS#1 signature using the mode from the context.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   val sig = hx_rsa_pkcs1_sign(alloc_rsa_context(rsa_context), alloc_int(RSA_PUBLIC) alloc_int(POLARSSL_MD_NONE), buffer_size(hash), buffer_val(hash));
 *
 * Parameters:
 *   value[k_rsa_context]     rsa_context the RSA context to encrypt in
 *   value[Int]               mode        the mode in which should be signed (e.g. RSA_PRIVATE (1))
 *   value[Int]               md_alg      the hashing algorithm (e.g. MD_SHA512)
 *   value[Int]               hashlen     the number of hash bytes (only if md_alg = NONE)
 *   value[haxe.io.BytesData] hash        the hash in bytes
 *
 * Returns:
 *   value[haxe.io.BytesData] the signature bytes
 *   or the error code [Int] together with a raised Neko error.
 */
value hx_rsa_pkcs1_sign(value rsa_context, value mode, value md_alg, value hashlen, value hash);


/*
 * Performs a PKCS#1 verification using the mode from the context.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value context = alloc_rsa_context(rsa_context);
 *   val sig = hx_rsa_pkcs1_sign(context, alloc_int(POLARSSL_MD_NONE), buffer_size(hash), buffer_val(hash));
 *   value hashArr = "Array with [0] = hashLen & [1] = hash
 *   val valid = hx_rsa_pkcs1_verify(context, alloc_int(RSA_PRIVATE), alloc_int(POLARSSL_MD_NONE), hashArr sig);
 *   if (val_int(valid) == 0) {
 *       // valid signature
 *   }
 *
 * Parameters:
 *   value[k_rsa_context]     rsa_context the RSA context to encrypt in
 *   value[Int]               mode        the mode in which should be signed (e.g. RSA_PRIVATE (1))
 *   value[Int]               md_alg      the hashing algorithm (e.g. MD_SHA512)
 *   value[Array<Dynamic>]    hashArr     Array with [0] = hash length [Int] and [1] = hash bytes [haxe.io.BytesData]
 *   value[haxe.io.BytesData] sig         the signature bytes to verify
 *
 * Returns:
 *   value[Int] the return code which is 0 == OK; otherwise a Neko error is also raised.
 */
value hx_rsa_pkcs1_verify(value rsa_context, value mode, value md_alg, value hashArr, value sig);


/*
 * Runs various health checks to ensure the RSA module works correctly.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   value ret = hx_rsa_self_test(alloc_bool(false));
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
value hx_rsa_self_test(value verbose);


/*
 * Set padding for an already initialized RSA context.
 *
 * See:
 *   https://polarssl.org/api/rsa_8h.html
 *
 * Example:
 *   hx_rsa_set_padding(alloc_rsa_context(rsa_context), alloc_int(RSA_PKCS_V15), alloc_int(0));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context on which the padding should be set
 *   value[Int]           padding     the padding scheme to use (e.g. PKCS_V15)
 *   value[Int]           hash_id     the hash identifier to use with PKCS_V21
 *
 * Returns:
 *   value[null] nothing is returned
 */
value hx_rsa_set_padding(value rsa_context, value padding, value hash_id);


/*
 * Finalizes the RSA context by freeing associated memory.
 *
 * Example:
 *   finalize_rsa_context(alloc_rsa_context(rsa_context));
 *
 * Parameters:
 *   value[k_rsa_context] rsa_context the RSA context to free
 */
void finalize_rsa_context(value rsa_context);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __HX_POLARSSL_RSA_HPP */
