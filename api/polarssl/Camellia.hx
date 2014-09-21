package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import lib.IllegalArgumentException;
import lib.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL Camellia implementation.
 */
class Camellia
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _crypt_cbc:CamelliaContext->Int->Int->BytesData->BytesData->BytesData = Loader.load("hx_camellia_crypt_cbc", 5);
    private static var _crypt_ecb:CamelliaContext->Int->BytesData->BytesData = Loader.load("hx_camellia_crypt_ecb", 3);
    private static var _free:CamelliaContext->Void = Loader.load("hx_camellia_free", 1);
    private static var _init:Void->CamelliaContext = Loader.load("hx_camellia_init", 0);
    private static var _self_test:Bool->Int        = Loader.load("hx_camellia_self_test", 1);
    private static var _setkey_dec:CamelliaContext->BytesData->Int->Void = Loader.load("hx_camellia_setkey_dec", 3);
    private static var _setkey_enc:CamelliaContext->BytesData->Int->Void = Loader.load("hx_camellia_setkey_enc", 3);

    /**
     * Possible Camellia mode values.
     */
    public static inline var DECRYPT:Int = 0;
    public static inline var ENCRYPT:Int = 1;

    /**
     * Stores the native Camellia context handle.
     *
     * @var Null<polarssl.Camellia.CamelliaContext>
     */
    private var context:Null<CamelliaContext>;


    /**
     * Constructor to initialize a new Camellia instance.
     *
     * @throws polarssl.PolarSSLException if the Camellia context init fails
     */
    public function new():Void
    {
        try {
            this.context = Camellia._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  Camellia.DECRYPT or Camellia.ENCRYPT
     * @param haxe.io.Bytes iv    the initialization vector
     * @param haxe.io.Bytes bytes the input bytes (must be % 16 == 0 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws lib.IllegalArgumentException if the mode is not supported
     * @throws lib.IllegalArgumentException if the initialization vector is not 16 bytes long
     * @throws lib.IllegalArgumentException if the input bytes length is not % 16 == 0
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function cryptCbc(mode:Int, iv:Bytes, bytes:Bytes):Bytes
    {
        if (mode != Camellia.DECRYPT && mode != Camellia.ENCRYPT) {
            throw new IllegalArgumentException("Provided Camellia mode is not supported");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("Initialization vector must be 16 bytes");
        }
        if (bytes == null || (bytes.length % 16) != 0) {
            throw new IllegalArgumentException("Input bytes' length must be a multiple of 16");
        }
        if (this.context == null) {
            throw new IllegalStateException("No Camellia context available");
        }

        // create a copy since it will be updated
        var copy:Bytes = Bytes.alloc(iv.length);
        copy.blit(0, iv, 0, iv.length);

        try {
            return Bytes.ofData(Camellia._crypt_cbc(this.context, mode, bytes.length, copy.getData(), bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  Camellia.DECRYPT or Camellia.ENCRYPT
     * @param haxe.io.Bytes bytes the input bytes (must be 16 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws lib.IllegalArgumentException if the mode is not supported
     * @throws lib.IllegalArgumentException if the input bytes length is not 16
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function cryptEcb(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != Camellia.DECRYPT && mode != Camellia.ENCRYPT) {
            throw new IllegalArgumentException("Provided Camellia mode is not supported");
        }
        if (bytes == null || bytes.length != 16) {
            throw new IllegalArgumentException("ECB block cipher mode requires 16 input bytes");
        }
        if (this.context == null) {
            throw new IllegalStateException("No Camellia context available");
        }

        try {
            return Bytes.ofData(Camellia._crypt_ecb(this.context, mode, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees all memory allocated for this Camellia instance.
     *
     * Attn: The Camellia instance can no longer be used after calling this method.
     *
     * @throws lib.IllegalStateException  if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No Camellia context available");
        }

        try {
            Camellia._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the Camellia module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = Camellia._self_test(verbose);
        } catch (ex:Dynamic) {
            #if POLARSSL_DEBUG
                throw new PolarSSLException(ex);
            #else
                ret = 1;
            #end
        }

        return ret == 0;
    }

    /**
     * Sets the decryption key.
     *
     * @param haxe.io.Bytes key the secret key to set
     *
     * @throws lib.IllegalArgumentException if the bytes are not a valid Camellia key
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function setDecryptionKey(key:Bytes):Void
    {
        if (key == null || (key.length != 16 /* 128 / 8 */ && key.length != 24 /* 196 / 8 */&& key.length != 32/* 256 / 8 */)) {
            throw new IllegalArgumentException("Bytes are not a valid Camellia key");
        }
        if (this.context == null) {
            throw new IllegalStateException("Camellia context not available");
        }

        try {
            Camellia._setkey_dec(this.context, key.getData(), key.length * 8);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Sets the encryption key.
     *
     * @param haxe.io.Bytes key the secret key to set
     *
     * @throws lib.IllegalArgumentException if the bytes are not a valid Camellia key
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function setEncryptionKey(key:Bytes):Void
    {
        if (key == null || (key.length != 16 /* 128 / 8 */ && key.length != 24 /* 196 / 8 */&& key.length != 32/* 256 / 8 */)) {
            throw new IllegalArgumentException("Bytes are not a valid Camellia key");
        }
        if (this.context == null) {
            throw new IllegalStateException("Camellia context not available");
        }

        try {
            Camellia._setkey_enc(this.context, key.getData(), key.length * 8);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}


/**
 * Extern for native Camellia context handles wrapped by Neko/C++ value.
 */
private extern class CamelliaContext {}
