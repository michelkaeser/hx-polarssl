package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import hext.IllegalArgumentException;
import hext.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL AES implementation.
 */
class AES
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _crypt_cbc:AESContext->Int->Int->BytesData->BytesData->BytesData = Loader.load("hx_aes_crypt_cbc", 5);
    private static var _crypt_ecb:AESContext->Int->BytesData->BytesData = Loader.load("hx_aes_crypt_ecb", 3);
    private static var _free:AESContext->Void                           = Loader.load("hx_aes_free", 1);
    private static var _init:Void->AESContext                           = Loader.load("hx_aes_init", 0);
    private static var _self_test:Bool->Int                             = Loader.load("hx_aes_self_test", 1);
    private static var _setkey_dec:AESContext->BytesData->Int->Void     = Loader.load("hx_aes_setkey_dec", 3);
    private static var _setkey_enc:AESContext->BytesData->Int->Void     = Loader.load("hx_aes_setkey_enc", 3);

    /**
     * Possible AES mode values.
     */
    public static inline var DECRYPT:Int = 0;
    public static inline var ENCRYPT:Int = 1;

    /**
     * Stores the native AES context handle.
     *
     * @var Null<polarssl.AES.AESContext>
     */
    private var context:Null<AESContext>;


    /**
     * Constructor to initialize a new AES instance.
     *
     * @throws polarssl.PolarSSLException if the AES context init fails
     */
    public function new():Void
    {
        try {
            this.context = AES._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  AES.DECRYPT or AES.ENCRYPT
     * @param haxe.io.Bytes iv    the initialization vector
     * @param haxe.io.Bytes bytes the input bytes (must be % 16 == 0 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws hext.IllegalArgumentException if the mode is not supported
     * @throws hext.IllegalArgumentException if the initialization vector is not 16 bytes long
     * @throws hext.IllegalArgumentException if the input bytes length is not % 16 == 0
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function cryptCbc(mode:Int, iv:Bytes, bytes:Bytes):Bytes
    {
        if (mode != AES.DECRYPT && mode != AES.ENCRYPT) {
            throw new IllegalArgumentException("Provided AES mode is not supported.");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("Initialization vector must be 16 bytes.");
        }
        if (bytes == null || (bytes.length % 16) != 0) {
            throw new IllegalArgumentException("Input bytes' length must be a multiple of 16.");
        }
        if (this.context == null) {
            throw new IllegalStateException("No AES context available.");
        }

        // create a copy since it will be updated
        var copy:Bytes = Bytes.alloc(iv.length);
        copy.blit(0, iv, 0, iv.length);

        try {
            return Bytes.ofData(AES._crypt_cbc(this.context, mode, bytes.length, copy.getData(), bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  AES.DECRYPT or AES.ENCRYPT
     * @param haxe.io.Bytes bytes the input bytes (must be 16 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws hext.IllegalArgumentException if the mode is not supported
     * @throws hext.IllegalArgumentException if the input bytes length is not 16
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function cryptEcb(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != AES.DECRYPT && mode != AES.ENCRYPT) {
            throw new IllegalArgumentException("Provided AES mode is not supported.");
        }
        if (bytes == null || bytes.length != 16) {
            throw new IllegalArgumentException("ECB block cipher mode requires 16 input bytes.");
        }
        if (this.context == null) {
            throw new IllegalStateException("No AES context available.");
        }

        try {
            return Bytes.ofData(AES._crypt_ecb(this.context, mode, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees all memory allocated for this AES instance.
     *
     * Attn: The AES instance can no longer be used after calling this method.
     *
     * @throws hext.IllegalStateException if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No AES context available.");
        }

        try {
            AES._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the AES module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = AES._self_test(verbose);
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
     * @throws hext.IllegalArgumentException if the bytes are not a valid AES key
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function setDecryptionKey(key:Bytes):Void
    {
        if (key == null || (key.length != 16 /* 128 / 8 */ && key.length != 24 /* 196 / 8 */&& key.length != 32/* 256 / 8 */)) {
            throw new IllegalArgumentException("Bytes are not a valid AES key.");
        }
        if (this.context == null) {
            throw new IllegalStateException("AES context not available.");
        }

        try {
            AES._setkey_dec(this.context, key.getData(), key.length * 8);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Sets the encryption key.
     *
     * @param haxe.io.Bytes key the secret key to set
     *
     * @throws hext.IllegalArgumentException if the bytes are not a valid AES key
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function setEncryptionKey(key:Bytes):Void
    {
        if (key == null || (key.length != 16 /* 128 / 8 */ && key.length != 24 /* 196 / 8 */&& key.length != 32/* 256 / 8 */)) {
            throw new IllegalArgumentException("Bytes are not a valid AES key.");
        }
        if (this.context == null) {
            throw new IllegalStateException("AES context not available.");
        }

        try {
            AES._setkey_enc(this.context, key.getData(), key.length * 8);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}


/**
 * Extern for native AES context handles wrapped by Neko/C++ value.
 */
private extern class AESContext {}
