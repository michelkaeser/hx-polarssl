package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import lib.IllegalArgumentException;
import lib.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL XTEA implementation.
 */
class XTEA
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _crypt_cbc:XTEAContext->Int->Int->BytesData->BytesData->BytesData = Loader.load("hx_xtea_crypt_cbc", 5);
    private static var _crypt_ecb:XTEAContext->Int->BytesData->BytesData = Loader.load("hx_xtea_crypt_ecb", 3);
    private static var _free:XTEAContext->Void             = Loader.load("hx_xtea_free", 1);
    private static var _init:Void->XTEAContext             = Loader.load("hx_xtea_init", 0);
    private static var _self_test:Bool->Int                = Loader.load("hx_xtea_self_test", 1);
    private static var _setup:XTEAContext->BytesData->Void = Loader.load("hx_xtea_setup", 2);

    /**
     * Possible XTEA mode values.
     */
    public static inline var DECRYPT:Int = 0;
    public static inline var ENCRYPT:Int = 1;

    /**
     * Stores the native XTEA context handle.
     *
     * @var Null<polarssl.XTEA.XTEAContext>
     */
    private var context:Null<XTEAContext>;


    /**
     * Constructor to initialize a new XTEA instance.
     *
     * @throws polarssl.PolarSSLException if the XTEA context init fails
     */
    public function new():Void
    {
        try {
            this.context = XTEA._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  XTEA.DECRYPT or XTEA.ENCRYPT
     * @param haxe.io.Bytes iv    the initialization vector
     * @param haxe.io.Bytes bytes the input bytes (must be % 8 == 0 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws lib.IllegalArgumentException if the mode is not supported
     * @throws lib.IllegalArgumentException if the initialization vector is not 8 bytes long
     * @throws lib.IllegalArgumentException if the input bytes length is not % 8 == 0
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function cryptCbc(mode:Int, iv:Bytes, bytes:Bytes):Bytes
    {
        if (mode != XTEA.DECRYPT && mode != XTEA.ENCRYPT) {
            throw new IllegalArgumentException("Provided XTEA mode is not supported");
        }
        if (iv == null || iv.length != 8) {
            throw new IllegalArgumentException("Initialization vector must be 8 bytes");
        }
        if (bytes == null || (bytes.length % 8) != 0) {
            throw new IllegalArgumentException("Input bytes' length must be a multiple of 8");
        }
        if (this.context == null) {
            throw new IllegalStateException("No XTEA context available");
        }

        // create a copy since it will be updated
        var copy:Bytes = Bytes.alloc(iv.length);
        copy.blit(0, iv, 0, iv.length);

        try {
            return Bytes.ofData(XTEA._crypt_cbc(this.context, mode, bytes.length, copy.getData(), bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  XTEA.DECRYPT or XTEA.ENCRYPT
     * @param haxe.io.Bytes bytes the input bytes (must be 8 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws lib.IllegalArgumentException if the mode is not supported
     * @throws lib.IllegalArgumentException if the input bytes length is not 8
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function cryptEcb(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != XTEA.DECRYPT && mode != XTEA.ENCRYPT) {
            throw new IllegalArgumentException("Provided XTEA mode is not supported");
        }
        if (bytes == null || bytes.length != 8) {
            throw new IllegalArgumentException("ECB block cipher mode requires 8 input bytes");
        }
        if (this.context == null) {
            throw new IllegalStateException("No XTEA context available");
        }

        try {
            return Bytes.ofData(XTEA._crypt_ecb(this.context, mode, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees all memory allocated for this XTEA instance.
     *
     * Attn: The XTEA instance can no longer be used after calling this method.
     *
     * @throws lib.IllegalStateException  if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No XTEA context available");
        }

        try {
            XTEA._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the XTEA module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = XTEA._self_test(verbose);
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
     * Setup the instance so it can be used for de-/encryption.
     *
     * @param haxe.io.Bytes key the secret key Bytes (length must be 16)
     *
     * @throws lib.IllegalArgumentException if the key is not 16 bytes long
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     */
    public function setup(key:Bytes):Void
    {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("XTEA keys must be 16 bytes in length");
        }
        if (this.context == null) {
            throw new IllegalStateException("No XTEA context available");
        }

        try {
            XTEA._setup(this.context, key.getData());
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}


/**
 * Extern for native XTEA context handles wrapped by Neko/C++ value.
 */
private extern class XTEAContext {}
