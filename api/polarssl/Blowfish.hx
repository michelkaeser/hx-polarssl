package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import hext.IllegalArgumentException;
import hext.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL Blowfish implementation.
 */
class Blowfish
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _crypt_cbc:BlowfishContext->Int->Int->BytesData->BytesData->BytesData = Loader.load("hx_blowfish_crypt_cbc", 5);
    private static var _crypt_ecb:BlowfishContext->Int->BytesData->BytesData = Loader.load("hx_blowfish_crypt_ecb", 3);
    private static var _free:BlowfishContext->Void                   = Loader.load("hx_blowfish_free", 1);
    private static var _init:Void->BlowfishContext                   = Loader.load("hx_blowfish_init", 0);
    private static var _setkey:BlowfishContext->BytesData->Int->Void = Loader.load("hx_blowfish_setkey", 3);

    /**
     * Possible Blowfish mode values.
     */
    public static inline var DECRYPT:Int = 0;
    public static inline var ENCRYPT:Int = 1;

    /**
     * Stores the native Blowfish context handle.
     *
     * @var Null<polarssl.Blowfish.BlowfishContext>
     */
    private var context:Null<BlowfishContext>;


    /**
     * Constructor to initialize a new Blowfish instance.
     *
     * @throws polarssl.PolarSSLException if the Blowfish context init fails
     */
    public function new():Void
    {
        try {
            this.context = Blowfish._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  Blowfish.DECRYPT or Blowfish.ENCRYPT
     * @param haxe.io.Bytes iv    the initialization vector
     * @param haxe.io.Bytes bytes the input bytes (must be % 8 == 0 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws hext.IllegalArgumentException if the mode is not supported
     * @throws hext.IllegalArgumentException if the initialization vector is not 8 bytes long
     * @throws hext.IllegalArgumentException if the input bytes length is not % 8 == 0
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function cryptCbc(mode:Int, iv:Bytes, bytes:Bytes):Bytes
    {
        if (mode != Blowfish.DECRYPT && mode != Blowfish.ENCRYPT) {
            throw new IllegalArgumentException("Provided Blowfish mode is not supported.");
        }
        if (iv == null || iv.length != 8) {
            throw new IllegalArgumentException("Initialization vector must be 8 bytes.");
        }
        if (bytes == null || (bytes.length % 8) != 0) {
            throw new IllegalArgumentException("Input bytes' length must be a multiple of 8.");
        }
        if (this.context == null) {
            throw new IllegalStateException("No Blowfish context available.");
        }

        // create a copy since it will be updated
        var copy:Bytes = Bytes.alloc(iv.length);
        copy.blit(0, iv, 0, iv.length);

        try {
            return Bytes.ofData(Blowfish._crypt_cbc(this.context, mode, bytes.length, copy.getData(), bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Puts the input bytes through the cipher function and returns the resulting ones.
     *
     * @param Int           mode  Blowfish.DECRYPT or Blowfish.ENCRYPT
     * @param haxe.io.Bytes bytes the input bytes (must be 8 in length)
     *
     * @return haxe.io.Bytes the crypted Bytes
     *
     * @throws hext.IllegalArgumentException if the mode is not supported
     * @throws hext.IllegalArgumentException if the input bytes length is not 8
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function cryptEcb(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != Blowfish.DECRYPT && mode != Blowfish.ENCRYPT) {
            throw new IllegalArgumentException("Provided Blowfish mode is not supported.");
        }
        if (bytes == null || bytes.length != 8) {
            throw new IllegalArgumentException("ECB block cipher mode requires 8 input bytes.");
        }
        if (this.context == null) {
            throw new IllegalStateException("No Blowfish context available.");
        }

        try {
            return Bytes.ofData(Blowfish._crypt_ecb(this.context, mode, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees all memory allocated for this Blowfish instance.
     *
     * Attn: The Blowfish instance can no longer be used after calling this method.
     *
     * @throws hext.IllegalStateException if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No Blowfish context available.");
        }

        try {
            Blowfish._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Sets the instances secret key.
     *
     * @param haxe.io.Bytes key the secret key
     *
     * @throws hext.IllegalArgumentException if the key is not valid (no less/much bits)
     * @throws hext.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException    if the FFI call raises an error
     */
    public function setKey(key:Bytes):Void
    {
        if (key == null || key.length < 4 /* 32 bit */ || key.length > 56 /* 448 bit */) {
            throw new IllegalArgumentException("Bytes are not a valid Blowfish key.");
        }
        if (this.context == null) {
            throw new IllegalStateException("No Blowfish context available.");
        }

        try {
            Blowfish._setkey(this.context, key.getData(), key.length * 8);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}


/**
 * Extern for native Blowfish context handles wrapped by Neko/C++ value.
 */
private extern class BlowfishContext {}
