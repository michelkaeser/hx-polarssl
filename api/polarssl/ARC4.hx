package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import hext.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL ARC4 implementation.
 */
class ARC4
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _crypt:ARC4Context->Int->BytesData->BytesData = Loader.load("hx_arc4_crypt", 3);
    private static var _free:ARC4Context->Void                       = Loader.load("hx_arc4_free", 1);
    private static var _init:Void->ARC4Context                       = Loader.load("hx_arc4_init", 0);
    private static var _self_test:Bool->Int                          = Loader.load("hx_arc4_self_test", 1);
    private static var _setup:ARC4Context->BytesData->Int->Void      = Loader.load("hx_arc4_setup", 3);

    /**
     * Stores the native ARC4 context handle.
     *
     * @var Null<polarssl.ARC4.ARC4Context>
     */
    private var context:Null<ARC4Context>;


    /**
     * Constructor to initialize a new ARC4 instance.
     *
     * @throws polarssl.PolarSSLException if the ARC4 context init fails
     */
    public function new():Void
    {
        try {
            this.context = ARC4._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs the input Bytes through the cipher function.
     *
     * @param haxe.io.Bytes bytes the Bytes to crypt
     *
     * @return haxe.io.Bytes the crypted input Bytes
     *
     * @throws hext.IllegalStateException if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function crypt(bytes:Bytes):Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("No ARC4 context available.");
        }

        try {
            return Bytes.ofData(ARC4._crypt(this.context, bytes.length, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees all memory allocated for this ARC4 instance.
     *
     * Attn: The ARC4 instance can no longer be used after calling this method.
     *
     * @throws hext.IllegalStateException if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No ARC4 context available.");
        }

        try {
            ARC4._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the ARC4 module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = ARC4._self_test(verbose);
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
     * Setup the instance's S-Boxes and other internals.
     *
     * @param haxe.io.Bytes key the secret key in Bytes
     *
     * @throws hext.IllegalStateException if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function setup(key:Bytes):Void
    {
        if (this.context == null) {
            throw new IllegalStateException("No ARC4 context available.");
        }

        try {
            ARC4._setup(this.context, key.getData(), key.length);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}


/**
 * Extern for native ARC4 context handles wrapped by Neko/C++ value.
 */
private extern class ARC4Context {}
