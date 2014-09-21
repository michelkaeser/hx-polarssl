package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import lib.IllegalArgumentException;
import lib.IllegalStateException;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL HAVEGE implementation.
 */
class HAVEGE
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _free:HS->Void             = Loader.load("hx_havege_free", 1);
    private static var _init:Void->HS             = Loader.load("hx_havege_init", 0);
    private static var _random:HS->Int->BytesData = Loader.load("hx_havege_random", 2);

    /**
     * Stores the wrapped HAVEGE state.
     *
     * @var Null<polarssl.HAVEGE.HS>
     */
    private var state:Null<HS>;


    /**
     * Constructor to initialize a new HAVEGE instance.
     *
     * @throws polarssl.PolarSSLException if the HAVEGE state init fails
     */
    public function new():Void
    {
        try {
            this.state = HAVEGE._init();
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Frees the HAVEGE state by removing all memory allocated for it.
     *
     * Attn: The HAVEGE instance can no longer be used afterwards.
     *
     * @throws lib.IllegalStateException  if the instance has already been freed
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public function free():Void
    {
        if (this.state == null) {
            throw new IllegalStateException("No HAVEGE state available");
        }

        try {
            HAVEGE._free(this.state);
            this.state = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Generates 'nbytes' of random bytes.
     *
     * @param Int nbytes the number of randoms to generate
     *
     * @return haxe.io.Bytes the random Bytes
     *
     * @throws lib.IllegalArgumentException if the number of random Bytes to generate is less than zero
     * @throws lib.IllegalStateException    if the instance has already been freed
     * @throws polarssl.PolarSSLException   if the FFI call throws an error
     */
    public function random(nbytes:Int):Bytes
    {
        if (nbytes < 0) {
            throw new IllegalArgumentException("Number of bytes cannot be less than zero");
        }
        if (this.state == null) {
            throw new IllegalStateException("No HAVEGE state available");
        }

        var bytes:Bytes;
        if (nbytes == 0) {
            bytes = Bytes.alloc(0);
        } else {
            try {
                bytes = Bytes.ofData(HAVEGE._random(this.state, nbytes));
            } catch (ex:Dynamic) {
                throw new PolarSSLException(ex);
            }
        }

        return bytes;
    }
}


/**
 * Extern for native HAVEGE state handles wrapped by Neko/C++ value.
 */
private extern class HS {}
