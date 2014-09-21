package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL Base64 implementation.
 */
class Base64
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _decode:BytesData->Int->BytesData = Loader.load("hx_base64_decode", 2);
    private static var _encode:BytesData->Int->BytesData = Loader.load("hx_base64_encode", 2);
    private static var _self_test:Bool->Int               = Loader.load("hx_base64_self_test", 1);


    /**
     * Returns Bytes encoded within the Base64 Bytes.
     *
     * @param haxe.io.Bytes bytes the encoded Bytes
     *
     * @return haxe.io.Bytes the decoded Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public static function decode(bytes:Bytes):Bytes
    {
        try {
            return Bytes.ofData(Base64._decode(bytes.getData(), bytes.length));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Returns the Base64 encoding of the input bytes.
     *
     * Attn: To get the encoded bytes as a String, use toHex() on the returned Bytes.
     *
     * @param haxe.io.Bytes bytes the Bytes to get the encoding for
     *
     * @return haxe.io.Bytes the encoded Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call throws an error
     */
    public static function encode(bytes:Bytes):Bytes
    {
        try {
            return Bytes.ofData(Base64._encode(bytes.getData(), bytes.length));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the Base64 module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = Base64._self_test(verbose);
        } catch (ex:Dynamic) {
            #if POLARSSL_DEBUG
                throw new PolarSSLException(ex);
            #else
                ret = 1;
            #end
        }

        return ret == 0;
    }
}
