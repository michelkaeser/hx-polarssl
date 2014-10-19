package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import hext.io.Path;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL MD2 implementation.
 */
class MD2
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _self_test:Bool->Int           = Loader.load("hx_md2_self_test", 1);
    private static var _sum:BytesData->Int->BytesData = Loader.load("hx_md2", 2);
    private static var _sum_file:Path->BytesData      = Loader.load("hx_md2_file", 1);


    /**
     * Runs various health checks to ensure the MD2 module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = MD2._self_test(verbose);
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
     * Returns the MD2 sum of the input bytes.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param haxe.io.Bytes bytes the Bytes to get the sum for
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sum(bytes:Bytes):Bytes
    {
        try {
            return Bytes.ofData(MD2._sum(bytes.getData(), bytes.length));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Returns the MD2 sum of the file specified by 'path'.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param hext.io.Path path the file's path
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sumOfFile(path:Path):Bytes
    {
        try {
            return Bytes.ofData(MD2._sum_file(path));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }
}
