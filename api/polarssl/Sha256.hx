package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import hext.io.Path;
import polarssl.Loader;
import polarssl.PolarSSLException;

/**
 * Haxe FFI wrapper class for the PolarSSL SHA-256 implementation.
 */
class SHA256
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _self_test:Bool->Int                = Loader.load("hx_sha256_self_test", 1);
    private static var _sum:BytesData->Int->Int->BytesData = Loader.load("hx_sha256", 3);
    private static var _sum_file:Path->Int->BytesData      = Loader.load("hx_sha256_file", 2);


    /**
     * Runs various health checks to ensure the SHA-256 module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = SHA256._self_test(verbose);
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
     * Returns the SHA-256 sum of the input bytes.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param haxe.io.Bytes bytes the Bytes to get the sum for
     * @param Bool          is224 either 224 bit SHA should be used or not
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sum(bytes:Bytes, is224:Bool = false):Bytes
    {
        var sum:Bytes;
        try {
            sum = Bytes.ofData(SHA256._sum(bytes.getData(), bytes.length, (is224) ? 1 : 0));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }

        if (is224) {
            sum = sum.sub(0, 28 /* 224 / 8 */);
        }

        return sum;
    }

    /**
     * Returns the SHA-256 sum of the file specified by 'path'.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param hext.io.Path path  the file's path
     * @param Bool        is224 either 224 bit SHA should be used or not
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sumOfFile(path:Path, is224:Bool = false):Bytes
    {
        var sum:Bytes;
        try {
            sum = Bytes.ofData(SHA256._sum_file(path, (is224) ? 1 : 0));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }

        if (is224) {
            sum = sum.sub(0, 28 /* 224 / 8 */);
        }

        return sum;
    }
}
