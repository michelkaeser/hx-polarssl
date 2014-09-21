package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import polarssl.Loader;
import polarssl.PolarSSLException;
import std.io.Path;

/**
 * Haxe FFI wrapper class for the PolarSSL SHA-512 implementation.
 */
class SHA512
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _self_test:Bool->Int                = Loader.load("hx_sha512_self_test", 1);
    private static var _sum:BytesData->Int->Int->BytesData = Loader.load("hx_sha512", 3);
    private static var _sum_file:Path->Int->BytesData      = Loader.load("hx_sha512_file", 2);


    /**
     * Runs various health checks to ensure the SHA-512 module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = SHA512._self_test(verbose);
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
     * Returns the SHA-512 sum of the input bytes.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param haxe.io.Bytes bytes the Bytes to get the sum of
     * @param Bool          is384 either 384 bit SHA should be used or not
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sum(bytes:Bytes, is384:Bool = false):Bytes
    {
        var sum:Bytes;
        try {
            sum = Bytes.ofData(SHA512._sum(bytes.getData(), bytes.length, (is384) ? 1 : 0));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }

        if (is384) {
            sum = sum.sub(0, 48 /* 384 / 8 */);
        }

        return sum;
    }

    /**
     * Returns the SHA-512 sum of the file specified by 'path'.
     *
     * Attn: To get the sum as a String, use toHex() on the returned Bytes.
     *
     * @param std.io.Path path  the file's path
     * @param Bool        is384 either 384 bit SHA should be used or not
     *
     * @return haxe.io.Bytes the sum Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     */
    public static function sumOfFile(path:Path, is384:Bool = false):Bytes
    {
        var sum:Bytes;
        try {
            sum = Bytes.ofData(SHA512._sum_file(path, (is384) ? 1 : 0));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }

        if (is384) {
            sum = sum.sub(0, 48 /* 384 / 8 */);
        }

        return sum;
    }
}
