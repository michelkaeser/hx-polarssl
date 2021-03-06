package polarssl;

import haxe.PosInfos;
import hext.Exception;

/**
 * Exceptions to be thrown when Exceptions from the C FFI need to be wrapped
 * or for any other kind of errors related to PolarSSL.
 */
class PolarSSLException extends Exception
{
    /**
     * @{inherit}
     */
    public function new(msg:Dynamic = "Uncaught PolarSSL exception.", ?info:PosInfos):Void
    {
        super(msg, info);
    }
}
