package polarssl;

import haxe.io.Bytes;
import haxe.io.BytesData;
import polarssl.MDType;
import polarssl.PKCS;
import polarssl.Loader;
import polarssl.PolarSSLException;
import std.IllegalArgumentException;
import std.IllegalStateException;

/**
 * Haxe FFI wrapper class for the PolarSSL RSA implementation.
 */
class RSA
{
    /**
     * Stores the references to the FFI implementations of the functions.
     */
    private static var _check_pubkey:RSAContext->Int      = Loader.load("hx_rsa_check_pubkey", 1);
    private static var _check_privkey:RSAContext->Int     = Loader.load("hx_rsa_check_privkey", 1);
    // private static var _copy:RSAContext->RSAContext->Int = Loader.load("hx_rsa_copy", 2);
    // private static var _export_pubkey:RSAContext->String = Loader.load("hx_rsa_export_pubkey", 1);
    private static var _free:RSAContext->Void             = Loader.load("hx_rsa_free", 1);
    private static var _gen_key:RSAContext->Int->Int->Int = Loader.load("hx_rsa_gen_key", 3);
    private static var _getD:RSAContext->BytesData        = Loader.load("hx_rsa_get_D", 1);
    private static var _getE:RSAContext->BytesData        = Loader.load("hx_rsa_get_E", 1);
    private static var _getN:RSAContext->BytesData        = Loader.load("hx_rsa_get_N", 1);
    private static var _getP:RSAContext->BytesData        = Loader.load("hx_rsa_get_P", 1);
    private static var _getQ:RSAContext->BytesData        = Loader.load("hx_rsa_get_Q", 1);
    private static var _init:PKCS->Int->RSAContext        = Loader.load("hx_rsa_init", 2);
    private static var _pkcs1_decrypt:RSAContext->Int->BytesData->BytesData = Loader.load("hx_rsa_pkcs1_decrypt", 3);
    private static var _pkcs1_encrypt:RSAContext->Int->BytesData->Int->BytesData = Loader.load("hx_rsa_pkcs1_encrypt", 4);
    private static var _pkcs1_sign:RSAContext->Int->MDType->Int->BytesData->BytesData = Loader.load("hx_rsa_pkcs1_sign", 5);
    private static var _pkcs1_verify:RSAContext->Int->MDType->Array<Dynamic>->BytesData->Int = Loader.load("hx_rsa_pkcs1_verify", 5);
    private static var _self_test:Bool->Int                     = Loader.load("hx_rsa_self_test", 1);
    private static var _set_padding:RSAContext->PKCS->Int->Void = Loader.load("hx_rsa_set_padding", 3);

    /**
     * Possible RSA mode values.
     */
    public static inline var PUBLIC:Int  = 0;
    public static inline var PRIVATE:Int = 1;

    /**
     * Stores the native RSA context handle.
     *
     * @var Null<polarssl.RSA.RSAContext>
     */
    private var context:Null<RSAContext>;

    /**
     * Property to access the private exponent.
     *
     * Attn:
     *   - Use .toHex() to get a human-readable format.
     *   - Use Std.parseInt("0x" + .toHex()) to get the property as an Int
     *     This may lead to wrong numbers however (overflow, sign bit, etc.)
     *
     * @var Bytes
     */
    public var D(get, never):Bytes;

    /**
     * Property to access the public exponent.
     *
     * @see polarss.RSA.D
     *
     * @var Bytes
     */
    public var E(get, never):Bytes;

    /**
     * Property to access the public modulus.
     *
     * @see polarss.RSA.D
     *
     * @var Bytes
     */
    public var N(get, never):Bytes;

    /**
     * Property to access the 1st prime factor.
     *
     * @see polarss.RSA.D
     *
     * @var Bytes
     */
    public var P(get, never):Bytes;

    /**
     * Property to access the 2nd prime factor.
     *
     * @see polarss.RSA.D
     *
     * @var Bytes
     */
    public var Q(get, never):Bytes;


    /**
     * Constructor to initialize a new RSA instance.
     *
     * @param polarssl.PKCS padding the padding scheme to use
     * @param Null<Int>     hashId  the hash identifier
     *
     * @throws polarssl.PolarSSLException   if the RSA context init fails
     * @throws std.IllegalArgumentException if PKCS.V21 is used but no hashId is provided
     */
    public function new(padding:PKCS, ?hashId:Int):Void
    {
        if (padding == PKCS.V21 && hashId == null) {
            throw new IllegalArgumentException("The selected padding scheme needs a hashId");
        }

        if (hashId == null) {
            hashId = 0;
        }

        try {
            this.context = RSA._init(padding, hashId);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Checks if the public key is valid.
     *
     * @return Bool
     *
     * @throws std.IllegalStateException if the instance has already been freed
     */
    public function checkPublicKey():Bool
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        var ret:Int;
        try {
            ret = RSA._check_pubkey(this.context);
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
     * Checks if the private key is valid.
     *
     * @return Bool
     *
     * @throws std.IllegalStateException if the instance has already been freed
     */
    public function checkPrivateKey():Bool
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        var ret:Int;
        try {
            ret = RSA._check_privkey(this.context);
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
     * Decrypts the encrypted Bytes 'bytes' using the RSAMode 'mode'.
     *
     * @param Int           mode  RSA.PUBLIC or RSA.PRIVATE
     * @param haxe.io.Bytes bytes the encrypted Bytes
     *
     * @return haxe.io.Bytes the decrypted Bytes
     *
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     * @throws std.IllegalArgumentException if the RSA mode is not PUBLIC or PRIVATE
     * @throws std.IllegalStateException    if the instance has already been freed
     */
    public function decrypt(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != RSA.PUBLIC && mode != RSA.PRIVATE) {
            throw new IllegalArgumentException("Invalid RSA mode selected");
        }
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._pkcs1_decrypt(this.context, mode, bytes.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Encrypts the plain Bytes 'bytes' using the RSAMode 'mode'.
     *
     * @param Int           mode  RSA.PUBLIC or RSA.PRIVATE
     * @param haxe.io.Bytes bytes the Bytes to encrypt
     *
     * @return haxe.io.Bytes the encrypted Bytes
     *
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     * @throws std.IllegalArgumentException if the RSA mode is not PUBLIC or PRIVATE
     * @throws std.IllegalStateException    if the instance has already been freed
     */
    public function encrypt(mode:Int, bytes:Bytes):Bytes
    {
        if (mode != RSA.PUBLIC && mode != RSA.PRIVATE) {
            throw new IllegalArgumentException("Invalid RSA mode selected");
        }
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._pkcs1_encrypt(this.context, mode, bytes.getData(), bytes.length));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Returns the public key which is exported as a String.
     *
     * @return String
     */
    // public function exportPublicKey():String
    // {
    //     if (this.context == null) {
    //         throw new IllegalStateException("RSA context not available");
    //     }

    //     try {
    //         return RSA._export_pubkey(this.context);
    //     } catch (ex:Dynamic) {
    //         throw new PolarSSLException(ex);
    //     }
    // }

    /**
     * Frees all memory allocated for this RSA instance.
     *
     * Attn: The RSA instance can no longer be used after calling this method.
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    public function free():Void
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            RSA._free(this.context);
            this.context = null;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Generates a new RSA keypair and associates it to the current instance.
     *
     * @param Int nbits the size in bits of the key
     * @param Int exponent the public exponent to use
     *
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     * @throws std.IllegalArgumentException if the keysize is less or equal to zero
     * @throws std.IllegalArgumentException if the public exponent is negative
     * @throws std.IllegalStateException    if the instance has already been freed
     */
    public function generateKeys(nbits:Int, exponent:Int):Void
    {
        if (nbits <= 0) {
            throw new IllegalArgumentException("Keysize cannot be <= 0");
        }
        if (exponent < 0) {
            throw new IllegalArgumentException("Exponent cannot be negative");
        }
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            RSA._gen_key(this.context, nbits, exponent) /* == 0? */;
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Internal getter method for the 'D' property.
     *
     * @return haxe.io.Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    private function get_D():Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._getD(this.context));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Internal getter method for the 'E' property.
     *
     * @return haxe.io.Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    private function get_E():Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._getE(this.context));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Internal getter method for the 'N' property.
     *
     * @return haxe.io.Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    private function get_N():Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._getN(this.context));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Internal getter method for the 'P' property.
     *
     * @return haxe.io.Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    private function get_P():Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._getP(this.context));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Internal getter method for the 'Q' property.
     *
     * @return haxe.io.Bytes
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    private function get_Q():Bytes
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            return Bytes.ofData(RSA._getQ(this.context));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Calculates and returns the RSA keys signature.
     *
     * @param Int                 mode RSA.PUBLIC or RSA.PRIVATE
     * @param polarssl.MDType     type the MD type/algorithm to use
     * @param Null<haxe.io.Bytes> hash the hash to "include" within the signature
     *
     * @return haxe.io.Bytes the signature Bytes
     *
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     * @throws std.IllegalArgumentException if the mode is not RSA.PUBLIC or RSA.PRIVATE
     * @throws std.IllegalArgumentException if MDType.NONE is used with no hash identifier
     * @throws std.IllegalStateException    if the instance has already been freed
     */
    public function sign(mode:Int, type:MDType, ?hash:Bytes):Bytes
    {
        if (mode != RSA.PUBLIC && mode != RSA.PRIVATE) {
            throw new IllegalArgumentException("Invalid RSA mode selected");
        }
        if (type == MDType.NONE && hash == null) {
            throw new IllegalArgumentException("MDType.NONE requires a unique hash identifier");
        }
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        if (hash == null) {
            hash = Bytes.alloc(0);
        }

        try {
            return Bytes.ofData(RSA._pkcs1_sign(this.context, mode, type, hash.length, hash.getData()));
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Runs various health checks to ensure the RSA module works correctly.
     *
     * @param Bool verbose either to output debug information or not
     *
     * @return Bool
     */
    public static function selfTest(verbose:Bool = #if POLARSSL_DEBUG true #else false #end):Bool
    {
        var ret:Int;
        try {
            ret = RSA._self_test(verbose);
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
     * Sets padding for the initialized RSA context.
     *
     * @param polarssl.PKCS padding the padding scheme to use
     * @param Int           hashId  the hash identifier
     *
     * @throws polarssl.PolarSSLException if the FFI call raises an error
     * @throws std.IllegalStateException  if the instance has already been freed
     */
    public function setPadding(padding:PKCS, hashId:Int):Void
    {
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        try {
            RSA._set_padding(this.context, padding, hashId);
        } catch (ex:Dynamic) {
            throw new PolarSSLException(ex);
        }
    }

    /**
     * Verifies the signature is valid.
     *
     * @param Int                 mode      RSA.PUBLIC or RSA.PRIVATE
     * @param polarssl.MDType     type      the MD type/algorithm to use
     * @param haxe.io.Bytes       signature the signature to verify
     * @param Null<haxe.io.Bytes> hash      the hash that was used to sign the signature
     *
     * @return Bool true if signature is valid
     *
     * @throws polarssl.PolarSSLException   if the FFI call raises an error
     * @throws std.IllegalArgumentException if mode is neither RSA.PUBLIC nor RSA.PRIVATE
     * @throws std.IllegalArgumentException if type is MDType.NONE but the hash is null
     * @throws std.IllegalStateException    if the instance has already been freed
     */
    public function verify(mode:Int, type:MDType, signature:Bytes, ?hash:Bytes):Bool
    {
        if (mode != RSA.PUBLIC && mode != RSA.PRIVATE) {
            throw new IllegalArgumentException("Invalid RSA mode selected");
        }
        if (type == MDType.NONE && hash == null) {
            throw new IllegalArgumentException("MDType.NONE requires a hash identifier");
        }
        if (this.context == null) {
            throw new IllegalStateException("RSA context not available");
        }

        if (hash == null) {
            hash = Bytes.alloc(0);
        }

        var hashArr:Array<Dynamic> = new Array<Dynamic>();
        hashArr[0] = hash.length;
        hashArr[1] = hash.getData();

        var ret:Int;
        try {
            ret = RSA._pkcs1_verify(this.context, mode, type, hashArr, signature.getData());
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


/**
 * Extern for native RSA context handles wrapped by Neko/C++ value.
 */
private extern class RSAContext {}
