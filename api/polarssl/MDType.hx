package polarssl;

/**
 *
 */
@:enum
abstract MDType(Int) from Int to Int
{
    var NONE      = 0;
    var MD2       = 1;
    var MD4       = 2;
    var MD5       = 3;
    var SHA1      = 4;
    var SHA224    = 5;
    var SHA256    = 6;
    var SHA384    = 7;
    var SHA512    = 8;
    var RIPEMD160 = 9;
}
