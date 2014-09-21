package polarssl;

/**
 *
 */
@:enum
abstract PKCS(Int) from Int to Int
{
    var V15 = 0;
    var V21 = 1;
}
