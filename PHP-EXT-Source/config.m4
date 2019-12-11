PHP_ARG_ENABLE(sspphp,
        [Whether to enable the "sspphp" extension],
        [-enable-sspphp  Enable "sspphp" extension support])
if test $PHP_SSPPHP != "no"; then
        PHP_SUBST(SSPPHP_SHARED_LIBADD)
        PHP_NEW_EXTENSION(sspphp, sspphp.c, $ext_shared)
fi