( function()
{
    function encode( str )
    {
        return new TextEncoder().encode( str.normalize( 'NFKC' ));
    }

    function decode( arr )
    {
        return new TextDecoder('utf-8').decode( arr );
    }

    function stringify( arr )
    {
        return String.fromCharCode.apply( null, arr );
    }

    function base64( data )
    {
        if( typeof data === 'string' ){ data = encode( data )}
        if( data.constructor === ArrayBuffer ){ data = new Uint8Array( data )}

        return btoa( stringify( data ));
    }

    function random_bytes( bytes )
    {
        return window.crypto.getRandomValues( new Uint8Array( bytes ))
    }

    function R( a, b )
    {
        return ( a << b ) | ( a >>> ( 32 - b ));
    }

    function arraycopy(src, srcPos, dest, destPos, length)
    {
        while( length-- ){ dest[destPos++] = src[srcPos++] }
    }

    function blockxor( S, Si, D, len )
    {
        for( let i = 0; i < len; ++i ){ D[i] ^= S[Si + i] }
    }

    function blockmix_salsa8( BY, Yi, r, x, _X )
    {
        arraycopy( BY, ( 2 * r - 1 ) * 16, _X, 0, 16 );

        for( let i = 0; i < 2 * r; ++i )
        {
            blockxor( BY, i * 16, _X, 16 );
            salsa20_8( _X, x );
            arraycopy( _X, 0, BY, Yi + ( i * 16 ), 16 );
        }

        for( let i = 0; i < r; ++i ){ arraycopy( BY, Yi + ( i * 2 ) * 16, BY, ( i * 16 ), 16 )}
        for( let i = 0; i < r; ++i ){ arraycopy( BY, Yi + ( i * 2 + 1 ) * 16, BY, ( i + r ) * 16, 16 )}
    }

    async function digest( algorithm, data )
    {
        return window.crypto.subtle.digest( algorithm, typeof data === 'string' ? encode( data ) : data );
    }

    async function get_key_material( algorithm, key, operations = [ 'deriveKey', 'deriveBits' ])
    {
        return  window.crypto.subtle.importKey( 'raw', key, { name: algorithm }, false, operations );
    }

    async function sha256( key )
    {
        return window.crypto.subtle.digest( 'SHA-256', new Uint8Array( key )).then( h => [ ...new Uint8Array( h )]);
    }

    async function pbkdf2_hmac_oneiter( key, salt, bytes )
    {
        key = ( key.length <= 64 ) ? key : await sha256( key );

        const innerLen = 64 + salt.length + 4, inner = new Array( innerLen ), outerKey = new Array(64);

        let i, dk = [];

        for( i = 0; i < 64; ++i ){ inner[i] = 0x36 }
        for( i = 0; i < key.length; ++i ){ inner[i] ^= key[i] }
        for( i = 0; i < salt.length; ++i ){ inner[64 + i] = salt[i] }
        for( i = innerLen - 4; i < innerLen; ++i ) { inner[i] = 0 }
        for( i = 0; i < 64; ++i ){ outerKey[i] = 0x5c }
        for( i = 0; i < key.length; ++i ){ outerKey[i] ^= key[i] }

        function incrementCounter()
        {
            for( let i = innerLen - 1; i >= innerLen - 4; --i )
            {
                if( ++inner[i] <= 0xff ){ return }
                inner[i] = 0;
            }
        }

        while( bytes >= 32 )
        {
            incrementCounter();
            dk = dk.concat( await sha256( outerKey.concat( await sha256( inner ))));
            bytes -= 32;
        }

        if( bytes > 0 )
        {
            incrementCounter();
            dk = dk.concat( await sha256( outerKey.concat( await sha256( inner ))).slice( 0, bytes ));
        }

        return dk;
    }

    async function pbkdf2_hmac( hash, key, salt, bytes, iterations = 1 )
    {
        if( key.constructor  !== Uint8Array ){ key  = new Uint8Array( key )}
        if( salt.constructor !== Uint8Array ){ salt = new Uint8Array( salt )}

        return window.crypto.subtle.deriveBits({ name: 'PBKDF2', salt, hash, iterations }, await get_key_material( 'PBKDF2', key ), bytes * 8 );
    }

    function salsa20_8( B, x )
    {
        arraycopy( B, 0, x, 0, 16 );

        for( let i = 8; i > 0; i -= 2 )
        {
            x[ 4] ^= R( x[ 0] + x[12],  7 ); x[ 8] ^= R( x[ 4] + x[ 0],  9 ); x[12] ^= R( x[ 8] + x[ 4], 13 ); x[ 0] ^= R( x[12] + x[ 8], 18 );
            x[ 9] ^= R( x[ 5] + x[ 1],  7 ); x[13] ^= R( x[ 9] + x[ 5],  9 ); x[ 1] ^= R( x[13] + x[ 9], 13 ); x[ 5] ^= R( x[ 1] + x[13], 18 );
            x[14] ^= R( x[10] + x[ 6],  7 ); x[ 2] ^= R( x[14] + x[10],  9 ); x[ 6] ^= R( x[ 2] + x[14], 13 ); x[10] ^= R( x[ 6] + x[ 2], 18 );
            x[ 3] ^= R( x[15] + x[11],  7 ); x[ 7] ^= R( x[ 3] + x[15],  9 ); x[11] ^= R( x[ 7] + x[ 3], 13 ); x[15] ^= R( x[11] + x[ 7], 18 );
            x[ 1] ^= R( x[ 0] + x[ 3],  7 ); x[ 2] ^= R( x[ 1] + x[ 0],  9 ); x[ 3] ^= R( x[ 2] + x[ 1], 13 ); x[ 0] ^= R( x[ 3] + x[ 2], 18 );
            x[ 6] ^= R( x[ 5] + x[ 4],  7 ); x[ 7] ^= R( x[ 6] + x[ 5],  9 ); x[ 4] ^= R( x[ 7] + x[ 6], 13 ); x[ 5] ^= R( x[ 4] + x[ 7], 18 );
            x[11] ^= R( x[10] + x[ 9],  7 ); x[ 8] ^= R( x[11] + x[10],  9 ); x[ 9] ^= R( x[ 8] + x[11], 13 ); x[10] ^= R( x[ 9] + x[ 8], 18 );
            x[12] ^= R( x[15] + x[14],  7 ); x[13] ^= R( x[12] + x[15],  9 ); x[14] ^= R( x[13] + x[12], 13 ); x[15] ^= R( x[14] + x[13], 18 );
        }

        for( let i = 0; i < 16; ++i ){ B[i] += x[i] }
    }

    async function scrypt( password, salt, N = 16384, r = 8, p = 1, dkLen = 32 )
    {
        if( typeof password === 'string' ){ password = await digest( 'SHA-256', password )}
        if( typeof salt     === 'string' ){ salt     = await digest( 'SHA-256', salt )}

        password = new Uint8Array( password );
        salt = new Uint8Array( salt );

        let b = new Uint8Array( await pbkdf2_hmac( 'SHA-256', password, salt, p * 128 * r ).catch( e => pbkdf2_hmac_oneiter( password, salt, p * 128 * r )));
        const B = new Uint32Array( p * 32 * r ), XY = new Uint32Array( 64 * r ), V = new Uint32Array( 32 * r * N ), Yi = 32 * r, x = new Uint32Array( 16 ), _X = new Uint32Array( 16 );

        for( let i = 0; i < B.length; ++i )
        {
            const j = i * 4;
            B[i] = (( b[j + 3] & 0xff ) << 24 ) | (( b[j + 2] & 0xff ) << 16 ) | (( b[j + 1] & 0xff ) << 8 ) | (( b[j + 0] & 0xff) << 0 );
        }

        arraycopy( B, 0, XY, 0, Yi );

        for( let i = 0; i < N; ++i )
        {
            arraycopy( XY, 0, V, i * Yi, Yi );
            blockmix_salsa8( XY, Yi, r, x, _X );
        }

        for( let i = 0; i < N; ++i )
        {
            const offset = ( 2 * r - 1 ) * 16, j = XY[offset] & ( N - 1 );
            blockxor( V, j * Yi, XY, Yi );
            blockmix_salsa8( XY, Yi, r, x, _X );
        }

        arraycopy( XY, 0, B, 0, Yi );

        b = [  ];
        for( let i = 0; i < B.length; ++i )
        {
            b.push(( B[i] >>  0 ) & 0xff );
            b.push(( B[i] >>  8 ) & 0xff );
            b.push(( B[i] >> 16 ) & 0xff );
            b.push(( B[i] >> 24 ) & 0xff );
        }

        return new Uint8Array( await pbkdf2_hmac( 'SHA-256', password, b, dkLen ).catch( e => pbkdf2_hmac_oneiter( password, b, dkLen )));
    }

    const Crypto = window.Crypto = class Crypto
    {
        static async derive_key( password, salt )
        {
            if( typeof password === 'string' ){ password = await digest( 'SHA-256', password )}
            if( typeof salt     === 'string' ){ salt     = await digest( 'SHA-256', salt )}

            return new Uint8Array( await pbkdf2_hmac( 'SHA-256', password, salt, 32, 100000 ));
        }

        static async derive_password( password, salt )
        {
            if( typeof password === 'string' ){ password = await digest( 'SHA-256', password )}
            if( typeof salt     === 'string' ){ salt     = await digest( 'SHA-256', salt )}

            return scrypt( password, salt );
        }

        static async generate_key()
        {
            let key = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [ 'deriveKey', 'deriveBits' ]);

            return (
            {
                'public'    : await window.crypto.subtle.exportKey( 'jwk', key.publicKey ),
                'private'   : await window.crypto.subtle.exportKey( 'jwk', key.privateKey )
            });
        }

        static base64( data )
        {
            return base64( data );
        }
    }
})();