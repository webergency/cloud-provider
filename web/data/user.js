!window.WebergencyCloud && ( window.WebergencyCloud = {});

( window.WebergencyCloud.User = ( function()
{
    //https://tools.ietf.org/id/draft-erdtman-jose-cleartext-jwe-00.html
    //https://mkjwk.org

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

    function random_bytes( bytes )
    {
        return window.crypto.getRandomValues( new Uint8Array( bytes ))
    }

    function base64( data )
    {
        if( typeof data === 'string' ){ data = encode( data )}
        if( data.constructor === ArrayBuffer ){ data = new Uint8Array( data )}

        return btoa( stringify( data ));
    }

    function base64decode( data )
    {
        return  Uint8Array.from( atob( data), c => c.charCodeAt( 0 ));
    }

    async function generate_key( encryption_key )
    {
        let key = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [ 'deriveKey', 'deriveBits' ]);

        let jwk =
        {
            'public'    : await window.crypto.subtle.exportKey( 'jwk', key.publicKey ),
            'private'   : await window.crypto.subtle.exportKey( 'jwk', key.privateKey )
        }

        let iv = random_bytes( 16 );

        jwk.encrypted = 
        {
            enc         : 'A256CBC',
            alg         : 'dir',
            //kid       :   "a256bitkey",
            iv          : base64( iv ),
            ciphertext  : base64( await window.crypto.subtle.encrypt
            (
                { name: 'AES-CBC', iv },
                await window.crypto.subtle.importKey( 'raw', encryption_key, { name: 'AES-CBC', length: 256, iv }, false, [ 'encrypt' ]),
                encode( JSON.stringify( jwk.private ))
            ))
        };
        
        return jwk;
    }

    async function decrypt_key( encrypted_key, encryption_key )
    {
        return JSON.parse( decode( await  window.crypto.subtle.decrypt
        (
            { name: 'AES-CBC', iv },
            await window.crypto.subtle.importKey( 'raw', key, { name: 'AES-CBC', length: 256, iv }, false, [ 'decrypt' ]),
            encrypted
        )));
    }

    async function POST( url, data )
    {
        const response = await fetch( url, 
        {
            method  : 'POST',
            headers : { 'Content-Type': 'application/json' },
            body    : JSON.stringify( data )
        });

        return response.json();
    }

    class User
    {
        static async login( data )
        {
            const pass = new WebergencyCloud.Password( data.password, data.email );
            const login = await POST( '/user/login', { email: data.email, password: base64( await pass.hash() )});
            
            if( login )
            {
                let iv = base64decode( login.keys.private.iv );
                let jwk = 
                { 
                    'private' : JSON.parse( decode( await window.crypto.subtle.decrypt
                    (
                        { name: 'AES-CBC', iv },
                        await window.crypto.subtle.importKey( 'raw', await pass.key(), { name: 'AES-CBC', length: 256, iv }, false, [ 'decrypt' ]),
                        base64decode( login.keys.private.ciphertext )
                    )))
                };

                console.log( jwk );
            }
            
            console.log( 'Login', login );
        }

        static async register( data )
        {
            const pass = new WebergencyCloud.Password( data.password, data.email );
            const [ hash, key ] = await Promise.all([ pass.hash(), pass.key() ]);
            const jwk = await generate_key( key );

            const register = await POST( '/user/register', { ...data, password: base64( hash ), keys: { public: jwk.public, private: jwk.encrypted }});

            console.log( 'Register', register );
        }
    }

    let enc = base64( 'abc' );
    let dec = base64decode( enc );

    console.log({ enc, dec, text: decode( dec )});

    return User;
})());