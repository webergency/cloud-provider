'use strict';

const fs = require('fs');
const BCrypt = require('bcrypt');
const JWT = require('@liqd-js/jwt');

const USER_ID = [ 1, Number.MAX_SAFE_INTEGER ];
const BCRYPT_SALT_ROUNDS = 12;

const auth = new JWT({ ES384: { key: fs.readFileSync( __dirname + '/../../config/certificates/auth.key' ) }});

function RANDOM( min, max )
{
    return min + Math.floor( Math.random() * ( max - min + 1 ));
}

const HashPassword = ( password ) => new Promise(( resolve, reject ) =>
{
    BCrypt.hash( password, BCRYPT_SALT_ROUNDS, ( err, hash ) => err ? reject( err ) : resolve( hash ));
});

const VerifyPassword = ( password, hash ) => new Promise(( resolve, reject ) =>
{
    BCrypt.compare( password, hash, ( err, verified ) => err ? reject( err ) : resolve( verified ));
});

module.exports = class User
{
    #ctx;

    constructor( ctx )
    {
        this.#ctx = ctx;
    }

    async create( data )
    {
        data._id = RANDOM( ...USER_ID );

        this.#ctx.db.collection('users').insertOne({ ...data, password: await HashPassword( data.password )});
    }

    async login( email, password )
    {
        // TOTP https://stefansundin.github.io/2fa-qr/

        let user = await this.#ctx.db.collection('users').findOne({ email }, { projection: { password: 1, 'keys.private': 1 }});

        if( user )
        {
            if( await VerifyPassword( password, user.password ))
            {
                delete user.password;

                return { user, token: auth.create({ userID: user._id }, { expires: '2h' })};
            }
        }

        return false;
    }
}