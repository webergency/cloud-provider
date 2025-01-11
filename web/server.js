'use strict';

const fs = require('fs');
const JWT = require('@liqd-js/jwt');
const Server = require('@liqd-js/server');
const Template = require('@liqd-js/template');
const Provider = require('../lib/provider');

const server = new Server();
const template = new Template({ directories: [ __dirname + '/templates' ]});
const auth = new JWT({ ES384: { pub: fs.readFileSync( __dirname + '/../config/certificates/auth.pub' ) }});
const provider = new Provider();

server.use(( req, res, next ) =>
{
    if( req.cookies.auth_token )
    {
        console.log( auth.parse( req.cookies.auth_token ));
    }

    next();
});

server.get( '/data/*', ( req, res ) =>
{
    res.reply( fs.createReadStream( __dirname + req.path ), 'application/javascript' );
})

server.get( '/entity/create', async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/EntityCreate' ), 'text/html' );
});

server.post( '/user/register', async( req, res ) =>
{
    let data = await req.body;

    provider.User.create( data );

    console.log( data );

    res.reply( true );
});

server.post( '/user/login', async( req, res ) =>
{
    try
    {
        let data = await req.body;
        let logged = await provider.User.login( data.email, data.password );

        console.log( logged );

        if( logged )
        {
            res.cookie( 'auth_token', logged.token, { maxAge: 2 * 60 * 60 });
            res.reply( logged.user );
        }
        else{ res.reply( false )}
    }
    catch( e )
    {
        console.log( e );
    }
});

server.get( '/user/create', async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/UserCreate' ), 'text/html' );
});

server.get( '/user/login', async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/Login' ), 'text/html' );
});

server.get( '/sql/create', async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/SQLCreate' ), 'text/html' );
});

server.post( '/api/entity', async( req, res, next ) =>
{
    let body = await req.body;

    console.log( body );

    res.redirect( 303, '/' );
});

server.get( async( req, res, next ) =>
{
    //provider.User.create({ email: 'jozo' });

    res.reply( await template.render( '', 'Page/Index' ), 'text/html' );
});

server.listen( 8080 );