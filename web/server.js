'use strict';

const Server = require('@liqd-js/server');
const Template = require('@liqd-js/template');

const server = new Server();
const template = new Template({ directories: [ __dirname + '/templates' ]});

server.get( '/entity/create', async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/EntityCreate' ), 'text/html' );
});

server.post( '/api/entity', async( req, res, next ) =>
{
    let body = await req.body;

    console.log( body );

    res.redirect( 303, '/' );
});

server.get( async( req, res, next ) =>
{
    res.reply( await template.render( '', 'Page/Index' ), 'text/html' );
});

server.listen( 8080 );