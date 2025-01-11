'use strict';

const User = require('./classes/user');
const MongoClient = require('mongodb').MongoClient;

module.exports = class Provider
{
    #db; #classes = {};

    constructor()
    {
        MongoClient.connect( 'mongodb://localhost:27017', { useUnifiedTopology: true }, ( err, client ) =>
        {
            this.#db = client.db('webergency_cloud');
        });
    }

    get Entity()
    {
        
    }

    get User()
    {
        return this.#classes.user || ( this.#classes.user = new User({ db: this.#db }));
    }
}