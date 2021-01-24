'use strict';
var express = require('express');
var bodyParser = require('body-parser');
var eth_crypto = require('eth-crypto');
let bitcoin = require('bitcoinjs-lib');
var http_port = 5000;

function containsAll(body, requiredKeys) {
    return requiredKeys.every(elem => body.indexOf(elem) > -1) && body.length == requiredKeys.length;
}

var initHttpServer = () => {
    var app = express();
    app.use(bodyParser.json());

    app.post('/crypto2/eth_sign', (req, res) => {
        var values = req.body;
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body');
        }

        var required = ["skey", "msg"];
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values');
        }

        //! **************************** DONE **************************** //
        const msg = req.body.msg;
        const skey = req.body.skey;

        console.log(msg);
        console.log(skey);

        const messageHash = eth_crypto.hash.keccak256(msg);
        const signature = eth_crypto.sign(skey, messageHash);

        res.send({ signature: signature, msg: msg});
    });

    app.post('/crypto2/eth_sign_to_addr', (req, res) => {
        var values = req.body;
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body');
        }

        var required = ["signature", "msg"];
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values');
        }

        //! **************************** DONE **************************** //
        
        const signature = req.body.signature;
        const msg = req.body.msg;

        const signer = eth_crypto.recover(signature, eth_crypto.hash.keccak256(msg));
        console.log(signer);

        res.send({address: signer});
    });

    app.post('/crypto2/eth_sign_verify', (req, res) => {
        var values = req.body;
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body');
        }

        var required = ["address", "msg", "signature"];
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values');
        }

        //! **************************** DONE **************************** //
        const address = req.body.address;
        const signature = req.body.signature;
        
        const msg = req.body.msg;
        let validOrInvalid = false;

        const signer = eth_crypto.recover(signature, eth_crypto.hash.keccak256(msg));
        
        if(signer === address){
            validOrInvalid = true;
        } else {
            validOrInvalid = false;
        }
        
        console.log(validOrInvalid);

        res.send({valid: validOrInvalid});
    });

    app.post('/crypto2/btc_skey_to_addr', (req, res) => {
        var values = req.body;
        if (Object.keys(values).length === 0) {
            return res.status(400).send('Missing Body');
        }

        var required = ["skey"];
        if (!containsAll(Object.keys(values), required)) {
            return res.status(400).send('Missing values');
        }

        //! **************************** DONE **************************** //
        let skey = req.body.skey;
        const keyPair = bitcoin.ECPair.fromWIF(skey);
        
        // console.log(skey);
        // console.log(keyPair.toWIF());
        // console.log(keyPair.getAddress());
        
        const address = bitcoin.payments.p2pkh({pubkey: keyPair.publicKey}).address;
        console.log(address);

        res.send({address: address});
    });

    app.listen(http_port, () => console.log("Listening http port: " + http_port));
};

initHttpServer();
