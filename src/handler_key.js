/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const util = require("./util")
const crypto = require('crypto')
const ipcheck = require('ip-range-check')

const STATUS_NORMAL = 10;

const handler = class {
    constructor(config) {
        this.db = config.db;
        this.post_key = this.post_key.bind(this)
        this.post_enc = this.post_enc.bind(this)
        this.post_dec = this.post_dec.bind(this)
    }

    async post_key(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
            util.ParameterCheck(req.body, 'passphrase', 'string', 8, 32);

            util.ParameterCheck(req.body, 'sign', 'string');
            util.ParameterCheck(req.body, 'w', 'int', 0, 2);
            util.ParameterCheck(req.body, 'ts', 'int', 1, 32);
        } catch (err) {
            return next(err);
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }

        // access ip, sign check
        let db_data;
        try {
            db_data = await this.db.get('DB:COMPANY:' + req.body.company_id);

            let company_data = JSON.parse(db_data);
            if (ipcheck(req.ip, company_data.ip) != true) {
                return next(errorACL("The IP is not allowed access"));
            }

            await util.sign_check(company_data.public_key, req.body.sign,
                [req.body.company_id, req.body.passphrase, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }

        // create RSA key & save db
        try {
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: req.body.passphrase
                }
            });

            let v = {
                company: req.body.company_id,
                status: STATUS_NORMAL,
                name: req.body.name,
                public_key: publicKey,
                private_key: privateKey
            };
            let key_id = await util.db_putnx(this.db, "DB:KEY", "K_", v);
            return util.send_success(res, { id: key_id });
        } catch (err) {
            return next(err);
        }

    }

    async post_enc(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
            util.ParameterCheck(req.body, 'key_id', 'string', 32, 32);
            util.ParameterCheck(req.body, 'text', 'string', 1, 40960);

            util.ParameterCheck(req.body, 'sign', 'string');
            util.ParameterCheck(req.body, 'w', 'int');
            util.ParameterCheck(req.body, 'ts', 'int');
        } catch (err) {
            return next(err);
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }

        // access ip, sign check
        try {
            let db_data = await this.db.get('DB:COMPANY:' + req.body.company_id);
            let company_data = JSON.parse(db_data);
            if (ipcheck(req.ip, company_data.ip) != true) {
                return next(errorACL("The IP is not allowed access"));
            }
            await util.sign_check(company_data.public_key, req.body.sign,
                [req.body.company_id, req.body.key_id, req.body.text, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }

        // Encrypt
        try {
            let db_data = await this.db.get('DB:KEY:' + req.body.key_id);
            let key_data = JSON.parse(db_data);
            let enc = crypto.publicEncrypt({
                key: key_data.public_key
            }, Buffer.from(req.body.text, 'utf8'));
            return util.send_success(res, enc.toString('base64'));
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Key ID ' + req.body.key_id + ' not found'));
            } else {
                return next(err);
            }
        }
    }

    async post_dec(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
            util.ParameterCheck(req.body, 'key_id', 'string', 32, 32);
            util.ParameterCheck(req.body, 'enc_text', 'string', 1, 40960);
            util.ParameterCheck(req.body, 'passphrase', 'string', 8, 32);

            util.ParameterCheck(req.body, 'sign', 'string');
            util.ParameterCheck(req.body, 'w', 'int');
            util.ParameterCheck(req.body, 'ts', 'int');
        } catch (err) {
            return next(err);
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }

        // access ip, sign check
        try {
            let db_data = await this.db.get('DB:COMPANY:' + req.body.company_id);
            let company_data = JSON.parse(db_data);
            if (ipcheck(req.ip, company_data.ip) != true) {
                return next(errorACL("The IP is not allowed access"));
            }

            await util.sign_check(company_data.public_key, req.body.sign,
                [req.body.company_id, req.body.key_id, req.body.enc_text, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }

        // get key & decrypt
        try {
            let db_data = await this.db.get('DB:KEY:' + req.body.key_id);
            let key_data = JSON.parse(db_data);
            let dec = crypto.privateDecrypt({
                key: key_data.private_key,
                passphrase: req.body.passphrase
            }, Buffer.from(req.body.enc_text, "base64")).toString('utf8');
            return util.send_success(res, dec);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Key ID ' + req.body.key_id + ' not found'));
            } else {
                return next(err);
            }
        }

    }
}

module.exports.handler = handler;
