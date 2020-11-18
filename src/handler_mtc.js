/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const util = require("./util")
const crypto = require('crypto')
const ipcheck = require('ip-range-check')

const axios = require('axios');
const axios_config = {
    proxy: {
        host: '192.168.10.2',
        port: 8888
    }
};


class handler {
    constructor(config) {
        this.db = config.db;
        this.post_address_mtc = this.post_address_mtc.bind(this);
        this.post_sign_mtc = this.post_sign_mtc.bind(this);
        this.post_import_mtc = this.post_import_mtc.bind(this);
    }

    async post_address_mtc(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id');
            util.ParameterCheck(req.body, 'network', "int", 0, 2);

            util.ParameterCheck(req.body, 'sign');
            util.ParameterCheck(req.body, 'w', 'int', 0, 2);
            util.ParameterCheck(req.body, 'ts', "int", 1, 32);
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
                [req.body.company_id, req.body.network, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }


        // operation
        let v = {
            private_key: "",
            address: ""
        };
        try {
            let hostname;
            switch (req.body.network) {
                case "9":
                    hostname = "http://192.168.40.182:20922";
                    break;
                case "10":
                    hostname = "https://rest.metacoin.network:20923";
                    break;
                case "20":
                    hostname = "https://testnetrest.metacoin.network:20923";
                    break;
                default:
                    return next("Metacoin network is invalid - 10:mainnet, 20:testnet but you select " + req.body.network);
            }

            const {privateKey, publicKey} = crypto.generateKeyPairSync("ec", {
                modulusLength: 0,    // ignore in "EC"
                namedCurve: "secp384r1",  // or "secp521r1"
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });

            let response = await axios.post(hostname + '/address', {
                'publickey': publicKey
            }, axios_config);

            if (response.status != 200) {
                return next("MTC server response errror - " + response.data);
            }

            v.private_key = privateKey;
            v.address = response.data;
        } catch (err) {
            if (err.isAxiosError) {
                return next("MTC server communication error - " + err.message);
            } else {
                return next(err);
            }
        }

        // save db
        try {
            let key_id = await util.db_putnx(this.db, "ADDR:" + req.body.company_id, "A_", v);
            return util.send_success(res, { id: key_id, address: v.address });
        } catch (err) {
            return next(err);
        }
    }

    async post_sign_mtc(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
            util.ParameterCheck(req.body, 'address_id', 'string', 32, 32);
            util.ParameterCheck(req.body, 'address', 'string', 40, 40);
            util.ParameterCheck(req.body, 'data', 'string', 1, 9999);
            util.ParameterCheck(req.body, 'w', 'int', 0, 2);
            util.ParameterCheck(req.body, 'ts', 'int', 1, 32);
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
                [req.body.company_id, req.body.address_id, req.body.data, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }

        // address
        try {
            let db_data = await this.db.get("ADDR:" + req.body.company_id + ":" + req.body.address_id);

            let addr_data = JSON.parse(db_data);
            if (addr_data.address != req.body.address) {
                throw new Error('Address not match');
            }
            const sign = crypto.createSign('SHA256');
            sign.write(req.body.data);
            sign.end();
            let signature = sign.sign(addr_data.private_key, 'base64');
            util.send_success(res, { sign: signature });
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Address ID ' + req.body.address_id + ' not found'));
            } else {
                return next(err);
            }
        }
    }


    async post_import_mtc(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
            util.ParameterCheck(req.body, 'address', 'string', 40, 40);
            util.ParameterCheck(req.body, 'private_key', 'string', 1, 9999);
            util.ParameterCheck(req.body, 'sign', 'string', 1, 9999);
            util.ParameterCheck(req.body, 'w', 'int', 0, 2);
            util.ParameterCheck(req.body, 'ts', 'int', 1, 32);
        } catch (err) {
            return next(err)
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }
        if (!util.key_type_check(req.body.private_key, "ec", "private")) {
            return next("Private Key is must be EC private");
        }

        // access ip, sign check
        try {
            let db_data = await this.db.get('DB:COMPANY:' + req.body.company_id)
            let company_data = JSON.parse(db_data);
            if (ipcheck(req.ip, company_data.ip) != true) {
                return next(errorACL("The IP is not allowed access"));
            }
            await util.sign_check(company_data.public_key, req.body.sign,
                [req.body.company_id, req.body.address, req.body.private_key, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }

        try {
            let v = {
                private_key: req.body.private_key,
                address: req.body.address,
                id: ''
            };
            let key_id = await util.db_putnx(this.db, "ADDR:" + req.body.company_id, "A_", v);
            return util.send_success(res, { id: key_id });
        } catch (err) {
            return next(err);
        }
    }
}

module.exports = handler;
