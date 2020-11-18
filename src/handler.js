/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const util = require("./util")
const crypto = require('crypto')
const rocks = require('level-rocksdb')
const ipcheck = require('ip-range-check')

const axios = require('axios');
const axios_config = {};

const STATUS_NORMAL = 10;

const handler = class {
    constructor(config) {
        this.db = rocks(config.DB_PATH, {
            createIfMissing: true
        });
        this.db.open();

        this.post_init = this.post_init.bind(this)
        this.post_company = this.post_company.bind(this)
        this.put_company = this.put_company.bind(this)
        this.post_address_mtc = this.post_address_mtc.bind(this)
        this.post_sign_mtc = this.post_sign_mtc.bind(this)

        this.post_key = this.post_key.bind(this)
        this.post_enc = this.post_enc.bind(this)
        this.post_dec = this.post_dec.bind(this)
    }

    post_init(req, res) {
        console.log('Remote Address', req.remoteAddress);
        util.ParameterCheck(req.body, 'access_ip', 'ip_list');
        util.ParameterCheck(req.body, 'public_key', 'string', 1, 999);

        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return util.send_error(res, "Public Key is must be EC public");
        }

        let v = {
            ip: JSON.parse(req.body.access_ip),
            public_key: req.body.public_key
        };

        let db = this.db;
        db.get('INIT:ADMIN')
            .then(function () {
                throw new Error("Already init");
            })
            .catch(function (err) {
                if (err.notFound) {
                    return db.put("INIT:ADMIN", JSON.stringify(v))
                } else {
                    throw err;
                }
            })
            .then(function () {
                util.send_success(res);
            })
            .catch(function (err) {
                util.send_error(res, err);
            });
    }

    post_company(req, res) {
        util.ParameterCheck(req.body, 'name');
        util.ParameterCheck(req.body, 'access_ip', 'ip_list', 6, 1024);
        util.ParameterCheck(req.body, 'public_key', 'string');
        util.ParameterCheck(req.body, 'sign', 'string');
        util.ParameterCheck(req.body, 'w', 'int');
        util.ParameterCheck(req.body, 'ts', 'int');

        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return util.send_error(res, "Public Key is must be EC public");
        }
        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }
        let db = this.db;
        db.get('INIT:ADMIN')
            .then(function (v) {
                let admin_data = JSON.parse(v);
                if (!ipcheck(req.ip, admin_data.ip)) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.name, req.body.access_ip, req.body.public_key, req.body.ts].join("|"), req.body.sign, admin_data.public_key)
                }
            })
            .then(() => {
                let v = {
                    name: req.body.name,
                    ip: JSON.parse(req.body.access_ip),
                    public_key: req.body.public_key,
                    status: STATUS_NORMAL
                };
                util.db_putnx(res, db, 'DB:COMPANY', 'C_', v, {});
            })
            .catch((err) => {
                console.log(err);
                return util.send_error(res, err);
            });
    }


    put_company(req, res) {
        util.ParameterCheck(req.body, 'company_id', 'string');
        util.ParameterCheck(req.body, 'name', 'string');
        util.ParameterCheck(req.body, 'access_ip', 'ip_list');
        util.ParameterCheck(req.body, 'public_key', 'string');
        util.ParameterCheck(req.body, 'admin_sign', 'string');
        util.ParameterCheck(req.body, 'company_sign', 'string');
        util.ParameterCheck(req.body, 'w', 'int');
        util.ParameterCheck(req.body, 'ts', 'int');

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }
        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return util.send_error(res, "Public Key is must be EC public");
        }

        let db = this.db;
        db.get('INIT:ADMIN')
            .then(function (v) {
                let admin_data = JSON.parse(v);
                if (!ipcheck(req.ip, admin_data.ip)) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.company_id, req.body.name, req.body.access_ip, req.body.public_key, req.body.ts].join("|"), req.body.admin_sign, admin_data.public_key)
                }
            })
            .catch((err) => {
                console.log(err);
                return Promise.reject(err);
            })
            .then(() => {
                return util.sign_check(db, 'DB:COMPANY:' + req.body.company_id, [req.body.company_id, req.body.name, req.body.access_ip, req.body.public_key].join("|"), req.body.company_sign);
            })
            .catch((err) => {
                console.log(err);
                return Promise.reject(err);
            })
            .then(() => {
                let v = {
                    name: req.body.name,
                    ip: JSON.parse(req.body.access_ip),
                    public_key: req.body.public_key,
                    status: STATUS_NORMAL
                };
                return util.db_put(db, 'DB:COMPANY:' + req.body.company_id, v);
            })
            .catch((err) => {
                console.log(err);
                util.send_error(res, err);
            })
            .then(() => {
                util.send_success(res);
            })
    }

    post_address_mtc(req, res) {
        util.ParameterCheck(req.body, 'company_id');
        util.ParameterCheck(req.body, 'network', "int", 0, 2);
        util.ParameterCheck(req.body, 'w', 'int', 0, 2);
        util.ParameterCheck(req.body, 'ts', "int", 1, 32);
        util.ParameterCheck(req.body, 'sign');

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }

        let hostname;
        switch (req.body.network) {
            case 10:
                hostname = "https://rest.metacoin.network:20923";
                break;
            case 20:
                hostname = "https://testnetrest.metacoin.network:20923";
                break;
            default:
                hostname = "http://192.168.40.182:20922";
        }
        let db = this.db;
        let v = {};
        db.get('DB:COMPANY:' + req.body.company_id)
            .then((value) => {
                let company_data = JSON.parse(value);
                if (ipcheck(req.ip, company_data.ip) != true) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.company_id, req.body.network, req.body.ts].join("|"), req.body.sign, company_data.public_key)
                }
            })
            .catch((err) => {
                if (err.notFound) {
                    return Promise.reject("Company not found");
                } else {
                    return Promise.reject(err);
                }
            })
            .then(() => {
                try {
                    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
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

                    v.private_key = privateKey;
                    return axios.post(hostname + '/address', {
                        'publickey': publicKey
                    }, axios_config)
                } catch (err) {
                    Promise.reject(err);
                }
            })
            .then(function (response) {
                if (response.status != 200) {
                    return Promise.reject("MTC server response errror");
                } else {
                    v.address = response.data;
                    util.db_putnx(res, db, "ADDR:" + req.body.company_id, "A_", v, { address: response.data });
                }
            })
            .catch(function (err) {
                if (err.isAxiosError) {
                    util.send_error(res, "MTC server communication error - " + err.message);
                } else {
                    util.send_error(res, err);
                }
            });
    }

    post_sign_mtc(req, res, next) {
        util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
        util.ParameterCheck(req.body, 'address_id', 'string', 32, 32);
        util.ParameterCheck(req.body, 'address', 'string', 40, 40);
        util.ParameterCheck(req.body, 'data', 'string', 1, 9999);
        util.ParameterCheck(req.body, 'w', 'int', 0, 2);
        util.ParameterCheck(req.body, 'ts', 'int', 1, 32);

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }

        let db = this.db;
        db.get('DB:COMPANY:' + req.body.company_id)
            .then((value) => {
                let company_data = JSON.parse(value);
                if (company_data.Buffer)
                    if (ipcheck(req.ip, company_data.ip) != true) {
                        return Promise.reject("The IP is not allowed access");
                    } else {
                        return util.sign_check(db, '', [req.body.company_id, req.body.address_id, req.body.data, req.body.ts].join("|"), req.body.sign, company_data.public_key);
                    }
            })
            .catch((err) => {
                if (err.notFound) {
                    return Promise.reject("Company not found");
                } else {
                    return Promise.reject(err);
                }
            })
            .then(() => {
                return db.get("ADDR:" + req.body.company_id + ":" + req.body.address_id);
            })
            .then(function (value) {
                let addr_data = JSON.parse(value);
                if (addr_data.address != req.body.address) {
                    return Promise.reject('Address not found');
                }

                const sign = crypto.createSign('SHA256');
                sign.write(req.body.data);
                sign.end();
                let signature = sign.sign(addr_data.private_key, 'base64');
                util.send_success(res, { sign: signature });
            })
            .catch(function (err) {
                if (err.notFound) {
                    util.send_error(res, 'Address ID not found');
                } else {
                    util.send_error(res, err);
                }
            });
    }

    post_key(req, res) {
        util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
        util.ParameterCheck(req.body, 'passphrase', 'string', 8, 32);
        util.ParameterCheck(req.body, 'sign', 'string');
        util.ParameterCheck(req.body, 'w', 'int', 0, 2);
        util.ParameterCheck(req.body, 'ts', 'int', 1, 32);

        let db = this.db;

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }
        db.get('DB:COMPANY:' + req.body.company_id)
            .then((value) => {
                let company_data = JSON.parse(value);
                if (ipcheck(req.ip, company_data.ip) != true) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.company_id, req.body.passphrase, req.body.ts].join("|"), req.body.sign, company_data.public_key)
                }
            })
            .then(() => {
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
                    util.db_putnx(res, db, "DB:KEY", "K_", v, {});
                } catch (err) {
                    Promise.reject(err);
                }
            })
            .catch((err) => {
                util.send_error(res, err);
            });
    }

    post_enc(req, res) {
        util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
        util.ParameterCheck(req.body, 'key_id', 'string', 32, 32);
        util.ParameterCheck(req.body, 'text', 'string', 1, 40960);
        util.ParameterCheck(req.body, 'w', 'int');
        util.ParameterCheck(req.body, 'ts', 'int');

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }
        let db = this.db;
        db.get('DB:COMPANY:' + req.body.company_id)
            .then((value) => {
                let company_data = JSON.parse(value);
                if (ipcheck(req.ip, company_data.ip) != true) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.company_id, req.body.key_id, req.body.text, req.body.ts].join("|"), req.body.sign, company_data.public_key)
                }
            })
            .catch((err) => {
                if (err.notFound) {
                    return Promise.reject("Company not found");
                } else {
                    return Promise.reject(err);
                }
            })
            .then(() => {
                return db.get('DB:KEY:' + req.body.key_id);
            })
            .then(function (value) {
                let key_data = JSON.parse(value);
                let enc = crypto.publicEncrypt({
                    key: key_data.public_key
                }, Buffer.from(req.body.text, 'utf8'));
                util.send_success(res, enc.toString('base64'));
            })
            .catch(function (err) {
                console.log(err);
                util.send_error(res, err);
            });
    }

    post_dec(req, res) {
        util.ParameterCheck(req.body, 'company_id', 'string', 1, 32);
        util.ParameterCheck(req.body, 'key_id', 'string', 32, 32);
        util.ParameterCheck(req.body, 'enc_text', 'string', 1, 40960);
        util.ParameterCheck(req.body, 'passphrase', 'string', 8, 32);

        util.ParameterCheck(req.body, 'w', 'int');
        util.ParameterCheck(req.body, 'ts', 'int');

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return util.send_error(res, "TS interval error");
        }
        let db = this.db;
        db.get('DB:COMPANY:' + req.body.company_id)
            .then((value) => {
                let company_data = JSON.parse(value);
                if (ipcheck(req.ip, company_data.ip) != true) {
                    return Promise.reject("The IP is not allowed access");
                } else {
                    return util.sign_check(db, '', [req.body.company_id, req.body.key_id, req.body.enc_text, req.body.ts].join("|"), req.body.sign, company_data.public_key)
                }
            })
            .catch((err) => {
                if (err.notFound) {
                    return Promise.reject("Company not found");
                } else {
                    return Promise.reject(err);
                }
            })
            .then(() => {
                return db.get('DB:KEY:' + req.body.key_id);
            })
            .then(function (value) {
                let key_data = JSON.parse(value);
                let dec = crypto.privateDecrypt({
                    key: key_data.private_key,
                    passphrase: req.body.passphrase
                }, Buffer.from(req.body.enc_text, "base64")).toString('utf8');
                util.send_success(res, dec);
            })
            .catch(function (err) {
                console.log(err);
                util.send_error(res, err);
            });
    }
}

module.exports.handler = handler;
