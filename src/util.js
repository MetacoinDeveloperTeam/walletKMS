/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const crypto = require('crypto');
const net = require('net');


class CustomError extends Error {
    constructor(error_msg, ...params) {
        super(...params);
        this.isParamError = 1;
        this.message = error_msg;
    }
}

function NumberPadding(a) {
    return ("0000000000000000" + a).substr(-16);
}

function ParameterCheck(v, n, checktype, minlength, maxlength) {
    if (v[n] === undefined) {
        if (minlength === 0) {
            v[n] = '';
            return;
        } else {
            throw new CustomError("Parameter " + n + " is missing");
        }
    }
    if (typeof v[n] != typeof "") {
        return;
    }
    v[n] = v[n].trim();


    if (maxlength != undefined && maxlength > 0) {
        if (v[n].length > maxlength) {
            throw new CustomError("The length of parameter " + n + "  must be less than " + maxlength);
        }
    }

    if (minlength != undefined && minlength > 0) {
        if (v[n].length < minlength) {
            throw new CustomError("The length of parameter " + n + "  must be greater  than " + minlength);
        }
    }


    switch (checktype) {
        case 'int':
            if (v[n] != "" && !isNormalInteger(v[n])) {
                throw new CustomError("The type of Parameter " + n + " must be integer");
            }
            break;
        case 'url':
            var urlRegex = '^(?!mailto:)(?:(?:http|https|ftp)://)(?:\\S+(?::\\S*)?@)?(?:(?:(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[0-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})))|localhost)(?::\\d{2,5})?(?:(/|\\?|#)[^\\s]*)?$';
            var url = new RegExp(urlRegex, 'i');
            if (v[n].length >= 2083 || !url.test(v[n])) {
                throw new CustomError("Parameter " + n + " is must be URL");
            }
            break;

        case 'ip_list':
            try {
                var j = JSON.parse(v[n]);
            } catch (err) {
                throw new CustomError("Parameter " + n + " is must be json string");
            }
            if (!Array.isArray(j)) {
                throw new CustomError("Parameter " + n + " is must be array");
            }
            for (var k in j) {
                if (!net.isIP(j[k])) {
                    throw new CustomError("Parameter " + n + " " + j[k] + " is must IPv4");
                }
            }
    }
}


function isNormalInteger(str) {
    return /^\+?(0|[1-9]\d*)$/.test(str);
}

function getRandomString(keylength) {
    let chars = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
    let rnd = crypto.randomBytes(keylength);
    let value = new Array(keylength);
    let len = Math.min(256, chars.length);
    let d = 256 / len;
    for (var i = 0; i < keylength; i++) {
        value[i] = chars[Math.floor(rnd[i] / d)];
    }
    return value.join('');
}


function send_error(res, message) {
    if (typeof message == typeof "") {
        res.status(400).send({
            result: 'ERROR',
            data: {},
            msg: message
        });
    } else {
        console.log(message);
        res.status(400).send({
            result: 'ERROR',
            data: {},
            msg: message.message
        });
    }
}

function send_success(res, data, message) {
    res.send({
        result: 'SUCCESS',
        data: data,
        msg: message
    });
}


function key_type_check(pem, asymmetricKeyType, type) {
    try {
        let obj = crypto.createPublicKey(pem);
        console.log(obj);
        return obj.symmetricKeySize == undefined && obj.type == type && obj.asymmetricKeyType == asymmetricKeyType;
    } catch (err) {
        return false;
    }
}

const db_key_exists = (db, key_id) => {
    return new Promise((resolve, reject) => {
        db.get(key_id)
            .then(() => {
                reject();
            })
            .catch((err) => {
                if (err.notFound) {
                    resolve();
                } else {
                    reject();
                }
            });

    });
}

const db_put = (db, key_id, save_value, return_value) => {
    return new Promise((resolve, reject) => {
        db.put(key_id, JSON.stringify(save_value))
            .then(function () {
                return resolve(return_value)
            })
            .catch(function (err) {
                return reject(err);
            });
    });
}

const db_putnx = async (res, db, db_prefix, key_prefix, save_value, return_value) => {
    let loop = true;
    let cnt = 0;
    while (loop && cnt < 10) {
        let key_id = key_prefix + getRandomString(30);
        let save_id = db_prefix + ":" + key_id;
        cnt = cnt + 1;
        try {
            await db_key_exists(db, save_id)
                .then(() => {
                    return db_put(db, save_id, save_value, return_value);
                }).catch(() => {
                    return Promise.reject("db_key_exists");
                }).then((v) => {
                    v.id = key_id;
                    send_success(res, v);
                    loop = false;
                }).catch((err) => {
                    if (err != 'db_key_exists') {
                        send_error(res, err);
                        loop = false;
                    }
                });
        } catch (err) {
            send_error(res, err);
        }
    }
}

const sign_check = (db, db_key, data, sign, public_key) => {
    console.log("DB key ", db_key);
    console.log("data   ", data);
    console.log("sign   ", sign);
    console.log("Pubkey ", public_key);

    if (public_key == undefined) {
        return db.get(db_key)
            .then(function (value) {
                let db_data = JSON.parse(value);
                let verify = crypto.createVerify('RSA-SHA384');
                verify.update(data);
                if (verify.verify(db_data.public_key, sign, 'base64')) {
                    return Promise.resolve();
                } else {
                    return Promise.reject("Invalid Signature");
                }
            })
            .catch(function (err) {
                console.log(err);
                return Promise.reject(err);
            });
    } else {
        try {
            let verify = crypto.createVerify('RSA-SHA384');
            verify.update(data);
            if (verify.verify(public_key, sign, 'base64')) {
                return Promise.resolve();
            } else {
                return Promise.reject("Invalid Signature");
            }
        } catch (err) {
            console.log(err);
            return Promise.reject(err);
        }
    }
}

const ts_check = (window, timestamp) => {
    let w = parseInt(window);
    let ts = parseInt(timestamp);
    if (w < 0 || w > 10) {
        return false;
    }
    if (Math.abs(Math.round(new Date().getTime() / 1000) - ts) > w) {
        return false;
    }
    return true;
}

module.exports.db_putnx = db_putnx;
module.exports.db_put = db_put;

module.exports.send_error = send_error;
module.exports.send_success = send_success;
module.exports.key_type_check = key_type_check;

module.exports.NumberPadding = NumberPadding;
module.exports.ParameterCheck = ParameterCheck;

module.exports.isNormalInteger = isNormalInteger;
module.exports.getRandomString = getRandomString;

module.exports.sign_check = sign_check;
module.exports.ts_check = ts_check;
