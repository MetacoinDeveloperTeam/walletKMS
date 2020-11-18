/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const util = require("./util")
const ipcheck = require('ip-range-check')

const STATUS_NORMAL = 10;


const handler = class {
    constructor(config) {
        this.db = config.db;

        this.post_company = this.post_company.bind(this)
        this.put_company = this.put_company.bind(this)
    }

    async post_company(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'name');
            util.ParameterCheck(req.body, 'access_ip', 'ip_list', 6, 1024);
            util.ParameterCheck(req.body, 'public_key', 'string');

            util.ParameterCheck(req.body, 'sign', 'string');
            util.ParameterCheck(req.body, 'w', 'int');
            util.ParameterCheck(req.body, 'ts', 'int');
        } catch (err) {
            return next(err)
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }
        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return next("Public Key is must be EC public");
        }

        // access ip, sign check
        try {
            let db_data = await this.db.get('INIT:ADMIN');
            let admin_data = JSON.parse(db_data);
            if (!ipcheck(req.ip, admin_data.ip)) {
                return next(util.errorACL("The IP is not allowed access"));
            }
            await util.sign_check(admin_data.public_key, req.body.sign,
                [req.body.name, req.body.access_ip, req.body.public_key, req.body.ts]);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorInit('Initialization is required.'));
            } else {
                return next(err);
            }
        }

        // save db
        try {
            let v = {
                name: req.body.name,
                ip: JSON.parse(req.body.access_ip),
                public_key: req.body.public_key,
                status: STATUS_NORMAL
            };
            let key_id = await util.db_putnx(this.db, 'DB:COMPANY', 'C_', v);
            console.log(key_id);
            return util.send_success(res, { id: key_id });
        } catch (err) {
            return next(err);
        }
    }

    async put_company(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'company_id', 'string');
            util.ParameterCheck(req.body, 'name', 'string');
            util.ParameterCheck(req.body, 'access_ip', 'ip_list');
            util.ParameterCheck(req.body, 'public_key', 'string');

            util.ParameterCheck(req.body, 'admin_sign', 'string');
            util.ParameterCheck(req.body, 'company_sign', 'string');
            util.ParameterCheck(req.body, 'w', 'int');
            util.ParameterCheck(req.body, 'ts', 'int');
        } catch (err) {
            return next(err)
        }

        if (!util.ts_check(req.body.w, req.body.ts)) {
            return next("The timestamp value is too old or invalid.");
        }
        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return next("Public Key is must be EC public");
        }

        // access ip, sign check
        try {
            let db_data = await this.db.get('INIT:ADMIN');
            let admin_data = JSON.parse(db_data);
            if (!ipcheck(req.ip, admin_data.ip)) {
                return next(util.errorACL("The IP is not allowed access"));
            }

            await util.sign_check(admin_data.public_key, req.body.admin_sign, [req.body.company_id, req.body.name, req.body.access_ip, req.body.public_key, req.body.ts]);

        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorInit('Initialization is required.'));
            } else {
                return next(err);
            }
        }

        // company sign check & save
        try {
            let db_data = await this.db.get('DB:COMPANY:' + req.body.company_id);
            let company_data = JSON.parse(db_data);
            await util.sign_check(company_data.public_key, req.body.company_sign,
                [req.body.company_id, req.body.name, req.body.access_ip, req.body.public_key])

            let v = {
                name: req.body.name,
                ip: JSON.parse(req.body.access_ip),
                public_key: req.body.public_key,
                status: STATUS_NORMAL
            };
            await util.db_put(this.db, 'DB:COMPANY:' + req.body.company_id, v);
            return util.send_success(res);
        } catch (err) {
            if (err.type == 'NotFoundError') {
                return next(util.errorNotFound('Company ID ' + req.body.company_id + ' not found'));
            } else {
                return next(err);
            }
        }
    }
}

module.exports.handler = handler;
