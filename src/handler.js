/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const util = require("./util")

class handler {
    constructor(config) {
        this.db = config.db;
        this.post_init = this.post_init.bind(this)
    }

    async post_init(req, res, next) {
        try {
            util.ParameterCheck(req.body, 'access_ip', 'ip_list');
            util.ParameterCheck(req.body, 'public_key', 'string', 1, 999);
        } catch (err) {
            return next(err);
        }

        if (!util.key_type_check(req.body.public_key, "ec", "public")) {
            return next("Public Key is must be EC public");
        }

        try {
            let is_init = await util.db_key_exists(this.db, 'INIT:ADMIN');
            if (is_init == true) {
                return next(util.errorInit("Initialization has already been completed."));
            }

            let init_data = {
                ip: JSON.parse(req.body.access_ip),
                public_key: req.body.public_key
            };

            await util.db_put(this.db, "INIT:ADMIN", init_data);
            return util.send_success(res);
        } catch (err) {
            return next(err);
        }
    }

}

module.exports = handler;
