/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const app_ver = "ver 1.0.0";
const app_title = "Inblock KMS";

const config = require('./config.json');
const util = require("./util");
const rocks = require('level-rocksdb')


const handler_company = require("./handler_company");
const handler_key = require("./handler_key");
const handler_mtc = require("./handler_mtc");
const handler = require("./handler");

console.log(app_title + " " + app_ver);

const http = require('http');



/* for express */
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const multer = require('multer');
const upload = multer();

app.set('trust proxy', 'loopback');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(function (req, res, next) {
    res.header('X-INBLOCK-KMS', app_ver);
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    req.remoteAddress = ip.replace('::ffff:', '');
    console.log(new Date().toTimeString(), req.remoteAddress, '\t', req.method, '\t', req.url);
    next();
});
app.disable('x-powered-by');


const db = rocks(config.DB_PATH, {
    createIfMissing: true
});
db.open();

config.db = db;

const request_handler_company = new handler_company(config);
const request_handler_key = new handler_key(config);
const request_handler_mtc = new handler_mtc(config);
const request_handler = new handler(config);

/**
 * @api {post} /v1/init register admin
 * @apiVersion 1.0.0
 * @apiGroup system
 * @apiDescription Initialization function to register Admin, can be called only once
 *
 * @apiParam {string} access_ip admin's access ip
 * @apiParam {string} public_key admin's public key
 *
 * @apiSuccess {String} result "SUCCESS"
 * @apiSuccess {String} data Empty string
 * @apiSuccess {String} msg Empty string
 *
 * @apiError  {String} result "ERROR"
 * @apiError  {String} data Empty string
 * @apiError  {String} msg Error message
 */
app.post('/v1/init', upload.array(), request_handler.post_init);

/**
 * @api {post} /v1/init register company
 * @apiVersion 1.0.0
 * @apiGroup company
 * @apiDescription Register company
 *
 * @apiParam {string} name company name
 * @apiParam {string} access_ip company's access ip
 * @apiParam {string} public_key company's public key
 * @apiParam {string} sign admin's signature
 *
 * @apiSuccess {String} result "SUCCESS"
 * @apiSuccess {String} data Empty string
 * @apiSuccess {String} msg Empty string
 *
 * @apiError  {String} result "ERROR"
 * @apiError  {String} data Empty string
 * @apiError  {String} msg Error message
 */
app.post('/v1/company', upload.array(), request_handler_company.post_company);

/**
 * @api {put} /v1/init modify company
 * @apiVersion 1.0.0
 * @apiGroup company
 * @apiDescription Modify company info
 *
 * @apiParam {string} name company name
 * @apiParam {string} access_ip company's access ip
 * @apiParam {string} public_key company's public key
 * @apiParam {string} sign admin's signature
 *
 * @apiSuccess {String} result "SUCCESS"
 * @apiSuccess {String} data Empty string
 * @apiSuccess {String} msg Empty string
 *
 * @apiError  {String} result "ERROR"
 * @apiError  {String} data Empty string
 * @apiError  {String} msg Error message
 */
app.put('/v1/company', upload.array(), request_handler_company.put_company);

// make new address
app.post('/v1/address/mtc', upload.array(), request_handler_mtc.post_address_mtc);

// data signing
app.post('/v1/sign/mtc', upload.array(), request_handler_mtc.post_sign_mtc);

// metacoin key & address save
app.post('/v1/import/mtc', upload.array(), request_handler_mtc.post_import_mtc);

// kms data generate
app.post('/v1/key', upload.array(), request_handler_key.post_key);

// kms data generate
app.post('/v1/enc', upload.array(), request_handler_key.post_enc);

// kms data generate
app.post('/v1/dec', upload.array(), request_handler_key.post_dec);


// undefine path handler
app.all('*', function (request, response) {
    response.send(404, 'Request not find');
});

app.use(function (error, req, res, next) {
    util.send_error(res, error);
});

try {
    http.createServer(app).listen(config.LISTEN_PORT, "0.0.0.0", function () {
        console.log(app_title + ' listening on port ' + config.LISTEN_PORT);
    });
} catch (err) {
    console.error(app_title + ' port ' + listen_port + ' bind error');
}
