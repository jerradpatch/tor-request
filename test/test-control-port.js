"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("../index");
var request = require("request");
var url = "http://api.ipify.org"; // this api returns your ip in the respnose body
var httpsUrl = "https://api.ipify.org";
var tcc = new index_1.TorClientControl({ password: '' });
var tr = new index_1.TorRequest();
describe('Testing request and tor-request with ControlPort enabled against ' + url, function () {
    this.timeout(15000);
    var public_ip = "";
    var tor_ip = "";
    describe('test http request', function () {
        it('should return without error', function (done) {
            request(url, function (err, res, body) {
                if (err)
                    throw err;
                console.log("The requests public ip was: " + body);
                public_ip = body;
                done();
            });
        });
    });
    describe('test http tor-request', function () {
        it('should return without error', function (done) {
            tr.torRequest(url, function (err, res, body) {
                if (err || body == public_ip)
                    throw err || new Error("request didn't go through tor - the tor ip and pulic ip were the same.");
                console.log("The requests public ip was: " + body);
                tor_ip = body;
                done();
            });
        });
    });
    /**
     * Test optional ControlPort Configuration
     * see: https://github.com/talmobi/tor-request#optional-configuring-tor-enabling-the-controlport
     */
    describe('request a new tor session with tr.newTorSession', function () {
        it('should return without error', function (done) {
            tcc.newTorSession()
                .subscribe(function (response) {
                done();
            }, function (err) {
                throw err;
            });
        });
    });
    // api.ipify.org returns your ip in the response body
    describe('verify that we have a new tor session (new ip)', function () {
        it('should return without error', function (done) {
            tr.torRequest(url, function (err0, res0, body0) {
                if (err0)
                    throw err0;
                if (!body0)
                    throw "no ip address was returned on first request";
                tcc.newTorSession()
                    .subscribe(function (response) {
                    tr.torRequest(url, function (err, res, body) {
                        if (err)
                            throw err;
                        if (!body)
                            throw "no ip address was returned on second request";
                        if (body0 === body || public_ip === body0 || public_ip === body)
                            throw "The public ip was the same as one of the tor ipAddresses; public_op: " + public_ip + ", firstTorIp: " + body0 + ", secondTorIp: " + body;
                        console.log("success, The requests public_op: " + public_ip + ", firstTorIp: " + body0 + ", secondTorIp: " + body);
                        tor_ip = body;
                        done();
                    });
                }, function (err) {
                    throw err;
                });
            });
        });
    });
});
