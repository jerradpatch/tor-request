"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var socks = require("socks");
var request = require("request");
var net = require("net");
var os = require("os");
var rxjs_1 = require("@reactivex/rxjs");
var TorRequest = /** @class */ (function () {
    function TorRequest() {
        this.get = this.verbFunc('get');
        this.head = this.verbFunc('head');
        this.post = this.verbFunc('post');
        this.put = this.verbFunc('put');
        this.patch = this.verbFunc('patch');
        this.del = this.verbFunc('del');
    }
    TorRequest.createProxySettings = function (ipaddress, socksPort, type) {
        var proxy_setup = {
            ipaddress: ipaddress || "localhost",
            port: socksPort || 9050,
            type: type || 5,
        };
        return proxy_setup;
    };
    TorRequest.createAgent = function (url) {
        var proxy_setup = TorRequest.createProxySettings();
        var isHttps = url.indexOf('https://') >= 0;
        var socksAgent = new socks.Agent({
            proxy: proxy_setup,
            timeout: 2 * 60 * 1000
        }, isHttps, // https
        false // rejectUnauthorized option passed to tls.connect().
        );
        return socksAgent;
    };
    TorRequest.prototype.verbFunc = function (verb) {
        var method = verb === 'del' ? 'DELETE' : verb.toUpperCase();
        return function (uri, options, callback) {
            var params = request.initParams(uri, options, callback);
            params.method = method;
            return this.torRequest(params.uri || params.url, params, params.callback);
        };
    };
    /*
     * complete list of options
     * https://www.npmjs.com/package/request
     * https://github.com/request/request
     */
    TorRequest.prototype.torRequest = function (uri, options, callback) {
        var _op = callback && options || {};
        var _cb = options && callback || options;
        var params = request.initParams(uri, _op, _cb);
        params.agent = TorRequest.createAgent(params.uri || params.url);
        return request(params, function (err, res, body) {
            // Connection header by default is keep-alive,
            // we have to manually end the socket
            var agent = params.agent;
            if (agent && agent['encryptedSocket']) {
                agent['encryptedSocket'].end();
            }
            params.callback(err, res, body);
        });
    };
    return TorRequest;
}());
exports.TorRequest = TorRequest;
//rewritten on the grounds that code requiring a response from an async request was not easily accomplished == mess to ensue
function circuitRdy(resp) {
    var allBuilt = resp.reduce(function (p, c) {
        var matches = c.match(/ BUILT |^\.$|^250/);
        return matches && matches.length > 0 && p;
    }, true);
    if (allBuilt) {
        return "success";
    }
    else {
        var someReady = resp.reduce(function (p, c) {
            return c.match(/ LAUNCHED|GUARD_WAIT|EXTENDED /) || p;
        }, false);
        if (someReady) {
            return "wait";
        }
        else {
            throw "circuit failed: " + resp;
        }
    }
}
function twoFiftyOk(resp) {
    var item = (resp && resp.length > 0 ? resp[0] : null);
    if (item == '250 OK') {
        return 'success';
    }
    else {
        throw resp;
    }
}
var commands = {
    authenticate: function (password) {
        return {
            commands: ["authenticate \"" + password + "\""],
            response: twoFiftyOk
        };
    },
    getinfo: {
        address: {
            commands: ['GETINFO address'],
            response: twoFiftyOk
        },
    },
    signal: {
        newnym: {
            commands: ['signal newnym'],
            response: twoFiftyOk,
            readyResponse: {
                commands: ['GETINFO circuit-status'],
                response: circuitRdy
            }
        }
    }
};
var Tunnel = /** @class */ (function () {
    function Tunnel(options) {
        var _this = this;
        this.options = options;
        this.subjConnected = new rxjs_1.BehaviorSubject(false);
        this.obsConnected = this.subjConnected.asObservable();
        this.subjSocketResponse = new rxjs_1.Subject();
        this.obsSocketResponse = this.subjSocketResponse.asObservable();
        this.subjSendCommand = new rxjs_1.Subject();
        this.obsConnected
            .subscribe(function (val) {
            if (val)
                _this.initCommandQueue(options);
        });
        this.initTunnel(options);
    }
    Tunnel.prototype.initTunnel = function (options) {
        var self = this;
        if (this.socketRaw) {
            this.socketRaw.destroy();
            this.socketRaw = null;
        }
        if (this.subjSocketResponse && !this.subjSocketResponse.closed) {
            this.subjSocketResponse.complete();
            this.subjSocketResponse = new rxjs_1.Subject();
            this.obsSocketResponse = this.subjSocketResponse.asObservable();
        }
        var socket = net.connect({
            host: options.host,
            port: options.controlPort
        }, function () {
            return self.rawSendData.call(self, options, commands.authenticate(options.password), true)
                .take(1)
                .subscribe(function () {
                self.subjConnected.next(true);
            }, function (err) {
                throw new Error("The client couldn't authenticate with Tor. Check that the given control port and password is correct. Error: " + err);
            });
        });
        socket.on('error', function (err) {
            self.subjSocketResponse.error(new Error("tor_client:initTunnel:error:" + err));
            self.initTunnel(self.options); //restart tunnel connection
        });
        var data = "";
        socket.on('data', function (chunk) {
            data += chunk.toString();
            if (data.endsWith("\r\n")) {
                self.subjSocketResponse.next(data.slice());
                data = "";
            }
        });
        socket.on('end', function (rdy) {
            self.subjSocketResponse.error(new Error("tor_client:initTunnel:error: socket connection closed unexpectedly"));
            self.initTunnel(self.options); //restart tunnel connection
        });
        this.socketRaw = socket;
    };
    Tunnel.prototype.initCommandQueue = function (options) {
        var _this = this;
        this.subjSendCommand.asObservable()
            .map(function (comm) {
            return _this.rawSendData(options, comm.command, comm.dontWaitForServer)
                .map(function (resp) {
                return { resp: resp, comm: comm };
            })
                .catch(function (err) {
                comm.subjResponse.error(err);
                return rxjs_1.Observable.of({ resp: '', comm: comm });
            });
        })
            .concatAll()
            .subscribe(function (respData) {
            if (!respData.comm.subjResponse.closed) {
                respData.comm.subjResponse.next(respData.resp);
                respData.comm.subjResponse.complete();
            }
        });
    };
    /**
     * sends the command and gets the response for the given command
     * ex: getinfo ipaddress => {ipaddress: "123.123.123.123"}
     * @param {ICommand} command
     * @param {boolean} waitTillServerReady
     * @returns {<{[p: string]: string}>}
     */
    Tunnel.prototype.sendCommand = function (command, dontWaitForServer) {
        var subjResp = new rxjs_1.ReplaySubject(1);
        this.subjSendCommand.next({ subjResponse: subjResp, command: command, dontWaitForServer: dontWaitForServer });
        return subjResp.asObservable().take(1);
    };
    Tunnel.prototype.rawSendData = function (options, command, dontWaitForServer) {
        var _this = this;
        var obsResp = this.rawTryAgain(command, 0)
            .switchMap(function (firstReponse) {
            return (!dontWaitForServer && command.readyResponse ?
                rxjs_1.Observable.defer(_this.rawSendData.bind(_this, options, command.readyResponse, false)) :
                rxjs_1.Observable.of(firstReponse));
        });
        return obsResp;
    };
    Tunnel.prototype.rawTryAgain = function (command, delay) {
        var _this = this;
        var obss = this.obsSocketResponse
            .take(1)
            .delay(delay)
            .map(function (res) {
            var lines = res && res.split(os.EOL).slice(0, -1).map(function (lin) {
                return (lin.endsWith("\r") ? lin.slice(0, -1) : lin);
            });
            var resp = command.response(lines);
            if (resp == 'success') {
                // let parsed = Tunnel.parseSuccessfulResponseData(res);
                return rxjs_1.Observable.of(lines);
            }
            else {
                return _this.rawTryAgain(command, 500);
            }
        })
            .switch();
        setTimeout(function () {
            var commandString = command.commands + "\n";
            _this.socketRaw.write(commandString);
        }, 0);
        return obss;
    };
    return Tunnel;
}());
var urlIfConfig = "http://api.ipify.org";
var TorClientControl = /** @class */ (function () {
    function TorClientControl(options) {
        this.options = options || {};
        TorClientControl.optionsValid(this.options);
        this.tunnel = new Tunnel(this.options);
    }
    TorClientControl.optionsValid = function (options) {
        if (options.password == 'undefined')
            throw new Error("tor_client:rawSendData: attempted to send a command without the password being set");
        options.host = options.host || 'localhost';
        options.controlPort = options.controlPort || 9051;
        options.type = options.type || 5;
    };
    TorClientControl.prototype.newTorSession = function () {
        var _this = this;
        var innerRetryCnt = 0;
        var outerRetryCnt = 0;
        return this.getTorIp()
            .switchMap(function (val) {
            if (_this.options['debug'])
                console.log("tor-request:newTorSession: sending request for new session");
            return _this.tunnel.sendCommand(commands.signal.newnym, false)
                .map(function () {
                return val;
            });
        })
            .switchMap(function (orgIpaddress) {
            return _this.getTorIp()
                .do(function (newIp) {
                if (newIp === orgIpaddress && innerRetryCnt < 10) {
                    if (_this.options['debug'])
                        console.log("tor-request:newTorSession: Ip was the same throwing, newIp: " + newIp + ", orgIpaddress: " + orgIpaddress);
                    throw "new Ip same as old " + newIp + " " + orgIpaddress;
                }
                if (_this.options['debug'])
                    console.log("tor-request:newTorSession: recieved new Ip address, newIp: " + newIp + ", orgIpaddress: " + orgIpaddress);
            })
                .retryWhen(function (errors) {
                return errors.delay(4000)
                    .do(function () {
                    if (_this.options['debug'])
                        console.log("tor-request:newTorSession: waiting 4 seconds for ip to be different, innerRetryCnt:" + innerRetryCnt);
                    innerRetryCnt++;
                });
            })
                .do(function (newIp) {
                if (innerRetryCnt > 10 && outerRetryCnt < 5) {
                    innerRetryCnt = 0;
                    throw "inner limit reached";
                }
            });
        })
            .retryWhen(function (errors) {
            return errors
                .do(function () {
                if (_this.options['debug'])
                    console.log("tor-request:newTorSession: fetching a new session, (inner wait failed), outerRetryCnt:" + outerRetryCnt);
                outerRetryCnt++;
            });
        })
            .take(1);
    };
    TorClientControl.prototype.getTorIp = function () {
        var ntr = new TorRequest();
        return rxjs_1.Observable.create(function (obs) {
            ntr.get(urlIfConfig, function (err, res, body) {
                if (err) {
                    obs.error(err);
                }
                else {
                    obs.next(body);
                }
            });
        });
    };
    return TorClientControl;
}());
exports.TorClientControl = TorClientControl;
//# sourceMappingURL=index.js.map