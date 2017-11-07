import * as socks from 'socks';
import * as request from 'request';
import * as net from 'net';
import * as os from 'os';
import { BehaviorSubject, ReplaySubject, Subject, Observable } from "@reactivex/rxjs";
export class TorRequest {
    constructor() {
        this.get = this.verbFunc('get');
        this.head = this.verbFunc('head');
        this.post = this.verbFunc('post');
        this.put = this.verbFunc('put');
        this.patch = this.verbFunc('patch');
        this.del = this.verbFunc('del');
    }
    static createProxySettings(ipaddress, socksPort, type) {
        let proxy_setup = {
            ipaddress: ipaddress || "localhost",
            port: socksPort || 9050,
            type: type || 5,
        };
        return proxy_setup;
    }
    static createAgent(url) {
        let proxy_setup = TorRequest.createProxySettings();
        let isHttps = url.indexOf('https://') >= 0;
        let socksAgent = new socks.Agent({
            proxy: proxy_setup,
        }, isHttps, // https
        false // rejectUnauthorized option passed to tls.connect().
        );
        return socksAgent;
    }
    verbFunc(verb) {
        let method = verb === 'del' ? 'DELETE' : verb.toUpperCase();
        return function (uri, options, callback) {
            let params = request.initParams(uri, options, callback);
            params.method = method;
            return this.torRequest(params.uri || params.url, params, params.callback);
        };
    }
    torRequest(uri, options, callback) {
        let _op = callback && options || {};
        let _cb = options && callback || options;
        let params = request.initParams(uri, _op, _cb);
        params.agent = TorRequest.createAgent(params.uri || params.url);
        return request(params, function (err, res, body) {
            // Connection header by default is keep-alive,
            // we have to manually end the socket
            let agent = params.agent;
            if (agent && agent['encryptedSocket']) {
                agent['encryptedSocket'].end();
            }
            params.callback(err, res, body);
        });
    }
}
//rewritten on the grounds that code requiring a response from an async request was not easily accomplished == mess to ensue
function circuitRdy(resp) {
    let allBuilt = resp.reduce((p, c) => {
        let matches = c.match(/ BUILT |^\.$|^250/);
        return matches && matches.length > 0 && p;
    }, true);
    if (allBuilt) {
        return "success";
    }
    else {
        let someReady = resp.reduce((p, c) => {
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
    let item = (resp && resp.length > 0 ? resp[0] : null);
    if (item == '250 OK') {
        return 'success';
    }
    else {
        throw resp;
    }
}
const commands = {
    authenticate: function (password) {
        return {
            commands: [`authenticate "${password}"`],
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
class Tunnel {
    constructor(options) {
        this.options = options;
        this.subjConnected = new BehaviorSubject(false);
        this.obsConnected = this.subjConnected.asObservable();
        this.subjSocketResponse = new Subject();
        this.obsSocketResponse = this.subjSocketResponse.asObservable();
        this.subjSendCommand = new Subject();
        this.obsConnected
            .subscribe((val) => {
            if (val)
                this.initCommandQueue(options);
        });
        this.initTunnel(options);
    }
    initTunnel(options) {
        let self = this;
        if (this.socketRaw) {
            this.socketRaw.destroy();
            this.socketRaw = null;
        }
        if (this.subjSocketResponse && !this.subjSocketResponse.closed) {
            this.subjSocketResponse.complete();
            this.subjSocketResponse = new Subject();
            this.obsSocketResponse = this.subjSocketResponse.asObservable();
        }
        let socket = net.connect({
            host: options.host,
            port: options.controlPort
        }, function () {
            return self.rawSendData.call(self, options, commands.authenticate(options.password), true)
                .take(1)
                .subscribe(() => {
                self.subjConnected.next(true);
            }, (err) => {
                throw new Error(`The client couldn't authenticate with Tor. Check that the given control port and password is correct. Error: ${err}`);
            });
        });
        socket.on('error', function (err) {
            self.subjSocketResponse.error(new Error("tor_client:initTunnel:error:" + err));
            self.initTunnel(self.options); //restart tunnel connection
        });
        let data = "";
        socket.on('data', function (chunk) {
            data += chunk.toString();
            if (data.endsWith("\r\n")) {
                self.subjSocketResponse.next(data.slice());
                data = "";
            }
        });
        socket.on('end', function (rdy) {
            self.subjSocketResponse.error(new Error("tor_client:initTunnel:error: socket connection closed unexpectidly"));
            self.initTunnel(self.options); //restart tunnel connection
        });
        this.socketRaw = socket;
    }
    initCommandQueue(options) {
        this.subjSendCommand.asObservable()
            .map((comm) => {
            return this.rawSendData(options, comm.command, comm.dontWaitForServer)
                .map((resp) => {
                return { resp: resp, comm: comm };
            })
                .catch((err) => {
                comm.subjResponse.error(err);
                return Observable.of({ resp: '', comm: comm });
            });
        })
            .concatAll()
            .subscribe((respData) => {
            if (!respData.comm.subjResponse.closed) {
                respData.comm.subjResponse.next(respData.resp);
                respData.comm.subjResponse.complete();
            }
        });
    }
    /**
     * sends the command and gets the response for the given command
     * ex: getinfo ipaddress => {ipaddress: "123.123.123.123"}
     * @param {ICommand} command
     * @param {boolean} waitTillServerReady
     * @returns {<{[p: string]: string}>}
     */
    sendCommand(command, dontWaitForServer) {
        let subjResp = new ReplaySubject(1);
        this.subjSendCommand.next({ subjResponse: subjResp, command: command, dontWaitForServer: dontWaitForServer });
        return subjResp.asObservable().take(1);
    }
    rawSendData(options, command, dontWaitForServer) {
        let obsResp = this.rawTryAgain(command, 0)
            .switchMap((firstReponse) => {
            return (!dontWaitForServer && command.readyResponse ?
                Observable.defer(this.rawSendData.bind(this, options, command.readyResponse, false)) :
                Observable.of(firstReponse));
        });
        return obsResp;
    }
    rawTryAgain(command, delay) {
        let obss = this.obsSocketResponse
            .take(1)
            .delay(delay)
            .map(res => {
            let lines = res && res.split(os.EOL).slice(0, -1).map((lin) => {
                return (lin.endsWith("\r") ? lin.slice(0, -1) : lin);
            });
            let resp = command.response(lines);
            if (resp == 'success') {
                // let parsed = Tunnel.parseSuccessfulResponseData(res);
                return Observable.of(lines);
            }
            else {
                return this.rawTryAgain(command, 500);
            }
        })
            .switch();
        setTimeout(() => {
            let commandString = `${command.commands}\n`;
            this.socketRaw.write(commandString);
        });
        return obss;
    }
}
const urlIfConfig = "http://api.ipify.org";
export class TorClientControl {
    constructor(options) {
        TorClientControl.optionsValid(options);
        this.tunnel = new Tunnel(options);
    }
    static optionsValid(options) {
        if (options.password == 'undefined')
            throw new Error("tor_client:rawSendData: attempted to send a command without the password being set");
        options.host = options.host || 'localhost';
        options.controlPort = options.controlPort || 9051;
        options.type = options.type || 5;
    }
    newTorSession() {
        return this.getTorIp()
            .concatMap(val => {
            return this.tunnel.sendCommand(commands.signal.newnym, false)
                .map(() => {
                return val;
            });
        })
            .switchMap((orgIpaddress) => {
            return this.getTorIp()
                .do(newIp => {
                if (newIp === orgIpaddress)
                    throw "new Ip same as old " + newIp + " " + orgIpaddress;
            })
                .retryWhen(on => on.delay(4000));
        });
    }
    getTorIp() {
        let ntr = new TorRequest();
        return Observable.create((obs) => {
            ntr.get(urlIfConfig, function (err, res, body) {
                if (err) {
                    obs.error(err);
                }
                else {
                    obs.next(body);
                }
            });
        });
    }
}
//# sourceMappingURL=index.js.map