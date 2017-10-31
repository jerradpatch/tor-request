

import * as socks from 'socks';
import * as request from 'request';
import * as net from 'net';
import * as os from 'os';
import {BehaviorSubject, ReplaySubject, Subject, Observable} from "@reactivex/rxjs";

export class TorRequest {

    static createProxySettings(ipaddress?, port?, type?) {

        let proxy_setup = {
            ipaddress: ipaddress || "localhost", // tor address
            port: port || 9050, // tor port
            type: type || 5,
        };
        return proxy_setup;
    }

    static createAgent(url) {
        let proxy_setup = TorRequest.createProxySettings();

        let isHttps = url.indexOf('https://') >= 0;

        let socksAgent = new socks.Agent({
                proxy: proxy_setup,
            },
            isHttps, // https
            false // rejectUnauthorized option passed to tls.connect().
        );

        return socksAgent;
    }

    private verbFunc(verb) {
        let method = verb === 'del' ? 'DELETE' : verb.toUpperCase();
        return function (uri, options, callback?) {
            let params = request.initParams(uri, options, callback);
            params.method = method;
            return this.torRequest(params, params.callback);
        }
    }

    torRequest(uri, options, callback?) {
        let params = request.initParams(uri, options, callback);
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

    get = this.verbFunc('get');
    head = this.verbFunc('head');
    post = this.verbFunc('post');
    put = this.verbFunc('put');
    patch = this.verbFunc('patch');
    del = this.verbFunc('del');

}

//rewritten on the grounds that code requiring a response from an async request was not easily accomplished == mess to ensue
interface ICommand {
    commands: string[];
    response: {
        success: string
        error: string
    };
    readyResponse?: ICommand;
}

interface IOptions {
    password: string;
    host?: string;
    port?: number;
    type?: number;
}

interface ISendsCommand {
    command: ICommand,
    waitTillServerReady: boolean | 'undefined',
    subjResponse: ReplaySubject<{ [key: string]: string }>
}

class Tunnel {
    private socketRaw: net.Socket;

    private subjConnected = new BehaviorSubject<boolean>(false);
    private obsConnected = this.subjConnected.asObservable();

    private subjSocketResponse = new Subject();
    private obsSocketResponse = this.subjSocketResponse.asObservable();

    private subjSendCommand = new Subject();

    constructor(private options) {

        this.obsConnected = new BehaviorSubject<boolean>(false);
        this.initTunnel(options);
        this.initCommandQueue(options)
    }

    private initTunnel(options: IOptions) {
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
            port: options.port
        }, function(rdy){
            self.subjConnected.next(true);
        });

        socket.on('error', function(err) {
            self.subjSocketResponse.error(new Error("tor_client:initTunnel:" + err));

            self.initTunnel(self.options); //restart tunnel connection
        });

        let data = "";
        socket.on('data', function(chunk) {
            data += chunk.toString();
        });

        socket.on('end', function(rdy) {
            self.subjSocketResponse.next(data);
        });

        this.socketRaw = socket;
    }

    private initCommandQueue(options) {
        this.subjSendCommand.asObservable()
            .map((comm: ISendsCommand) => {
                return this.rawSendData(options, comm.command, comm.waitTillServerReady)
                    .map((resp) => {
                        return {resp: resp, comm: comm};
                    })
                    .catch((err) => {
                        comm.subjResponse.error(err);
                        return Observable.of({resp: '', comm: comm});
                    });
            })
            .concatAll()
            .subscribe((respData: { resp: { [key: string]: string }, comm: ISendsCommand }) => {
                if (!respData.comm.subjResponse.closed) {
                    respData.comm.subjResponse.next(respData.resp);
                    respData.comm.subjResponse.complete();
                }
            })

    }

    /**
     * sends the command and gets the response for the given command
     * ex: getinfo ipaddress => {ipaddress: "123.123.123.123"}
     * @param {ICommand} command
     * @param {boolean} waitTillServerReady
     * @returns {<{[p: string]: string}>}
     */
    public sendCommand(command: ICommand, waitTillServerReady?: boolean): Observable<{ [key: string]: string }> {
        let subjResp = new ReplaySubject<{ [key: string]: string }>(1);
        this.subjSendCommand.next({subjResponse: subjResp, command: command, waitTillServerReady: waitTillServerReady});
        return subjResp.asObservable().take(1);
    }

    private rawSendData(options: IOptions, command: ICommand, waitTillServerReady: boolean | 'undefined'): Observable<{ [key: string]: string }> {

        let obsResp = Observable.create(obs => {
            this.obsSocketResponse
                .take(1)
                .subscribe(res => {
                    switch (res) {
                        case command.response.success:
                            let parsed = Tunnel.parseSuccessfulResponseData(res);
                            obs.next(parsed);
                            obs.complete();
                            break;
                        case command.response.error:
                            obs.error(new Error("tor_client:rawSendData:" + res));
                            break;
                        default:
                            obs.error(new Error(`tor_client:rawSendData:default unknown error response, res: ${res}`));
                    }
                })
        });

        if (waitTillServerReady && command.readyResponse)
            obsResp.switchMap(this.rawSendData(options, command.readyResponse, false));

        //need to authenticate first then send commands
        let commandString = `authenticate \"${this.options.password}\"\n${command.commands}\nquit\n`;
        // let commandString = commands.join('\n') + '\n';

        this.socketRaw.write(commandString);

        return obsResp;

    }

    static parseSuccessfulResponseData(data) {
        let lines = data.split(os.EOL).slice(0, -1);

        let success = lines.every(function (val) {
            // each response from the ControlPort should start with 250 (OK STATUS)
            return val.indexOf('250') == 0;
        });

        if (success && lines.length >= 2) {
            //remove ending success lines (hold no value)
            let valueLines = lines.slice(0, lines.length - 2);

            let ret = valueLines.filter(line => {
                //remove all ok lines
                return line !== "250 OK\r";

            }).map(line => {
                //remove new line return chars
                return line.slice(4).replace(/\r?\n|\r/, "");

            }).reduce((p, c: string) => {
                //convert to an object
                let split = c.split("=");
                p[split[0]] = split[1];
                return p;

            }, {});
            return ret;
        }
    }

}

export class TorClientControl {
    static commands = {
        signal: {
            newnym: {
                commands: ['signal newnym'],
                response: {
                    success: '250 OK',
                    error: '552 Unrecognized signal'
                }
            }
        },
        getinfo: {
            address: {
                commands: ['GETINFO address'],
                response: {
                    success: '250 OK',
                    error: '551'
                }
            }
        }
    };

    private tunnel;

    constructor(options: IOptions) {
        TorClientControl.optionsValid(options);
        this.tunnel = new Tunnel(options);
    }

    static optionsValid(options: IOptions) {
        if (options.password == 'undefined')
            throw new Error("tor_client:rawSendData: attempted to send a command without the password being set");

        options.host = options.host || 'localhost';
        options.port = options.port || 9050;
        options.type = options.type || 5;
    }

    newTorSession(waitForServer?: boolean) {
        return this.tunnel.sendCommand(TorClientControl.commands.signal.newnym, waitForServer);
    }
}
