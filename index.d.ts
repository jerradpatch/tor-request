/// <reference types="request" />
import * as request from 'request';
import { Observable } from "@reactivex/rxjs";
export declare class TorRequest {
    static createProxySettings(ipaddress?: any, socksPort?: any, type?: any): {
        ipaddress: any;
        port: any;
        type: any;
    };
    static createAgent(url: any): any;
    private verbFunc(verb);
    torRequest(uri: any, options: any, callback?: any): request.Request;
    get: (uri: any, options: any, callback?: any) => any;
    head: (uri: any, options: any, callback?: any) => any;
    post: (uri: any, options: any, callback?: any) => any;
    put: (uri: any, options: any, callback?: any) => any;
    patch: (uri: any, options: any, callback?: any) => any;
    del: (uri: any, options: any, callback?: any) => any;
}
export interface IOptions {
    debug?: boolean;
    password: string;
    host?: string;
    controlPort?: number;
    socksPort?: number;
    type?: number;
}
export declare class TorClientControl {
    private tunnel;
    private options;
    constructor(options?: IOptions);
    static optionsValid(options: IOptions): any;
    newTorSession(): Observable<string>;
    private getTorIp();
}
