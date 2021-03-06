import {TorClientControl, TorRequest} from '../index';
import * as request from 'request';
import {Observable} from "@reactivex/rxjs";

var torOptions = {
    "debug": true,
    "password": "LoveMaoMao1234"
};

var url = "http://api.ipify.org"; // this api returns your ip in the respnose body
var tcc = new TorClientControl(torOptions);
var tr = new TorRequest();

describe('Testing request and tor-request with ControlPort enabled against ' + url, function () {
  this.timeout(15000);

  describe('test http request', function () {
    it('should return without error', function (done) {
      request(url, function (err, res, body) {
        if (err) throw err;
        console.log("The requests public ip was: " + body);
        done();
      });
    });
  });

  describe('test http tor-request', function () {
    it('should return without error', function (done) {
        request(url, function (err, res, public_ip) {
            tr.torRequest(url, function (err, res, body) {
                if (err || body == public_ip)
                    throw err || new Error("request didn't go through tor - the tor ip and pulic ip were the same.");

                console.log("The requests public_ip was: " + public_ip+ " torIp was:"+body);
                done();
            });
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
            .subscribe((ipAddress: string)=>{
                if(!ipAddress)
                    throw "invalid response, not a 250";
                done();
            }, (err)=>{
                 throw err;
            });
    });
  });

  // api.ipify.org returns your ip in the response body
  describe('verify that we have a new tor session (new ip)', function () {
    it('should return without error', function (done) {

        request(url, function (err, res, public_ip) {
            if (err)
                throw err;

            tr.torRequest(url, function (err0, res0, firstIp) {
              if(err0)
                throw err0;

              if(!firstIp)
                throw "no ip address was returned on first request";

              tcc.newTorSession()
                .subscribe((secondIp: string) => {

                  if(!secondIp)
                      throw "no ip address was returned on second request";

                  if(firstIp === secondIp || public_ip === secondIp)
                    throw `The public ip was the same as one of the tor ipAddresses; public_op: ${public_ip}, firstTorIp: ${firstIp}, secondTorIp: ${secondIp}`;

                  console.log(`success, The requests public_op: ${public_ip}, firstTorIp: ${firstIp}, secondTorIp: ${secondIp}`);

                  done();

                }, (err) => {
                    throw err;
                });
            });
        });
      });
    });

    describe('test http tor-request by requesting a new session and then fetching the webpage multiplue times', function () {
        it('All pages should have the same length and content', function (done) {

            let arrs = [];
            for(var i = 0; i < 20;++i){
                arrs.push(newSessReqPage());
            }

            Observable.from(arrs)
                .concatAll()
                .reduce((acc,curr)=>{
                    acc.push(curr);
                    return acc;
                }, [])
                .subscribe((pages: {page: string, ip: string}[])=>{
                    let errMsg = "the pages were not long enough";

                    let firstPage = pages[0];
                    if(firstPage.page.length < 10000) {
                        throw new Error(errMsg)
                    }

                    for(let i = 1; i < pages.length; ++i){
                        if(pages[i].page.length < 10000) {
                            throw new Error(errMsg)
                        }

                        done();
                    }
                });


            function newSessReqPage() {
                return tcc.newTorSession()
                    .map((val): Promise<{page: string, ip: string}> => {
                        let promReq = new Promise<any>((res, rej)=> {
                            tr.torRequest('http://animeheaven.eu', function (e, resp, body) {
                                res({page: body, ip: val});
                            });
                        });

                        return promReq;
                    })
                    .switch();
            }
        });
    });
});
