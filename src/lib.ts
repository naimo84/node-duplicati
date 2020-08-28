
const axios = require('axios').default;
import { Config } from 'config';
import { isNumber } from 'util';
const FormData = require('form-data')
const qs = require('querystring')
const CryptoJS = require('crypto-js');
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
const tough = require('tough-cookie');
const Cookie = tough.Cookie;

export class Duplicati {
    config: Config;
    constructor(config?: Config) {
        this.config = config;
        axiosCookieJarSupport(axios);

    }
    private sha256(to_sign) {
        var hash = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(to_sign));
        var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
        return hashInBase64.toString('base64');
    }

    public async login(password) {
        let backups = await axios.post(this.config.url + `/login.cgi`, qs.stringify({ 'get-nonce': 1 }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        let data = JSON.parse(backups.data.trim('"'));
        let salt = data.Salt;
        let nonce = data.Nonce;
        let reqex = /.*xsrf-token=(.*?); expires.*/g
        let match = reqex.exec(backups.headers['set-cookie'][0])
        let token2 = decodeURIComponent(match[1]);

        let saltedpwd = this.sha256(Buffer.concat([Buffer.from(password, 'utf-8'), Buffer.from(salt, 'base64')]));
        let noncedpwd = this.sha256(Buffer.concat([Buffer.from(nonce, 'base64'), Buffer.from(saltedpwd, 'base64')]));

        try {
            const cookieJar = new tough.CookieJar();
            cookieJar.setCookieSync(Cookie.parse(`xsrf-token=${encodeURIComponent(token2)}`), this.config.url + `/login.cgi`);
            cookieJar.setCookieSync(Cookie.parse(`session-nonce=${encodeURIComponent(nonce)}`), this.config.url + `/login.cgi`);
            let login2 = await axios.post(this.config.url + `/login.cgi`, qs.stringify({ password: noncedpwd }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                withCredentials: true,
                jar: cookieJar
            });
            let reqexauth = /.*session-auth=(.*?); expires.*/g
            let matchauth = reqexauth.exec(login2.headers['set-cookie'][0])
            let auth = decodeURIComponent(matchauth[1]);


            let reqex2 = /.*expires=(.*?);path.*/g
            let expires = new Date(reqex2.exec(login2.headers['set-cookie'][0])[1])

            return {
                auth,
                expires,
                nonce
            }
        } catch (err) {
            console.log(err)
        }
        return null;
    }

    public async getToken() {
        let reponse = await axios.get(this.config.url);
        let headers = reponse.headers['set-cookie'];
        let reqex = /.*xsrf-token=(.*?); expires.*/g
        let match = reqex.exec(headers)
        let token = decodeURIComponent(match[1]);
        let reqex2 = /.*expires=(.*?);path.*/g
        let match2 = reqex2.exec(headers)

        let token2 = new Date(decodeURIComponent(match2[1]));
        return {
            token,
            expires: token2
        };

    }

    public async getBackups(token: String) {

        let backups = await axios.get(this.config.url + '/api/v1/backups', {
            headers: {
                'x-xsrf-token': token
            }
        })
        return JSON.parse(backups.data.trim());
    }

    public async runBackup(backup: Number | any, token: string) {
        let backupId: number;
        if (isNumber(backup)) {
            backupId = backup;
        } else {
            backupId = backup.id;
        }
        let backups = await axios.post(this.config.url + `/api/v1/backup/${backupId}/run`, {}, {
            headers: {
                'x-xsrf-token': token
            }
        })
        return JSON.parse(backups.data.trim());
    }

    public async setServerstate(state, duration: string, token: string, auth?) {
        let url = this.config.url + `/api/v1/serverstate/${state}?duration=${duration}`;
        return await this.post(url, token, auth);
    }

    private async post(url, token, auth?) {
        let options = {
            headers: {
                'x-xsrf-token': token
            }
        }
        if (auth) {
            const cookieJar = new tough.CookieJar();

            cookieJar.setCookieSync(Cookie.parse(`xsrf-token=${encodeURIComponent(token)}`), url);
            cookieJar.setCookieSync(Cookie.parse(`session-nonce=${encodeURIComponent(auth.nonce)}`), url);
            cookieJar.setCookieSync(Cookie.parse(`session-auth=${encodeURIComponent(auth.auth)}`), url);
            options = Object.assign(options, {
                jar: cookieJar,
                withCredentials: true
            });
        }
        let req = await axios.post(url, {}, options);
        return JSON.parse(req.data.trim());
    }

}