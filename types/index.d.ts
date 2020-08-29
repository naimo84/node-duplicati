import { Config } from './config';

/** Declaration file generated by dts-gen */

export class Duplicati {
    constructor(config: Config);
    public getToken();
    public login(password);
    public setServerstate(state,duration,token: string, auth?);
    public runBackup(id,token)
    public getBackups(token);
}

