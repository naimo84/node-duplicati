import { Duplicati } from "../dist/lib";

const ev = new Duplicati({
    url: 'http://backup:8200'
});

ev.getToken().then(token => {
    ev.runBackup(3,token.token).then((data:String) => console.log(data)).catch((err)=>console.log(err));
    
})
