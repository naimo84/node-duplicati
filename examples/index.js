"use strict";
exports.__esModule = true;
var lib_1 = require("../dist/lib");
var ev = new lib_1.Duplicati({
    url: 'http://backup:8200'
});
ev.getToken().then(function (token) {
    ev.runBackup(3, token.token).then(function (data) { return console.log(data); })["catch"](function (err) { return console.log(err); });
});
