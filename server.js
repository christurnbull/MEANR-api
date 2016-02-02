'use strict';
/**
 * MEANr relational stack API server
 *
 * @author Chris Turnbull <https://github.com/christurnbull>
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var express = require('express');
var http = require('http');
var https = require('https');
var socketio = require('socket.io');
var ioRouter = require('socket.io-events')();
var fs = require('fs');


/**
 * create server
 */
var app = express();
require('./src/c_config')(app);
var server;
if (app.appCfg.app.ssl.enabled) {
  var credentials = {
    key: fs.readFileSync(app.appCfg.app.ssl.key),
    cert: fs.readFileSync(app.appCfg.app.ssl.cert)
  };
  server = https.createServer(credentials, app);
  console.log('Using HTTPS');
} else {
  server = http.createServer(app);
}
var io = socketio.listen(server);
io.use(ioRouter);
app.io = ioRouter;


/**
 * load files
 */
var db = require('./src/c_db-mysql')(app);
require('./src/c_models')(app, db);
var lib = require('./src/c_lib')(app, db);
require('./src/c_routes')(app, lib);
require('./src/c_errHandler')(app, lib);


/**
 * run server
 */
server.listen(app.appCfg.app.port, app.appCfg.app.host, function() {
  var protocol = app.appCfg.app.ssl.enabled ? 'https://' : 'http://';
  console.log('Server listening at', protocol + server.address().address + ':' + server.address().port);
});
