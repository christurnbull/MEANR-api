'use strict';
/**
 * Golobal error handler
 *
 * @module c_errHandler
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  /**
   * main error object
   */
  app.appErr = function(errData) {
    var message = typeof errData[0] === 'undefined' ? errData : errData[0].msg;
    var err = new Error(message);
    err.name = 'appError';
    err.msg = message;
    err.status = typeof errData[0] === 'undefined' || typeof errData[0].status === 'undefined' ? 500 : errData[0].status;
    err.desc = typeof errData[0] === 'undefined' ? '' : errData[0].desc;
    return err;
  };


  /**
   * error object for intrusion detection system
   */
  app.idsErr = function(errData) {
    var message = typeof errData[0] === 'undefined' ? errData : errData[0].msg;
    var err = new Error(message);
    err.name = 'idsError';
    err.msg = message;
    err.status = 403;
    err.desc = typeof errData[0] === 'undefined' ? '' : errData[0].desc;
    return err;
  };


  /**
   * HTTP error handler
   */
  app.use(function errHandler(err, req, res, next) {
    switch (err.name) {
      case 'appError':
        err.msg = err.message || err.msg;
        res.status(err.status).json([err]);
        err.ip = req.ip;
//        console.log(err);
        break;
      case 'idsError':
        res.status(err.status).json([err]);
        err.ip = req.ip;
//        console.log(err);
        break;
      case 'JsonSchemaValidation':
        var objType;
        if (typeof err.validations.body === 'object') {
          objType = 'body';
        } else if (typeof err.validations.query === 'object') {
          objType = 'query';
        } else {
          objType = 'params';
        }
//        console.log(err);
//        console.log(err.validations[objType]);
        var property = err.validations[objType][0].property.replace('request.' + objType + '.', '').replace('request.' + objType, '');
        err.msg = property + ' ' + err.validations[objType][0].messages[0];
        err.msg = err.msg.replace('password does not match pattern "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{6,16}$"', 'Password must contain 1 number, lowercase and uppercase character');
        res.status(400).json([{
          msg: err.msg
        }]);
        if (err.msg.indexOf('illegal property under strict mode') >= 0) {
          lib.core.ids.logIp(req.ip, 's', function() {});
        }
        break;
      default:
//        console.log('Default error handler');
//        console.log(err);
//        console.log(err.stack);
        err.msg = err.message;
        res.status(err.status).json([err]);
    }
    lib.core.audit.security(req, res, err);
  });


  /**
   * 404 not found handler
   */
  app.use(function errHandler404(req, res, next) {
    var err = app.appErr([{
      msg: 'Not found',
      status: 404,
      desc: req.url
    }]);
//    console.log(err);
    res.status(404).json([err]) //	lib.core.audit.security(req, res, err)
    ;
  });


  /**
   * socket IO error handler
   */
  app.io.use(function(err, sock, args, next) {
    switch (err.name) {
      case 'appError':
        err.msg = err.message || err.msg;
        break;
      case 'idsError':
        break;
      case 'JsonSchemaValidation':
        var property = err.validations.body[0].property.replace('request.body.', '').replace('request.body', '');
        err.msg = property + ' ' + err.validations.body[0].messages[0];
        break;
      default:
        //console.log('Default socketIO error handler');
    }
    err.ip = sock.sock.conn.remoteAddress;
//    console.log(err);
    sock.emit('err', [err]);
    var req = {
      utoken: sock.utoken,
      ip: err.ip,
      headers: sock.sock.handshake.headers,
      route: {
        path: args[0]
      },
      url: sock.sock.handshake.url,
      method: 'socketio',
      params: {
        id: sock.id
      },
      query: {},
      body: {
        msg: args[1]
      }
    };
    var res = {
      statusCode: 403
    };
    lib.core.audit.security(req, res, err);
  });


  /**
   * uncaughtException handler
   */
  process.on('uncaughtException', function(err) {
    switch (err.name) {
      case 'appError':
        console.log(err);
        break;
      default:
        console.log('uncaughtException, exiting...');
        console.log(err);
        console.log(err.stack);
        process.exit(1); // use forever in production site
    }
  });
};
