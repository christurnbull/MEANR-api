'use strict';
/**
 * Express config
 *
 * @module config/c_express
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var session = require('express-session');
var bodyParser = require('body-parser');
var compression = require('compression');
var morgan = require('morgan');
var toobusy = require('toobusy-js');

module.exports = function(app) {

  /**
   * use session store only for social login routes (required by Oauth1)
   */
  app.session = session({
    resave: false,
    saveUninitialized: false,
    secret: app.appCfg.passport.sessionSecret
  });
  app.use(bodyParser.json());
  app.use(compression());
  app.set('trust proxy', true);


  /**
   * CORS
   */
  if (app.appCfg.cors.enabled) {
    app.use(function CORS(req, res, next) {
      res.header('Access-Control-Allow-Credentials', true);
      res.header('Access-Control-Allow-Origin', app.appCfg.cors.allowedOrigins);
      res.header('Access-Control-Allow-Headers', app.appCfg.cors.allowedHeaders);
      res.header('Access-Control-Allow-Methods', app.appCfg.cors.allowedMethods);
      next();
    });
  }


  /**
   * return options requests immediately, add custom headers
   */
  app.use(function OPTIONSOK(req, res, next) {
    res.header('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    next();
  });


  /**
   * gracefully handle high load
   */
  toobusy.maxLag(app.appCfg.app.tooBusyLag);
  app.use(function tooBusy(req, res, next) {
    if (toobusy()) {
      throw {
        name: 'appError',
        msg: 'Too busy',
        status: 503
      };
    } else {
      next();
    }
  });


  /**
   * common log format
   */
  morgan.token('msg', function(req, res) {
    return req.msg;
  });
  app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" ":msg"'));
  //app.use(morgan(':method :url :status :response-time ms - :res[content-length] ":msg"'));


  /**
   * store info about routes
   */
  app.appCfg.routeInfo = {}; // store info/description of each route
  app.appCfg.aclRoles = {}; // store assigned roles for each route

};
