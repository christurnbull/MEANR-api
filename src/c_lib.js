'use strict';
/**
 * Golobal library
 *
 * @module c_lib
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var mailgunTransport = require('nodemailer-mailgun-transport');
var Hashids = require('hashids');
var acl = require('acl');
var aclSeq = require('acl-sequelize');
// could use redis but risk inconsistency between redis & mysql

module.exports = function(app, db) {

  /**
   * core library modules
   */
  var libEx = {
    core: {
      jwtoken: require('jsonwebtoken'),
      bcrypt: require('bcryptjs'),
      mailer: nodemailer.createTransport(mailgunTransport(app.appCfg.mailer.mailgun)),
      hashids: new Hashids(app.appCfg.hashids.salt, app.appCfg.hashids.len),
      moment: require('moment'),
      acl: new acl(new aclSeq(db, {
        prefix: 'acl_'
      })),
      redis: require(app.appCfg.redis.engine).createClient(app.appCfg.redis.port, app.appCfg.redis.host, app.appCfg.redis.options),
      eventloopLag: require('event-loop-lag')(app.appCfg.eventloop.interval),
      usage: require('usage'),
      memwatch: require('memwatch-next'),
      geoip: require('geoip-lite'),
      uaparser: require('ua-parser'),
      stripe: require('stripe')(app.appCfg.stripe.key),
      countryData: require('country-data'),
      currencySymbol: require('currency-symbol-map')
    },
    usr: {}
  };


  /**
   * IDS - simple Intrusion Detection System
   */
  libEx.core.ids = require('./core/lib/c_l_ids')(app, db, libEx);
  libEx.core.jsonSchema = require('./core/lib/c_l_jsonSchema')(app, db, libEx);
  libEx.core.global = require('./core/lib/c_l_global')(app, db, libEx);
  libEx.core.audit = require('./core/lib/c_l_audit')(app, db, libEx);
  libEx.core.auth = require('./core/lib/c_l_auth')(app, db, libEx);
  libEx.core.passport = require('./core/lib/c_l_passport')(app, db, libEx);
  libEx.core.user = require('./core/lib/c_l_user')(app, db, libEx);
  libEx.core.admin = require('./core/lib/c_l_admin')(app, db, libEx);
  libEx.core.minigun = require('./core/lib/c_l_minigun')(app, db, libEx);
  libEx.core.stripePay = require('./core/lib/c_l_stripePay')(app, db, libEx);
  libEx.core.schedule = require('./core/c_schedule')(app, db, libEx);
  require('./core/lib/c_l_init')(app, db, libEx);


  /**
   * usr library modules
   */
  libEx.usr.schedule = require('./usr/schedule')(app, db, libEx);
  return libEx;
};
