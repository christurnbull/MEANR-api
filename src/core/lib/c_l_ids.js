'use strict';
/**
 * Intrusion Detection System library
 *
 * @module core/lib/c_l_ids
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var ExpressBrute = require('express-brute');
var RedisStore = require('express-brute-redis');
var crypto = require('crypto');

module.exports = function(app, db, lib) {

    /*
     * Secuirty stack (http & socketio):
     * HTTPS Request (json) -> CORS -> IDS -> JsonSchema -> Ratelimit -> JWT -> ACL -> HTTPS Response (json)
     *
     * IDS - simple Intrusion Detection System
     * check, deny and log requests with missing headers or xss & sqli patterns, then ban the IP
     * errHandler logs 401, 403, 404, 500 errors to security audit
     *
     * Intrusion Prevention
     * SQLi:
     *  strict json schema validates & strips out object properties that are not explicitly specified
     *  sequelize ORM sanitizes input
     *  bodyparser only uses json - not urlencoded
     * XXS:
     *  no html is/should be handled, data is parsed using standard json library after validation
     *  headers set - Content-Type: application/json, X-Content-Type-Options: nosniff
     *  input sanitized client side (angular) - https://code.angularjs.org/1.4.7/docs/misc/faq
     *  http://stackoverflow.com/questions/18673697/how-do-i-prevent-a-restful-service-from-xss-attacks
     * CRSF:
     *  no cookies being used, crsf token not deemed necessary
     *  jwt bearer tokens are not sent by the browser automatically - http://stackoverflow.com/questions/21357182/csrf-token-necessary-when-using-stateless-sessionless-authentication
     * LFI:
     *  no static files are served
     * Rate Limits:
     *  particular routes (eg auth routes) are protected by a brute force variable rate limit (express-brute)
     *  socketio events are rate limited
     *
     * follow best practice - https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
     * test routes with mocha/minigun/sqlmap
     */
    var act = {
      banSeconds: app.appCfg.ids.banSeconds,
      s: {
        msg: 'Suspicious activity which violates the T&Cs has been logged. Any malicious activity will be immediately reported to the ICCC (http:/ic3.gov), invoking a criminal investigation',
        strikes: app.appCfg.ids.strikes.suspicious
      },
      m: {
        msg: 'Malicious activity, which violates the T&Cs has been logged. A detailed report has been submitted to the ICCC (http:/ic3.gov) for criminal investigation',
        strikes: app.appCfg.ids.strikes.malicious
      },
      banned: {
        msg: ' has been banned due to suspicious or malicious activity'
      }
    };

    var patterns = {
      xss: [
        /((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/i,
      // simple
        /((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/i,
      // img
        /((\%3C)|<)[^\n]+((\%3E)|>)/i,
      // paranoid
        /(\%22)(\%20)*[a-z0-9=\%22]*/i,
        /" [a-z]*="/i
      ],
      sqli: [/(((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;)))|(\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52)))|(((\%27)|(\'))union)|(exec(\s|\+)+(s|x)p\w+)|(UNION(?:\s+ALL)?\s+SELECT)/i]
    };

    var mandatoryHeaders = [
      'host',
      'user-agent'
    ];


    /**
     * store suspicious/malicious request ips in redis for ban strikes
     */
    var logIp = function(ip, type, cb) {
      lib.core.redis.get(app.appCfg.redis.prefix.banip + ip, function(err, d) {
        var strikes = d ? JSON.parse(d) : {
          m: 0,
          s: 0,
          key: null,
          hash: null
        };
        strikes[type]++;
        lib.core.redis.setex(app.appCfg.redis.prefix.banip + ip, act.banSeconds, JSON.stringify(strikes));
        return cb();
      });
    };


    /**
     * scan http or socket io requests
     */
    function scan(req, sock, cb) {
      // whitelist urls
      if (req.url === '/audit/jsnlog') {
        return cb(null);
      }
      var headers = null,
        body = null,
        url = null;
      if (sock) {
        // socketio requests
        headers = sock.sock.handshake.headers;
        url = req[0];
        body = req[1];
      } else {
        // http requests
        headers = req.headers;
        url = req.url;
        body = JSON.stringify(req.body);
        // forbidden http methods
        if (app.appCfg.cors.allowedMethods.indexOf(req.method) === -1) {
          return cb({
            msg: 'Method not allowed',
            type: 's'
          });
        }
      }
      // mandatory headers
      for (var i = 0; i < mandatoryHeaders.length; i++) {
        if (typeof headers[mandatoryHeaders[i]] === 'undefined' || headers[mandatoryHeaders[i]] === '') {
          return cb({
            msg: 'Headers missing',
            type: 's'
          });
        }
      }
      process.nextTick(function() {
        // XXS - identify anyone probing xss urls, though we (should) never serve html so we shouldn't be vulnerable to this anyway
        // test using:  ><img src=x onerror=alert("XSS")><noscript>')
        for (var i = 0; i < patterns.xss.length; i++) {
          if (patterns.xss[i].test(url) || patterns.xss[i].test(body)) {
            return cb({
              msg: 'XSS attack detected',
              type: 'm'
            });
          }
        }
        process.nextTick(function() {
          // SQLi - identify anyone probing urls with sql injection
          // test using:  \'1\'=\'1'
          for (var i = 0; i < patterns.sqli.length; i++) {
            if (patterns.sqli[i].test(url) || patterns.sqli[i].test(body)) {
              return cb({
                msg: 'SQLi attack detected',
                type: 'm'
              });
            }
          }
          return cb(null);
        });
      });
    }


    /**
     * check ip count to determined if banned
     */
    function checkBan(ip, cb) {
      lib.core.redis.get(app.appCfg.redis.prefix.banip + ip, function(err, d) {
        if (d) {
          d = JSON.parse(d);
          if (d.s >= act.s.strikes || d.m >= act.m.strikes) {
            return cb(true);
          }
        }
        return cb(false);
      });
    }


    /**
     * Middleware
     */


    /**
     * scan socketio requests
     */
    app.io.use(function IDSsocktio(sock, args, next) {
      var ip = sock.sock.conn.remoteAddress;
      // process whitelist
      if (app.appCfg.ids.whitelist.indexOf(ip) >= 0) {
        return next();
      }
      checkBan(ip, function(banned) {
        if (banned) {
          return next(app.idsErr([{
            msg: 'IP blacklisted',
            desc: ip + act.banned.msg
          }]));
        }
        scan(args, sock, function(found) {
          if (found) {
            process.nextTick(function() {
              logIp(ip, found.type, function() {
                return next(app.idsErr([{
                  msg: found.msg,
                  desc: act[found.type].msg
                }]));
              });
            });
          } else {
            return next();
          }
        });
      });
    });


    /**
     * scan http requests
     */
    app.use(function IDS(req, res, next) {
      var ip = req.ip;
      // process whitelist
      if (app.appCfg.ids.whitelist.indexOf(ip) >= 0) {
        return next();
      }
      checkBan(ip, function(banned) {
        if (banned) {
          return next(app.idsErr([{
            msg: 'IP blacklisted',
            desc: ip + act.banned.msg
          }]));
        }
        scan(req, null, function(found) {
          if (found) {
            process.nextTick(function() {
              logIp(ip, found.type, function() {
                return next(app.idsErr([{
                  msg: found.msg,
                  desc: act[found.type].msg
                }]));
              });
            });
          } else {
            return next();
          }
        });
      });
    });


    /**
     * Rate limiting
     */


    /**
     * rate limit brute force attempts
     */
    var rateLimitBruteforce = new ExpressBrute(new RedisStore({
      client: lib.core.redis,
      prefix: app.appCfg.redis.prefix.rateLimit
    }), {
      //Start slowing requests after 50 requests
      freeRetries: 49,
      minWait: 5 * 60 * 1000, // deny all requests for 5 minutes
      maxWait: 60 * 60 * 1000, // stop slowing after 1 hour
      failCallback: function(req, res, next, nextValidRequestDate) {
        // generate key
        var hash = crypto.createHash('sha256').update(req.ip).digest('base64');
        hash += crypto.createHash('sha256').update('brute1').digest('base64');
        hash = crypto.createHash('sha256').update(hash).digest('base64');
        // store hash for ip
        var d = {
          key: 'Bruteforce',
          hash: hash
        };
        lib.core.redis.setex(app.appCfg.redis.prefix.banipRL + req.ip, 3600, JSON.stringify(d));
        return next(app.appErr([{
          msg: 'Too many requests',
          desc: 'Rate limit exceeded by IP ' + req.ip,
          status: 429
        }]));
      }
    });


    /**
     * rate limit socketio requests
     */
    var rateLimitSocketio = new ExpressBrute(new RedisStore({
      client: lib.core.redis,
      prefix: app.appCfg.redis.prefix.rateLimit
    }), {
      // no more than 1000 requests per day per IP
      freeRetries: 1000,
      attachResetToRequest: false,
      refreshTimeoutOnRequest: false,
      minWait: 25 * 60 * 1000, // 1 day 1 hour (should never reach this wait time)
      maxWait: 25 * 60 * 1000, // 1 day 1 hour (should never reach this wait time)
      lifetime: 24 * 60 * 60, // 1 day
      failCallback: function(req, res, next, nextValidRequestDate) {
        // generate key
        var hash = crypto.createHash('sha256').update(req.ip).digest('base64');
        hash += crypto.createHash('sha256').update('brute2').digest('base64');
        hash = crypto.createHash('sha256').update(hash).digest('base64');
        // store hash for ip
        var d = {
          key: 'Socketio',
          hash: hash
        };
        lib.core.redis.setex(app.appCfg.redis.prefix.banipRL + req.ip, 86400, JSON.stringify(d));
        return next(app.appErr([{
          msg: 'Too many requests',
          desc: 'Rate limit exceeded by IP ' + req.ip,
          status: 429
        }]));
      }
    });


    /**
     * expose IP to express-brute when using socketio and apply rate limit
     */
    app.io.use(function(sock, args, next) {
      sock.connection = {
        remoteAddress: sock.sock.conn.remoteAddress
      };
      next();
    });
    app.io.use(rateLimitSocketio.prevent);
    return {
      logIp: logIp,
      bruteForce: function bruteForce(req, res, next) {
        // wrap the middleware so we can name the function
        return rateLimitBruteforce.prevent(req, res, next);
      },
      bruteforce: rateLimitBruteforce.prevent
    };
  }
  /*
   * Pen testing:
   * python sqlmap.py -u "http://localhost:3000/auth" --dbms "mysql" -z "ign,flu,bat" --banner -f --data '{"email":"admin@meanr.io","password":"123"}'
   * python sqlmap.py -u "http://localhost:3000/auth/reset" --dbms "mysql" -z "ign,flu,bat" --banner -f --data '{"email":"admin@meanr.io"}'
   * python sqlmap.py -u "http://localhost:3000/auth/reset" --method=PUT --dbms "mysql" -z "ign,flu,bat" --banner -f --data '{"hashid":"test","password":"123"}'
   * python sqlmap.py -u "http://localhost:3000/auth/confirm" --dbms "mysql" -z "ign,flu,bat" --banner -f --method=PUT --data '{"hashid":"test"}'
   * python sqlmap.py -u "http://localhost:3000/auth/logout" --dbms "mysql" -z "ign,flu,bat" --banner -f
   * python sqlmap.py -u "http://localhost:3000/user" --dbms "mysql" -z "ign,flu,bat" --banner -f --data '{"email":"admin@meanr.io","password":"123"}'
   *
   */
;
