'use strict';
/**
 * Audit library
 *
 * @module core/lib/c_l_audit
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var os = require('os');
module.exports = function(app, db, lib) {

  /*
   * Cache log entries and bulk create
   */
  var prefix = app.appCfg.redis.prefix.audit;
  var cacheKey = prefix + 'a',
    cacheKeySecurity = prefix + 'as',
    cacheKeyJSNLog = prefix + 'aj';

  setInterval(function() {
    var k = cacheKey,
      ks = cacheKeySecurity,
      kj = cacheKeyJSNLog;

    // divert new log entries to other key during interval
    // stops log entries being missed whilst storing in db
    if (cacheKey === prefix + 'a') {
      cacheKey = prefix + 'b';
      cacheKeySecurity = prefix + 'bs';
      cacheKeyJSNLog = prefix + 'bj';
    } else {
      cacheKey = prefix + 'a';
      cacheKeySecurity = prefix + 'as';
      cacheKeyJSNLog = prefix + 'aj';
    }

    // create audit records in db
    lib.core.redis.lrange(k, 0, -1, function(err, d) {
      if (d.length > 0) {
        var kRows = [];
        for (var ik = 0; ik < d.length; ik++) {
          kRows.push(JSON.parse(d[ik]));
        }
        db.models.audit.bulkCreate(kRows).then(function() {
          lib.core.redis.del(k);
        });
      }
    });

    // create security records in db
    lib.core.redis.lrange(ks, 0, -1, function(err, d) {
      if (d.length > 0) {
        var ksRows = [];
        for (var iks = 0; iks < d.length; iks++) {
          ksRows.push(JSON.parse(d[iks]));
        }
        db.models.auditSecurity.bulkCreate(ksRows).then(function() {
          lib.core.redis.del(ks);
        });
      }
    });

    // create JSNLog records in db
    lib.core.redis.lrange(kj, 0, -1, function(err, d) {
      if (d.length > 0) {
        var kjRows = [];
        for (var ikj = 0; ikj < d.length; ikj++) {
          kjRows.push(JSON.parse(d[ikj]));
        }
        db.models.auditJSNLog.bulkCreate(kjRows).then(function() {
          lib.core.redis.del(kj);
        });
      }
    });
  }, app.appCfg.app.auditCachePeriod);


  /*
   * log memory leaks to secuirty log
   */
  lib.core.memwatch.on('leak', function(info) {
    lib.core.usage.lookup(process.pid, {
      keepHistory: true
    }, function(err, usage) {
      var la = os.loadavg();
      var audit = {
        userUid: null,
        persist: null,
        name: 'Memory leak',
        msg: info.growth,
        description: info.reason,
        code: null,
        ip: null,
        country: null,
        ll: null,
        headers: null,
        route: null,
        url: null,
        method: 'memwatch',
        params: null,
        query: null,
        body: JSON.stringify(info),
        lag: lib.core.eventloopLag(),
        cpu: isFinite(usage.cpu) ? usage.cpu : la[0],
        memory: usage.memory,
        duration: info.end - info.start,
        timestamp: new Date().getTime()
      };
      audit.duration = isFinite(audit.duration) ? audit.duration : null;
      lib.core.redis.rpush(cacheKeySecurity, audit);
    });
  });


  /*
   * public
   */
  return {

    /**
     * get audit data
     */
    data: function(inObj, cb) {
      var chart = inObj.chart;
      var model = 'audit';
      if (chart === 'security') {
        model = 'auditSecurity';
      }
      if (chart === 'JSNLog') {
        model = 'auditJSNLog';
      }
      var query = {
        where: {
          createdAt: {
            $between: [
              inObj.from,
              inObj.to
            ]
          }
        },
        order: chart === 'JSNLog' ? 'createdAt DESC' : 'timestamp DESC',
        limit: inObj.limit
      };
      delete inObj.from;
      delete inObj.to;
      delete inObj.limit;
      delete inObj.chart;
      for (var k in inObj) {
        query.where[k] = inObj[k];
      }
      db.models[model].findAll(query).then(function(dbdata) {
        return cb(null, dbdata);
      }).catch(function(err) {
        return cb(err, null);
      });
    },


    /**
     *  log activity
     */
    log: function auditLog(req, action, context) {
      process.nextTick(function() {
        if (app.appCfg.app.demo) {
          req.body = {
            msg: 'Data removed for demo'
          };
        }
        var userId = null,
          persist = null;
        if (typeof req.utoken === 'object') {
          userId = req.utoken.sub.userId;
          persist = req.utoken.sub.persist;
        } else if (app.appCfg.app.activityAudit === 'authOnly') {
          return;
        }
        if (!app.appCfg.app.activityAudit) {
          return;
        }
        lib.core.usage.lookup(process.pid, {
          keepHistory: true
        }, function(uerr, usage) {
          var la = os.loadavg();
          var geo = lib.core.geoip.lookup(req.ip);
          var audit = {
            userId: userId,
            persist: persist,
            action: action,
            context: JSON.stringify(context),
            ip: req.ip,
            country: geo === null ? null : geo.country,
            ll: geo === null ? null : JSON.stringify(geo.ll),
            ua: req.headers['user-agent'],
            route: req.route.path,
            url: req.url,
            method: req.method,
            params: Object.keys(req.params).length === 0 ? null : JSON.stringify(req.params),
            query: Object.keys(req.query).length === 0 ? null : JSON.stringify(req.query),
            body: Object.keys(req.body).length === 0 ? null : JSON.stringify(req.body),
            lag: lib.core.eventloopLag(),
            cpu: la[0],
            //			cpu: isFinite(usage.cpu) ? usage.cpu : la[0],
            memory: usage.memory,
            duration: new Date() - req._startTime,
            timestamp: new Date().getTime()
          };
          audit.duration = isFinite(audit.duration) ? audit.duration : null;
          lib.core.redis.rpush(cacheKey, JSON.stringify(audit));
        });
      });
      return;
    },


    /**
     * log security
     */
    security: function auditSecurityLog(req, res, err) {
      process.nextTick(function() {
        if (app.appCfg.app.demo) {
          req.body = {
            msg: 'Data removed for demo'
          };
        }
        var userId = null,
          persist = null;
        if (typeof req.utoken === 'object') {
          userId = req.utoken.sub.userId;
          persist = req.utoken.sub.persist;
        }
        lib.core.usage.lookup(process.pid, {
          keepHistory: true
        }, function(uerr, usage) {
          var la = os.loadavg();
          var geo = lib.core.geoip.lookup(req.ip);
          var audit = {
            userId: userId,
            persist: persist,
            name: err.name,
            msg: err.msg,
            description: err.desc,
            code: res.statusCode,
            ip: req.ip,
            country: geo === null ? null : geo.country,
            ll: geo === null ? null : JSON.stringify(geo.ll),
            headers: JSON.stringify(req.headers),
            route: typeof req.route === 'undefined' ? null : req.route.path,
            url: req.url,
            method: req.method,
            params: Object.keys(req.params).length === 0 ? null : JSON.stringify(req.params),
            query: Object.keys(req.query).length === 0 ? null : JSON.stringify(req.query),
            body: Object.keys(req.body).length === 0 ? null : JSON.stringify(req.body),
            lag: lib.core.eventloopLag(),
            cpu: la[0],
            //			cpu: isFinite(usage.cpu) ? usage.cpu : la[0],
            memory: usage.memory || 0,
            duration: new Date() - req._startTime,
            timestamp: new Date().getTime()
          };
          audit.duration = isFinite(audit.duration) ? audit.duration : null;
          lib.core.redis.rpush(cacheKeySecurity, JSON.stringify(audit));
        });
      });
      return;
    },


    /**
     * log JSNLog
     */
    JSNLog: function JSNLog(inObj, cb) {
      process.nextTick(function() {
        var d = {};
        try {
          var json = JSON.parse(inObj.body.lg[0].m);
          d.name = json.name;
          d.message = json.message;
          d.logData = json.logData;
          d.stack = json.stack;
          if (!d.name && !d.message && !d.stack) {
            d.stack = inObj.body.lg[0].m;
          }
          d.route = inObj.headers['jsnlog-route'];
        } catch (e) {
          d.message = inObj.body.lg[0].m;
        }
        var uao = lib.core.uaparser.parse(inObj.headers['user-agent']);
        d.browser = uao.ua.family;
        d.browserMajor = uao.ua.major;
        d.browserMinor = uao.ua.minor;
        d.browserPatch = uao.ua.patch;
        d.os = uao.os.family;
        d.osMajor = uao.os.major;
        d.osMinor = uao.os.minor;
        d.osPatch = uao.os.patch;
        d.device = uao.device.family;
        if (inObj.headers.authorization) {
          var token = inObj.headers.authorization.replace(/Bearer /, '');
          lib.core.jwtoken.verify(token, app.appCfg.jwt.secret, function(err, decoded) {
            if (decoded) {
              d.userId = decoded.sub.userId;
              d.persist = decoded.sub.persist;
              lib.core.redis.rpush(cacheKeyJSNLog, JSON.stringify(d));
              return cb(null, [{
                msg: 'Logged'
              }]);
            }
          });
        } else {
          lib.core.redis.rpush(cacheKeyJSNLog, JSON.stringify(d));
          return cb(null, [{
            msg: 'Logged'
          }]);
        }
      });
      return;
    }
  };
};
