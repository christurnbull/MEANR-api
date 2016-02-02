'use strict';
/**
 * Admin library
 *
 * @module core/lib/c_l_admin
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  return {

    /**
     * get all users
     */
    users: function(inObj, cb) {
      db.models.user.findAll({
        attributes: [
          'id',
          'name',
          'email',
          'confirmed',
          'revokeBefore',
          'enabled',
          'provider',
          'createdAt',
          'updatedAt'
        ],
        include: db.models.acl_users
      }).then(function(dbdata) {
        dbdata.forEach(function(item, i) {
          item.dataValues.acl_user.value = JSON.parse(item.dataValues.acl_user.value);
        });
        return cb(null, dbdata);
      }).catch(function(err) {
        return cb(err, null);
      });
    },


    /**
     * ban a user
     */
    ban: function(inObj, cb) {
      db.models.user.update({
        enabled: inObj.enabled
      }, {
        where: {
          id: inObj.userId
        }
      }).then(function(dbdata) {
        if (!dbdata[0]) {
          return cb([{
            msg: 'Could not enable/disable user'
          }], null);
        }
        lib.core.redis.set(app.appCfg.redis.prefix.revokeBefore + inObj.userId, new Date());
        // activate revokation immediately
        // delete all user's persist tokens store in db - purges stale records
        db.models.persistToken.destroy({
          where: {
            userId: inObj.userId
          }
        }).then(function(dbdata) {
          return cb(null, [{
            msg: inObj.enabled
          }]);
        }).catch(function(err) {
          return cb([{
            msg: err,
            desc: err
          }], null);
        });
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * Change a user's password
     */
    changePass: function(inObj, cb) {
      lib.core.bcrypt.hash(inObj.password, app.appCfg.jwt.saltLen, function(err, hash) {
        var revokeBefore = new Date();
        db.models.user.update({
          password: hash,
          revokeBefore: revokeBefore
        }, {
          where: {
            id: inObj.userId
          }
        }).then(function(dbdata) {
          // store password reset date in redis
          lib.core.redis.set(app.appCfg.redis.prefix.revokeBefore + inObj.userId, revokeBefore);
          // delete all user's tokens store in db - purges stale records
          db.models.persistToken.destroy({
            where: {
              userId: inObj.userId
            }
          }).then(function(dbdata) {
            return cb(null, [{
              msg: 'Password changed'
            }]);
          }).catch(function(err) {
            return cb([{
              msg: err,
              desc: err
            }], null);
          });
        }).catch(function(err) {
          return cb([{
            msg: 'User not found'
          }], null);
        });
      });
    },


    /*
     * App routes
     */
    routes: function(cb) {
      var stack = app._router.stack;
      var r = {},
        routes = {
          middleware: [],
          routes: []
        };
      var id;
      for (var k in app.appCfg.routeInfo) {
        id = k.split(',');
        if (id[0] === 'socketio') {
          stack.push({
            route: {
              methods: {
                socketio: 'true'
              },
              path: id[1]
            }
          });
        }
      }
      for (var i = 0; i < stack.length; i++) {
        if (typeof stack[i].route === 'undefined') {
          routes.middleware.push(stack[i]);
        } else {
          r = stack[i];
          var method = Object.keys(r.route.methods)[0];
          id = method + ',' + r.route.path;
          r.aclRoles = app.appCfg.aclRoles[id] || ['public'];
          r.routeInfo = app.appCfg.routeInfo[id];
          r.jsonSchema = app.appCfg.jsonSchema[id] || app.appCfg.jsonSchema.default;
          r.route.method = method.toUpperCase();
          r.route.route = r.route.path;
          routes.routes.push(r);
        }
      }
      return cb(null, [routes]);
    },


    /*
     * Banned IP addresses including rate limited. CAUTION - uses redis.keys which can block for long time
     */
    banned: function(cb) {
      var keys = app.appCfg.redis.prefix.banip + '*';
      lib.core.redis.keys(keys, function(err, k) {
        var banned = [];

        function repeater(i, l) {
          lib.core.redis.get(k[i], function(err, d) {
            if (d) {
              d = JSON.parse(d);
              var ip, type = null;
              if (d.s >= app.appCfg.ids.strikes.suspicious) {
                type = 'Suspicious';
                ip = k[i].replace(app.appCfg.redis.prefix.banip, '');
              }
              if (d.m >= app.appCfg.ids.strikes.malicious) {
                type = 'Malicious';
                ip = k[i].replace(app.appCfg.redis.prefix.banip, '');
              }
              if (d.key) {
                type = 'Rate Limit - ' + d.key;
                ip = k[i].replace(app.appCfg.redis.prefix.banipRL, '');
              }
              if (type) {
                banned.push({
                  ip: ip,
                  geo: lib.core.geoip.lookup(ip),
                  type: type,
                  hash: d.hash
                });
              }
            }
            if (i < l) {
              i++;
              process.nextTick(function() {
                repeater(i, l);
              });
              return;
            } else {
              // done
              return cb(null, banned);
            }
          });
        }
        repeater(0, k.length - 1);
      });
    },


    /*
     * Unban IP address
     */
    unban: function(inObj, cb) {
      var key, res;
      if (inObj.hash) {
        var hres;
        // rate limited
        key = app.appCfg.redis.prefix.banipRL + inObj.ip;
        hres = lib.core.redis.del(key);
        key = app.appCfg.redis.prefix.rateLimit + inObj.hash;
        hres += lib.core.redis.del(key);
        res = hres === 2 ? 1 : 0;
      } else {
        // ids
        key = app.appCfg.redis.prefix.banip + inObj.ip;
        res = lib.core.redis.del(key);
      }
      if (res) {
        return cb(null, [{
          msg: 'Unbanned'
        }]);
      } else {
        return cb([{
          msg: 'Error unbanning'
        }], null);
      }
    }
  };
};
