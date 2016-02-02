'use strict';
/**
 * Admin routes
 *
 * @module core/routes/c_r_admin
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  var route, method, id;

  /**
   * Get all users
   *
   * @param route /admin/users
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/admin/users',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.get(route, lib.core.jsonSchema(), lib.core.auth.chk, function getUsers(req, res, next) {
    lib.core.admin.users({}, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      if (app.appCfg.app.demo) {
        data.forEach(function(user) {
          user.dataValues.email = '';
        });
      }
      res.json(data);
    });
  });


  /**
   * Ban a user - dont allow a user to login
   *
   * @param route /admin/ban/:userId
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/admin/ban/:userId',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        enabled: {
          type: 'boolean'
        }
      },
      required: ['enabled']
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), lib.core.auth.chk, function banUser(req, res, next) {
    if (app.appCfg.app.demo) {
      return res.status(400).json([{
        msg: 'Cannot ban user.',
        desc: 'Feature disabled for demo'
      }]);
    } else {
      lib.core.admin.ban({
        userId: req.params.userId,
        enabled: req.body.enabled
      }, function(err, data) {
        if (err) {
          return next(app.appErr(err));
        }
        res.json(data);
      });
    }
  });


  /**
   * Change a users password
   *
   * @param route /admin/password/:userId
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/admin/password/:userId',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        password: {
          type: 'string'
        }
      },
      required: ['password']
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), lib.core.auth.chk, function changePassword(req, res, next) {
    if (app.appCfg.app.demo) {
      return res.status(400).json([{
        msg: 'Cannot change user password.',
        desc: 'Feature disabled for demo'
      }]);
    } else {
      lib.core.admin.changePass({
        userId: req.params.userId,
        password: req.body.password
      }, function(err, data) {
        if (err) {
          return next(app.appErr(err));
        }
        res.json(data);
      });
    }
  });


  /**
   * List of http and socketio routes
   *
   * @param route /admin/routes
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/admin/routes',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.get(route, lib.core.jsonSchema(), lib.core.auth.chk, function appRoutes(req, res, next) {
    lib.core.admin.routes(function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * List of banned IP addresses
   *
   * @param route /admin/banned
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/admin/banned',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.get(route, lib.core.jsonSchema(), lib.core.auth.chk, function banned(req, res, next) {
    lib.core.admin.banned(function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Unban an IP address
   *
   * @param route /admin/banned
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/admin/banned',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        ip: {
          type: 'string'
        },
        hash: {
          type: 'string'
        }
      },
      required: ['ip']
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), lib.core.auth.chk, function banned(req, res, next) {
    lib.core.admin.unban(req.body, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Socket.io Routes
   */


  /**
   * Start load testing a route using minigun
   *
   * @param route /admin/minigun
   * @param method SOCKETIO
   * @returns {Array} data or error message
   */
  route = '/admin/minigun',
    method = 'socketio',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        route: {
          type: 'string'
        },
        path: {
          type: 'string'
        },
        method: {
          type: 'string'
        },
        duration: {
          type: 'integer'
        },
        rps: {
          type: 'integer'
        },
        samples: {
          type: 'integer'
        },
        token: {
          type: 'string'
        }
      },
      required: [
        'route',
        'path',
        'method',
        'duration',
        'rps',
        'samples'
      ]
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.io.on(route, lib.core.jsonSchema(id), lib.core.auth.chk, function minigun(sock, args, next) {
    if (app.appCfg.app.demo) {
      sock.emit('err', [{
        msg: 'Cannot run minigun test.',
        desc: 'Feature disabled for demo'
      }]);
    } else {
      var ioevt = args[0],
        iodata = args[1];
      lib.core.minigun.run(iodata, sock, function(err, data) {
        if (err) {
          return next(app.appErr(err));
        }
        sock.emit('/admin/minigun', data);
      });
    }
  });


  /**
   * Example unauthenticated socketio request
   *
   * @param route /ping
   * @param method SOCKETIO
   * @returns {Array} data or error message
   */
  route = '/ping',
    method = 'socketio',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        token: {
          type: 'string'
        },
        // every socketio request must be able to accept token
        msg: {
          type: 'string'
        }
      },
      required: ['msg']
    }
  };
  app.io.on(route, lib.core.jsonSchema(id), function ping(sock, args) {
    sock.emit('/ping', [{
      msg: 'pong'
    }]);
  });


  /**
   * Example authenticated socketio request
   *
   * @param route /ding
   * @param method SOCKETIO
   * @returns {Array} data or error message
   */
  route = '/ding',
    method = 'socketio',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        token: {
          type: 'string'
        },
        msg: {
          type: 'string'
        }
      },
      required: [
        'token',
        'msg'
      ]
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.io.on(route, lib.core.jsonSchema(id), lib.core.auth.chk, function ding(sock, args) {
    sock.emit('/ding', [{
      msg: 'dong'
    }]);
  });
};
