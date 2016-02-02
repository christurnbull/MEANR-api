'use strict';
/**
 * Auth routes
 *
 * @module core/routes/c_r_auth
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  var route, method, id;

  /**
   * Authorize local user
   *
   * @param route /auth
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        email: {
          type: 'string',
          format: 'email'
        },
        password: {
          type: 'string'
        },
        persist: {
          type: 'boolean'
        }
      },
      required: [
        'email',
        'password',
        'persist'
      ]
    }
  };
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function localAuth(req, res, next) {
    req.brute.reset;
    lib.core.auth.authLocal({
      email: req.body.email,
      password: req.body.password,
      persist: req.body.persist,
      ua: req.headers['user-agent']
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      req.body.password = '';
      // don't store password in audit
      res.json(data);
      lib.core.audit.log(req, 'login local');
    });
  });


  /**
   * Refresh token
   *
   * @param route /auth/refresh
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/refresh',
    method = 'post',
    id = method + ',' + route;
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(), function refresh(req, res, next) {
    req.brute.reset;
    lib.core.auth.refreshToken({
      token: req.headers.authorization,
      ip: req.ip
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Request reset password
   *
   * @param route /auth/reset
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/reset',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        email: {
          type: 'string',
          format: 'email'
        }
      },
      required: ['email']
    }
  };
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function reqPassword(req, res, next) {
    req.brute.reset;
    lib.core.auth.passResetReq({
      email: req.body.email
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Reset password on confirmation
   *
   * @param route /auth/reset
   * @param method PUT
   * @returns {Array} data or error message
   */
  route = '/auth/reset',
    method = 'put',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        hashid: {
          type: 'string'
        },
        password: {
          type: 'string',
          minLength: 6,
          maxLength: 16,
          pattern: '^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{6,16}$' // must contain at least 1 upper, lower, number
        }
      },
      required: [
        'hashid',
        'password'
      ]
    }
  };
  app.put(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function resetPassword(req, res, next) {
    req.brute.reset;
    lib.core.auth.passReset({
      hashid: req.body.hashid,
      password: req.body.password
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      res.json(data);
      req.body.password = '';
      lib.core.audit.log(req, 'reset password');
    });
  });


  /**
   * Re-send confirmation email to user
   *
   * @param route /auth/resend/:userId
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/auth/resend/:userId',
    method = 'get',
    id = method + ',' + route;
  app.get(route, lib.core.ids.bruteForce, lib.core.jsonSchema(), function resend(req, res, next) {
    req.brute.reset;
    lib.core.auth.resend({
      userId: req.params.userId
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: req.params.userId
        }
      };
      // store userId in audit log
      res.json(data);
      lib.core.audit.log(req, 'resent confirmation email');
    });
  });


  /**
   * Confirm new user
   *
   * @param route /auth/confirm
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/confirm',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        hashid: {
          type: 'string'
        }
      },
      required: ['hashid']
    }
  };
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function confirm(req, res, next) {
    req.brute.reset;
    lib.core.auth.signupConfirm({
      hashid: req.body.hashid
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      res.json(data);
      lib.core.audit.log(req, 'signup confirmed');
    });
  });


  /**
   * Logout user
   *
   * @param route /auth/logout
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/auth/logout',
    method = 'get',
    id = method + ',' + route;
  app.get(route, lib.core.ids.bruteForce, lib.core.jsonSchema(), function logout(req, res, next) {
    req.brute.reset;
    lib.core.auth.logout({
      token: req.headers.authorization,
      ip: req.ip
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      res.json(data);
      lib.core.audit.log(req, 'logout');
    });
  });


  /**
   * Revoke a persist token
   * Need userId to verify ACL. Token id is used for sql lookup, token in body to store in redis
   *
   * @param route /auth/revoke/:userId/:tid
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/revoke/:userId/:tid',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        token: {
          type: 'string'
        }
      },
      required: ['token']
    }
  };
  app.appCfg.aclRoles[id] = ['everyone'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), lib.core.auth.chk, function revoke(req, res, next) {
    req.brute.reset;
    lib.core.auth.revokeToken({
      tid: req.params.tid,
      token: req.body.token
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: req.params.userId
        }
      };
      // store userId in audit log
      res.json(data);
      lib.core.audit.log(req, 'revoke token');
    });
  });


  /**
   * Signup a new local user
   *
   * @param route /auth/signup
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/signup',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        name: {
          type: 'name'
        },
        email: {
          type: 'string',
          format: 'email'
        },
        password: {
          type: 'string',
          minLength: 6,
          maxLength: 16,
          pattern: '^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{6,16}$' // must contain at least 1 upper, lower, number
        },
        persist: {
          type: 'boolean'
        }
      },
      required: [
        'email',
        'password'
      ]
    }
  };
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function signup(req, res, next) {
    req.brute.reset;
    lib.core.auth.signup(req, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      res.json(data);
      lib.core.audit.log(req, 'signup');
    });
  });


  /**
   * Passport requests
   */


  /**
   * Redirect to oauth provider
   *
   * @param route /auth/provider
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/auth/provider',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    query: {
      type: 'object',
      strict: true,
      properties: {
        provider: {
          type: 'string'
        }
      },
      required: ['provider']
    }
  };
  app.get(route, app.session, lib.core.passport.authProvider);


  /**
   * Callback from oauth provider. Redirect to login form
   *
   * @param route /auth/provider/callback
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/auth/provider/callback',
    method = 'get',
    id = method + ',' + route;
  app.get(route, lib.core.ids.bruteForce, app.session, lib.core.passport.authProviderCb, function authProviderCb(req, res) {
    req.brute.reset;
    res.redirect(app.appCfg.passport.redirect + '?provider=' + req.session.id);
    req.session.destroy();
  });


  /**
   * Generate JWT from oauth provider callback
   *
   * @param route /auth/provider/login
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/auth/provider/login',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        sid: {
          type: 'string'
        },
        persist: {
          type: 'boolean'
        }
      },
      required: [
        'sid',
        'persist'
      ]
    }
  };
  app.post(route, lib.core.ids.bruteForce, lib.core.jsonSchema(id), function authProviderLogin(req, res, next) {
    req.brute.reset;
    lib.core.passport.authProviderLogin(req, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      req.utoken = {
        sub: {
          userId: data[0].userId
        }
      };
      // store userId in audit log
      delete data[0].userId;
      // don't issue userId
      res.json(data);
      lib.core.audit.log(req, 'login ' + data[0].provider);
    });
  });
};
