'use strict';
/**
 * Stripe routes
 *
 * @module core/routes/c_r_user
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  var route, method, id;

  /**
   * Get capabilities for anonymous user
   *
   * @param route /user/capabilities
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/user/capabilities',
    method = 'get',
    id = method + ',' + route;
  app.get(route, lib.core.jsonSchema(), function getCapabilitiesAnon(req, res, next) {
    lib.core.user.capabilities({
      ip: req.ip
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Get capabilities for user
   *
   * @param route /user/capabilities/:userId
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/user/capabilities/:userId',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.aclRoles[id] = ['everyone'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.get(route, lib.core.jsonSchema(), lib.core.auth.chk, function getCapabilities(req, res, next) {
    lib.core.user.capabilities({
      userId: req.params.userId,
      ip: req.ip
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Get profile info about user
   *
   * @param route /user/:userId
   * @param method GET
   * @returns {Array} data or error message
   */
  route = '/user/:userId',
    method = 'get',
    id = method + ',' + route;
  app.appCfg.aclRoles[id] = ['everyone'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.get(route, lib.core.jsonSchema(), lib.core.auth.chk, function getProfile(req, res, next) {
    if (app.appCfg.app.demo && req.params.userId !== req.utoken.sub.userId.toString()) {
      return res.status(400).json([{
        msg: 'Cannot get other user tokens.',
        desc: 'Feature disabled for demo'
      }]);
    } else {
      lib.core.user.profile({
        userId: req.params.userId
      }, function(err, data) {
        if (err) {
          return next(app.appErr(err));
        }
        res.json(data);
      });
    }
  });


  /**
   * Update user profile
   *
   * @param route /user/:userId
   * @param method PUT
   * @returns {Array} data or error message
   */
  route = '/user/:userId',
    method = 'put',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        name: {
          type: 'string'
        },
        email: {
          type: 'string',
          format: 'email'
        }
      },
      minProperties: 1
    }
  };
  app.appCfg.aclRoles[id] = ['everyone'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  // use :userId for user ids for safer ACL
  app.put(route, lib.core.jsonSchema(id), lib.core.auth.chk, function saveProfile(req, res, next) {
    lib.core.user.profileUpdate({
      params: req.params,
      body: req.body
    }, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });
};
