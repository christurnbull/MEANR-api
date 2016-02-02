'use strict';
/**
 * Audit routes
 *
 * @module core/routes/c_r_audit
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  var route, method, id;

  /**
   * Retreive audit data
   *
   * @param route /audit
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/audit',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        from: {
          type: 'string',
          format: 'date-time'
        },
        to: {
          type: 'string',
          format: 'date-time'
        },
        limit: {
          type: 'integer'
        },
        chart: {
          type: 'string'
        },
        userId: {
          type: 'string'
        },
        action: {
          type: 'string'
        },
        context: {
          type: 'string'
        },
        ip: {
          type: 'string'
        },
        country: {
          type: 'string'
        },
        ua: {
          type: 'string'
        },
        method: {
          type: 'string'
        },
        route: {
          type: 'string'
        },
        name: {
          type: 'string'
        },
        msg: {
          type: 'string'
        },
        description: {
          type: 'string'
        },
        code: {
          type: 'intger'
        },
        message: {
          type: 'string'
        },
        browser: {
          type: 'string'
        },
        os: {
          type: 'string'
        },
        device: {
          type: 'string'
        }
      },
      required: [
        'from',
        'to'
      ]
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), lib.core.auth.chk, function auditData(req, res, next) {
    lib.core.audit.data(req.body, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Typeahead for search criteria
   *
   * @param route /audit/typeahead
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/audit/typeahead',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        chart: {
          type: 'string'
        },
        userId: {
          type: 'string'
        },
        action: {
          type: 'string'
        },
        context: {
          type: 'string'
        },
        ip: {
          type: 'string'
        },
        country: {
          type: 'string'
        },
        ua: {
          type: 'string'
        },
        method: {
          type: 'string'
        },
        route: {
          type: 'string'
        },
        name: {
          type: 'string'
        },
        msg: {
          type: 'string'
        },
        description: {
          type: 'string'
        },
        code: {
          type: 'string'
        },
        message: {
          type: 'string'
        },
        browser: {
          type: 'string'
        },
        os: {
          type: 'string'
        },
        device: {
          type: 'string'
        }
      },
      maxProperties: 2,
      required: ['chart']
    }
  };
  app.appCfg.aclRoles[id] = ['admins'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), lib.core.auth.chk, function typeahead(req, res, next) {
    var model = 'audit';
    if (req.body.chart === 'security') {
      model = 'auditSecurity';
    }
    if (req.body.chart === 'JSNLog') {
      model = 'auditJSNLog';
    }
    delete req.body.chart;
    var lookup = {
      model: model,
      key: Object.keys(req.body)[0],
      val: req.body[Object.keys(req.body)[0]]
    };
    if (lookup.key === 'message') {
      lookup.val = JSON.stringify(lookup.val);
    }
    lib.core.global.typeahead(lookup, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });


  /**
   * Store jsnlog client error data
   *
   * @param route /audit/jsnlog
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/audit/jsnlog',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        r: {
          type: 'string'
        },
        lg: {
          type: 'array'
        }
      },
      required: [
        'r',
        'lg'
      ]
    }
  };
  app.appCfg.aclRoles[id] = ['everyone'];
  lib.core.acl.allow(app.appCfg.aclRoles[id], id, method);
  app.post(route, lib.core.jsonSchema(id), function auditJSNLog(req, res, next) {
    lib.core.audit.JSNLog(req, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });
};
