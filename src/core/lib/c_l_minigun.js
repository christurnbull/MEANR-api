'use strict';
/**
 * Minigun library
 *
 * @module core/lib/c_l_minigun
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var minigun = require('minigun-core');
var jsf = require('json-schema-faker');
var qs = require('querystring');

module.exports = function(app, db, lib) {

  return {

    run: function(inObj, sock, cb) {

      if (inObj.route.indexOf(':') >= 0) {
        return cb([{
          msg: 'Route parameters must be specified',
          status: 400
        }], null);
      }

      var minigunTask = {
        timestamp: new Date(),
        config: {
          target: 'http://' + app.appCfg.app.host + ':' + app.appCfg.app.port,
          phases: [{
            duration: inObj.duration,
            // seconds to run the test for
            arrivalRate: inObj.rps
          }],
          defaults: {
            headers: {
              'content-type': 'application/json',
              'user-agent': 'minigun',
              authorization: inObj.token
            }
          }
        },
        scenarios: [{
          flow: []
        }]
      };

      var schema = app.appCfg.jsonSchema[inObj.method.toLowerCase() + ',' + inObj.path] || app.appCfg.jsonSchema.default;
      var json = {};

      for (var i = 0; i < inObj.samples; i++) {
        var r = {};
        r[inObj.method.toLowerCase()] = {
          url: inObj.route,
          json: json
        };
        if (Object.keys(schema.body.properties).length > 0) {
          json = jsf(schema.body);
          r = {};
          r[inObj.method.toLowerCase()] = {
            url: inObj.route,
            json: json
          };
        }
        if (Object.keys(schema.query.properties).length > 0) {
          var sample = jsf(schema.query);
          sample = qs.stringify(sample);
          r = {};
          r[inObj.method.toLowerCase()] = {
            url: inObj.route + '?' + sample,
            json: json
          };
        }
        minigunTask.scenarios[0].flow.push(r);
      }

      var result = {
        task: minigunTask,
        report: {},
        done: false
      };

      var minigunRunner = minigun.runner(minigunTask);
      minigunRunner.on('stats', function(stats) {
        result.report = stats;
        sock.emit(sock.event, [result]);
      });

      minigunRunner.on('done', function(report) {
        result.report = report.aggregate;
        result.done = true;
        return cb(null, [result]);
      });

      minigunRunner.run();
    }
  };
};
