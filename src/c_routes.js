'use strict';
/**
 * Initialise routes
 *
 * @module c_routes
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var fs = require('fs');
var commentParse = require('comment-parser');
module.exports = function(app, lib) {

  var dir;

  /**
   * core routes
   */
  dir = __dirname + '/core/routes/';
  fs.readdirSync(dir).forEach(function(file) {
    if (file.substr(file.lastIndexOf('.') + 1) !== 'js') {
      return;
    }
    require(dir + file)(app, lib);
    storeDesc(dir + file, 'core');
  });


  /**
   * usr routes
   */
  dir = __dirname + '/usr/routes/';
  fs.readdirSync(dir).forEach(function(file) {
    if (file.substr(file.lastIndexOf('.') + 1) !== 'js') {
      return;
    }
    require(dir + file)(app, lib);
    storeDesc(dir + file);
  });


  /**
   * Parse route comments and store id/description
   *
   * @param {string} filepath directory and filename
   * @param {string} [core] core or usr route
   * @returns {undefined}
   */
  function storeDesc(filepath, core) {
    var src = fs.readFileSync(filepath, 'utf8');
    var cp = commentParse(src);
    cp.forEach(function(routeFunc) {
      var route = null,
        method = null,
        id = null,
        description = null,
        desc = null,
        type = null;
      routeFunc.tags.forEach(function(tag) {
        if (tag.tag === 'param' && tag.name === 'route') {
          route = tag.description;
        }
        if (tag.tag === 'param' && tag.name === 'method') {
          method = tag.description.toLowerCase();
        }
        if (tag.tag === 'description') {
          description = tag.source.replace('@description', '').trim();
        }
        if (tag.tag === 'desc') {
          desc = tag.source.replace('@desc', '').trim();
        }
      });
      if (route && method) {
        id = method + ',' + route;
        type = core ? ' (core)' : ' (usr)';
        app.appCfg.routeInfo[id] = (routeFunc.description || description || desc) + type;
      }
    });
  }
};
