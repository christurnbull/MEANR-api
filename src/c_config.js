'use strict';
/**
 * Initialise config files
 *
 * @module c_config
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var fs = require('fs');
module.exports = function(app) {
  var config = require('../config/' + (process.env.NODE_ENV ? process.env.NODE_ENV : 'c_development') + '.js');
  app.appCfg = config;
  fs.readdirSync(__dirname + '/../config').forEach(function(file) {
    if (file.substr(file.lastIndexOf('.') + 1) !== 'js') {
      return;
    }
    var name = file.substr(0, file.indexOf('.'));
    if (name !== 'c_development' && name !== 'c_production') {
      require('../config/' + name)(app);
    }
  });
};
