'use strict';
/**
 * Initialise databse connection
 *
 * @module c_db-mysql
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var Sequelize = require('sequelize');
module.exports = function(app) {
  var db = new Sequelize(app.appCfg.sequelize.dbname, app.appCfg.sequelize.username, app.appCfg.sequelize.password, app.appCfg.sequelize.options);
  app.Sequelize = Sequelize;
  return db;
};
