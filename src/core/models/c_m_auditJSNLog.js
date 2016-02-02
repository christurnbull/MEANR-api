'use strict';
/**
 * Audit JSNLog database model
 *
 * @module core/model/c_m_auditJSNLog
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('auditJSNLog', {
    name: Sequelize.STRING,
    message: Sequelize.STRING,
    logData: Sequelize.TEXT,
    stack: Sequelize.TEXT,
    route: Sequelize.TEXT,
    userId: Sequelize.INTEGER,
    persist: Sequelize.BOOLEAN,
    browser: Sequelize.STRING,
    browserMajor: Sequelize.STRING,
    browserMinor: Sequelize.STRING,
    browserPatch: Sequelize.STRING,
    os: Sequelize.STRING,
    osMajor: Sequelize.STRING,
    osMinor: Sequelize.STRING,
    osPatch: Sequelize.STRING,
    device: Sequelize.STRING
  });
};
