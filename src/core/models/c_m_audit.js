'use strict';
/**
 * Audit database model
 *
 * @module core/model/c_m_audit
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('audit', {
    persist: Sequelize.BOOLEAN,
    action: Sequelize.STRING,
    context: Sequelize.STRING,
    ip: Sequelize.STRING,
    country: Sequelize.STRING,
    ll: Sequelize.STRING,
    ua: Sequelize.STRING,
    route: Sequelize.STRING,
    url: Sequelize.STRING,
    method: Sequelize.STRING,
    params: Sequelize.STRING,
    query: Sequelize.STRING,
    body: Sequelize.TEXT,
    lag: Sequelize.FLOAT,
    cpu: Sequelize.FLOAT,
    memory: Sequelize.INTEGER,
    duration: Sequelize.INTEGER,
    timestamp: Sequelize.BIGINT
  });
};
