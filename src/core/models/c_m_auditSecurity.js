'use strict';
/**
 * Audit security database model
 *
 * @module core/model/c_m_auditSecurity
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('auditSecurity', {
    persist: Sequelize.BOOLEAN,
    name: Sequelize.STRING,
    msg: Sequelize.STRING,
    description: Sequelize.STRING,
    code: Sequelize.INTEGER,
    ip: Sequelize.STRING,
    country: Sequelize.STRING,
    ll: Sequelize.STRING,
    headers: Sequelize.TEXT,
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
