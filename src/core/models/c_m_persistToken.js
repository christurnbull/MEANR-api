'use strict';
/**
 * Persistent tokens database model
 *
 * @module core/model/c_m_persistToken
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('persistToken', {
    token: Sequelize.STRING,
    provider: Sequelize.STRING,
    refreshToken: Sequelize.STRING,
    ua: Sequelize.STRING
  });
};
