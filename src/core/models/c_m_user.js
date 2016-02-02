'use strict';
/**
 * User database model
 *
 * @module core/model/c_m_user
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('user', {
    name: Sequelize.STRING,
    email: Sequelize.STRING,
    password: Sequelize.STRING,
    confirmed: Sequelize.DATE,
    revokeBefore: {
      type: Sequelize.DATE,
      defaultValue: Sequelize.NOW
    },
    enabled: {
      type: Sequelize.BOOLEAN,
      defaultValue: true
    },
    provider: Sequelize.STRING,
    providerId: Sequelize.STRING
  });
};
