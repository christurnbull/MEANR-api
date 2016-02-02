'use strict';
/**
 * Passport social logins database model
 *
 * @module core/model/c_m_passport
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(db, Sequelize) {
  return db.define('passport', {
    id: {
      type: Sequelize.STRING,
      primaryKey: true
    },
    key: Sequelize.STRING,
    value: Sequelize.STRING
  });
};
