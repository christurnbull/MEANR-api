'use strict';
/**
 * Global library
 *
 * @module core/lib/c_l_global
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  return {

    /**
     * Typeahead - lookup a value given a key (field) and model
     * CAUTION - use safely, this can retrieve ANY data rom the db
     */
    typeahead: function(inObj, cb) {
      var where = {};
      where[inObj.key] = {
        like: '%' + inObj.val + '%'
      };
      db.models[inObj.model].findAll({
        where: where,
        attributes: [[
          app.Sequelize.literal('DISTINCT `' + inObj.key + '`'),
          inObj.key
        ]]
      }).then(function(dbdata) {
        return cb(null, dbdata);
      }).catch(function(err) {
        if (err.message.indexOf('ER_BAD_FIELD_ERROR') >= 0) {
          return cb([{
            msg: 'Bad field',
            status: 400
          }], null);
        }
        return cb(err, null);
      });
    }
  };
};
