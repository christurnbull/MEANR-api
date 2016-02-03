'use strict';
/**
 * Initialise database models and relationships
 *
 * @module c_models
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var fs = require('fs');
module.exports = function(app, db) {

  //  db.sync({ force: true }) //drop and re-create tables - shortcut for dev only
  var model = {};

  /**
   * core models
   */
  fs.readdirSync(__dirname + '/core/models').forEach(function(file) {
    if (file.substr(file.lastIndexOf('.') + 1) !== 'js') {
      return;
    }
    var filename = file.substr(0, file.indexOf('.'));
    var name = filename.replace(/^c_m_/, '');
    model[name] = db.import(__dirname + '/core/models/' + filename);
  });


  /**
   * core relationships
   */
  db.models.user.hasMany(db.models.persistToken);
  db.models.user.hasMany(db.models.passport);
  db.models.user.hasMany(db.models.audit);
  db.models.user.hasMany(db.models.auditSecurity);


  /**
   * usr models
   */
  fs.readdirSync(__dirname + '/usr/models').forEach(function(file) {
    if (file.substr(file.lastIndexOf('.') + 1) !== 'js') {
      return;
    }
    var filename = file.substr(0, file.indexOf('.'));
    var name = filename.replace(/^m_/, '');
    model[name] = db.import(__dirname + '/usr/models/' + filename);
  });
  
  /**
   * usr relationships
   */


  return model; // models are available in db.models
};
