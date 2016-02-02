'use strict';
/**
 * Initialise server library
 *
 * @module core/lib/c_l_init
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  // create initial admin and non-admin users
  lib.core.bcrypt.hash(app.appCfg.app.defaultPassword, app.appCfg.jwt.saltLen, function(err, hash) {
    addUsers();

    function addUsers() {
      var now = new Date();
      db.models.user.findOrCreate({
        where: {
          id: 1
        },
        defaults: {
          name: app.appCfg.app.adminName,
          email: app.appCfg.app.adminEmail,
          password: hash,
          confirmed: now,
          revokeBefore: now
        }
      }).then(function(dbdata) {
        // associate acl with users table
        db.models.user.hasOne(db.models.acl_users, {
          foreignKey: 'key'
        });
        if (dbdata[1]) {
          // newly created user
          // add ACL roles for admin
          lib.core.acl.addUserRoles(1, [
            'everyone',
            'admins'
          ]);
          if (app.appCfg.app.demo) {
            // add ACL roles for users
            lib.core.acl.addUserRoles(2, [
              'everyone',
              'members'
            ]);
            lib.core.acl.addUserRoles(3, 'everyone');
            // add non-admin users
            db.models.user.bulkCreate([
              {
                name: 'Joe',
                email: 'joe@meanr.io',
                password: hash,
                confirmed: now,
                revokeBefore: now
              },
              {
                name: 'Abi',
                email: 'abi@meanr.io',
                password: hash,
                revokeBefore: now
              }
            ]);
          }
        }
      }).catch(function(err) {
        // user table not found, sync all the models
        console.log('It looks like your database was empty. If all went well the tables should now be created');
        db.sync().then(function(err) {
          addUsers();
        });
      });
    }
  });


  /**
   * on loading server put all user revokeBefore dates into redis
   * this list must be updated when user changes password and when disabling users
   */
  db.models.user.findAll({
    attributes: [
      'id',
      'revokeBefore'
    ]
  }).then(function(dbdata) {
    var multi = lib.core.redis.multi();
    for (var i = 0; i < dbdata.length; i++) {
      multi.set(app.appCfg.redis.prefix.revokeBefore + dbdata[i].dataValues.id, dbdata[i].dataValues.revokeBefore);
    }
    multi.exec(function(err, execres) {});
  });
  return;
};
