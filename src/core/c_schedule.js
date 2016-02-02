'use strict';
/**
 * Core Scheduler
 *
 * @module core/c_schedule
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var schedule = require('node-schedule');
module.exports = function(app, db, lib) {
  schedule.scheduleJob('0,30 * * * *', function() {

    /**
     * purge all unconfirmed users that are older than refresh expiry interval
     */
    db.models.user.destroy({
      where: {
        confirmed: null,
        createdAt: {
          lt: lib.core.moment().subtract(app.appCfg.jwt.refreshExpiresIn, 'minutes').format()
        }
      }
    }).then(function(dbdata) {}).catch(function(err) {
      console.log('purge fail');
    });
  });

  return schedule;
};
