'use strict';
/**
 * Usr Scheduler
 *
 * @module core/c_schedule
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var schedule = require('node-schedule');
module.exports = function(app, db, lib) {
  schedule.scheduleJob('0,30 * * * *', function() {});
  return schedule;
};
