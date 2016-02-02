'use strict';
/**
 * User library
 *
 * @module core/lib/c_l_user
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  return {

    /*
     * User capabilities - roles, confirmed, isAdmin
     */
    capabilities: function(inObj, cb) {
      var cap = {
        name: 'Anonymous',
        provider: null,
        confirmed: null,
        noEmail: true,
        roles: [],
        passport: {},
        currency: {
          code: 'USD',
          symbol: '$'
        }
      };
      var geo = lib.core.geoip.lookup(inObj.ip);
      if (geo) {
        cap.currency.code = lib.core.countryData.countries[geo.country].currencies[0];
        cap.currency.symbol = lib.core.currencySymbol(cap.currency.code);
      }
      if (inObj.userId) {
        db.models.user.find({
          where: {
            id: inObj.userId
          },
          attributes: [
            'name',
            'email',
            'confirmed',
            'provider'
          ],
          include: [
            {
              model: db.models.acl_users
            },
            {
              model: db.models.passport,
              attributes: [
                'key',
                'value'
              ]
            }
          ]
        }).then(function(dbdata) {
          cap.name = dbdata.dataValues.name;
          cap.provider = dbdata.dataValues.provider;
          cap.confirmed = dbdata.dataValues.confirmed;
          cap.noEmail = dbdata.dataValues.email ? false : true;
          cap.roles = JSON.parse(dbdata.dataValues.acl_user.dataValues.value);
          cap.isAdmin = cap.roles.indexOf('admins') >= 0 ? true : false;
          for (var i = 0; i < dbdata.dataValues.passports.length; i++) {
            cap.passport[dbdata.dataValues.passports[i].key] = dbdata.dataValues.passports[i].value;
          }
          return cb(null, [cap]);
        }).catch(function(err) {
          return cb(err, null);
        });
      } else {
        return cb(null, [cap]);
      }
    },


    /*
     * Profile info
     */
    profile: function(inObj, cb) {
      db.models.user.findAll({
        where: {
          id: inObj.userId
        },
        attributes: [
          [
            'id',
            'userId'
          ],
          'name',
          'email'
        ],
        include: db.models.persistToken
      }).then(function(dbdata) {
        if (!dbdata || dbdata.length === 0) {
          return cb([{
            msg: 'User not found',
            status: 400
          }], null);
        }
        return cb(null, dbdata);
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * Profile info update
     */
    profileUpdate: function(inObj, cb) {
      var criteria = {
        id: inObj.params.userId
      };
      if (inObj.body.email) {
        criteria.email = null;
      }
      db.models.user.update(inObj.body, {
        where: criteria
      }).then(function(dbdata) {
        if (!dbdata[0]) {
          return cb([{
            msg: 'Could not save.',
            desc: 'An email address cannot be changed'
          }], null);
        }
        if (inObj.body.email) {
          var unhashed = new Date().getTime() + '' + inObj.params.userId;
          var hashid = lib.core.hashids.encode(parseInt(unhashed));
          var mail = {
            from: 'MEANr <noreply@meanr.io>',
            to: inObj.body.email,
            subject: 'MEANr Signup Confirmation',
            text: 'You recently signed up to MEANr.io. Click here to confirm your account: https://meanr.io/#!/confirm/' + hashid,
            html: 'You recently signed up to MEANr.io. Click <a href="https://meanr.io/#!/confirm/' + hashid + '">here</a> to confirm your account'
          };
          lib.core.mailer.sendMail(mail, function(err, info) {
            if (err) {
              return cb([{
                msg: 'Saved.',
                desc: 'But we could not send the confirmation email'
              }], null);
            }
            return cb(null, [{
              msg: 'Saved.',
              desc: 'Confirmation email has been sent'
            }]);
          });
        } else {
          return cb(null, [{
            msg: 'Saved'
          }]);
        }
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    }
  };
};
