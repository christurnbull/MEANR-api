'use strict';
/**
 * Auth library
 *
 * @module core/lib/c_l_auth
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  return {

    /*
     * JWT authentication and ACL authorization middleware
     */
    chk: function authChk(req, res, next) {
      // handle http and socketio requests
      var token = null,
        body = null,
        targetUid = null,
        route = null,
        method = null;

      if (typeof req.httpVersion === 'undefined') {
        //socketio request
        body = res[1];
        // pass though json schema validator middleware first
        targetUid = body.userId;
        // for acl using socketio userId must be given in the message
        method = 'socketio';
        route = method + ',' + res[0];
        // route is the event
        token = body.token;
      } else {
        targetUid = req.params.userId;
        // for acl use userId from url param first
        if (!targetUid) {
          targetUid = req.body.userId;
        }
        // then userId in body
        if (!targetUid) {
          targetUid = req.query.userId;
        }
        // then userId in query
        method = req.method.toLowerCase();
        route = method + ',' + req.route.path;
        // static route (eg /route/:userId)
        token = req.headers.authorization;
      }

      // Check JWT - verify/refresh token
      if (!token) {
        return next(app.appErr([{
          msg: 'No token',
          status: 401
        }]));
      }
      token = token.replace(/Bearer /, '');

      lib.core.jwtoken.verify(token, app.appCfg.jwt.secret, function(err, decoded) {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            return next(app.appErr([{
              msg: 'Expired token',
              status: 401
            }]));
          } else {
            lib.core.ids.logIp(req.ip, 's', function() {});
            return next(app.appErr([{
              msg: 'Invalid token',
              status: 401
            }]));
          }
        }

        req.utoken = decoded;
        // store in req object to use later on in the route
        req.token = token;

        // invalid if password has been changed since last token issue
        lib.core.redis.get(app.appCfg.redis.prefix.revokeBefore + decoded.sub.userId, function(err, d) {
          var revokeBefore = parseInt(lib.core.moment(new Date(d)).format('X'));
          if (decoded.iat < revokeBefore) {
            return next(app.appErr([{
              msg: 'Revoked token',
              status: 401,
              desc: 'Issued using old password'
            }]));
          }

          // invalid if in revoke list (user logged out)
          lib.core.redis.get(app.appCfg.redis.prefix.revoked + token, function(err, d) {
            if (d) {
              lib.core.ids.logIp(req.ip, 's', function() {});
              return next(app.appErr([{
                msg: 'Revoked token',
                status: 401,
                desc: 'User logged out'
              }]));
            }
            // Check ACL - verify permissions.
            //	targetUid is aquired from http param/body/query or socketio message
            //  userId SHOULD ALWAYS be supplied to ensure acl are secure because it
            //	compares the static route path (eg /route/:id), not the dynamic route url (eg /route/123) or socket event
            //	if userId has been supplied and it does not match the userId in token
            //	then the route will be denied, unless is an admin - doesn't allow routes for other users
            //	if no userId is supplied the static route path is checked which in theory may allow routes for other users
            lib.core.acl.hasRole(decoded.sub.userId, 'admins', function(err, hasRole) {
              if (hasRole) {
                return next();
              }
              if (targetUid && targetUid !== decoded.sub.userId.toString()) {
                return next(app.appErr([{
                  msg: 'ACL permission denied',
                  desc: 'Bad UID',
                  status: 403
                }]));
              }
              // CAUTION - if no userId has been supplied then be careful how you use dynamic params in routes
              lib.core.acl.isAllowed(decoded.sub.userId, route, method, function(err, allow) {
                if (err || !allow) {
                  return next(app.appErr([{
                    msg: 'ACL permission denied',
                    desc: '',
                    status: 403
                  }]));
                }
                return next();
              });
            });
          });
        });
      }); // add tokens to revoke list when logging out, changing password, banning users
      // http://www.kdelemme.com/2014/05/12/use-redis-to-revoke-tokens-generated-from-jsonwebtoken/
      // http://stackoverflow.com/questions/26739167/jwt-json-web-token-automatic-prolongation-of-expiration
      /*
       * Token issue/revoke logic
       *
       * return 401 and upsert to revoke list where (check list in redis every request):
       *  iat is before pwd reset date for user (password chg func adds user id to list & ban func)
       *  token in logout list (expire same time as token expiry) (logout func adds token to list)
       *
       *
       * don't issue/refresh where (check mysql only when logging in or refreshing:
       *  token in revoke list
       *  user disabled (field in mysql, enforce immediately by changing pwd reset date)
       *  iat is more than 6 hours if via web (logout single web session only - period must be bigger than token exp period)
       *
       *
       * A revoked token means an err is sent to client. The client can then delete the token
       *
       *
       * different auth types: web & app
       * web - refresh expires, store/check logged out tokens for period of expiration in redis
       * app - refresh doesn't expire
       *    on login store each token a user has in db.
       *    on logout add token to revoke list - expire in refreshExpMin & delete from db
       *    on refresh don't re-issue if absent from db
       *    on req check revoke list for logged out tokens
       *
       *
       */
    },


    /*
     * Authorize local user
     */
    authLocal: function(inObj, cb) {
      db.models.user.find({
        where: {
          email: inObj.email
        }
      }).then(function(dbdata) {
        if (dbdata === null) {
          return cb([{
            msg: 'Not a registered email',
            status: 401
          }], null);
        }
        if (!dbdata.dataValues.enabled) {
          return cb([{
            msg: 'Account disabled',
            status: 401
          }], null);
        }
        lib.core.bcrypt.compare(inObj.password, dbdata.dataValues.password, function(err, hashres) {
          if (hashres) {
            var utoken = {
              sub: {
                userId: dbdata.dataValues.id,
                persist: inObj.persist === true ? 1 : 0 // persist - refresh does not expire - web=0 or mobile app=1
              }
            };
            var token = lib.core.jwtoken.sign(utoken, app.appCfg.jwt.secret, {
              expiresIn: app.appCfg.jwt.expiresIn
            });
            if (utoken.sub.persist) {
              db.models.persistToken.create({
                userId: utoken.sub.userId,
                token: token,
                ua: inObj.ua
              }).then(function(dbdata) {
                return cb(null, [{
                  msg: 'Token issued',
                  token: token,
                  userId: utoken.sub.userId
                }]);
              }).catch(function(err) {
                return cb([{
                  msg: 'Could not store token',
                  status: 401
                }], null);
              });
            } else {
              return cb(null, [{
                msg: 'Token issued',
                token: token,
                userId: utoken.sub.userId
              }]);
            }
          } else {
            return cb([{
              msg: 'Incorrect password',
              status: 401
            }], null);
          }
        });
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * refresh token
     */
    refreshToken: function(inObj, cb) {
      if (!inObj.token) {
        lib.core.ids.logIp(inObj.ip, 's', function() {});
        return cb([{
          msg: 'No token',
          status: 401
        }], null);
      }
      var token = inObj.token.replace(/Bearer /, '');
      lib.core.jwtoken.verify(token, app.appCfg.jwt.secret, function(err, decoded) {
        if (err) {
          if (err.name !== 'TokenExpiredError') {
            lib.core.ids.logIp(inObj.ip, 's', function() {});
            return cb([{
              msg: 'Invalid token',
              status: 401
            }], null);
          } else {
            var decodedExp = lib.core.jwtoken.decode(token);
            // don't refresh if using refresh expiry and token was issued before refresh token expiry limit
            if (!decodedExp.sub.persist && new Date().getTime() > (decodedExp.iat + app.appCfg.jwt.refreshExpiresIn) * 1000) {
              return cb([{
                msg: 'Refresh token expired',
                status: 401,
                desc: 'Refresh period expired'
              }], null);
            }
            // don't refresh if password has been changed since last token issue
            lib.core.redis.get(app.appCfg.redis.prefix.revokeBefore + decodedExp.sub.userId, function(err, d) {
              var revokeBefore = parseInt(lib.core.moment(new Date(d)).format('X'));
              if (decodedExp.iat < revokeBefore) {
                return cb([{
                  msg: 'Revoked token',
                  status: 401,
                  desc: 'Issued using old password HERE'
                }], null);
              }
              // don't refresh if in revoke list (user logged out)
              lib.core.redis.get(app.appCfg.redis.prefix.revoked + token, function(err, d) {
                if (d) {
                  lib.core.ids.logIp(inObj.ip, 's', function() {});
                  return cb([{
                    msg: 'Revoked token',
                    status: 401,
                    desc: 'User logged out'
                  }], null);
                }
                // don't refresh if user is disabled
                db.models.user.find({
                  attributes: ['enabled']
                }, {
                  where: {
                    id: decodedExp.sub.userId
                  }
                }).then(function(dbdata) {
                  if (!dbdata.dataValues.enabled) {
                    return cb([{
                      msg: 'Account disabled',
                      status: 401
                    }], null);
                  }
                  var tokenNew = lib.core.jwtoken.sign({
                    sub: decodedExp.sub
                  }, app.appCfg.jwt.secret, {
                    expiresIn: app.appCfg.jwt.expiresIn
                  });
                  // don't refresh if using no refresh exipiry and token is not stored in db
                  if (decodedExp.sub.persist) {
                    db.models.persistToken.update({
                      token: tokenNew
                    }, {
                      where: {
                        token: token,
                        userId: decodedExp.sub.userId
                      }
                    }).then(function(dbdata) {
                      if (!dbdata[0]) {
                        lib.core.ids.logIp(inObj.ip, 's', function() {});
                        return cb([{
                          msg: 'Revoked token',
                          status: 401,
                          desc: 'User logged out'
                        }], null);
                      } else {
                        return cb(null, [{
                          msg: 'Token refreshed',
                          token: tokenNew
                        }]);
                      }
                    }).catch(function(err) {
                      return cb([{
                        msg: err,
                        desc: err
                      }], null);
                    }); // TODO: check/refresh oauth provider token
                  } else {
                    return cb(null, [{
                      msg: 'Token refreshed',
                      token: tokenNew
                    }]);
                  }
                }).catch(function(err) {
                  return cb([{
                    msg: err,
                    desc: err
                  }], null);
                });
              });
            });
          }
        }
      });
    },


    /*
     * Request reset password
     */
    passResetReq: function(inObj, cb) {
      if (inObj.email.indexOf('@meanr.io') >= 0) {
        return cb([{
          msg: 'Cannot send notification.',
          desc: 'Feature disabled for demo MEANr accounts',
          status: 400
        }], null);
      }
      db.models.user.find({
        where: {
          email: inObj.email
        }
      }).then(function(dbdata) {
        if (dbdata === null) {
          return cb([{
            msg: 'Email not found',
            status: 400
          }], null);
        }
        var unhashed = new Date().getTime() + '' + dbdata.dataValues.id;
        var hashid = lib.core.hashids.encode(parseInt(unhashed));
        var mail = {
          from: 'MEANr <noreply@meanr.io>',
          to: inObj.email,
          subject: 'MEANr Reset Password',
          text: 'You recently requested to reset your passsword. Visit here to enter a new password: https://meanr.io/#!/reset/' + hashid,
          html: 'You recently requested to reset your passsword. Visit <a href="https://meanr.io/#!/reset/' + hashid + '">here</a> to enter a new password'
        };
        lib.core.mailer.sendMail(mail, function(err, info) {
          if (err) {
            return cb([{
              msg: 'Could not send notification email'
            }], null);
          }
          return cb(null, [{
            msg: 'Reset notification sent, please check your email'
          }]);
        });
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * Reset password on confirmation
     */
    passReset: function(inObj, cb) {
      var unhashed = lib.core.hashids.decode(inObj.hashid);
      unhashed = String(unhashed[0]);
      if (unhashed.length < 13) {
        lib.core.ids.logIp(inObj.ip, 's', function() {});
        return cb([{
          msg: 'Invalid hash',
          status: 401
        }], null);
      }
      var timestamp = parseInt(unhashed.substr(0, 13));
      var userId = unhashed.substr(13);
      if (new Date().getTime() > timestamp + app.appCfg.jwt.passResetExpiresIn * 1000) {
        return cb([{
          msg: 'Notification expired',
          desc: 'Request a new notification'
        }], null);
      }
      lib.core.bcrypt.hash(inObj.password, app.appCfg.jwt.saltLen, function(err, hash) {
        var revokeBefore = new Date();
        var requestDate = new Date(timestamp);
        db.models.user.update({
          password: hash,
          revokeBefore: revokeBefore
        }, {
          where: {
            id: userId,
            revokeBefore: {
              $lt: requestDate
            }
          }
        }).then(function(dbdata) {
          if (!dbdata[0]) {
            return cb([{
              msg: 'Notification already used.',
              desc: 'Request a new notification'
            }], null);
          }
          // can use only once
          // store password reset date in redis
          lib.core.redis.set(app.appCfg.redis.prefix.revokeBefore + userId, revokeBefore);
          // delete all user's tokens store in db - purges stale records
          db.models.persistToken.destroy({
            where: {
              userId: userId
            }
          }).then(function(dbdata) {
            return cb(null, [{
              msg: 'Password changed',
              userId: userId
            }]);
          });
        }).catch(function(err) {
          return cb([{
            msg: 'User not found',
            desc: err
          }], null);
        });
      });
    },


    /*
     * Confirm new user
     */
    signupConfirm: function(inObj, cb) {
      var unhashed = lib.core.hashids.decode(inObj.hashid);
      unhashed = String(unhashed[0]);
      if (unhashed.length < 13) {
        lib.core.ids.logIp(inObj.ip, 's', function() {});
        return cb([{
          msg: 'Invalid hash',
          status: 401
        }], null);
      }
      var timestamp = parseInt(unhashed.substr(0, 13));
      var userId = unhashed.substr(13);
      if (new Date().getTime() > timestamp + app.appCfg.jwt.passResetExpiresIn * 1000) {
        return cb([{
          msg: 'Notification expired'
        }], null);
      }
      timestamp = new Date();
      db.transaction().then(function(t) { // transaction
        return db.models.user.update({
          confirmed: timestamp
        }, {
          where: {
            id: userId
          },
          transaction: t
        }).then(function(dbdata) {
          if (dbdata[0]) {
            lib.core.acl.addUserRoles(userId, ['members'], function(err) {
              if (err) {
                t.rollback();
                return cb([{
                  msg: 'Error saving ACL permissions',
                  status: 401
                }], null);
              }
              t.commit();
              // TODO: send welcome email
              return cb(null, [{
                msg: 'Account confirmed',
                confirmed: timestamp,
                userId: userId
              }]);
            });
          } else {
            return cb([{
              msg: 'Unknown user',
              status: 401
            }], null);
          }
        }).catch(function(err) {
          return cb([{
            msg: err,
            desc: err
          }], null);
        }); // transaction
      });
    },


    /*
     * logout user
     */
    logout: function(inObj, cb) {
      if (inObj.token) {
        var token = inObj.token.replace(/Bearer /, '');
        if (!token) {
          return cb(null, [{
            msg: 'No token'
          }]);
        }
      }
      lib.core.jwtoken.verify(token, app.appCfg.jwt.secret, function(err, decoded) {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            return cb(null, [{
              msg: 'Expired token'
            }]);
          } else {
            lib.core.ids.logIp(inObj.ip, 's', function() {});
            return cb(null, [{
              msg: 'Invalid token'
            }]);
          }
        }
        // store token in redis until refresh expires
        lib.core.redis.setex(app.appCfg.redis.prefix.revoked + token, app.appCfg.jwt.expiresIn, 1);
        // delete from db if using persist token
        if (decoded.sub.persist) {
          db.models.persistToken.destroy({
            where: {
              userId: decoded.sub.userId,
              token: token
            }
          }).then(function(dbdata) {
            return cb(null, [{
              msg: 'Token now revoked',
              userId: decoded.sub.userId
            }]);
          }).catch(function(err) {
            return cb([{
              msg: err,
              desc: err
            }], null);
          });
        } else {
          return cb(null, [{
            msg: 'Token now revoked',
            userId: decoded.sub.userId
          }]);
        }
      });
    },


    /*
     * Revoke a persist token
     */
    revokeToken: function(inObj, cb) {
      db.models.persistToken.destroy({
        where: {
          id: inObj.tid
        }
      }).then(function(dbdata) {
        if (!dbdata) {
          return cb([{
            msg: 'Could not revoke token'
          }], null);
        }
        lib.core.redis.setex(app.appCfg.redis.prefix.revoked + inObj.token, app.appCfg.jwt.expiresIn, 1);
        return cb(null, [{
          msg: 'Revoked'
        }]);
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * Signup a new local user
     */
    signup: function(inObj, cb) {
      var plainPassword = inObj.body.password;
      lib.core.bcrypt.hash(plainPassword, app.appCfg.jwt.saltLen, function(err, hash) {
        inObj.body.password = hash;
        db.transaction().then(function(t) { // transaction
          return db.models.user.findOrCreate({
            where: {
              email: inObj.body.email
            },
            defaults: inObj.body,
            transaction: t
          }).then(function(dbdata) {
            if (!dbdata[1]) {
              return cb([
                {
                  msg: 'Email already exists, please reset you password',
                  status: 401
                },
                null
              ]);
            }
            var userId = dbdata[0].dataValues.id;
            // set ACL - add user to everyone group
            lib.core.acl.addUserRoles(userId, 'everyone', function(err) {
              if (err) {
                t.rollback();
                return cb([{
                  msg: err,
                  desc: err
                }], null);
              }
              t.commit();
              // store password reset date in redis
              lib.core.redis.set(app.appCfg.redis.prefix.revokeBefore + userId, new Date());
              var unhashed = new Date().getTime() + '' + dbdata[0].dataValues.id;
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
                  lib.core.audit.log(inObj, 'Confirmation email failed to send');
                }
              });
              lib.core.auth.authLocal({
                email: inObj.body.email,
                password: plainPassword,
                persist: inObj.body.persist
              }, function(err, data) {
                if (err) {
                  return cb(err, null);
                }
                data[0].msg = 'Signup complete, check your email to confirm your account';
                data[0].userId = userId;
                return cb(null, data);
              });
            });
          }).catch(function(err) {
            return cb([{
              msg: err,
              desc: err
            }], null);
          }); // transaction
        });
      });
    },


    /*
     * Resend a confirmation email to user
     */
    resend: function(inObj, cb) {
      db.models.user.find({
        where: {
          id: inObj.userId
        }
      }).then(function(dbdata) {
        if (dbdata === null) {
          return cb([{
            msg: 'User not found',
            status: 400
          }], null);
        }
        if (!dbdata.dataValues.email) {
          return cb([{
            msg: 'Missing email address',
            status: 400
          }], null);
        }
        var unhashed = new Date().getTime() + '' + dbdata.dataValues.id;
        var hashid = lib.core.hashids.encode(parseInt(unhashed));
        var mail = {
          from: 'MEANr <noreply@meanr.io>',
          to: dbdata.dataValues.email,
          subject: 'MEANr Signup Confirmation',
          text: 'You recently signed up to MEANr.io. Click here to confirm your account: https://meanr.io/#!/confirm/' + hashid,
          html: 'You recently signed up to MEANr.io. Click <a href="https://meanr.io/#!/confirm/' + hashid + '">here</a> to confirm your account'
        };
        lib.core.mailer.sendMail(mail, function(err, info) {
          if (err) {
            return cb([{
              msg: 'Could not send confirmation email'
            }], null);
          }
          return cb(null, [{
            msg: 'Confirmation email sent, please check your inbox'
          }]);
        });
      }).catch(function(err) {
        return cb([{
          msg: err,
          desc: err
        }], null);
      });
    },


    /*
     * Signup a new local user with strict confirmation. Need to add acl & revokeBefore after confirm
     */
    signupStrictConfirm: function(inObj, cb) {
      lib.core.bcrypt.hash(inObj.password, app.appCfg.jwt.saltLen, function(err, hash) {
        inObj.password = hash;
        inObj.confirmed = null;
        db.models.user.findOrCreate({
          where: {
            email: inObj.email
          },
          defaults: inObj
        }).then(function(dbdata) {
          if (dbdata[1]) {
            var unhashed = new Date().getTime() + '' + dbdata[0].dataValues.id;
            var hashid = lib.core.hashids.encode(parseInt(unhashed));
            var mail = {
              from: 'MEANr <noreply@meanr.io>',
              to: inObj.email,
              subject: 'MEANr Signup Confirmation',
              text: 'You recently signed up to MEANr.io. Click here to complete the signup: https://meanr.io/#!/confirm/' + hashid,
              html: 'You recently signed up to MEANr.io. Click <a href="https://meanr.io/#!/confirm/' + hashid + '">here</a> to complete the signup'
            };
            lib.core.mailer.sendMail(mail, function(err, info) {
              if (err) {
                return cb([{
                  msg: 'Could not send confirmation email'
                }], null);
              }
              return cb(null, [{
                msg: 'Sign up confirmation sent, please check your email'
              }]);
            });
          } else {
            if (dbdata[0].dataValues.confirmed) {
              return cb(null, [{
                msg: 'Email already exists, please reset you password'
              }]);
            } else {
              return cb(null, [{
                msg: 'Awaiting confirmation, please check your email'
              }]); // todo: re-send confirmation
            }
          }
        }).catch(function(err) {
          return cb([{
            msg: err,
            desc: err
          }], null);
        }).finally(function() {});
      });
    }
  };
};
