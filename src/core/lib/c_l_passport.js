'use strict';
/**
 * Passport library
 *
 * @module core/lib/c_l_passport
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var passport = require('passport');
var GitHubStrategy = require('passport-github').Strategy;
var LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var FacebookStrategy = require('passport-facebook');
var TwitterStrategy = require('passport-twitter').Strategy;


module.exports = function(app, db, lib) {

  var github = new GitHubStrategy(app.appCfg.passport.github, function(accessToken, refreshToken, profile, done) {
    return done(null, {
      accessToken: accessToken,
      profile: profile
    });
  });
  passport.use(github);
  var linkedin = new LinkedInStrategy(app.appCfg.passport.linkedin, function(accessToken, refreshToken, profile, done) {
    return done(null, {
      accessToken: accessToken,
      profile: profile
    });
  });
  passport.use(linkedin);
  var google = new GoogleStrategy(app.appCfg.passport.google, function(accessToken, refreshToken, profile, done) {
    return done(null, {
      accessToken: accessToken,
      profile: profile
    });
  });
  passport.use(google);
  var facebook = new FacebookStrategy(app.appCfg.passport.facebook, function(token, tokenSecret, profile, done) {
    return done(null, {
      accessToken: token,
      profile: profile
    });
  });
  passport.use(facebook);
  var twitter = new TwitterStrategy(app.appCfg.passport.twitter, function(token, tokenSecret, profile, done) {
    return done(null, {
      accessToken: token,
      profile: profile
    });
  });
  passport.use(twitter);


  /**
   * public
   */
  return {

    /*
     * Redirect to oauth provider
     */
    authProvider: function authProvider(req, res, next) {
      var state = req.query.provider;
      var scope = '';
      if (req.query.provider === 'google') {
        scope = 'profile';
      }
      req.session.regenerate(function() {
        return passport.authenticate(req.query.provider, {
          scope: scope,
          state: state,
          display: 'popup'
        })(req, res, next);
      });
    },


    /*
     * oauth provider callback
     */
    authProviderCb: function authProviderCb(req, res, next) {
      var provider;
      if (req.session.hasOwnProperty('oauth:twitter')) {
        provider = 'twitter';
      } else {
        provider = req.query.state;
      }
      return passport.authenticate(provider, function(err, user, info) {
        if (err) {
          return next(app.appErr([{
            msg: 'Social login failed',
            status: 401
          }]));
        }
        //		console.log(user)
        lib.core.redis.setex(app.appCfg.redis.prefix.provider + req.session.id, 120, JSON.stringify(user));
        return next();
      })(req, res, next);
    },


    /*
     * Login user
     */
    authProviderLogin: function(inObj, cb) {
      lib.core.redis.get(app.appCfg.redis.prefix.provider + inObj.body.sid, function(err, d) {
        if (!d) {
          return cb([{
            msg: 'Login timeout',
            status: 401
          }], null);
        }
        d = JSON.parse(d);
        db.transaction().then(function(t) { // transaction
          var criteria = {
            provider: d.profile.provider,
            providerId: d.profile.id
          };
          var defaults = criteria;
          defaults.name = d.profile.displayName;
          return db.models.user.findOrCreate({
            where: criteria,
            defaults: defaults,
            transaction: t
          }).then(function(dbdataUser) {
            // store profile data
            var userId = dbdataUser[0].dataValues.id;
            var profileUrl, avatarUrl;
            switch (d.profile.provider) {
              case 'github':
                profileUrl = d.profile.profileUrl;
                avatarUrl = d.profile._json.avatar_url;
                break;
              case 'linkedin':
                profileUrl = d.profile._json.publicProfileUrl;
                avatarUrl = d.profile._json.pictureUrl;
                break;
              case 'google':
                profileUrl = null;
                avatarUrl = d.profile._json.image.url;
                break;
              case 'facebook':
                profileUrl = d.profile.profileUrl;
                avatarUrl = 'http://graph.facebook.com/' + d.profile.id + '/picture?type=square';
                break;
              case 'twitter':
                profileUrl = 'https://twitter.com/' + d.profile.username;
                avatarUrl = d.profile._json.profile_image_url_https;
                break;
              default:
                profileUrl = null;
                avatarUrl = null;
            }
            var profileData = [
              {
                id: userId + '-id',
                userId: userId,
                key: 'id',
                value: d.profile.id
              },
              {
                id: userId + '-displayName',
                userId: userId,
                key: 'displayName',
                value: d.profile.displayName
              },
              {
                id: userId + '-profileUrl',
                userId: userId,
                key: 'profileUrl',
                value: profileUrl
              },
              {
                id: userId + '-avatarUrl',
                userId: userId,
                key: 'avatarUrl',
                value: avatarUrl
              }
            ];
            return db.models.passport.bulkCreate(profileData, {
              updateOnDuplicate: ['value'],
              transaction: t
            }).then(function(dbdata) {
              // generate token
              var utoken = {
                sub: {
                  userId: userId,
                  persist: inObj.body.persist
                }
              };
              var timestamp = new Date();
              var token = lib.core.jwtoken.sign(utoken, app.appCfg.jwt.secret, {
                expiresIn: app.appCfg.jwt.expiresIn
              });
              var data = [{
                msg: 'Token issued',
                token: token,
                provider: d.profile.provider,
                userId: userId
              }];
              // store if persist token
              if (inObj.body.persist) {
                /*
                 * CAUTION: persist tokens using oauth providers - on refresh the
                 * provider accessToken will not be checked if it's been revoked
                 */
                var tokenData = {
                  userId: userId,
                  token: token,
                  refreshToken: d.refreshToken,
                  provider: d.profile.provider,
                  ua: inObj.headers['user-agent']
                };
                return db.models.persistToken.create(tokenData, {
                  transaction: t
                }).then(function(dbdata) {
                  issueToken(function(err, data) {
                    return cb(err, data);
                  });
                });
              } else {
                issueToken(function(err, data) {
                  return cb(err, data);
                });
              }

              function issueToken(cb) {
                if (dbdataUser[1]) {
                  // set ACL - add user to everyone group
                  lib.core.acl.addUserRoles(userId, 'everyone', function(err) {
                    if (err) {
                      t.rollback();
                      return cb([{
                        msg: 'Error saving ACL permissions',
                        status: 401
                      }], null);
                    }
                    // store password reset date in redis
                    lib.core.redis.set(app.appCfg.redis.prefix.revokeBefore + userId, timestamp);
                    t.commit();
                    return cb(null, data);
                  });
                } else {
                  t.commit();
                  return cb(null, data);
                }
              }
            }).catch(function(err) {
              t.rollback();
              return cb([{
                msg: 'Error saving oauth provider details',
                status: 401
              }], null);
            });
          });
        }); // transaction
      });
    }
  };
};
