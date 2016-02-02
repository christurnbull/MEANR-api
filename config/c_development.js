'use strict';
/**
 * Config objects
 *
 * @module config/c_development
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var appName = 'MEANr';
exports.app = {
  title: appName,
  host: '0.0.0.0',
  port: 3000,
  ssl: {
    enabled: false,
    key: 'privkey.pem',
    cert: 'cert.pem'
  },
  cluster: false,
  adminEmail: 'admin@meanr.io',
  adminName: 'Admin',
  defaultPassword: '123',
  activityAudit: true, // can be 'true', 'false' or 'authOnly'
  auditCachePeriod: 500, // milliseconds
  tooBusyLag: 200, // default 70ms
  demo: true
};
exports.ids = {
  whitelist: [
    '127.0.0.1',
    '::ffff:127.0.0.1'
  ],
  banSeconds: 24 * 60 * 60 * 20, // 20 days,
  strikes: {
    suspicious: 50,
    malicious: 5
  }
};
exports.cors = {
  enabled: true,
  allowedOrigins: ['*'],
  allowedMethods: [
    'POST',
    'GET',
    'PUT',
    'DELETE',
    'OPTIONS'
  ],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'JSNLog-RequestId',
    'JSNLog-Route'
  ]
};
exports.sequelize = {
  dbname: 'db-name',
  username: 'db-user',
  password: 'db-password',
  options: {
    host: 'localhost',
    logging: false
  }
};
exports.jwt = {
  secret: '3M9jL9HLDBu6zpV9zpfHk2nxgsrMm6HzRTXVYSyp',
  saltLen: 10,
  expiresIn: 60 * 60, // seconds (1 hour expiry) - lifetime of every issued token
  refreshExpiresIn: 60 * 120, // seconds (2 hour expiry) - period of web session
  passResetExpiresIn: 60 * 30 // seconds (30 min expiry)
};
exports.redis = {
  engine: 'fakeredis', // change to 'redis' for production
  host: '',
  port: '',
  options: {},
  prefix: {
    provider: appName + '_provider_', // appName_provider_hash, oauth provider user object
    revokeBefore: appName + '_revokeBefore_', // appName_revokeBefore_userId, password change date
    revoked: appName + '_revoked_', // appName_revoked_token, 1 (token is revoked)
    banip: appName + '_banip_', // appName_banip_address, number of strikes
    banipRL: appName + '_banip_RL_', // appName_banip_RL_address, rate limit ip/key/hash
    rateLimit: appName + '_rl_', // store for expressBrute ratelimit
    audit: appName + '_audit_'
  }
};
exports.mailer = {
  direct: {
    host: 'smtp.example.io',
    port: 465,
    ignoreTLS: false,
    auth: {
      user: 'username',
      pass: 'password'
    }
  },
  mailgun: {
    auth: {
      api_key: 'key-123456789',
      domain: 'example.com'
    }
  },
  gmail: {
    service: 'Gmail',
    // XOauth2 method or https://www.google.com/settings/security/lesssecureapps
    auth: {
      user: 'email@gmail.com',
      pass: 'password'
    }
  }
};
exports.stripe = {
  key: 'sk_test_123456789'
};
exports.hashids = {
  // used for confirming new users/passwords
  salt: 'JCJw3SnAVhJLesVNgx5Z',
  len: 50
};
exports.eventloop = {
  interval: 5000 // milliseconds
};
exports.passport = {
  redirect: 'http://localhost:9000/#!/signin',
  sessionSecret: 'jvWSkc8BEh5FUL7s9QyaCHEN3C4YyB6DpRGbBdte',
  github: {
    clientID: 'id-123456789',
    clientSecret: 'secret-123456789',
    callbackURL: 'http://localhost:3000/auth/provider/callback'
  },
  linkedin: {
    clientID: 'id-123456789',
    clientSecret: 'secret-123456789',
    callbackURL: 'http://localhost:3000/auth/provider/callback'
  },
  google: {
    // jansysltd@gmail.com
    clientID: 'id-123456789',
    clientSecret: 'secret-123456789',
    callbackURL: 'http://localhost:3000/auth/provider/callback'
  },
  facebook: {
    clientID: 'id-123456789',
    clientSecret: 'secret-123456789',
    callbackURL: 'http://localhost:3000/auth/provider/callback'
  },
  twitter: {
    consumerKey: 'key-123456789',
    consumerSecret: 'secret-123456789',
    callbackURL: 'http://localhost:3000/auth/provider/callback'
  }
};
