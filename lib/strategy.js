/**
 * Module dependencies.
 */

var passport = require('passport-strategy');
var util = require('util');
var hash = require('crypto').createHash;

function HerokuSSOStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) throw new TypeError('HerokuSSOStrategy requires a verify callback');
  if (!options.salt) throw new TypeError('HerokuSSOStrategy requires a salt option');

  passport.Strategy.call(this);
  this.name = options.name || 'heroku-sso';
  this._verify = verify;

  this._salt = options.salt;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */

util.inherits(HerokuSSOStrategy, passport.Strategy);

/**
 * Authenticate a heroku sso request
 */

HerokuSSOStrategy.prototype.authenticate = function(req, options) {
  var self = this;
  if (!req.body) return this.error(new TypeError('bodyParser needed for heroku-sso strategy'));
  var id = req.query.id || req.body.id;
  var token = req.query.token || req.body.token;
  var timestamp = req.query.timestamp || req.body.timestamp;
  var navData = req.query['nav-data'] || req.body['nav-data'];
  var app = req.query.app || req.body.app;
  var email = req.query.email || req.body.email;

  if (!id ||
      !timestamp ||
      !token ||
      !validateToken(id, this._salt, timestamp, token)) return this.fail({message: 'Invalid token'});

  function verified(err, user, info) {
    if (err) return self.error(err);
    if (!user) return self.fail(info);
    self.success(user, info);
  }

  try {
    var arity = self._verify.length;
    var passReq = self._passReqToCallback;
    var verify = self._verify;

    if (arity === 6) return verify(req, id, email, app, navData, verified);
    if (arity === 5 && passReq) return verify(req, id, email, app, verified);
    if (arity === 5) return verify(id, email, app, navData, verified);
    if (arity === 4 && passReq) return verify(req, id, email, verified);
    if (arity === 4) return verify(id, email, app, verified);
    if (arity === 3 && passReq) return verify(req, id, verified);
    if (arity === 3) return verify(id, email, verified);
    verify(id, verified);
  } catch (err) {
    return self.error(err);
  }
}

function validateToken(id, salt, timestamp, thiers) {
  var sha = hash('sha1');
  sha.update([id, salt, timestamp].join(':'));
  try {
    return scmp(sha.digest(), new Buffer('' + thiers, 'hex')) && parseInt(timestamp) > (now() - 2 * 60);
  } catch (e) {
    return false;
  }
}

function now() {
  return Math.round(Date.now() / 1000);
}

function scmp(a, b) {
  // things must be the same length to compare them.
  if (a.length != b.length) return false;

  // constant-time compare
  //   hat-tip to https://github.com/freewil/scmp for |=
  var same = 0;
  for (var i = 0; i < a.length; i++) {
    same |= a[i] ^ b[i];
  }
  return same === 0;
}

module.exports = HerokuSSOStrategy;
