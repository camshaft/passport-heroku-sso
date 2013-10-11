/**
 * Module dependencies.
 */

var passport = require('passport-strategy');
var util = require('util');
var hash = require('crypto').createHash;
var scmp = require('scmp');

function HerokuSSOStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) throw new TypeError('HerokuSSOStrategy requires a verify callback');
  if (!options.salt) throw new TypeError('HerokuSSOStrategy requires a salt option');

  passport.Strategy.call(this);
  this.name = 'heroku-sso';
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
  var id = req.query.id;
  var token = req.query.token;
  var timestamp = req.query.timestamp;
  var navData = req.query['nav-data'];
  var email = req.query.email;

  if (!checkToken(id, this._salt, timestamp, token)) return this.fail({message: 'Invalid token'});

  function verified(err, user, info) {
    if (err) return self.error(err);
    if (!user) return self.fail(info);
    self.success(user, info);
  }

  try {
    var arity = self._verify.length;
    var passReq = self._passReqToCallback;
    var user = {email: email};
    var verify = self._verify;

    if (arity === 5) return verify(req, id, user, navData, verified);
    if (arity === 4 && passReq) return verify(req, id, user, verified);
    if (arity === 4) return verify(id, user, navData, verified);
    if (arity === 3 && passReq) return verify(req, id, verified);
    if (arity === 3) return verify(id, user, verified);
    verify(id, verified);
  } catch (err) {
    return self.error(err);
  }
}

function checkToken(id, salt, timestamp, thiers) {
  var sha = hash('sha1');
  sha.update([id, salt, timestamp].join(':'));
  return scmp(sha.digest(), new Buffer(thiers, 'hex')) && parseInt(timestamp) < (now() - 2 * 60);
}

function now() {
  return Math.round(Date.now() / 1000);
}
