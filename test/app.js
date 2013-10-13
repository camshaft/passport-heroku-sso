/**
 * Module dependencies
 */

var stack = require('simple-stack-common');
var passport = require('passport');
var HerokuSSOStrategy = require('..').Strategy;

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  done(err, {id: id});
});

passport.use(new HerokuSSOStrategy({
  salt: '910af1bf607c6b742842a02905fa2cfe7edc0a04bc0c178471f0f66d8b8dd544'
}, function(req, id, email, app, navData, done) {
  done(null, {
    app: app,
    email: email,
    id: 'user-id'
  });
}));

var app = module.exports = stack();

app.useBefore('router', '/', stack.middleware.cookieParser());
app.useBefore('router', '/', stack.middleware.session({ secret: 'keyboard cat' }));
app.useBefore('router', '/', 'passport:init', passport.initialize());
app.useBefore('router', '/', 'passport:session', passport.session());

app.post('/',
  passport.authenticate('heroku-sso', { failureRedirect: '/unauthenticated' }),
  function(req, res, next) {
    res.send('ok');
  });

app.get('/unauthenticated', function(req, res) {
  res.send(401);
});