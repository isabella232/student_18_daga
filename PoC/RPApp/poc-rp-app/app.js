var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var session = require('express-session');
var passport = require('passport');
var OidcStrategy = require('passport-openidconnect').Strategy;

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var profileRouter = require('./routes/profile');


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// app.use(function (req, res, next) {
//   console.info(req.method, req.originalUrl);
//     res.on('finish', () => {
//         console.info(`${res.statusCode} ${res.statusMessage}; ${res.get('Content-Length') || 0}b sent`)
//     })
//   next();
// })

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// set up passport
passport.use('daga_oidc', new OidcStrategy({
  issuer: 'http://' + process.env.DOCKER_HOST_IP + ':5556/dex',  // TODO TLS + PORT from env
  sessionKey: 'http://' + process.env.DOCKER_HOST_IP + ':5556/dex',
  authorizationURL: 'http://' + process.env.DOCKER_HOST_IP + ':5556/dex/auth',
  tokenURL: 'http://' + process.env.DOCKER_HOST_IP + ':5556/dex/token',
  // TODO would be nice to use discovery but don't get how it works with this passport module..
  // getClientCallback: function(issuer, cb) {
  //   cb(null, {
  //     id: 'poc-rp-app',
  //     secret: '37C2F6159B63D3DD25C3F9AE5C7190EE',
  //     redirectURIs: ['http://127.0.0.1:' + process.env.PORT + '/authorization-code/callback']
  //   })
  // },
  clientID: 'poc-rp-app',
  clientSecret: '37C2F6159B63D3DD25C3F9AE5C7190EE',
  callbackURL: 'http://' + process.env.DOCKER_HOST_IP + ':' + process.env.PORT + '/authorization-code/callback',
  skipUserProfile: true
}, (issuer, sub, done) => {
  return done(null, sub);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/profile', profileRouter);

// passport openid-connect login/logout
app.use('/login', passport.authenticate('daga_oidc'));
app.use('/authorization-code/callback',
  passport.authenticate('daga_oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/profile');
  }
);
app.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy();
    res.redirect('/');
});


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
