var express = require('express');
var router = express.Router();

function ensureLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login')
}

/* GET profile */
router.get('/', ensureLoggedIn, (req, res, next) => {
    res.render('profile', { title: 'Express', user: req.user, secret: process.env.SESSION_SECRET });
});

module.exports = router;
