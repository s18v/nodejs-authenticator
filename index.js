let express = require('express')
let morgan = require('morgan')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy
let nodeifyit = require('nodeifyit')
let bcrypt = require('bcrypt')
let flash = require('connect-flash') // flash messages
let mongoose = require('mongoose') //mongo db
let User = require('./user')
require('songbird')

const NODE_ENV = process.env.NODE_ENV || 'dev'
const PORT = process.env.PORT || 8000
const SALT = bcrypt.genSaltSync(10)

mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

let app = express()
app.set('view engine', 'ejs')

app.use(flash())

// logging
app.use(morgan('dev'))

// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))

// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

// In-memory session support, required by passport.session()
app.use(session({
	secret: 'ilovethenodejs',
	resave: true,
	saveUninitialized: true
}))

// Use the passport middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())

let user = {
	email: 'foo@foo.com',
	password: bcrypt.hashSync('asdf', SALT)
}

app.listen(PORT, () => console.log(`Listening at http://127.0.0.1:${PORT} on ${NODE_ENV} environment`))

app.get('/', (req, res) => res.render('index.ejs', {message: req.flash('error')}))

passport.use(new LocalStrategy({
	usernameField: 'email',
	failureFlash: true
}, nodeifyit(async(email, password) => {
	email = (email || '').toLowerCase()
	if (email != user.email) {
		// return flash message
		return [false, {message: 'Invalid username'}]
	}
	if (!await bcrypt.promise.compare(password, user.password)) {
		return [false, {message: 'Invalid password'}]
	}
	return user
}, {spread: true})))

passport.use('local-signup', new LocalStrategy({
	usernameField: 'email'
}, nodeifyit(async (email, password) => {
	email = (email || '').toLowerCase()
	// Is the email taken?
	if (await User.promise.findOne({email})) {
		return [false, {message: 'That email has already been taken.'}]
	}

	// else, create user
	let user = new User()
	user.email = email
	// Use a password hash instead of plain-text
	user.password = await bcrypt.promise.hash(password, SALT)
	return await user.save()
}, {spread: true})))


passport.serializeUser(nodeifyit(async (user) => user.email))
passport.deserializeUser(nodeifyit(async (email) => {
	return await User.findOne({email}).exec()
}))

app.post('/login', passport.authenticate('local', {
	successRedirect: '/profile',
	failureRedirect: '/',
	failureFlash: true
}))

app.post('/signup', passport.authenticate('local-signup', {
	successRedirect: '/profile',
	failureRedirect: '/',
	failureFlash: true
}))

function isLoggedIn(req, res, next) {
	if (req.isAuthenticated()) return next()
	res.redirect('/')
}
app.get('/profile', isLoggedIn, (req, res) => res.render('profile.ejs', {}))
