//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session'); //for cookie session
const passportLocalMongoose = require('passport-local-mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));

//create cookie session
app.use(session({
    secret: "my little password",
    resave: false,
    saveUninitialized: false
}));

//initialize and use passport and session
app.use(passport.initialize());
app.use(passport.session()); 

mongoose.connect('mongodb://localhost:27017/userDB');


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String
});
const  secretSchema = new mongoose.Schema({
    user: String,
    title: String,
    secret: String
});

//
userSchema.plugin(passportLocalMongoose);
secretSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const secret = process.env.SECRET;

const Secret = new mongoose.model('Secret', secretSchema);
const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());


// using passport global se/de-rialization
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// using passport local se/de-rialization
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// passport-google-oauth20 login strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Passport-facebook login strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', function(req, res){
    res.render('home');
});

// google-oauth20 login authenticate
app.get('/auth/google',
    passport.authenticate('google', {scope: ['profile']})   
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  // Passport-facebook login authenticate
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


app.get('/register', function(req, res){
    res.render('register');
});

app.get('/secrets', function(req, res){
    Secret.find({}, function(err, foundSecrets){
        if(err){
            console.log(err);
        }else{
            if(foundSecrets){
                res.render('secrets', {secrets : foundSecrets});
            }
        }
    });
});

app.get('/submit', function(req, res){
    if(req.isAuthenticated()){
        res.render('submit');
    }else {
        res.redirect('/login');
    }
});

app.post('/submit', function(req, res){
    const submittedSecret = new Secret({
        user: req.user.id,
        title: req.body.secretTitle,
        secret: req.body.secret});
    submittedSecret.save();
    res.redirect('/secrets');


    // User.findById(req.user.id, function(err, foundUser){
    //     if(err){
    //         console.log(err);
    //     }else {
    //         if(foundUser){
    //             foundUser.secrets.push(submittedSecret);
    //             // foundUser.secrets = submittedSecret;
    //             foundUser.save(function(){
                    
    //                 res.redirect('/secrets');
    //             });
    //             console.log(foundUser);
    //         }
    //     }
    // });
});

app.get('/login', function(req, res){
    res.render('login');
});

app.post('/register', function(req, res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err) {
            console.log(err);
            res.redirect('/register');
        }else {
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets');
            });
        }
    });
});

app.post('/login', function(req, res){
   
    const user = new User({
    email: req.body.username,
    password: req.body.password
   });
   req.login(user, function(err){
    if(err){
        res.redirect('/login')
        console.log(err);
        
    }else {
        passport.authenticate('local')(req, res, function(){
            res.redirect('/secrets');
        });
    }
   });


});

app.get('/logout', function(req, res){
    req.logout(function(err) {
        if (!err) {
            res.redirect('/');
        }else{
            console.log(err);
        }
        
      });
});




app.listen(3000, function(){
    console.log('Server is up and running on port 3000');
});