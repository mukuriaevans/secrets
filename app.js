//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session'); //for cookie session
const passportLocalMongoose = require('passport-local-mongoose');
const passport = require('passport');


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
    email: String,
    password: String
});

//
userSchema.plugin(passportLocalMongoose);

const secret = process.env.SECRET;

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', function(req, res){
    res.render('home');
});
app.get('/register', function(req, res){
    res.render('register');
});

app.get('/secrets', function(req, res){
    if(req.isAuthenticated()){
        res.render('secrets');
    }else {
        res.redirect('/login');
    }
})

app.get('/login', function(req, res){
    res.render('login');
});

app.post('/register', function(req, res){
    User.register({email: req.body.username}, req.body.password, function(err, user){
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
    username: req.body.username,
    password: req.body.password
   });
   req.login(user, function(err){
    if(err){
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