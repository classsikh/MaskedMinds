import express from "express";
import bodyparser from "body-parser";
import "dotenv/config";
import mongoose from "mongoose";
import _ from "lodash";
import session from "express-session";
import passport from "passport";
import passportLocalMongoose  from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import findOrCreate from "mongoose-findorcreate";

const app = express();
const port = process.env.port || 3000;

app.use(express.static("public"));

app.use(bodyparser.urlencoded({ extended: true }));
app.use(bodyparser.json());

app.use(session({
    secret:"Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    id: String,
    secret:{
        type: [String]
      }
    });



userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());



passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
   
  },
  function(accessToken, refreshToken, profile, cb) {
    
    User.findOrCreate({ id: profile.id, username: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username});
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
  
app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/register", (req, res) => {
    res.render("register.ejs");
   });



app.post("/register", (req, res) => {
   console.log(req.body);
const email = _.toLower(req.body.username);

const pass = req.body.password;
if (!email || !pass) {
    // Handle the case where email or password is missing
    res.status(400).send("Both email and password are required.");
    return;
  }
    User.register({username: email}, pass, function(err, user) {
        if (err) { 
            console.log(err);
            res.redirect("/register");
         } else{
            passport.authenticate("local")(req,res, () =>{
                res.redirect("/secrets");
            });
         }
        });
});
   

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/secrets", (req, res) => {
    User.find({secret: {$ne:[]}})
    .then(function(foundUser){
        if(foundUser){
            console.log(foundUser);
            res.render("secrets.ejs", {arr : foundUser});
         }
     })
     .catch(function(err){
         console.log(err);
       });
    
    
});
app.post("/login", (req, res) => {
const email = _.toLower(req.body.username);
    const user = new User({
        username: email,
        password: req.body.password
    });
    
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res, () =>{
                res.redirect("/secrets");
            });
        }
    })
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()){
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
   });

app.post("/submit", (req,res) => {
const newSecret = req.body.secret;


    User.findOne({username: req.user.username})
    .then(function(foundUser){
       if(foundUser){
          
           foundUser.secret.push(newSecret);
           foundUser.save();
           
           res.redirect("/secrets");
        }
    })
    .catch(function(err){
        console.log(err);
      });
    
});

app.get("/logout", (req, res, next) => {
    req.logout(function(err){
        if(err){return next(err);}
    });
    res.redirect("/");
   });

app.listen(port, () => {
    console.log("Server started on port " + port)
})

