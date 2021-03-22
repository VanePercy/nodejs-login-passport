const passport = require("passport");
const localStrategy = require("passport-local").Strategy;

const User = require("../models/user");

// Data serialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Data deserialize
passport.deserializeUser(async (id, done) => {
  // Against  the database
  const user = await User.findById(id);
  done(null, user);
});


// User authentication
passport.use(
  "local-signup",
  new localStrategy(
    {
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, email, password, done) => {
      const newUser = new User();
      newUser.email = email;
      newUser.password = newUser.encryptPassword(password);
      await newUser.save();
      done(null, newUser);
    }
  )
);
