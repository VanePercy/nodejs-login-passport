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
      // Validate user
      const user = await User.findOne({ "email": email });
      if (user) {
        return done(
          null,
          false,
          req.flash("signupMessage", "The email is already taken.")
        );
      } else {
        const newUser = new User();
        newUser.email = email;
        newUser.password = newUser.encryptPassword(password);
        await newUser.save();
        done(null, newUser);
      }
    }
  )
);
