import LocalStrategy from "passport-local";
import bcrypt from "bcrypt";
import {db} from "./dbConfig.js";
import GoogleStrategy from "passport-google-oauth20";

function initialize(passport) {
    console.log("Passport Initialized");
  
    const authenticateUser = (email, password, done) => {
      //console.log(email, password);
      db.query(`SELECT * FROM users WHERE email = $1`,[email],(err, results) => {
          if (err) {
            throw err;
          }
          //console.log(results.rows);
  
          if (results.rows.length > 0) {
            const user = results.rows[0];
  
            bcrypt.compare(password, user.password, (err, isMatch) => {
              if (err) {
                console.log(err);
              }
              if (isMatch) {
                return done(null, user);
              } else {
                //password is incorrect
                return done(null, false, { message: "Password is incorrect" });
              }
            });
          } else {
            // No user
            return done(null, false, {
              message: "No user with that email address",
            });
          }
        }
      );
    };
  
    passport.use(
      new LocalStrategy(
        { usernameField: "username", passwordField: "password" },
        authenticateUser
      )
    );
  
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.CLIENT_ID,
          clientSecret: process.env.CLIENT_SECRET,
          callbackURL: process.env.OAUTH_CB_URL,
        },
        async (_, __, profile, done) => {
          const account = profile._json;
          //console.log(account);
          let user = {};
          try {
            const currentUserQuery = await db.query(
              "SELECT * FROM users WHERE email=$1",
              [account.email]
            );
  
            if (currentUserQuery.rows.length === 0) {
              // create user
              //inserting the account sub in the password column
              await db.query(
                "INSERT INTO users (email, password) VALUES ($1,$2)",
                [account.email, account.sub]
              );
  
              const id = await db.query(
                "SELECT id FROM users WHERE password=$1",
                [account.sub]
              );
              user = {
                id: id.rows[0].id,
                email: account.email,
                password: account.sub,
              };
            } else {
              // have user
              user = {
                id: currentUserQuery.rows[0].id,
                email: currentUserQuery.rows[0].email,
                password: currentUserQuery.rows[0].password,
              };
            }
            done(null, user);
          } catch (error) {
            done(error);
          }
        }
      )
    );
  
    passport.serializeUser((user, done) => {
      // loads into req.session.passport.user
      done(null, user);
    });
  
    passport.deserializeUser((user, done) => {
      // loads into req.user
      done(null, user);
    });
  }

  export{initialize};