 import express from "express";
import bodyParser from "body-parser";
import {db} from "./dbConfig.js";
import session from "express-session";
import passport from "passport";
import bcrypt from "bcrypt";
import  {initialize}  from "./auth.js";

const app = express();
const port = process.env.PORT || 3000;

//middleware
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

db.connect();

//passport set-up
app.use(
  session({
    secret: process.env.PASSPORT_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

initialize(passport);

//get requests
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", async(req, res) => {
  const result=await db.query("select secret from users where secret is not null");
  const userWithSecrets=result.rows;
  let btn='home';
  if(req.isAuthenticated()){
    btn='logout';
  }
  if(userWithSecrets){
    res.render("secrets.ejs",{userWithSecrets : userWithSecrets,btn: btn});
  }
  else{
    res.render("secrets.ejs",{btn: btn});
  }
});

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  }else{
    res.redirect("/login");
  }
})

app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/auth/google", passport.authenticate("google", { scope: "email" }));

app.get("/auth/google/secrets", passport.authenticate("google", {failureRedirect: "/login" }),(req, res)=>{
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

//post requests

app.post("/register", async (req, res) => {
  let email = req.body.username;
  let password = req.body.password;
  let errors = [];
  if (!email || !password) {
    errors.push({ message: "Please enter all fields" });
  }
  if (password.length < 6) {
    errors.push({ message: "Password must be 6 characters long" });
  }
  if (errors.length > 0) {
    res.render("register.ejs", { errors: errors });
  } else {
    //successful form store info in db
    let hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query("select * from users");
    const userTable = result.rows;
    const foundUser = userTable.find((user) => user.email === email);
    if (foundUser) {
      errors.push({ message: "Email already registered" });
      res.render("register.ejs", { errors: errors });
    } else {
      //no user of the same email exists
      await db.query("insert into users (email,password) values ($1, $2)", [
        email,
        hashedPassword,
      ]);
      res.render("login.ejs", {
        message: "Suceessfully registered! please log in",
      });
    }
  }
});

app.post("/login",passport.authenticate("local",{
    successRedirect: "/secrets",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.post("/submit",async (req,res)=>{
  const submittedSecret= req.body.secret;
  //console.log(req.user);
  const result = await db.query("SELECT * FROM users WHERE email = $1", [req.user.email]);
  const currentUser = result.rows[0];
  if(currentUser.secret===null){
    currentUser.secret=[];
  }
  currentUser.secret.push(submittedSecret);
  // console.log(typeof(currentUser.secret));
  await db.query("UPDATE users SET secret = $1 WHERE email = $2", [currentUser.secret, req.user.email]);


  // await db.query("update users set secret=$1 where email=$2",[submittedSecret,currentUser.email]);
  res.redirect("/secrets");
});


app.listen(port, () => console.log(`Server started at port: ${port}`));
