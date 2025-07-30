const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const User = require("./user");

// Auth check middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

// Home → redirect to dashboard or login
router.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

// Register Page
router.get("/register", (req, res) => res.render("register"));
router.post("/register", async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;
  if (!fullName || !email || !password || !confirmPassword)
    return res.send("All fields are required.");
  if (password !== confirmPassword)
    return res.send("Passwords do not match.");
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ fullName, email, password: hash });
    res.redirect("/login");
  } catch (err) {
    res.send("Error or user already exists.");
  }
});

// Login Page
router.get("/login", (req, res) => res.render("login"));
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.send("All fields are required.");
  const user = await User.findOne({ email });
  if (!user) return res.send("Invalid credentials.");
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.send("Invalid credentials.");
  req.session.user = { id: user._id, fullName: user.fullName, email: user.email };
  res.redirect("/dashboard");
});

// Dashboard
router.get("/dashboard", isAuth, (req, res) => {
  res.render("dashboard", { user: req.session.user });
});

// Logout
router.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) console.error(err);
    res.redirect("/login");
  });
});

module.exports = router;