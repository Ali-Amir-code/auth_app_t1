const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const path = require("path");


const MongoStore = require("connect-mongo");

const app = express();

// Database
mongoose.connect(process.env.MONGODB_URI,)
  .then(() => console.log(" MongoDB Connected"))
  .catch(err => console.error(" MongoDB Error:", err));

// Middleware & View Engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Routes
app.use(require("./routes"));

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));