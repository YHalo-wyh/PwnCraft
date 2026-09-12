const express = require("express");
const crypto = require("crypto");

const db = require("./src/db.js");
const mw = require("./src/middleware.js");

const app = express();

const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("etag", false);
app.use(require("express-session")({
    secret: crypto.randomBytes(64).toString("hex"),
    resave: false,
    saveUninitialized: false
}));
app.use(require('cookie-parser')());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
});

app.use(express.static("static"));

app.use((req, res, next) => {

    res.locals.user = null;
    if (req.session.user && db.users.has(req.session.user)) {
        req.user = db.users.get(req.session.user);
        res.locals.user = req.user;
    }

    if(req.headers.auth) {
        req.role = req.headers.auth;
    }

    next();
});

app.use("/api/", require("./routes/api.js"));

app.get("/login/", mw.requiresNoLogin, (req, res) => res.render("login"));
app.get("/register/", mw.requiresNoLogin, (req, res) => res.render("register"));

app.get("/post/", (req, res) => res.render("post"));
app.get("/search/", mw.requiresLogin, (req, res) => res.render("search"));
app.get("/", (req, res) => res.render("home"));

app.listen(PORT, () => console.log(`Blog listening on port ${PORT}`));
