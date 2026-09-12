const express = require("express");
const crypto = require("crypto");

const db = require("../src/db.js");
const mw = require("../src/middleware.js");
const router = express.Router();
const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");


router.get("/post", (req, res) => {
    let {id} = req.query;

    if (!id || typeof id !== "string") {
        return res.jsonp({
            success: false,
            error: "Missing id"
        });
    }

    if (!db.posts.has(id)) {
        return res.jsonp({
            success: false,
            error: "No post found with that id"
        });
    }

    let post = db.posts.get(id);

    if (req.role !== "admin" && !post.isPublic && (!req.user || !req.user.posts.includes(id))) {
        return res.jsonp({
            success: false,
            error: "No permission to view this post"
        });
    }

    return res.jsonp({
        success: true,
        name: post.name,
        body: post.body
    });
});

router.post("/login", (req, res) => {
    let {user, pass} = req.body;

    if (!user || !pass) {
        return res.redirect("/login?msg=Missing user or pass");
    }

    if (typeof user !== "string" || typeof pass !== "string") {
        return res.redirect("/login?msg=Missing user or pass");
    }

    let dbUser = db.users.get(user);
    if (!dbUser || sha256(pass) !== dbUser.pass) {
        return res.redirect("/login?msg=Invalid user or pass");
    }

    req.session.user = user;
    res.redirect("/");
});

router.post("/register", mw.requiresNoLogin, (req, res) => {
    let {user, pass} = req.body;

    if (!user || !pass) {
        return res.redirect("/register?msg=Missing user or pass");
    }

    if (typeof user !== "string" || typeof pass !== "string") {
        return res.redirect("/register?msg=Missing user or pass");
    }

    if (user.length < 5 || pass.length < 8) {
        return res.redirect("/register?msg=Please choose a more secure user/pass");
    }

    if (user.length > 12) {
        return res.redirect("/register?msg=Too long username");
    }

    let dbUser = db.users.get(user);
    if (dbUser) {
        return res.redirect("/register?msg=A user already exists with that name");
    }

    db.users.set(user, {
        user,
        pass: sha256(pass),
        posts: []
    });

    req.session.user = user;
    res.redirect("/");
});


router.get("/logout", mw.requiresLogin, (req, res) => {
    req.session.destroy();
    res.redirect("/");
});


router.post("/create", mw.requiresLogin, (req, res) => {
    let {name, body, isPublic} = req.body;

    if (!name || !body) {
        return res.redirect("/?msg=Missing name or body");
    }

    if (typeof name !== "string" || typeof body !== "string") {
        return res.redirect("/?msg=Missing name or body");
    }

    let id = crypto.randomUUID();
    db.posts.set(id, {
        name, body, isPublic
    });
    req.user.posts.push(id);

    res.redirect("/post/?id=" + id);
});

router.get("/search", mw.requiresLogin, (req, res) => {

    let {username} = req.query;

    if (!username) {
        return res.jsonp({
            success: false,
            error: "Missing username"
        });
    }

    if (username === "admin") {
        return res.jsonp({
            success: false,
            error: "Forbidden !"
        });
    }

    if (username.length > 12) {
        return res.jsonp({
            success: false,
            error: "Too long parameter"
        });
    }

    let list = [];
    db.users.forEach((value, key) => {
        if (key == username) {
            value.posts.forEach((id) => {
                list.push(id);
            });
        }
    });

    return res.jsonp({
        success: true,
        list
    });
});


module.exports = router;
