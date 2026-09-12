const crypto = require("crypto");

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");
const users = new Map();
const posts = new Map();

(() => {
    let flagId = crypto.randomUUID();
    let welcomeId = crypto.randomUUID();
    console.log(`flag post ID: ${flagId}`);

    posts.set(flagId, {
        name: "Flag",
        body: process.env.FLAG || "wdflag{test_flag}"
    });

    posts.set(welcomeId, {
        name: "Welcome to My Blog !",
        body: "I'm sure you'll have a great time here.",
        isPublic: "on"
    } );

    users.set("admin", Object.freeze({
        user: "admin",
        pass: sha256(process.env.ADMIN_PASSWORD || "password"),
        posts: [flagId]
    }));

    users.set("test", Object.freeze({
        user: "test",
        pass: sha256("test"),
        posts: [welcomeId]
    }));

    console.log(`created user admin | ${process.env.ADMIN_PASSWORD || "password"}`)
})();

module.exports = { users, posts };