const requiresLogin = (req, res, next) => {
    if (!req.user) {
        return res.redirect("/?msg=Login required");
    }
    next();
};

const requiresNoLogin = (req, res, next) => {
    if (req.user) {
        return res.redirect("/?msg=You are already logged in!");
    }
    next();
};



module.exports = { requiresLogin, requiresNoLogin};