const jwt = require("jsonwebtoken");

exports.requireSignin = (req, res, next) => {
  if (req.headers.authorization) {
    const token = req.headers.authorization.split(" ")[1];
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
  } else {
    return res.status(400).json({ error: "Authorization required" });
  }
  next();
};

exports.handleError = (err, req, res, next) => {
  if (err) {
    res.status(err.status || 500).json({
      message: err.message || 'Something went wrong, please try again.'
    });
  }
}

