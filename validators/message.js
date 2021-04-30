const { check, validationResult } = require('express-validator');

exports.MessageValidated = [
  check('messageBody').notEmpty().withMessage('Message should not be empty.'),
];

exports.isMessageValidated = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.array().length > 0) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
};
