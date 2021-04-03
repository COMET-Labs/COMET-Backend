const { check, validationResult } = require("express-validator");

exports.validateSignupRequest = [
  check("fullName").notEmpty().withMessage("Please enter your name"),
  check("password")
  .notEmpty()
  .withMessage('password is required')
  .isLength({ min: 8 })
  .withMessage('password must be 8 characters'),
  check("rollNumber").notEmpty().withMessage("Roll number id required"),
  check("contact").notEmpty().withMessage("Contact number is required"),
];

exports.validateMailRequest = [
  check("email")
  .notEmpty()
  .withMessage('Email is required')
  .isEmail()
  .withMessage("Invalid Email")
]

exports.validateOtpRequest = [
  check("email")
  .notEmpty()
  .withMessage('Email is required')
  .isEmail()
  .withMessage("Invalid Email"),
  check("otp")
  .notEmpty()
  .withMessage("OTP is required")
  .isLength({ min: 4, max:4 })
  .withMessage("Invalid OTP")
]

exports.validateSigninRequest = [
  check("email")
  .notEmpty()
  .withMessage('Email is required')
  .isEmail()
  .withMessage("Invalid Email"),
  check("password")
  .notEmpty()
  .withMessage('password is required')
  .isLength({ min: 8 })
  .withMessage('password must be 8 characters')
];

exports.validateLoginWithPassword = [
  check("email")
  .notEmpty()
  .withMessage('Email is required')
  .isEmail()
  .withMessage("Invalid Email"),
  check("password")
  .notEmpty()
  .withMessage('password is required')
  .isLength({ min: 8 })
  .withMessage('password must be 8 characters'),
  check("remember")
  .notEmpty()
  .withMessage("Remember is required")
  .isBoolean()
  .withMessage("Remember must be a Boolean")
]

exports.validateLoginWithLinkedIn = [
  check("accessToken")
  .notEmpty()
  .withMessage("AccessToken is Required"),
  check("remember")
  .notEmpty()
  .withMessage("Remember is required")
  .isBoolean()
  .withMessage("Remember must be a Boolean")
]

exports.validateSignupWithPassword = [
  check("fullName").notEmpty().withMessage("Please enter your name"),
  check("password")
  .notEmpty()
  .withMessage('password is required')
  .isLength({ min: 8 })
  .withMessage('password must be 8 characters'),
  check("rollNumber").notEmpty().withMessage("Roll number id required"),
  check("contact").notEmpty().withMessage("Contact number is required"),
  check("accessToken")
  .notEmpty()
  .withMessage("AccessToken is Required"),
  check("personalEmail")
  .notEmpty()
  .withMessage('Personal Email is required')
  .isEmail()
  .withMessage("Invalid Personal Email"),
  check("instituteEmail")
  .notEmpty()
  .withMessage('Institute Email is required')
  .isEmail()
  .withMessage("Invalid Institute Email"),  
  check("personalEmailOtp")
  .notEmpty()
  .withMessage("OTP is required")
  .isLength({ min: 4, max:4 })
  .withMessage("Invalid OTP"),
  check("instituteEmailOtp")
  .notEmpty()
  .withMessage("OTP is required")
  .isLength({ min: 4, max:4 })
  .withMessage("Invalid OTP")  
]


exports.isRequestValidated = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.array().length > 0) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
};