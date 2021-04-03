const express = require("express");
const router = express.Router();
const {
  mailOtp,
  verifyOtp,
  isIiitian,
  loginWithPassword,
  isAuthenticated,
  logout,
  loginWithLinkedIn,
  verifyBothOtp,
  signupWithPassword
} = require("../controllers/auth");
const {
  validateMailRequest,
  validateOtpRequest,
  isRequestValidated,
  validateLoginWithPassword,
  validateLoginWithLinkedIn,
  validateSignupWithPassword,
} = require("../validators/auth");
const { handleError } = require("../middlewares/index");
router.post(
  "/mailotp",
  validateMailRequest,
  isRequestValidated,
  mailOtp,
  handleError
);

router.post(
  "/verifyotp",
  validateOtpRequest,
  isRequestValidated,
  verifyOtp,
  handleError
);

router.post(
  "/verifyiiitianemail",
  validateMailRequest,
  isRequestValidated,
  isIiitian,
  mailOtp,
  handleError
);

router.post(
  "/loginwithpassword",
  validateLoginWithPassword,
  isRequestValidated,
  loginWithPassword,
  handleError
);

router.post("/logout", isAuthenticated, logout, handleError);

router.post(
  "/loginwithlinkedin",
  validateLoginWithLinkedIn,
  isRequestValidated,
  loginWithLinkedIn,
  handleError
);

router.post(
  "/signupwithpassword",
  validateSignupWithPassword,
  isRequestValidated,
  verifyBothOtp,
  handleError,
  signupWithPassword,
  handleError
);

module.exports = router;
