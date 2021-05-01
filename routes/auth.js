const express = require('express');
const router = express.Router();
const {
  mailOtp,
  verifyOtp,
  loginWithPassword,
  isAuthenticated,
  logout,
  loginWithLinkedIn,
  isNewUser,
  isUserWithPassword,
  resetPassword,
  signupNoniniPasswordless,
  signupiniPasswordless,
  signupnoniniPassword,
  signupiniPassword,
  linkedinInfo,
  getEmail,
  checkUser,
} = require('../controllers/auth');
const {
  validateMailRequest,
  validateOtpRequest,
  isRequestValidated,
  validateLoginWithPassword,
  validateLoginWithLinkedIn,
  validateResetPasswordRequest,
  validateSignupNoniniPasswordless,
  validateSignupNoniniPassword,
} = require('../validators/auth');
const { handleError } = require('../middlewares/index');
router.post(
  '/signup/mailotp',
  validateMailRequest,
  isRequestValidated,
  isNewUser,
  mailOtp,
  handleError
);

router.post(
  '/forgotpassword/mailotp',
  validateMailRequest,
  isRequestValidated,
  isUserWithPassword,
  mailOtp,
  handleError
);

router.post(
  '/verifyotp',
  validateOtpRequest,
  isRequestValidated,
  verifyOtp,
  handleError
);

router.post(
  '/loginwithpassword',
  validateLoginWithPassword,
  isRequestValidated,
  isUserWithPassword,
  loginWithPassword,
  handleError
);

router.post('/logout', isAuthenticated, logout, handleError);

router.post(
  '/loginwithlinkedin',
  validateLoginWithLinkedIn,
  isRequestValidated,
  loginWithLinkedIn,
  handleError
);

router.post(
  '/resetpassword',
  validateResetPasswordRequest,
  isRequestValidated,
  resetPassword,
  handleError
);

router.post(
  '/signup/nonini/passwordless',
  validateSignupNoniniPasswordless,
  isRequestValidated,
  getEmail,
  checkUser,
  linkedinInfo,
  signupNoniniPasswordless,
  handleError
);

router.post(
  '/signup/ini/passwordless',
  validateSignupNoniniPasswordless,
  isRequestValidated,
  getEmail,
  checkUser,
  linkedinInfo,
  signupiniPasswordless,
  handleError
);

router.post(
  '/signup/nonini/password',
  validateSignupNoniniPassword,
  isRequestValidated,
  checkUser,
  linkedinInfo,
  signupnoniniPassword,
  handleError
);

router.post(
  '/signup/ini/password',
  validateSignupNoniniPassword,
  isRequestValidated,
  checkUser,
  linkedinInfo,
  signupiniPassword,
  handleError
);

module.exports = router;
