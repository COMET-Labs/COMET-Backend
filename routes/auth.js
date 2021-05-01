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
} = require('../controllers/auth');
const {
  validateMailRequest,
  validateOtpRequest,
  isRequestValidated,
  validateLoginWithPassword,
  validateLoginWithLinkedIn,
  validateResetPasswordRequest,
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

module.exports = router;
