const express = require('express');
const router = express.Router();
const {
  new_message,
  past_message,
  delete_message,
  insertStar,
  deleteStar,
} = require('../controllers/messages');
const { requireSignin } = require('../middlewares/index');
const {
  MessageValidated,
  isMessageValidated,
} = require('../validators/message');

router.post(
  '/new_message',
  requireSignin,
  MessageValidated,
  isMessageValidated,
  new_message
);
router.post('/past_message', requireSignin, past_message);
router.post('/delete_message', requireSignin, delete_message);
router.post('/insert_star', requireSignin, insertStar);
router.post('/delete_star', requireSignin, deleteStar);

module.exports = router;
