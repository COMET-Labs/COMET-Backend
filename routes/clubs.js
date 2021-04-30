const express = require('express');
const router = express.Router();
const { requireSignin } = require('../middlewares/index');
const {
  myClubs,
  addMyClub,
  deleteMyClub,
  banUser,
} = require('../controllers/club');

// For fetching all clubs of the user
router.get('/myClubs', requireSignin, myClubs);
router.post('/addMyClub', requireSignin, addMyClub);
router.post('/deleteMyClub', requireSignin, deleteMyClub);
router.post('/banUser', requireSignin, banUser);
module.exports = router;
