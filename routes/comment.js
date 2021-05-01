const express = require('express');
const router = express.Router();
const {
  commentValidated,
  isCommentValidated,
} = require('../validators/comment');
const { requireSignin } = require('../middlewares/index');
const {
  allComments,
  newComment,
  updateComment,
  deleteComment,
} = require('../controllers/comment');

router.get('/all_comments', requireSignin, allComments);
router.post(
  '/new_comment',
  requireSignin,
  commentValidated,
  isCommentValidated,
  newComment
);
router.patch(
  '/update_comment',
  requireSignin,
  commentValidated,
  isCommentValidated,
  updateComment
);
router.delete('/delete_comment', requireSignin, deleteComment);

module.exports = router;
