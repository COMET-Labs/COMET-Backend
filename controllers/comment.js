const Comment = require('../models/comment');
const Message = require('../models/message');

exports.allComments = (req, res) => {
  const { messageId } = req.body;

  Message.findById(messageId)
    .populate({
      path: 'comments',
      model: 'Comment',
    })
    .exec((error, message) => {
      if (error) {
        return res.status(400).json({ error: 'Something went wrong' });
      }
      if (message) {
        return res.status(200).json({
          comments: message.comments,
        });
      }
    });
};

exports.newComment = (req, res) => {
  const { messageId, commentBody } = req.body;
  const userId = req.user._id;
  const comment = new Comment({ userId, commentBody });

  comment.save((error, data) => {
    if (error) {
      return res.status(400).json({ error: 'Something went wrong' });
    }
    if (data) {
      Message.updateOne(
        { _id: messageId },
        { $push: { comments: [data._id] } }
      ).exec((error, data) => {
        if (error) {
          return res.status(400).json({ error: 'Something went wrong' });
        }
        if (data) {
          return res
            .status(200)
            .json({ message: 'Your comment has been successfully added.' });
        }
      });
    }
  });
};

exports.updateComment = (req, res) => {
  const { commentId, commentBody } = req.body;

  Comment.updateOne(
    { _id: commentId },
    {
      commentBody,
      isEdited: true,
    }
  ).exec((error, data) => {
    if (error) {
      return res.status(400).json({ error: 'Something went wrong' });
    }
    if (data) {
      return res
        .status(200)
        .json({ message: 'Your comment has been successfully updated.' });
    }
  });
};

exports.deleteComment = (req, res) => {
  const { commentId, messageId } = req.body;

  Message.findByIdAndUpdate(messageId, { $pull: { comments: commentId } }).exec(
    (error, data) => {
      if (error) {
        return res.status(400).json({ error: 'Something went wrong' });
      }

      if (data) {
        Comment.findByIdAndDelete(commentId).exec((error, data) => {
          if (error) {
            return res.status(400).json({ error: 'Something went wrong' });
          }
          if (data) {
            return res
              .status(200)
              .json({ message: 'Your comment has been successfully deleted.' });
          }
        });
      }
    }
  );
};
