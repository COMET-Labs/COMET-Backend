const Message = require('../models/message');
const Comment = require('../models/comment');
const Club = require('../models/club');

// For Fetching Past Messages
exports.past_message = (req, res) => {
  Message.find({ recieverClub: req.body.clubId })
    .sort({ createdAt: -1 })
    .then(user => {
      return res.status(200).json(user);
    })
    .catch(err => {
      return res.status(400).json({ error: 'Something went wrong' });
    });
};

// For Saving and Emiting new Message
exports.new_message = (req, res) => {
  const senderId = req.user._id;
  const messageBody = req.body.messageBody;
  const recieverClub = req.body.recieverClub;

  const _message = new Message({
    senderId,
    messageBody,
    recieverClub,
  });

  _message.save((error, data) => {
    if (error) {
      console.log(error);
      return res.status(400).json({ error: 'Something went wrong' });
    }

    if (data) {
      return res.status(200).json({
        message: 'Sent',
      });
    }
  });
};

exports.delete_message = (req, res) => {
  const senderId = req.user._id;
  const messageId = req.body.messageId;

  Message.findOne({ _id: messageId }).exec((error, message) => {
    if (message) {
      if (message.senderId.toString() === senderId) {
        Comment.deleteMany({ _id: { $in: message.comments } }).exec(
          (error, data) => {
            if (error) return res.json({ message: 'Something Went Wrong !' });
            Message.deleteOne({ _id: messageId }).exec((error, data) => {
              if (error) return res.json({ message: 'Something Went Wrong !' });
              return res.json({ message: 'You Deleted the Message' });
            });
          }
        );
      } else if (message) {
        Club.findOne({ _id: message.recieverClub.toString() }).exec(
          (clubError, clubDetails) => {
            if (clubDetails) {
              var isfound = false;
              clubDetails.mentors.forEach(function (entry) {
                if (entry.toString() === senderId) {
                  isfound = true;
                  Comment.deleteMany({ _id: { $in: message.comments } }).exec(
                    (error, data) => {
                      if (error)
                        return res.json({ message: 'Something Went Wrong !' });
                      Message.deleteOne({ _id: messageId }).exec(
                        (error, data) => {
                          if (error)
                            return res.json({
                              message: 'Something Went Wrong !',
                            });
                          return res.json({
                            message: 'You Deleted the Message',
                          });
                        }
                      );
                    }
                  );
                }
              });
              clubDetails.moderators.forEach(function (entry) {
                if (entry.toString() === senderId) {
                  isfound = true;
                  Comment.deleteMany({ _id: { $in: message.comments } }).exec(
                    (error, data) => {
                      if (error)
                        return res.json({ message: 'Something Went Wrong !' });
                      Message.deleteOne({ _id: messageId }).exec(
                        (error, data) => {
                          if (error)
                            return res.json({
                              message: 'Something Went Wrong !',
                            });
                          return res.json({
                            message: 'You Deleted the Message',
                          });
                        }
                      );
                    }
                  );
                }
              });
              if (!isfound)
                return res.json({ message: "You Don't Have Permission :)" });
            }
          }
        );
      } else {
        return res.json({ message: "You Don't Have Permission :)" });
      }
    } else return res.status(400).json({ message: 'Something went Wrong' });
  });
};

// Adding star to the message
exports.insertStar = (req, res) => {
  const messageId = req.body.messageId;
  Message.updateOne(
    {
      _id: messageId,
    },
    {
      $addToSet: {
        star: req.user._id,
      },
    }
  )
    .exec()
    .then(response => res.json(response))
    .catch(error => res.json(error));
};

exports.deleteStar = (req, res) => {
  const messageId = req.body.messageId;
  Message.updateOne(
    {
      _id: messageId,
    },
    {
      $pull: {
        star: req.body.userId,
      },
    }
  )
    .exec()
    .then(response => res.json(response))
    .catch(error => res.json(error));
};
