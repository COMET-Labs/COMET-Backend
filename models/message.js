const mongoose = require('mongoose');
const Comment = require('./comment');

const messageSchema = mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    messageBody: {
      type: String,
    },
    recieverClub: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Club',
    },
    star: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    comments: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Comment',
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model('Message', messageSchema);
