// No need of this schema For Messaging Api

const mongoose = require('mongoose');

const conversationSchema = mongoose.Schema(
  {
    participants: [
      {
        id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      },
    ],
  },
  { timestamps: true }
);
module.exports = mongoose.model('Conversation', conversationSchema);
