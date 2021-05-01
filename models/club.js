const mongoose = require('mongoose');

const clubSchema = mongoose.Schema(
  {
    clubName: {
      type: String,
      required: true,
      unique: true,
    },
    clubDescription: {
      type: String,
      required: false,
    },
    ofInstitute: {
      type: String,
      required: true,
    },
    mentors: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    moderators: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    banned: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
  },
  { timestamps: true }
);
module.exports = mongoose.model('Club', clubSchema);
