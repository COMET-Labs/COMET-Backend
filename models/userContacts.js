const mongoose = require('mongoose');

const contactsSchema = mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    //contacts is an array of club id in which user is enroled in...
    contacts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Club',
      },
    ],
  },
  { timestamps: true }
);
module.exports = mongoose.model('Usercontact', contactsSchema);
