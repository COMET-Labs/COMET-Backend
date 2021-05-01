const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = mongoose.Schema(
  {
    fullName: {
      type: String,
      maxlength: 50,
    },
    instituteName: {
      type: String,
    },
    rollNumber: {
      type: String,
    },
    joiningYear: {
      type: Number,
    },
    email: {
      institute: {
        type: String,
        trim: true,
        unique: 1,
      },
      personal: {
        type: String,
        trim: true,
        unique: 1,
      },
    },
    hash_password: {
      type: String,
      minlength: 8,
    },
    contact: {
      type: Number,
      required: true,
    },
    headline: {
      type: String,
    },
    about: {
      type: String,
    },

    //Base-64 encoded display picture
    dp: {
      profile: String,
      cover: String,
    },

    //Social Media handles
    socialHandle: {
      twitter: {
        type: String,
      },
      facebook: {
        type: String,
      },
      instagram: {
        type: String,
      },
      linkedin: {
        type: String,
      },
      gitHub: {
        type: String,
      },
      discord: {
        type: String,
      },
    },
  },
  { timestamps: true }
);

userSchema.virtual('password').set(function (password) {
  this.hash_password = bcrypt.hashSync(password, 10);
});

userSchema.methods = {
  authenticate: function (password) {
    return bcrypt.compareSync(password, this.hash_password);
  },
};

module.exports = mongoose.model('User', userSchema);
