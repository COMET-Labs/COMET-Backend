const Usercontact = require('../models/userContacts');
const club = require('../models/club');

exports.myClubs = (req, res) => {
  Usercontact.findOne({
    userId: req.user._id,
  }).exec((error, userData) => {
    if (error) {
      return res.status(400).json({ error });
    }
    if (userData) {
      return res.status(200).json(userData);
    } else {
      return res.status(400).json({
        message: userData,
      });
    }
  });
};

exports.addMyClub = (req, res) => {
  const clubId = req.body.clubId;
  const userId = req.user._id;
  Club.findOne({ _id: clubId })
    .exec((clubError, clubDetails) => {
      if (clubDetails) {
        var isfound = false;

        clubDetails.banned.forEach(function (entry) {
          if (entry.toString() === userId) {
            isfound = true;
            return res.json({ message: 'You have been banned from club :(' });
          }
        });
        if (!isfound)
          Usercontact.updateOne(
            {
              userId: req.user._id,
            },
            {
              $addToSet: {
                contacts: req.body.clubId,
              },
            }
          )
            .exec()
            .then(response => res.json(response))
            .catch(error => res.json(error));
      }
    })
    .catch(error => res.json('Something Went Wrong'));
};

exports.deleteMyClub = (req, res) => {
  const clubId = req.body.clubId;
  Usercontact.updateOne(
    {
      userId: req.user._id,
    },
    {
      $pull: {
        contacts: req.body.clubId,
      },
    }
  )
    .exec()
    .then(response => res.json(response))
    .catch(error => res.json(error));
};

exports.banUser = (req, res) => {
  const clubId = req.body.clubId;
  const banId = req.body.banId;
  Club.findOne({ _id: clubId })
    .exec((clubError, clubDetails) => {
      if (clubDetails) {
        var isfound = false;
        clubDetails.mentors.forEach(function (entry) {
          if (entry.toString() === senderId) {
            isfound = true;
            Club.updateOne(
              {
                _id: clubId,
              },
              {
                $addToSet: {
                  banned: banId,
                },
              }
            );
            Usercontact.updateOne(
              {
                userId: req.user._id,
              },
              {
                $pull: {
                  contacts: req.body.clubId,
                },
              }
            )
              .exec()
              .then(response => res.json(response))
              .catch(error => res.json(error));
          }
        });
        clubDetails.moderators.forEach(function (entry) {
          if (entry.toString() === senderId) {
            isfound = true;
            Club.updateOne(
              {
                _id: clubId,
              },
              {
                $addToSet: {
                  banned: banId,
                },
              }
            );
            Usercontact.updateOne(
              {
                userId: req.user._id,
              },
              {
                $pull: {
                  contacts: req.body.clubId,
                },
              }
            )
              .exec()
              .then(response => res.json(response))
              .catch(error => res.json(error));
          }
        });
        if (!isfound)
          return res.json({ message: "You Don't Have Permission :)" });
      }
    })
    .catch(error => res.json('Something Went Wrong'));
};
