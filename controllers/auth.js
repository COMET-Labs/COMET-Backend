const jwt = require('jsonwebtoken');
const axios = require('axios').default;
var AWS = require('aws-sdk');
const bcrypt = require('bcrypt');

AWS.config.update({
  region: process.env.region,
  accessKeyId: process.env.accessKeyId,
  secretAccessKey: process.env.secretAccessKey,
});

var docClient = new AWS.DynamoDB.DocumentClient();

exports.isNewUser = (req, res, next) => {
  let params = {
    TableName: 'Users',
    Key: {
      personalEmail: req.body.email,
    },
  };
  docClient.get(params, function (err, data) {
    if (err) {
      res.status(200).json({
        error: 'Some error occured',
      });
    } else {
      if (data && data.Item) {
        res.status(200).json({
          error: 'Already Registered Kindly Login',
        });
      } else {
        next();
      }
    }
  });
};

exports.isUserWithPassword = (req, res, next) => {
  let params = {
    TableName: 'Users',
    Key: {
      personalEmail: req.body.email,
    },
  };

  docClient.get(params, function (err, data) {
    if (err) {
      res.status(200).json({
        error: 'Some error occured',
      });
    } else {
      if (data && data.Item) {
        if (data.Item.hashPassword) {
          next();
        } else {
          res.status(200).json({
            error: 'You account has no password. Login with Google or LinkedIn',
          });
        }
      } else {
        res.status(200).json({
          error: 'You do not have an account. Kindly Signup',
        });
      }
    }
  });
};

exports.resetPassword = (req, res, next) => {
  try {
    const email = jwt.verify(
      req.body.temporaryToken,
      process.env.RESET_PASSWORD_JWT_SECRET
    ).email;
    let updateParams = {
      TableName: 'Users',
      Key: {
        personalEmail: email,
      },
      UpdateExpression: 'set hashPassword = :p',
      ExpressionAttributeValues: {
        ':p': req.body.password,
      },
      ReturnValues: 'NONE',
    };
    docClient.update(updateParams, function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Some error occured',
        });
      } else {
        res.status(200).json({
          success: 'Password Updated',
        });
      }
    });
  } catch (err) {
    next({ status: 400, message: 'Get a new OTP and verify your OTP Again' });
  }
};

exports.mailOtp = async (req, res, next) => {
  try {
    const response = await axios.post(
      'https://66ec05ryyl.execute-api.us-east-2.amazonaws.com/getOtpFromEmail',
      { email_id: req.body.email }
    );
    if (response.data.statusCode === 200) {
      res.status(200).json({
        success: 'OTP sent',
      });
    } else {
      res.status(200).json({
        error: 'Error in mailing OTP',
      });
    }
  } catch (err) {
    next({ status: 400 });
  }
};

exports.verifyOtp = (req, res, next) => {
  try {
    var params = {
      TableName: 'otp',
      Key: {
        email_id: req.body.email,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Expired or Incorrect OTP',
        });
      } else {
        if (data && data.Item && data.Item.otp === req.body.otp) {
          let tempToken;
          if (req.body.newUser) {
            tempToken = jwt.sign(
              { email: req.body.email },
              process.env.SIGNUP_JWT_SECRET,
              {
                expiresIn: '1d',
              }
            );
          } else {
            tempToken = jwt.sign(
              { email: req.body.email },
              process.env.RESET_PASSWORD_JWT_SECRET,
              {
                expiresIn: '1d',
              }
            );
          }
          res.status(200).json({
            temporaryToken: tempToken,
          });
        } else {
          res.status(200).json({
            error: 'Expired or Incorrect OTP',
          });
        }
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};

exports.loginWithPassword = (req, res, next) => {
  try {
    let params = {
      TableName: 'Users',
      Key: {
        personalEmail: req.body.email,
      },
    };
    docClient.get(params, async function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Some error occured',
        });
      } else {
        if (data && data.Item) {
          let result;
          try {
            result = await bcrypt.compare(
              req.body.password,
              data.Item.hashPassword
            );
            if (result) {
              const accessToken = jwt.sign(
                { email: req.body.email },
                process.env.JWT_SECRET,
                {
                  expiresIn: req.body.remember === true ? '30d' : '1d',
                }
              );
              let updateParams = {
                TableName: 'Users',
                Key: {
                  personalEmail: req.body.email,
                },
                UpdateExpression: 'set accessToken = :a',
                ExpressionAttributeValues: {
                  ':a': accessToken,
                },
                ReturnValues: 'ALL_NEW',
              };
              docClient.update(updateParams, function (err, data) {
                if (err) {
                  res.status(200).json({
                    error: 'Some error occured',
                  });
                } else {
                  res.status(200).json({
                    user: { ...data.Attributes },
                  });
                }
              });
            } else {
              res.status(200).json({
                error: 'Invalid email/password combination',
              });
            }
          } catch (err) {
            next({ status: 500, message: err });
          }
        } else {
          res.status(200).json({
            error: 'You do not have an account. Kindly Signup',
          });
        }
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};

exports.isAuthenticated = (req, res, next) => {
  try {
    if (req.headers.authorization) {
      const accessToken = req.headers.authorization.split(' ')[1];
      const email = jwt.verify(accessToken, process.env.JWT_SECRET).email;
      let params = {
        TableName: 'Users',
        Key: {
          personalEmail: email,
        },
      };
      docClient.get(params, function (err, data) {
        if (err) {
          res.status(200).json({
            error: 'Some error occured',
          });
        } else {
          if (data && data.Item && data.Item.accessToken === accessToken) {
            req.email = email;
            next();
          } else {
            res.status(401).json({ error: 'Unauthorized' });
          }
        }
      });
    } else {
      res.status(401).json({ error: 'Unauthorized' });
    }
  } catch (err) {
    next({ status: 400 });
  }
};

exports.logout = (req, res, next) => {
  try {
    let updateParams = {
      TableName: 'Users',
      Key: {
        personalEmail: req.email,
      },
      UpdateExpression: 'set accessToken = :a',
      ExpressionAttributeValues: {
        ':a': '',
      },
      ReturnValues: 'NONE',
    };
    docClient.update(updateParams, function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Some error occured',
        });
      } else {
        res.status(200).json({
          success: 'Logged Out Successfully',
        });
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};

exports.loginWithLinkedIn = async (req, res, next) => {
  try {
    let auth = 'Bearer ' + req.body.accessToken;
    const response = await axios.get('https://api.linkedin.com/v2/me', {
      method: 'GET',
      headers: { Connection: 'Keep-Alive', Authorization: auth },
    });
    const linkeinId = response.data.id;
    let params = {
      TableName: 'Users',
      IndexName: 'linkedin-index',
      ExpressionAttributeValues: {
        ':v1': linkeinId,
      },
      KeyConditionExpression: 'linkedin = :v1',
    };
    docClient.query(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Some error occured',
        });
      } else {
        if (data && data.Items && data.Items[0]) {
          const email = data.Items[0].personalEmail;
          const accessToken = jwt.sign(
            { email: email },
            process.env.JWT_SECRET,
            {
              expiresIn: req.body.remember === true ? '30d' : '1d',
            }
          );
          let updateParams = {
            TableName: 'Users',
            Key: {
              personalEmail: email,
            },
            UpdateExpression: 'set accessToken = :a',
            ExpressionAttributeValues: {
              ':a': accessToken,
            },
            ReturnValues: 'ALL_NEW',
          };
          docClient.update(updateParams, function (err, data) {
            if (err) {
              res.status(200).json({
                error: 'Some error occured',
              });
            } else {
              res.status(200).json({
                user: { ...data.Attributes },
              });
            }
          });
        } else {
          res.status(200).json({
            error: 'You do not have an account. Kindly Signup',
          });
        }
      }
    });
  } catch (err) {
    next({ status: 401 });
  }
};

exports.signupNoniniPasswordless = async (req, res, next) => {
  
  var createParams = {
    TableName: 'Users',
    Item: {
      fullName: req.body.userInfo.name,
      fullNameInstitute: req.body.fullNameInstitute,
      firstName: req.body.userInfo.given_name,
      lastName: req.body.userInfo.family_name,
      contact: req.body.contact,
      personalEmail: req.body.userInfo.email,
      instituteEmail: req.body.instituteEmail,
      dpProfile: req.body.userInfo.picture,
      discord: req.body.discord,
      facebook: req.body.facebook,
      instagram: req.body.instagram,
      instituteName: req.body.instituteName,
      batch: req.body.batch,
      joiningYear: req.body.joiningYear,
      linkedin: req.body.linkedinId,
    },
  };

  docClient.put(createParams, function (err, data) {
    if (err) {
      res.status(500).json({
        error: 'Unable to add item',
      });
    } else {
      res.status(200).json({
        success: 'SignUp Successful',
      });
    }
  });
};

exports.signupiniPasswordless = async (req, res, next) => {
  
  // console.log(Date.now());
  // expTime is in milliseconds
  let expTime = Math.floor(Date.now() / 1000);
  expTime = expTime + parseInt(process.env.EXPIRATION_TIME)
  // console.log(expTime);  
  
  var createParams = {
    TableName: 'Users',
    Item: {
      fullName: req.body.userInfo.name,
      fullNameInstitute: req.body.fullNameInstitute,
      firstName: req.body.userInfo.given_name,
      lastName: req.body.userInfo.family_name,
      contact: req.body.contact,
      personalEmail: req.body.userInfo.email,
      instituteEmail: req.body.instituteEmail,
      dpProfile: req.body.userInfo.picture,
      discord: req.body.discord,
      facebook: req.body.facebook,
      instagram: req.body.instagram,
      instituteName: req.body.instituteName,
      batch: req.body.batch,
      joiningYear: req.body.joiningYear,
      linkedin: req.body.linkedinId,
      expTime: expTime,
    },
  };

  docClient.put(createParams, function (err, data) {
    if (err) {
      res.status(500).json({
        error: 'Unable to add item',
      });
    } else {
      res.status(200).json({
        success: 'SignUp Successful',
      });
    }
  });
};

exports.signupnoniniPassword = async (req, res, next) => {

  req.body.hashPassword = await bcrypt.hash(req.body.hashPassword,5);
  
  var createParams = {
    TableName: 'Users',
    Item: {
      fullName: req.body.fullName,
      fullNameInstitute: req.body.fullNameInstitute,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      contact: req.body.contact,
      personalEmail: req.body.personalEmail,
      instituteEmail: req.body.instituteEmail,
      discord: req.body.discord,
      facebook: req.body.facebook,
      instagram: req.body.instagram,
      instituteName: req.body.instituteName,
      batch: req.body.batch,
      joiningYear: req.body.joiningYear,
      linkedin: req.body.linkedinId,
      hashPassword: req.body.hashPassword,
    },
  };

  docClient.put(createParams, function (err, data) {
    if (err) {
      res.status(500).json({
        error: 'Unable to add item',
      });
    } else {
      res.status(200).json({
        success: 'SignUp Successful',
      });
    }
  });
};

// It will give name, ProfileURL, email address of the user signed by google.
async function getUserInfo(accessToken) {
  let auth = 'Bearer ' + accessToken;
  const response = await axios.get(
    'https://www.googleapis.com/oauth2/v1/userinfo',
    {
      method: 'GET',
      headers: { Connection: 'Keep-Alive', Authorization: auth },
    }
  );

  return response.data;
}

// It checks whether there is a user with same linkedin-id or not
exports.linkedinInfo = async (req, res, next) => {
  let auth = 'Bearer ' + req.body.linkedinAccessToken;
  const response = await axios.get('https://api.linkedin.com/v2/me', {
    method: 'GET',
    headers: { Connection: 'Keep-Alive', Authorization: auth },
  });
  let params = {
    TableName: 'Users',
    IndexName: 'linkedin-index',
    ExpressionAttributeValues: {
      ':v1': response.data.id,
    },
    KeyConditionExpression: 'linkedin = :v1',
  };
  try {
    docClient.query(params, function (err, data) {
      if (data && data.Items && data.Items[0]) {
        res.status(200).json({
          error:
            'You have an linkedin account with different personal email ID',
        });
      } else {
        req.body.linkedinId = response.data.id;
        next();
      }
    });
  } catch (err) {
    res.status(200).json({
      error: err,
    });
  }
};

exports.getEmail = async (req, res, next) => {
  try {
    const tokenResponse = await axios.post(
      'https://www.googleapis.com/oauth2/v4/token',
      {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: req.body.googleRefreshToken,
        grant_type: 'refresh_token',
      }
    );
    const userInfo = await getUserInfo(tokenResponse.data.access_token);
    req.body.personalEmail = userInfo.email;
    req.body.userInfo = userInfo;
    // console.log(userInfo.email);
    next();
  } catch (err) {
    res.status(200).json({
      error: err,
    });
  }
};

exports.checkUser = async (req, res, next) => {
  try {
    let params = {
      TableName: 'Users',
      Key: {
        personalEmail: req.body.personalEmail,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: 'Some error occured',
        });
      } else {
        if (data && data.Item) {
          res.status(200).json({
            error: 'You already have an account. Kindly Login',
          });
        } else {
          next();
        }
      }
    });
  } catch (err) {
    res.status(200).json({
      error: err,
    });
  }
};
