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
            result = await bcrypt.compare(req.body.password, data.Item.hashPassword);
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
