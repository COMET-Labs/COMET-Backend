const jwt = require("jsonwebtoken");
const axios = require("axios").default;
var AWS = require("aws-sdk");

AWS.config.update({
  region: process.env.region,
  accessKeyId: process.env.accessKeyId,
  secretAccessKey: process.env.secretAccessKey,
});

var docClient = new AWS.DynamoDB.DocumentClient();

exports.mailOtp = async (req, res) => {
  try {
    const response = await axios.post(
      "https://66ec05ryyl.execute-api.us-east-2.amazonaws.com/getOtpFromEmail",
      { email_id: req.body.email }
    );
    if (response.data.statusCode === 200) {
      res.status(200).json({
        success: "OTP sent",
      });
    } else {
      res.status(200).json({
        error: "Error in mailing OTP",
      });
    }
  } catch (err) {
    next({ status: 400 });
  }
};

exports.verifyOtp = (req, res) => {
  try {
    var params = {
      TableName: "otp",
      Key: {
        email_id: req.body.email,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Expired or Incorrect OTP",
        });
      } else {
        if (data && data.Item && data.Item.otp === req.body.otp) {
          res.status(200).json({
            success: "OTP is Correct",
          });
        } else {
          res.status(200).json({
            error: "Expired or Incorrect OTP",
          });
        }
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};

exports.isIiitian = (req, res, next) => {
  // more logic will be added later
  next();
};

exports.loginWithPassword = (req, res) => {
  try {
    let params = {
      TableName: "Users",
      Key: {
        personalEmail: req.body.email,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Some error occured",
        });
      } else {
        if (data && data.Item) {
          const hash = "hash"; // will be replaced by function soon
          if (
            data.Item.passwordLess === false &&
            data.Item.hashPassword === hash
          ) {
            const accessToken = jwt.sign(
              { email: req.body.email },
              process.env.JWT_SECRET,
              {
                expiresIn: req.body.remember === true ? "30d" : "1d",
              }
            );
            let updateParams = {
              TableName: "Users",
              Key: {
                personalEmail: req.body.email,
              },
              UpdateExpression: "set accessToken = :a",
              ExpressionAttributeValues: {
                ":a": accessToken,
              },
              ReturnValues: "ALL_NEW",
            };
            docClient.update(updateParams, function (err, data) {
              if (err) {
                res.status(200).json({
                  error: "Some error occured",
                });
              } else {
                res.status(200).json({
                  user: { ...data.Attributes },
                });
              }
            });
          } else {
            res.status(200).json({
              error: "Invalid email/password combination",
            });
          }
        } else {
          res.status(200).json({
            error: "You do not have an account. Kindly Signup",
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
      const accessToken = req.headers.authorization.split(" ")[1];
      const email = jwt.verify(accessToken, process.env.JWT_SECRET).email;
      let params = {
        TableName: "Users",
        Key: {
          personalEmail: email,
        },
      };
      docClient.get(params, function (err, data) {
        if (err) {
          res.status(200).json({
            error: "Some error occured",
          });
        } else {
          if (data && data.Item && data.Item.accessToken === accessToken) {
            req.email = email;
            next();
          } else {
            res.status(401).json({ error: "Unauthorized" });
          }
        }
      });
    } else {
      res.status(401).json({ error: "Unauthorized" });
    }
  } catch (err) {
    next({ status: 400 });
  }
};

exports.logout = (req, res) => {
  try {
    let updateParams = {
      TableName: "Users",
      Key: {
        personalEmail: req.email,
      },
      UpdateExpression: "set accessToken = :a",
      ExpressionAttributeValues: {
        ":a": "",
      },
      ReturnValues: "NONE",
    };
    docClient.update(updateParams, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Some error occured",
        });
      } else {
        res.status(200).json({
          success: "Logged Out Successfully",
        });
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};

exports.loginWithLinkedIn = async (req, res, next) => {
  try {
    let auth = "Bearer " + req.body.accessToken;
    const userEmail = await axios.get(
      "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
      {
        method: "GET",
        headers: { Connection: "Keep-Alive", Authorization: auth },
      }
    );
    const email = userEmail.data.elements[0]["handle~"].emailAddress;
    let params = {
      TableName: "Users",
      Key: {
        personalEmail: email,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Some error occured",
        });
      } else {
        if (data && data.Item) {
          const accessToken = jwt.sign(
            { email: email },
            process.env.JWT_SECRET,
            {
              expiresIn: req.body.remember === true ? "30d" : "1d",
            }
          );
          let updateParams = {
            TableName: "Users",
            Key: {
              personalEmail: email,
            },
            UpdateExpression: "set accessToken = :a",
            ExpressionAttributeValues: {
              ":a": accessToken,
            },
            ReturnValues: "ALL_NEW",
          };
          docClient.update(updateParams, function (err, data) {
            if (err) {
              res.status(200).json({
                error: "Some error occured",
              });
            } else {
              res.status(200).json({
                user: { ...data.Attributes },
              });
            }
          });
        } else {
          res.status(200).json({
            error: "You do not have an account. Kindly Signup",
          });
        }
      }
    });
  } catch (err) {
    next({ status: 401 });
  }
};

exports.verifyBothOtp = (req, res, next) => {
  try {
    var params = {
      TableName: "otp",
      Key: {
        email_id: req.body.personalEmail,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Expired or Incorrect OTP",
        });
      } else {
        if (data && data.Item && data.Item.otp === req.body.personalEmailOtp) {


            var instituteEmailParams = {
              TableName: "otp",
              Key: {
                email_id: req.body.instituteEmail,
              },
            };
            docClient.get(instituteEmailParams, function (err, data) {
              if (err) {
                res.status(200).json({
                  error: "Expired or Incorrect OTP",
                });
              } else {
                if (data && data.Item && data.Item.otp === req.body.instituteEmailOtp) {
                  res.status(200).json({
                    success: "OTP is Correct",
                  });
                } else {
                  res.status(200).json({
                    error: "Expired or Incorrect OTP",
                  });
                }
              }
            });          
          

          res.status(200).json({
            success: "OTP is Correct",
          });
        } else {
          res.status(200).json({
            error: "Expired or Incorrect OTP",
          });
        }
      }
    });
  } catch (err) {
    next({ status: 401 });
  }
};

exports.signupWithPassword = (req, res) => {
  try {
    let params = {
      TableName: "Users",
      Key: {
        personalEmail: req.body.personalEmail,
      },
    };
    docClient.get(params, function (err, data) {
      if (err) {
        res.status(200).json({
          error: "Some error occured",
        });
      } else {
        if (data && data.Item) {
          res.status(200).json({
            error: "You already have an account. Kindly Login",
          });
        } else {


          var createParams = {
            TableName:Users,
            Item:{
                "fullName": req.body.fullName,
                "hashPassword": req.body.password,
                "rollNumber": req.body.rollNumber,
                "contact": req.body.contact,
                "accessToken": req.body.accessToken,
                "personalEmail": req.body.personalEmail,
                "instituteEmail": req.body.instituteEmail
            }
        };
        docClient.put(createParams, function(err, data) {
            if (err) {
                res.status(500).json({
                  error: "Unable to add item",
                });                
            } else {
                res.status(200).json({
                  success: "OTP is Correct",
                });
            }
        });


        }
      }
    });
  } catch (err) {
    next({ status: 400 });
  }
};