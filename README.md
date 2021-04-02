# Massaging-Plugin-Backend

Massaging Plugin Backend

`npm i`

`npm start`

`PORT=3000`

### End Points

* health check
`/api`

* POST /api/mailotp
    * Sample Request
    ```json
    {
    "email":"example@gmail.com"
    }
    ```
    * Sample Response 
    ```json
    {
    "success": "OTP sent"
    }
    ```
* POST /api/verifyotp
    * Sample Request
    ```json
    {
        "email":"example@gmail.com",
        "otp":"5248"
    }
    ```
    * Sample Response 
    ```json
    {
    "success": "OTP is Correct"
    }
    ```
* POST /api/verifyiiitianemail
    * Sample Request
    ```json
    {
    "email":"collegemail@iiit.ac.in"
    }
    ```
    * Sample Response 
    ```json
    {
    "success": "OTP sent"
    }
    ```
* POST /api/loginwithpassword
    * Sample Request
    ```json
    {
    "email":"example@gmail.com",
    "password":"your_password",
    "remember": true
    }
    ```
    * Sample Response 
    ```json
    {
    "user": {
        // all or some portion of user data will be here as per requirement this is just a sample response
        "passwordLess": false,
        "personalEmail": "example@gmail.com",
        "hashPassword": "hashofyourpassword",
        "accessToken": "your_accessToken"
        }
    }
    ```
* POST /api/logout
    * Sample Request
    ```json
    // the accessToken should be present in the request header as bearer token
    ```
    * Sample Response 
    ```json
    {
    "success": "Logged Out Successfully"
    }
    ```
* POST /api/loginwithlinkedin
    * Sample Request
    ```json
    {
    "accessToken":"Token-From-LinkedIn",
    "remember":false
    }
    ```
    * Sample Response 
    ```json
    {
    "user": {
        // all or some portion of user data will be here as per requirement this is just a sample response
        "passwordLess": false,
        "personalEmail": "example@gmail.com",
        "hashPassword": "hashofyourpassword",
        "accessToken": "your_accessToken"
        }
    }
    ```
