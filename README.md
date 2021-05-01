# Massaging-Plugin-Backend

Massaging Plugin Backend

`npm i`

`npm start`

`PORT=3000`

### End Points

* health check
`/api`

* POST /api/signup/mailotp
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
* POST /api/forgotpassword/mailotp
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
        * newUser true for signUp OTP verification
        * newUser false for resetPassword OTP verification
    ```json
    {
        "email":"example@gmail.com",
        "otp":"5248",
        "newUser":false
    }
    ```
    * Sample Response 
    ```json
    {
    "temporaryToken": "temp token with 1 day of validity which will be used at the signup time or at reset password time to verify that your otp has been verified."
    }
    ```
* POST /api/resetpassword
    * Sample Request
    ```json
    {
    "temporaryToken": "Temporary Token obtained after otp verification",
    "password":"New Password"
    }
    ```
    * Sample Response 
    ```json
    {
    "success": "Password Updated"
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
        * all or some portion of user data will be here as per requirement this is just a sample response
    ```json
    {
    "user": {
        "passwordLess": false,
        "personalEmail": "example@gmail.com",
        "hashPassword": "hashofyourpassword",
        "accessToken": "your_accessToken"
        }
    }
    ```
* POST /api/logout
    * Sample Request
      * the accessToken should be present in the request header as bearer token
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
        * all or some portion of user data will be here as per requirement this is just a sample response 
    ```json
    {
    "user": {
        "passwordLess": false,
        "personalEmail": "example@gmail.com",
        "hashPassword": "hashofyourpassword",
        "accessToken": "your_accessToken"
        }
    }
    ```
* POST /api/signup/nonini/passwordless
    * Sample Request
    ```json
    {
      "fullNameInstitute": "fullNameInstitute",
      "contact": "contact",
      "instituteEmail": "instituteEmail",
      "discord": "discord",
      "facebook": "facebook",
      "instagram": "instagram",
      "instituteName": "instituteName",
      "batch": "batch",
      "joiningYear": "joiningYear",
      "linkedinAccessToken": "Linkedin Access Token",
      "googleRefreshToken": "Google Refresh Token",      
    }
    ```
    * Sample Response
        * AWS Response about whether the item is added or not. 
    ```json
    {
        "success": "Item added successfully"
    }
    ```

* POST /api/signup/ini/passwordless
    * Sample Request
    ```json
    {
      "fullNameInstitute": "fullNameInstitute",
      "contact": "contact",
      "instituteEmail": "instituteEmail",
      "discord": "discord",
      "facebook": "facebook",
      "instagram": "instagram",
      "instituteName": "instituteName",
      "batch": "batch",
      "joiningYear": "joiningYear",
      "linkedinAccessToken": "Linkedin Access Token",
      "googleRefreshToken": "Google Refresh Token",      
    }
    ```
    * Sample Response
        * AWS Response about whether the item is added or not. 
    ```json
    {
        "success": "Item added successfully"
    }
    ```    