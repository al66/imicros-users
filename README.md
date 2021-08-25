# imicros-users
[![Build Status](https://travis-ci.org/al66/imicros-users.svg?branch=master)](https://travis-ci.org/al66/imicros-users)
[![Coverage Status](https://coveralls.io/repos/github/al66/imicros-users/badge.svg?branch=master)](https://coveralls.io/github/al66/imicros-users?branch=master)

[Moleculer](https://github.com/moleculerjs/moleculer) services for storing user data in the imicros framework

This is a replacemnet of the users service in imicros-auth using neo4j database insteand of MongoDB.
It doesn't support the direct calls of the event handlers to send the verification mails, it just throw the events.

## Installation
```
$ npm install imicros-users --save
```
## Dependencies
Requires a running Neo4j Instance.

Requires a running service which reacts on the events
 - users.password.reset.requested with params { email, locale, token }  
 - users.verification.requested with params { email, locale, token }
 - users.deletion.requested with params { email, locale, token }


# Usage
## Usage Users
```js
const { ServiceBroker } = require("moleculer");
const { Users } = require("imicros-users");

broker = new ServiceBroker({
    logger: console
});
service = broker.createService(Users, Object.assign({ 
    settings: { 
        $secureSettings: ["user", "password", "verifiedUsers"], 
        uri: process.env.NEO4J_URI || "bolt://localhost:7687",
        user: "neo4j",
        password: "neo4j",
        verifiedUsers: ["first.admin@imicros.de"],
        services: {
            keys: "keys"
        }
    } 
}));
broker.start();

```
### Actions
action create { email, password } => { user }
action requestConfirmationMail { } => { result }
action confirm { token } => { result }
action requestPasswordResetMail { email } => { result }
action resetPassword { token, password } => { result }
action login { email, password } => { user, token }
action resolveToken { token } => { user }
action me { } => { user }
action requestDeletion { } => { result }
action confirmDeletion { token } => { result }

#### Create
For REST call via API. Or as a direct call:
```js
let param = {
    email: "example@test.com",  // valid email
    password: "my secret",      // min 8
    locale: "en"                // optional - 2 character
}
broker.call("users.create", param).then(user => {
    // user.id is filled
})
```
#### requestConfirmationMail
For REST call via API. 
Or as a direct call:
```js
let param = {
    email: "example@test.com"   // registered email (user created)
}
broker.call("users.requestConfirmationMail", param).then(user => {
    // emit the event users.verification.requested with default parameters:
    //   {
    //      email: user.email,
    //      locale: user.locale,
    //      token:  token
    //   }
    // the token should be added to a link in the confirmation mail
    // in case of a successful call it returns
    //  {
    //      sent: "example@test.com"
    //  }
})
```
#### confirm
This method must be called by the method which handles the confirmation link in the confirmation mail.
```js
let param = {
    token: token  // valid token (received as return value from requestConfirmationMail)
}
broker.call("users.confirm", param).then(user => {
    // in case of a successful call it returns
    //  {
    //      verified: "example@test.com"
    //  }
})
```
#### requestPasswordResetMail
For REST call via API. 
Or as a direct call:
```js
let param = {
    email: "example@test.com"   // registered email (user created)
}
broker.call("users.requestPasswordResetMail", param).then(user => {
    // emit the event users.password.reset.requested with default parameters:
    //   {
    //      email: user.email,
    //      locale: user.locale,
    //      token:  token
    //   }
    // in case of a successful call it returns
    //  {
    //      sent: "example@test.com"
    //  }
})
```
#### resetPassword
For REST call via API. 
Or as a direct call:
```js
let param = {
    token: token,               // valid token (received as return value from requestPasswordResetMail)
    password: "my new secret",  // new password, min 8
}
broker.call("users.resetPassword", param).then(user => {
    // in case of a successful call it returns
    //  {
    //      reset: user.id
    //  }
})
```
#### login
For REST call via API. 
Or as a direct call:
```js
let param = {
    email: "example@test.com",  // registered email (user created)
    password: "my secret"       // min 8
}
broker.call("users.login", param).then(user => {
    // in case of a successful call it returns
    //  {
    //      token: generated token
    //      user: user object
    //  }
})
```
#### resolveToken
This method is for calling in moleculer-web method authorize.  
If further imicros services like imicros-groups or imicros-acl will be used, the user must be added to ctx.meta - at least user.id and user.email.  
```js
let param = {
    token: token                // valid token (received as return value from login)
}
broker.call("users.resolveToken", param).then(user => {
    // in case of a successful call it returns
    //  {
    //      user: user object
    //  }
})
```
#### me
For REST call via API. Must be authorized by token - ctx.meta.user.id is then filled and the user is returned.
```js
broker.call("users.me", param).then(user => {
    // in case of a successful call it returns
    //  {
    //      user: user object
    //  }
})
```



