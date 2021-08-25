/**
 * @license MIT, imicros.de (c) 2021 Andreas Leinen
 */
"use strict";

class UserError extends Error {
    constructor(e, params = {} ) {
        super(e);
        Error.captureStackTrace(this, this.constructor);
        this.message = e.message || e;
        this.name = this.constructor.name;
        for(let prop in params) {
            if (!(prop in this)) this[prop] = params[prop];
        }
    }
}
 
class UserNotAuthenticated extends UserError {}
class UserUnvalidToken extends UserError {}
class UserNotAuthorizedByToken extends UserError {}
class UserNotCreated extends UserError {}
class UserVerification extends UserError {}
class UserAuthentication extends UserError {}
class UserNotFound extends UserError {}
class UserNotAuthorized extends UserError {}
 
module.exports = {
    UserError,
    UserNotAuthenticated,
    UserUnvalidToken,
    UserNotAuthorizedByToken,
    UserNotCreated,
    UserNotFound,
    UserVerification,
    UserAuthentication,
    UserNotAuthorized
};