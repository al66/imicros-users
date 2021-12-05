/**
 * @license MIT, imicros.de (c) 2018 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const crypto = require("crypto");
const jwt 			= require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const { Serializer } = require("./util/serializer");
const { UserError, 
    UserNotCreated, 
    UserNotAuthenticated, 
    UserNotFound,
    UserAuthentication, 
    UserVerification
} = require("./util/errors");

/** Actions */
// action create { email, password } => { user }
// action requestConfirmationMail { } => { result }
// action confirm { token } => { result }
// action requestPasswordResetMail { email } => { result }
// action resetPassword { token, password } => { result }
// action login { email, password } => { user, token }
// action resolveToken { token } => { user }
// action me { } => { user }
// action requestDeletion { } => { result }
// action confirmDeletion { token } => { result }
//TODO: action count { }                                      // admin only: acl=core 
//TODO: action find { email } => { userId }                   // admin only: acl=core 
//TODO: action requestDeletion { email } => { result }        // admin only: acl=core 
//TODO: action denyDeletion { token } => { result } 

/** Secret for JWT */
const JWT_SECRET = process.env.JWT_USERS_SECRET || "jwt-imicros-users-secret";

module.exports = {
    name: "users",
    mixins: [dbMixin],

    /**
     * Service settings
     */
    settings: {
        /* $secureSettings: ["database.user", "database.password", "verifiedUsers"], */

        /** Database */
        /*
        database: {
            uri: process.env.NEO4J_URI || "bolt://localhost:7687",
            user: "neo4j",
            password: "neo4j",
        },
        */

        /** Initial user without confirmation **/
        /*
        verifiedUsers: ["initial.admin1@imicros.de","initial.admin2@imicros.de"],
        */

        /** Service names of used services **/
        /*
        services: {
            keys: "keys"
        }
        */

        /** API */
        /*
        links: {
            confirmation: "http://www.imicros.de/confirm",
            resetPassword: "http://www.imicros.de/reset"
        }
        */
        
    },

    /**
     * Service metadata
     */
    metadata: {},

    /**
     * Service dependencies
     */
    //dependencies: [],	

    /**
     * Actions
     */
    actions: {

        /**
         * Register a new user
         * 
         * @actions
         * @param {Email} email
         * @param {String} password 
         * 
         * @returns {Object} Created user with id
         */
        create: {
            params: {
                email: { type: "email" },
                password: { type: "string", min: 8 },
                locale: { type: "string", min: 2, max:2, pattern: /^[a-zA-Z]+$/, optional: true }
            },			
            async handler(ctx) {
                let user = await this.addUser({ email: ctx.params.email, password: ctx.params.password, locale: ctx.params.loacle });
                if (!user) throw new UserNotCreated("db insert failed", { email: ctx.params.email } );
                if (user.existing) throw new UserNotCreated("user already exist!", { email: ctx.params.email }); 
                this.logger.debug("return created user", user);
                // delete secure attributes
                delete user.password;
                return user;
            }
        },

        /**
         * Request confirmation mail
         * 
         * @actions
         * 
         * @returns {Object} result with property {String} sent: email 
         */
        requestConfirmationMail: {
            async handler(ctx) {
                if (!ctx.meta.user || !ctx.meta.user.id) {
                    throw new UserNotAuthenticated("not authenticated" );
                }
                let user = await this.getUser({ id:ctx.meta.user.id });
                if (user.verified) throw new UserVerification("user already verified", { email: user.email });
                let token = this.signedJWT({ type: "verify_token", email: user.email });
                let data = {
                    email: user.email,
                    locale: user.locale,
                    token:  token
                };
                // create link
                if (this.settings.links && this.settings.links.confirmation) {
                    data.link = this.settings.links.confirmation + "?token=" + token;
                }
                ctx.meta.ownerId = this.ownerId;
                await ctx.emit("users.verification.requested",data);
                return { sent: user.email };
            }
        },

        /**
         * Confirm registration with token
         * 
         * @actions
         * @param {String} token - confirmation token
         * 
         * @returns {Object} Logged in user with token
         */
        confirm: {
            params: {
                token: { type: "string", min: 1 }
            },
            async handler(ctx) {
                let token = ctx.params.token;
                let decoded;
                try { 
                    decoded = jwt.verify(token, JWT_SECRET);
                    if (!(decoded.type == "verify_token" && decoded.email)) throw new UserVerification("token not valid", { token } );
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserVerification("token not valid", { token } );
                }
                try {
                    let user = await this.getUserByEmail({ email: decoded.email });
                    await this.confirmUser({ id: user.id });
                    return { verified: decoded.email };
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserNotFound("user not found", { email: decoded.email });
                }
            }
        },        
        
        /**
         * Request password reset mail
         * 
         * @actions
         * 
         * @returns {Object} result with property {String} sent: email 
         */
        requestPasswordResetMail: {
            params: {
                email: { type: "email" }
            },
            async handler(ctx) {
                let user = await this.getUserByEmail({ email: ctx.params.email });                
                if (!user.verified) throw new UserVerification("user not yet verified", { email: user.email });
                let token = this.signedJWT({ type: "reset_token", id: user.id });
                let data = {
                    email: user.email,
                    locale: user.locale,
                    token:  token
                };
                // create link
                let link = this.settings?.links?.resetPassword ?? null;
                if (link) {
                    data.link = link + "?token=" + token;
                }
                ctx.meta.ownerId = this.ownerId;
                await ctx.emit("users.password.reset.requested",data);
                return { sent: user.email };
            }
        },

        /**
         * Reset password with token
         * 
         * @actions
         * @param {String} token - reset password token
         * @param {String} password
         * 
         * @returns {Object} With properties {Object} user and {String} token
         */
        resetPassword: {
            params: {
                token: { type: "string", min: 1 },
                password: { type: "string", min: 8 }
            },
            async handler(ctx) {
                let token = ctx.params.token;
                let decoded;
                try { 
                    decoded = jwt.verify(token, JWT_SECRET);
                    if (!(decoded.type == "reset_token" && decoded.id)) throw new UserVerification("token not valid", { token } );
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserVerification("token not valid", { token } );
                }
                try {
                    let user = await this.getUser({ id:decoded.id });
                    await this.resetUserPassword({ id: user.id, password: ctx.params.password });
                    return { reset: user.id };
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserNotFound("user not found", { id: decoded.id });
                }
            }
        },        

        /**
         * Login with username & password
         * 
         * @actions
         * @param {Email} email
         * @param {String} password 
         * 
         * @returns {Object} With properties {Object} user and {String} token
         */
        login: {
            params: {
                email: { type: "email" },
                password: { type: "string", min: 1 }
            },
            async handler(ctx) {
                let user = await this.getUserByEmail({ email: ctx.params.email });
                if (!(this.getHash(ctx.params.password) === user.password)) throw new UserAuthentication("wrong password", { email: ctx.params.email });
                // delete secure attributes
                delete user.password;
                let response = {
                    token: this.signedJWT({ type: "user_token", id: user.id }),
                    user
                };
                return response;
            }
        },

        /**
         * Get user by JWT token (for API gateway authentication)
         * 
         * @actions
         * @param {String} token - JWT token
         * 
         * @returns {Object} With property {Object} user as resolved user
         */
        resolveToken: {
            params: {
                token: "string"
            },
            async handler(ctx) {
                try {
                    let decoded = jwt.verify(ctx.params.token, JWT_SECRET);
                    if (decoded.type !== "user_token" || !decoded.id) throw new UserAuthentication("token not valid", { token: ctx.params.token} );
                    let user = await this.getUser({ id:decoded.id });
                    user.token = ctx.params.token;
                    // delete secure attributes
                    delete user.password;
                    return { user };
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserAuthentication("token not valid", { token: ctx.params.token} );
                }
            }
        },
        
        /**
         * Get current user entity.
         * 
         * @actions
         * 
         * @returns {Object} user
         */
        me: {
            async handler(ctx) {
                if (!ctx.meta.user || !ctx.meta.user.id) {
                    throw new UserNotAuthenticated("not authenticated" );
                }
                let user = await this.getUser({ id:ctx.meta.user.id });
                // delete secure attributes
                delete user.password;
                return user;
            }
        },
        
        /**
         * Request deletion
         * 
         * @actions
         * 
         * @returns {Object} result with property {String} sent: email 
         */
        requestDeletion: {
            async handler(ctx) {
                if (!ctx.meta.user || !ctx.meta.user.id) {
                    throw new UserNotAuthenticated("not authenticated" );
                }
                let user = await this.getUser({ id:ctx.meta.user.id });
                if (!user.verified) {
                    // unverified users can be deleted directly
                    await this.deleteUser({ id: user.id });
                    return { deleted: user.email };
                }
                let token = this.signedJWT({ type: "deletion_token", email: user.email });
                let data = {
                    email: user.email,
                    locale: user.locale,
                    token:  token
                };
                // create link
                if (this.settings.links && this.settings.links.deletion) {
                    data.link = this.settings.links.deletion + "?token=" + token;
                }
                ctx.meta.ownerId = this.ownerId;
                await ctx.emit("users.deletion.requested",data);
                return { sent: user.email };
            }
        },

        /**
         * Confirm deletion with token
         * 
         * @actions
         * @param {String} token - deletion token
         * 
         * @returns {Object} result
         */
        delete: {
            params: {
                token: { type: "string", min: 1 }
            },
            async handler(ctx) {
                let token = ctx.params.token;
                let decoded;
                try { 
                    decoded = jwt.verify(token, JWT_SECRET);
                    if (!(decoded.type == "deletion_token" && decoded.email)) throw new UserVerification("token not valid", { token } );
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserVerification("token not valid", { token } );
                }
                try {
                    let user = await this.getUserByEmail({ email: decoded.email });
                    await this.deleteUser({ id: user.id });
                    return { deleted: decoded.email };
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserNotFound("user not found", { email: decoded.email });
                }
            }
        }        
        

    },
    
    /**
     * Events
     */
    events: {},

    /**
     * Methods
     */
    methods: {

        getHash(value) {
            return crypto.createHash("sha256")
                .update(value)
                .digest("hex");
        },

        async encryptData(obj) {
            // serialize and encrypt user data 
            let sek = await this.getKey();
            let iv = crypto.randomBytes(this.encryption.ivlen);
            let serialized = await this.serializer.serialize(obj); 
            this.logger.info("Serialized data to encrypt", serialized);
            try {
                // hash encription key with iv
                let key = crypto.pbkdf2Sync(sek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                // encrypt value
                let value = this.encrypt({ value: serialized, secret: key, iv });
                this.logger.info("Has been encrypted", { value });
                let decryptedAgain = this.decrypt({ encrypted: value, secret: key, iv });
                this.logger.info("Has been encrypted", { decryptedAgain });
                let encrypted = await this.serializer.serialize({
                    key: sek.id,
                    iv: iv.toString("hex"),
                    value    
                });
                return encrypted;
            } catch (err) {
                this.logger.error("Failed to encrypt value", { 
                    error: err, 
                    iterations: this.encryption.iterations, 
                    keylen: this.encryption.keylen,
                    digest: this.encryption.digest
                });
                throw new Error("failed to encrypt");
            }
        },

        async decryptData(data) {
            if (!data || !(data.length > 0)) return {};
            try {
                let container = await this.serializer.deserialize(data);
                this.logger.info("container to decrypt", container);
                let iv = Buffer.from(container.iv, "hex");
                let encrypted = container.value;
                let sek = await this.getKey({ id: container.key });
                // hash received key with salt
                let key = crypto.pbkdf2Sync(sek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                let value = this.decrypt({ encrypted, secret: key, iv });
                // deserialize value
                value = await this.serializer.deserialize(value);
                this.logger.info("decrypted data", value);
                return value;            
            } catch (err) {
                this.logger.error("failed to decrypt", err);
                throw new Error("failed to decrypt");
            }
        },

        async addUser({ email = null, password = null, locale = null }) {
            let user = {
                key: this.getHash(email),
                uid: uuid(),
                password: this.getHash(password),
                locale: locale ? locale.toLowerCase() : "en",
                verified: false
            };

            let data = await this.encryptData({ email });

            if (this.verifiedUsers.indexOf(email)>=0) {
                this.logger.info("verified user will be created",{ verifiedUsers: this.verifiedUsers, user: email});
                user.verified = true;
            }

            let queryParams = {
                key: user.key,
                uid: user.uid,
                password: user.password,
                locale: user.locale,
                verified: user.verified,
                data
            };
            let statement = "MERGE (u:User { key: $key }) ";
            statement += "ON CREATE SET u.uid = $uid, u.password = $password, u.locale = $locale, u.verified = $verified, u.data = $data ";
            statement += "WITH u, CASE WHEN u.password IS NULL THEN $password ELSE u.password END AS password ";
            statement += "SET u.password = password ";
            statement += "RETURN u.uid AS id, u.locale AS locale, u.verified AS verified;";
            this.logger.debug("create user", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            if (result[0]) {
                let found = result[0];
                found.email = email;
                if (found.id !== user.uid) found.existing = true;
                this.logger.info("added user", { found, result: result[0], data });
                return found;
            }
            // failed
            this.logger.debug("failed to create user");
            return null;            
        },

        async resetUserPassword({ id = null, password = null }) {
            let queryParams = {
                uid: id,
                password: this.getHash(password)
            };
            let statement = "MATCH (u:User { uid: $uid }) ";
            statement += "SET u.password = $password ";
            statement += "RETURN u.uid AS id;";
            this.logger.debug("change user password", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            if (result[0] && result[0].id !== id) {
                this.logger.info("changed user password", { id });
                return id;
            }
            // failed
            this.logger.debug("failed to create user");
            return null;            
        },

        async getUser({ id = null}) {
            let queryParams = {
                uid: id
            };
            let statement = "MATCH (u:User { uid: $uid }) ";
            statement += "RETURN u.uid AS id, u.locale AS locale, u.verified AS verified, u.data AS data;";
            this.logger.debug("get user", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            if (result[0]) {
                let found = result[0];
                this.logger.info("found user", { found, result: result[0] });
                let data = await this.decryptData(found.data);
                delete found.data;
                found = Object.assign(found, data);
                this.logger.info("found user", { found, data });
                return found;
            }
            throw new UserNotFound("user not found", { id });
        },

        async getUserByEmail({ email = null}) {
            let queryParams = {
                key: this.getHash(email)
            };
            let statement = "MATCH (u:User { key: $key }) ";
            statement += "RETURN u.uid AS id, u.password AS password, u.locale AS locale, u.verified AS verified, u.data AS data;";
            this.logger.debug("get user", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            if (result[0]) {
                let found = result[0];
                this.logger.info("found user", { found, result: result[0] });
                let data = await this.decryptData(found.data);
                delete found.data;
                found = Object.assign(found, data);
                this.logger.info("found user", { found, data });
                return found;
            }
            throw new UserNotFound("user not found", { email });
        },

        async confirmUser({ id = null}) {
            let queryParams = {
                uid: id
            };
            let statement = "MATCH (u:User { uid: $uid }) ";
            statement += "SET u.verified = true ";
            statement += "RETURN u.uid AS id, u.verified AS verified;";

            this.logger.info("confirm user", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            if (result[0]) {
                return true;
            }
            throw new UserNotFound("user not found", { id });
        },

        async deleteUser({ id = null}) {
            let queryParams = {
                uid: id
            };
            let statement = "MATCH (u:User { uid: $uid }) ";
            statement += "DETACH DELETE u;";

            this.logger.debug("delete user", { statement, queryParams });
            let result = await this.run(statement, queryParams);
            this.logger.info("result delete", { result });
            return true;
        },

        async getKey ({ id = null } = {}) {
            
            // key id is already known
            if (id && (this.keys?.id ?? false)) return {
                id,
                key: this.keys.id
            };
            // default key is already available
            if (!id && (this.keys?.default ?? false) && this.keys[this.keys.default]) return {
                id: this.keys.default,
                key: this.keys[this.keys.default]
            };

            // call key service and retrieve keys
            let result = {};
            let opts;
            let params = {
                token: this.serviceToken,
                id,
                service: this.name
            };
            try {
                result = await this.broker.call(this.services.keys + ".getSek", params, opts);
                this.logger.debug("Got key from key service", { id });
            } catch (err) {
                this.logger.error("Failed to receive key from key service", { params, opts });
                throw err;
            }
            if (!result.id || !result.key) throw new Error("Failed to receive key from service", { result });
            // remember key
            if (!this.keys) this.keys = {};
            this.keys[result.id] = result.key;
            if (!id) this.keys.default = result.id;
            return result;
        },

        /**
         * Generate a signed JWT token
         * 
         * @param {Object} payload 
         * 
         * @returns {String} Signed token
         */
        signedJWT(payload) {
            let today = new Date();
            let exp = new Date(today);
            exp.setDate(today.getDate() + 60);
            payload.exp = Math.floor(exp.getTime() / 1000);

            return jwt.sign(payload, JWT_SECRET);
        },
        
        encrypt ({ value = ".", secret, iv }) {
            let cipher = crypto.createCipheriv("aes-256-cbc", secret, iv);
            let encrypted = cipher.update(value, "utf8", "hex");
            encrypted += cipher.final("hex");
            return encrypted;
        },

        decrypt ({ encrypted, secret, iv }) {
            let decipher = crypto.createDecipheriv("aes-256-cbc", secret, iv);
            let decrypted = decipher.update(encrypted, "hex", "utf8");
            decrypted += decipher.final("utf8");
            return decrypted;            
        },
        
         
    },

    /**
     * Service created lifecycle event handler
     */
    created() {

        // array of default users - valid without verification
        this.verifiedUsers = this.settings?.verifiedUsers ?? [];

        // instance of serializer
        this.serializer = new Serializer();

        // encryption setup
        this.encryption = {
            iterations: 1000,
            ivlen: 16,
            keylen: 32,
            digest: "sha512"
        };

        // set actions
        this.services = {
            keys: this.settings?.services?.keys ?? "keys"
        };        

        // service token to retrieve encryption key from keys service
        this.serviceToken = process.env.SERVICE_TOKEN;

        // Settings for event handling in imicros-flow
        this.ownerId = process.env.EVENT_OWNER_ID;

        this.broker.waitForServices(Object.values(this.services));
        
    },

    /**
     * Service started lifecycle event handler
     */
    async started () {

    },

    /**
     * Service stopped lifecycle event handler
     */
    async stopped() {

    }
    
};

 