/**
 * @license MIT, imicros.de (c) 2018 Andreas Leinen
 */
"use strict";

const Cassandra = require("cassandra-driver");
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
// action requestConfirmationMail { email } => { result }
// action confirm { token } => { result }
// action requestPasswordResetMail { email } => { result }
// action resetPassword { token, password } => { result }
// action login { email, password } => { user, token }
// action resolveToken { token } => { user }
// action me { } => { user }
//TODO: ? action list { }
//TODO: ? action get { token } => { user }
//TODO: ? action delete { email, password }
 
/** Secret for JWT */
const JWT_SECRET = process.env.JWT_USERS_SECRET || "jwt-imicros-users-secret";
 
module.exports = {
    name: "users",
    mixins: [],
 
    /**
      * Service settings
      */
    settings: {
 
        /** Database */
        /*
         cassandra: {
             contactPoints: process.env.CASSANDRA_CONTACTPOINTS || "127.0.0.1", 
             datacenter: process.env.CASSANDRA_DATACENTER || "datacenter1", 
             keyspace: process.env.CASSANDRA_KEYSPACE || "imicros_users" 
         },
         */
 
        /** Initial user without confirmation **/
        /*
         verifiedUsers: ["initial.admin1@imicros.de","initial.admin2@imicros.de"],
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
                let index = await this.getByEmail({ email: ctx.params.email });
                if (index.userId) {
                    // ensure that the user has been inserted (no ACID database)
                    await this.insertUser({ id: index.userId, email: ctx.params.email, locale: ctx.params.locale || "en"  });
                    throw new UserNotCreated("user already exist!", { email: ctx.params.email });   
                }
                index.password = this.getHash(ctx.params.password);
                index.userId = await this.insertEmail(index);
                let user = await this.insertUser({ id: index.userId, email: ctx.params.email, locale: ctx.params.locale || "en" });
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
                    let index = await this.getByEmail({ email: decoded.email });
                    if (!index.userId) throw new UserNotFound("user not found", { email: decoded.email });
                    await this.confirmUser({ id: index.userId });
                    return { verified: decoded.email };
                } catch (err) {
                    if (err instanceof UserError) throw err;
                    throw new UserNotFound("user not found", { email: decoded.email });
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
                let index = await this.getByEmail({ email: ctx.params.email });
                if (!index.userId) throw new UserNotFound("user not found", { email: ctx.params.email });
                if (!(this.getHash(ctx.params.password) === index.password)) throw new UserAuthentication("wrong password", { email: ctx.params.email });
                let user = await this.getUser({ id: index.userId });
                let response = {
                    token: this.signedJWT({ type: "user_token", id: index.userId }),
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
                return user;
            }
        },
         
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
 
        async getByEmail ({ email = null }) {
            let query = "SELECT email, user, password FROM " + this.emailTable;
            query += " WHERE email = :email;";
            let params = { 
                email
            };
            try {
                let result = await this.cassandra.execute(query, params, { prepare: true });
                let row = result.first();
                if (row) return {
                    email,
                    password: row.password,
                    userId: row.user.toString()
                };
            } catch (err) /* istanbul ignore next */ {
                this.logger.error("Cassandra select error", { error: err.message, query });
            }
            return { 
                email,
                password: null,
                userId: null
            };
        },
 
        async insertEmail({ email = null, password = null }) {
            // insert new hash
            let query = "INSERT INTO " + this.emailTable + " (email,user,password) VALUES (:email,:user,:password);";
            let params = { 
                email, 
                user: uuid(),      
                password
            };
            try {
                let result =await this.cassandra.execute(query, params, {prepare: true});
                this.logger.info("hash entry created", params, result);
                return params.user;
            } catch (err) /* istanbul ignore next */ {
                this.logger.error("Cassandra insert error", { error: err.message, query: query, params: params });
                throw new UserNotCreated("db insert failed", { email } );
            }
 
        },
 
        async insertUser({ id = null, email = null, locale = null }) {
            // serialize and encrypt user data 
            let uek = await this.getKey();
            let iv = crypto.randomBytes(this.encryption.ivlen);
            let verified = false;
            // default admin user - no verifcation required
            if (this.verifiedUsers.indexOf(email)>=0) {
                this.logger.info("verified user will be created",{ verifiedUsers: this.verifiedUsers, user: email});
                verified = true;
            }
            let value = await this.serializer.serialize({ email, locale }); 
            try {
                // hash encription key with iv
                let key = crypto.pbkdf2Sync(uek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                // encrypt value
                value = this.encrypt({ value: value, secret: key, iv: iv });
            } catch (err) {
                this.logger.error("Failed to encrypt value", { 
                    error: err, 
                    iterations: this.encryption.iterations, 
                    keylen: this.encryption.keylen,
                    digest: this.encryption.digest
                });
                throw new Error("failed to encrypt");
            }
            // insert user - record: user uuid, value varchar, uek uuid, iv varchar
            let query = "INSERT INTO " + this.userTable + " (user,verified,value,uek,iv) VALUES (:id,:verified,:value,:uek,:iv) IF NOT EXISTS;";
            let params = { 
                id, 
                verified,
                value,
                uek: uek.id,
                iv: iv.toString("hex")
            };
            try {
                let result =await this.cassandra.execute(query, params, {prepare: true});
                this.logger.info("user created", params, result);
                return {
                    id,
                    email,
                    locale,
                    verified
                };
            } catch (err) /* istanbul ignore next */ {
                this.logger.error("Cassandra insert error", { error: err.message, query: query, params: params });
                throw new UserNotCreated("db insert failed", { email } );
            }
 
        },
 
        async getUser({ id = null}) {
            let query = "SELECT user, verified, value, uek, iv FROM " + this.userTable;
            query += " WHERE user = :id;";
            let params = { 
                id
            };
            try {
                let result = await this.cassandra.execute(query, params, { prepare: true });
                let row = result.first();
                if (row) {
                    let uekId = row.get("uek");
                    let iv = Buffer.from(row.get("iv"), "hex");
                    let encrypted = row.get("value");
                    let value = null;
                    let verified = row.get("verified");
                     
                    // get owner's encryption key
                    let uek;
                    try {
                        uek = await this.getKey({ id: uekId });
                    } catch (err) {
                        this.logger.Error("Failed to retrieve user encryption key", { userId: id, key: uekId });
                        throw new Error("failed to retrieve user encryption key");
                    }
 
                    // decrypt value
                    try {
                        // hash received key with salt
                        let key = crypto.pbkdf2Sync(uek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                        value = this.decrypt({ encrypted: encrypted, secret: key, iv: iv });
                    } catch (err) {
                        throw new Error("failed to decrypt");
                    }
                     
                    // deserialize value
                    value = await this.serializer.deserialize(value);
                    let user = Object.assign({ id, verified }, value);
                    this.logger.info("Me", user);
                    return user;
                } else {
                    this.logger.info("Unvalid or empty result", { result, first: row, query, params });
                    throw new UserNotFound("user not found", { id });
                }
            } catch (err) /* istanbul ignore next */ {
                this.logger.info("Cassandra select error", { error: err.message, query });
                throw new UserNotFound("user not found", { id });
            }
        },
 
        async confirmUser({ id = null}) {
            let query = "UPDATE " + this.userTable + " SET verified=true WHERE user=:id;";
            let params = { 
                verified: true,
                id
            };
            try {
                let result = await this.cassandra.execute(query, params, { prepare: true });
                this.logger.info("Cassandra update", { query, params, result });
                let row = result.first();
                if (row) {
                    throw new UserNotFound("user not found", { id });
                } else {
                    return true;
                }
            } catch (err) /* istanbul ignore next */ {
                this.logger.info("Cassandra update error", { error: err.message, query });
                throw new UserNotFound("user not found", { id });
            }
        },
 
        async getKey ({ id = null } = {}) {
             
            let result = {};
             
            // call key service and retrieve keys
            /*
             let opts;
             if ( ctx ) opts = { meta: ctx.meta };
             let params = { 
                 service: this.name
             };
             if ( id ) params.id = id;
             try {
                 result = await this.broker.call(this.services.keys + ".getUek", params, opts);
                 this.logger.debug("Got key from key service", { id: id });
             } catch (err) {
                 this.logger.error("Failed to receive key from key service", { id: id, meta: ctx.meta });
                 throw err;
             }
             if (!result.id || !result.key) throw new Error("Failed to receive key from service", { result: result });
             */
            result = {
                id: uuid(),
                key: "this is the user encryption key retrieved by keys service"
            };
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
         
        async connect () {
 
            // connect to cassandra cluster
            await this.cassandra.connect();
            this.logger.info("Connected to cassandra", { contactPoints: this.contactPoints, datacenter: this.datacenter, keyspace: this.keyspace });
             
            // validate parameters
            // TODO! pattern doesn't work...
             
            // create tables, if not exists
            let query = `CREATE TABLE IF NOT EXISTS ${this.keyspace}.${this.userTable} `;
            query += " ( user uuid, verified Boolean, value varchar, uek uuid, iv varchar, PRIMARY KEY (user) ) ";
            query += " WITH comment = 'storing user data';";
            await this.cassandra.execute(query);
 
            query = `CREATE TABLE IF NOT EXISTS ${this.keyspace}.${this.emailTable} `;
            query += " ( email varchar, user uuid, password varchar, PRIMARY KEY (email) ) ";
            query += " WITH comment = 'index email';";
            await this.cassandra.execute(query);
 
            query = `CREATE TABLE IF NOT EXISTS ${this.keyspace}.${this.contextTable} `;
            query += " ( user uuid, key varchar, value varchar, uek uuid, iv varchar, PRIMARY KEY (user,key) ) ";
            query += " WITH comment = 'storing extended user data';";
            await this.cassandra.execute(query);
        },
         
        async disconnect () {
 
            // close all open connections to cassandra
            await this.cassandra.shutdown();
            this.logger.info("Disconnected from cassandra", { contactPoints: this.contactPoints, datacenter: this.datacenter, keyspace: this.keyspace });
             
        }
          
    },
 
    /**
      * Service created lifecycle event handler
      */
    created() {
 
        // cassandra setup
        let cassandra = this.settings ? ( this.settings.cassandra ? this.settings.cassandra : {} ) : {}; 
        this.contactPoints = ( cassandra.contactPoints ? cassandra.contactPoints : "127.0.0.1" ).split(",");
        this.datacenter = cassandra.datacenter ? cassandra.datacenter : "datacenter1";
        this.keyspace = cassandra.keyspace ? cassandra.keyspace : "imicros_users";
        this.userTable = cassandra.userTable ? cassandra.userTable : "user";
        this.emailTable = cassandra.emailTable ? cassandra.emailTable : "email";
        this.contextTable = cassandra.contextTable ? cassandra.contextTable : "context";
        this.cassandra = new Cassandra.Client({ contactPoints: this.contactPoints, localDataCenter: this.datacenter, keyspace: this.keyspace });
 
        // array of default users - valid without verification
        this.verifiedUsers = this.settings ? ( this.settings.verifiedUsers ? this.settings.verifiedUsers : [] ) : [];
 
        // instance of serializer
        this.serializer = new Serializer();
 
        // encryption setup
        this.encryption = {
            iterations: 1000,
            ivlen: 16,
            keylen: 32,
            digest: "sha512"
        };
 
        // Settings for event handling in imicros-flow
        this.serviceToken = process.env.SERVICE_TOKEN; // not yet used
        this.ownerId = process.env.EVENT_OWNER_ID;
 
        // this.broker.waitForServices(Object.values(this.services));
         
    },
 
    /**
      * Service started lifecycle event handler
      */
    async started () {
 
        // connect to db
        await this.connect();
 
    },
 
    /**
      * Service stopped lifecycle event handler
      */
    async stopped() {
 
        // disconnect from db
        await this.disconnect();
         
    }
     
};
 
  