"use strict";

const { ServiceBroker } = require("moleculer");
const { Users } = require("../index");
const { UserNotCreated, UserNotAuthenticated, UserNotFound, UserAuthentication } = require("../index").Errors;
const { v4: uuid } = require("uuid");

let timestamp = Date.now();

process.env.SERVICE_TOKEN = "bVTWhK8G5ASfoMjVAiUhSLHq2P5p8135PEm+0GRvo4Q=";

// helper service to collect emitted events
let calls = [];
const Collect = {
    name: "helper.collect",
    events: {
        "**"(payload, sender, event, ctx) {
            // console.log("called", {payload, sender, event, ctx});
            this.calls[event] ? this.calls[event].push({payload, sender, event, ctx}) : this.calls[event] = [{payload, sender, event, ctx}];
        }
    },
    created () {
        this.calls = calls;
    }
};
function clear(calls) {
    for (let event in calls) {
        calls[event].splice(0, calls[event].length);
    }
}

// mock keys service
const keys = {
    current: uuid(),
    previous: uuid()
};
const KeysMock = {
    name: "keys",
    actions: {
        getSek: {
            handler(ctx) {
                if (!ctx.params || !ctx.params.service) throw new Error("Missing service name");
                if (ctx.params.token !== process.env.SERVICE_TOKEN) throw new Error("Wrong service token");
                if ( ctx.params.id == keys.previous ) {
                    return {
                        id: keys.previous,
                        key: "myPreviousSecret"
                    };    
                }
                return {
                    id: keys.current,
                    key: "mySecret"
                };
            }
        }
    }
};

describe("Test user service", () => {

    let broker, service, initialUser;
    
    beforeAll(() => {
    });
    
    afterAll(() => {
    });
    
    beforeEach(() => clear(calls));

    describe("Test create service", () => {

        it("it should start the broker", async () => {
            broker = new ServiceBroker({
                logger: console,
                logLevel: "info" //"debug"
            });
            initialUser = `admin-${timestamp}@imicros.de`;
            service = await broker.createService(Users, Object.assign({ 
                settings: {
                    $secureSettings: ["database.user", "database.password", "verifiedUsers"], 
                    database: {
                        uri: process.env.NEO4J_URI,
                        user: process.env.NEO4J_USER,
                        password: process.env.NEO4J_PASSWORD
                    },
                    verifiedUsers: [initialUser],
                    services: {
                        keys: "keys"
                    }
                },
                dependencies: ["keys"]
            }));
            await broker.createService(KeysMock);
            await broker.createService(Collect);
            await broker.start();
            expect(service).toBeDefined();
        });

    });

    describe("Test users service", () => {   
        let opts, id;
        let email = "test-"+ Date.now() + "@host.com";
        let token;
        
        beforeEach(() => {
            opts = { };
        });
        
        it("it should return created entry with id", () => {
            let params = {
                email: email,
                password: "my secret"
            };
            return broker.call("users.create", params, opts).then(res => {
                id = res.id;
                expect(res.id).toBeDefined();
                expect(res.password).not.toBeDefined();
                expect(res).toEqual(expect.objectContaining({ email: params.email, locale: "en" }));
            });
        });

        it("it should return with error", async () => {
            let params = {
                email: email,
                password: "my secret"
            };
            expect.assertions(3);
            await broker.call("users.create", params, opts).catch(err => {
                expect(err instanceof UserNotCreated).toBe(true);
                expect(err.message).toEqual("user already exist!");
                expect(err.email).toEqual(email);
            });
        });

        it("it should return error not authenticated", async () => {
            opts = { };
            let params = {
            };
            expect.assertions(2);
            await broker.call("users.me", params, opts).catch(err => {
                expect(err instanceof UserNotAuthenticated).toBe(true);
                expect(err.message).toEqual("not authenticated");
            });
        });
        
        it("it should return error user not found", async () => {
            opts = { meta: { user: { id: uuid() } } };
            let params = {
            };
            expect.assertions(3);
            await broker.call("users.me", params, opts).catch(err => {
                expect(err instanceof UserNotFound).toBe(true);
                expect(err.message).toEqual("user not found");
                expect(err.id).toEqual(opts.meta.user.id);
            });
        });

        it("it should return new user", () => {
            opts = { meta: { user: { id: id } } };
            let params = {
            };
            return broker.call("users.me", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ email: email, verified: false }));
            });
        });

        it("it should send confirmation mail", () => {
            opts = { meta: { user: { id: id } } };
            let params = {
            };
            return broker.call("users.requestConfirmationMail", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ sent: email }));
                broker.logger.info("Collected calls",calls);
                broker.logger.info("Payload",calls["users.verification.requested"][0].payload);
                expect(calls["users.verification.requested"]).toBeDefined();
                expect(calls["users.verification.requested"][0].payload.token).toBeDefined();
                expect(calls["users.verification.requested"][0].payload.email).toEqual(email);
                token = calls["users.verification.requested"][0].payload.token;
            });
        });        

        it("it should confirm user", () => {
            opts = {};
            let params = {
                token: token
            };
            return broker.call("users.confirm", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ verified: email }));
            });
        });
        
        it("it should return confirmed user", () => {
            opts = { meta: { user: { id: id } } };
            let params = {
            };
            return broker.call("users.me", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ email: email, verified: true }));
            });
        });

        it("it should login new user", () => {
            let params = {
                email: email,
                password: "my secret"
            };
            return broker.call("users.login", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
                expect(res.user).toEqual(expect.objectContaining({ email: email }));
            });
        });
        
        it("it should throw error wrong password", async () => {
            let params = {
                email: email,
                password: "my wrong secret"
            };
            expect.assertions(3);
            await broker.call("users.login", params, opts).catch(err => {
                expect(err instanceof UserAuthentication).toBe(true);
                expect(err.message).toEqual("wrong password");
                expect(err.email).toEqual(email);
            });
        });

        it("it should resolve access token", () => {
            let params = {
                token: token
            };
            return broker.call("users.resolveToken", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.user).toEqual(expect.objectContaining({ email: email }));
                expect(res.user).toEqual(expect.objectContaining({ token }));
            });
        });

        it("it should send deletion mail", () => {
            opts = { meta: { user: { id: id } } };
            let params = {
            };
            return broker.call("users.requestDeletion", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ sent: email }));
                broker.logger.info("Collected calls",calls);
                broker.logger.info("Payload",calls["users.deletion.requested"][0].payload);
                expect(calls["users.deletion.requested"]).toBeDefined();
                expect(calls["users.deletion.requested"][0].payload.token).toBeDefined();
                expect(calls["users.deletion.requested"][0].payload.email).toEqual(email);
                token = calls["users.deletion.requested"][0].payload.token;
            });
        });        

        it("it should delete user", () => {
            opts = {};
            let params = {
                token: token
            };
            return broker.call("users.delete", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({ deleted: email }));
            });
        });
        
        
    });

    describe("Test create initial user", () => {

        it("it should return initial verified user with id", () => {
            let opts;
            let params = {
                email: initialUser,
                password: "my secret"
            };
            return broker.call("users.create", params, opts).then(res => {
                expect(res.id).toBeDefined();
                expect(res.password).not.toBeDefined();
                expect(res).toEqual(expect.objectContaining({ email: params.email, locale: "en", verified: true }));
            });
        });
        
    });    

    describe("Test stop broker", () => {
        it("should stop the broker", async () => {
            expect.assertions(1);
            await broker.stop();
            expect(broker).toBeDefined();
        });
    });
    
});