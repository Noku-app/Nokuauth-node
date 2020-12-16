var express = require('express');
var router = express.Router();
var bodyParser = require("body-parser");
var databaseModule = require("@noku-app/nokubase").database;
var encryptio = require("./encryptio");
var uid = encryptio.SnowflakeGenerator();

var database = new databaseModule(
    {
        config: require("../config.json"),
        clean: true
    }
);

const validateEmail= email => {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

const data = (_data) => {
    return {
        error: false,
        data: _data
    };
};

const error = (reason, message) => {
    return {
        error: true, 
        data: {
            reason: reason,
            message: message
        }
    };
};

router.use(bodyParser.json());

router.post(
    '/creation', 
    async (req, res) => {

        if (!req.body.email || !req.body.password || !req.body.nick) {
            res.status(401);
            res.send(
                error("missing_params", "client sent a request missing some parameters.")
            );
            return;
        };

        let email = req.body.email;

        if (!validateEmail(email)) {
            res.status(401);
            return res.send(
                error("invalid_email", "Your email is invalid.")
            );
        };

        let nick = req.body.nick;
        let password = req.body.password;
        
        const finalCallback = async() => {
            let NewUID = Number(uid.generate());
            let hashed = encryptio.hash(password);
            let token = encryptio.generateToken();
                
            await database.tokenUser(
                NewUID,
                await hashed,
                await token
            );
                        
            database.registerUser(
                {
                    email: email,
                    uid: NewUID,
                    nick: nick,
                }
            );
                        
            return res.send(
                data(
                    {
                        uid: NewUID,
                        token: await token
                    }
                )
            );
        };

        const nickCallback = async(nickTaken) => {
            if (nickTaken) {
                res.status(401);
                res.send(error("nick_taken", `${nick} is taken`));
                return;
            } else {
                finalCallback();
            };
        };

        const emailCallback = async(emailTaken) => {
            if (emailTaken) {
                res.status(401);
                res.send(error("email_taken", `${email} is taken`));
                return
            } else {
                database.isNickTaken(
                    nick,
                    nickCallback
                );
            };
        };

        database.isEmailTaken(
            email,
            emailCallback
        );
    }
);

router.post("/token", 
    async (req, res) => {
        if (!req.body.token) {
            res.status(401);
            return res.send(
                error("missing_params", "client sent a request missing some parameters.")
            );
        };

        const uidcallback = async (uid) => {
            if (!uid) {
                res.status(401);
                return res.send(
                    error("invalid_token", "the token you provided is invalid or expired.")
                );
            };

            let token = encryptio.generateToken();

            database.updateToken(uid, await token);
            
            return res.send(
                data(
                    {
                        uid: uid,
                        token: await token
                    }
                )
            );

        };
        
        database.getUIDbyToken(req.body.token, uidcallback);
    }
);

router.post("/login",
    async (req, res) => {
        let uid;
        if (!req.body.email || !req.body.password) {
            res.status(401);
            res.send(
                error("missing_params", "client sent a request missing some parameters.")
            );
            return;
        };

        const secretCallback = async(secret)  => {
            if (!secret) {
                res.status(401);
                return res.send(
                    error("unknown", "something went wrong")
                );
            };
            let is_correct = encryptio.checkSecret(
                req.body.password,
                secret
            );
            if (!is_correct) {
                res.status(401);
                return res.send(
                    error("invalid_password", "You provided an invalid password. . .")
                )
            };
            let token = encryptio.generateToken()
            database.updateToken(uid, await token);
            return res.send(
                data(
                    {
                        uid: uid,
                        token: await token
                    }
                )
            )
        };

        const emailCallback = async(_uid) => {
            uid = _uid;
            if (!uid) {
                res.status(401);
                return res.send(
                    error("invalid_email", "email is invalid")
                );
            };
            
            database.getSecretbyUID(
                uid,
                secretCallback
            );
        };

        database.getUIDbyEmail(
            req.body.email,
            emailCallback
        );
    }
);

module.exports = router;