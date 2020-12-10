var express = require('express');
var router = express.Router();
var bodyParser = require("body-parser");
var databaseModule = require("../database").database;
var encryptio = require("./encryptio");
const e = require('express');
var uid = encryptio.SnowflakeGenerator();

var database = new databaseModule(
    {
        config: require("../config.json"),
        clean: true
    }
);

const data = (_data) => {return {data: _data}};
const error = (_error) => {return {error: true, reason: _error}};

router.use(bodyParser.json());

router.post('/creation', async (req, res) => {

        if (!req.body.email || !req.body.password || !req.body.nick) {
            res.status(401);
            res.send(error("missing_params"));
            return;
        };

        let email = req.body.email;
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
                res.send(error("nick_taken"));
                return;
            } else {
                finalCallback();
            }
        }

        const emailCallback = async(emailTaken) => {
            if (emailTaken) {
                res.status(401);
                res.send(error("email_taken"));
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

module.exports = router;