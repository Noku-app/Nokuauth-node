const crypt = require("bcrypt");
const base64url = require("base64url")
const SnowFlake = require("snowflake-id").default;
const crypto = require("crypto")


const hash = async(password, iter=15) => {
    let passwordHashed = crypt.hashSync(
        password,
        iter
    );
    return passwordHashed;
};

const checkSecret = async (password, passwordHashed) => {
    let verify = crypt.compareSync(
        password,
        passwordHashed
    );
    return verify;
};

const SnowflakeGenerator = (mid=12, offset=(2019-1970)*31536000*1000) => {
    let SnowFlakeObject = new SnowFlake(
        {
            mid: mid,
            offset: offset
        }
    );
    return SnowFlakeObject;
};

const generateToken = async () => {
    return base64url(
        crypto.randomBytes(
            64
        )
    );
};

module.exports = {
    hash: hash,
    checkSecret: checkSecret,
    SnowflakeGenerator: SnowflakeGenerator,
    generateToken: generateToken
};
