const jwt = require('jsonwebtoken')
const bcrypt = require("bcryptjs");


function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(401);
        req.user = user;
        next();
    });
}

async function encryptPassword(password) {
    try {
        const hash = await bcrypt.hash(password, 10);
        return hash;
    } catch (err) {
        console.error(err);
        return null; // Return null or handle error appropriately
    }
}

async function verifyPassword(plainPassword, hashedPassword) {
    try {
        const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
        return isMatch;
    } catch (err) {
        console.error(err);
        return false;
    }
}


module.exports = {
    authenticateToken,
    encryptPassword,
    verifyPassword
}