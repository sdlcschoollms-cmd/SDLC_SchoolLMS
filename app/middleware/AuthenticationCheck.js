
const jwt = require("jsonwebtoken");
const TokenModel = require("../model/RefreshTokenModel");

const authCheck = async (req, res, next) => {
    try {
        const accessToken = req.cookies?.accessToken || req.headers["x-access-token"];

        //if no token found above check bearer header
        if (!accessToken && req.headers["authorization"]) {
            let bearerHeader = req.headers["authorization"];
            accessToken = bearerHeader.split(" ")[1];
        }

        //if still no token
        if (!accessToken) {
            return res.status(400).json({
                message: "No token found"
            });
        }

        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
        req.user = decoded;
        return next();

    } catch (error) {
        throw new Error(error.meassage);
    }
}


module.exports = authCheck;