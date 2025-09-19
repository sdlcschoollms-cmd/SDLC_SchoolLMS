
const jwt = require("jsonwebtoken");
const TokenModel = require("../model/RefreshTokenModel");

const generateTokens = async (user, rememberMe) => {
    try {
        let payload = {
            _id: user._id,
            email: user.email,
            role: user.role
        }
        const rememberMeFlag = ["yes", "on", "1", "true"].includes(rememberMe);
        let refreshTokenExpiry = rememberMeFlag ? "30d" : "2h";
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: "15m" });
        const refreshToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: refreshTokenExpiry });

        //saving token to db
        await TokenModel.findOneAndUpdate(
            { userId: user._id },
            { token: refreshToken, rememberMe: rememberMeFlag },
            { upsert: true, new: true }
        );

        return { accessToken, refreshToken, rememberMeFlag };
    } catch (error) {
        throw new Error(error.message);
    }
}

module.exports = generateTokens;