const UserModel = require("../model/UserModel");
const TokenModel = require("../model/RefreshTokenModel");
const { userSchemaValidator } = require("../middleware/SchemaValidator");
const bcrypt = require("bcryptjs");
const generateTokens = require("../helper/GenerateTokens");
const jwt = require("jsonwebtoken");
const transporter = require("../config/EmailConfig");

class UserController {

    //all user(testing purpose)
    async allusers(req, res) {
        const allUser = await UserModel.find({});
        return res.status(200).json({
            status: true,
            message: "User fetch successfully",
            totalusers: allUser.length,
            data: allUser
        });
    }

    //User Registration
    async registerUser(req, res) {

        //validating form
        const { error } = userSchemaValidator.validate(req.body, { abortEarly: false });
        if (error) {
            const allErrors = error.details.map((err) => err.message);
            return res.status(401).json({
                message: allErrors
            });
        }

        const { firstName, lastName, email, password, role, studentClass } = req.body;

        //check for existing user
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(200).json({
                message: "User is already exists"
            });
        }

        //hashing password before save
        const hashedPassword = await bcrypt.hash(password, 10);

        //saving new user to db
        const newUser = await new UserModel({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            role,
            studentClass: role === "student" ? studentClass : undefined
        }).save();

        //send a welcome message to mail
        transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: newUser.email,
            subject: "Welcome Message",
            html: `<b><p>Welcome ${newUser.firstName},you have successfully registered to our website</p></b>`
        });

        //sending final json response
        return res.status(200).json({
            status: true,
            message: "User created successfully",
            data: newUser
        });
    }

    //User Login
    async loginUser(req, res) {

        const { email, password, rememberMe } = req.body;

        //check if user exists
        const existingUser = await UserModel.findOne({ email });
        if (!existingUser) {
            return res.status(401).json({
                message: "User does not exists"
            });
        }

        // if user exists matching password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid password"
            });
        }

        //generating Tokens
        const { accessToken, refreshToken, rememberMeFlag } = await generateTokens(existingUser, rememberMe);
        const accessTokenMaxAge = rememberMeFlag ? 15 * 60 * 1000 : undefined;
        const refreshTokenMaxAge = rememberMeFlag ? 30 * 24 * 60 * 60 * 1000 : undefined;
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            maxAge: accessTokenMaxAge
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            maxAge: refreshTokenMaxAge
        });

        //sending final json response
        return res.status(200).json({
            status: true,
            message: "User login successfully",
            user: {
                _id: existingUser._id,
                email: existingUser.email,
                role: existingUser.role
            }
        });
    }

    //refresh accessToken
    async refreshAccessToken(req, res) {
        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.status(404).json({
                message: "invalid token"
            });
        }

        const storedToken = await TokenModel.findOne({ token: refreshToken });
        if (!storedToken) {
            return res.status(404).json({
                message: "No token found"
            });
        }

        const verifyToken = jwt.verify(refreshToken, process.env.JWT_SECRET_KEY);
        const payload = {
            _id: verifyToken._id,
            email: verifyToken.email,
            role: verifyToken.role
        }
        const newAccessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: "15m" });

        let accessTokenMaxAge = (storedToken.rememberMe === true ? 15 * 60 * 1000 : undefined);
        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            maxAge: accessTokenMaxAge
        });

        return res.status(200).json({
            message: "Token refreshed successfully"
        });

    }

    // Dashboard(testing purpose)
    async dashboard(req, res) {
        return res.status(200).json({
            message: `Welcome to the ${req.user.email} dashboard`
        });
    }

    //Logout user
    async logout(req, res) {

        //This is for logout from all device
        // const userId = req.user._id;
        // await TokenModel.deleteMany({userId});
        // res.clearCookie("accessToken");
        // res.clearCookie("refreshToken");

        // This for specific session/device
        const { refreshToken } = req.cookies;
        const deletedToken = await TokenModel.findOneAndDelete({ token: refreshToken });
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");

        return res.status(200).json({
            message: "User logout successfully",
            tokenData: deletedToken
        });
    }


    //Reset Password Link
    async resetPasswordLink(req, res) {

        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ status: false, message: "Email field is required" });
        }

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ status: false, message: "Email doesn't exist" });
        }

        // Generate token for password reset
        const secret = user._id + process.env.JWT_SECRET_KEY;
        const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '20m' });

        // Reset Link and this link generate by frontend developer
        const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password/${user._id}/${token}`;

        // Send password reset email  
        transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: user.email,
            subject: "Password Reset Link",
            html: `<p>Hello ${user.firstName},</p><p>Please <a href="${resetLink}">Click here</a> to reset your password.</p>`
        });

        // Send success response
        res.status(200).json({
            status: true, 
            message: "Password reset link sent to your email. Please check your email.",
            link: resetLink
        });
    }

    //Reset password
    async resetPassword(req, res) {
        const { password, confirmPassword } = req.body
        const { id, token } = req.params

        const user = await UserModel.findById(id)
        if (!user) {
            return res.status(400).json({
                status: false,
                message: 'User not found'
            })
        }

        const new_secret = user._id + process.env.JWT_SECRET_KEY
        jwt.verify(token, new_secret)

        if (!password || !confirmPassword) {
            return res.status(400).json({
                status: false,
                message: "All input fields required"
            })
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                status: false,
                message: 'Password and confirm Password does not match'
            })
        }

        const newHashPassword = await bcrypt.hash(password, 10);

        await UserModel.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } })

        return res.status(200).json({
            status: false,
            message: 'Password reset successfully'
        })
    }

    //Delete User(testing purpose)
    async deleteUser(req,res) {
        const existingUser = await UserModel.findById(req.params.id);
        if(!existingUser) {
            return res.status(404).json({
                message: "No User Found"
            });
        }

        const deletedUser = await UserModel.findByIdAndDelete(req.params.id);
        return res.status(200).json({
            message: "User deleted successfully",
            user: deletedUser
        });
    }
}

module.exports = new UserController();