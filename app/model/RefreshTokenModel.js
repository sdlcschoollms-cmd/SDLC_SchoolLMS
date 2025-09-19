
const { required } = require("joi");
const mongoose = require("mongoose");

const TokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },
    token: {
        type: String,
        required: true
    },
    rememberMe: {
        type: Boolean,
        default: false,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 30 * 24 * 60 * 60 //30 days in sec
    }
});


module.exports = mongoose.model("RefreshToken", TokenSchema);