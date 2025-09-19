
const mongoose = require("mongoose");

const connection = async () => {
    try {
        const dbConnect = await mongoose.connect(process.env.MONGODB_URL);
        if (dbConnect) {
            console.log("mogodb connected successfully");
        }
    } catch (error) {
        console.log("connection error!");
    }
}

module.exports = connection;