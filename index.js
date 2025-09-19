
//Importing required Files
require("dotenv").config();
const express = require("express");
const dbCon = require("./app/config/dbConnection");
const path = require("path");
const cookieParser = require("cookie-parser");


//Executing required functions
const app = express();
dbCon();


// //Set view engine to EJS
// app.set("view engine", "ejs");
// app.set("views", path.join(__dirname,"views"));


//Parsing data
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(cookieParser());


//Serve Static Files
app.use(express.static(path.join(__dirname,"uploads")));
app.use(express.static(path.join(__dirname,"public")));


//Using routes
const UserRouter = require("./app/router/UserRouter");
app.use(UserRouter);


// Basic error handling
const handlingErrors = require("./app/middleware/HandlingErrors");
app.use(handlingErrors);


//Creating Server
const port = 8080 || process.env.PORT;

app.listen(port, ()=>{
    console.log(`Server started at ${port}`);
});