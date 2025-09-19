
function handlingErrors(err,req,res,next) {
    let { status = 500, message = "Internal Server Error"} = err;
    return res.status(status).json({
        message: message
    });
}

module.exports = handlingErrors;