const Joi = require("joi");

// +++++++++++++ Validate User Schema ++++++++++++++++
const userSchemaValidator = Joi.object({
    firstName: Joi.string().required().trim(),
    lastName: Joi.string().required().trim(),
    email: Joi.string().required().trim(),
    password: Joi.string().required().trim(),
    confirmPassword: Joi.ref('password'),
    role: Joi.string().valid("student","teacher","admin").required(),
    studentClass: Joi.when("role", {
        is: "student",
        then: Joi.string().required(),
        otherwise: Joi.string().allow("",null).strip()
    })
});

module.exports = { userSchemaValidator };