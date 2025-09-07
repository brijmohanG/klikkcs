const User = require('../db/models/user');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const joiToForms = require('joi-errors-for-forms').form;
const changeCaseObject = require('change-case-object');

module.exports.register = async function (req, res) {
    try {
        const body = req.body
        /* preparing the validation body */
        const validatedObject = Joi.object({
            firstName: Joi.string(),
            lastName: Joi.string(),
            password: Joi.string(),
            email: Joi.string()
        })
        /* validating the validation values */
        const validateValue = validatedObject.validate({
            firstName: body.firstName,
            lastName: body.lastName,
            password: body.password,
            email: body.email
        }, { abortEarly: false })

        /* converts errors in key : value pair */
        const convertToForms = joiToForms([
            {
                regex: '/[0-9]{10}/',
                message: '"${key}" must be a valid 10 digit contact number.'
            }
        ])
        const validationError = convertToForms(validateValue.error)
        /* checking for any validation error,
        If received error then throw it to client */
        if (validationError) {
            return res.status(200).json({
                success: false,
                message: "Validation error"
            })
        }
        const validatedValues = validateValue.value;
        const updateValues = changeCaseObject.snakeCase(validatedValues);
        const saltRounds = 10;
        User.findAll({
            where: {
                email: updateValues.email
            }
        }).then(data => {
            if (data.length > 0) {
                return res.status(200).json({
                    success: true,
                    message: 'user already registred'
                })
            } else {
                bcrypt.hash(updateValues.password, saltRounds, function (err, hash) {
                    if (err) {
                        return res.status(500).json({
                            success: false,
                            message: 'Error hashing password',
                            error: err.message
                        });
                    }
                    updateValues.password = hash;

                    User.create(updateValues).then(user => {
                        if (user) {
                            return res.status(200).json({
                                success: true,
                                message: 'user register successfully',
                                response: user
                            })
                        } else {
                            res.status(200).json({
                                success: false,
                                message: 'database error'
                            })
                        }
                    })
                });
            }
        }).catch(err => {
            console.error('Error querying users:', err);
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: `exception ${error}`
        })
    }
}


module.exports.login = async function (req, res){
    try{
        const body = req.body
        /* preparing the validation body */
        const validatedObject = Joi.object({
            password: Joi.string(),
            email: Joi.string()
        })
        /* validating the validation values */
        const validateValue = validatedObject.validate({
            password: body.password,
            email: body.email
        }, { abortEarly: false })

        /* converts errors in key : value pair */
        const convertToForms = joiToForms()
        const validationError = convertToForms(validateValue.error)
        /* checking for any validation error,
        If received error then throw it to client */
        if (validationError) {
            return res.status(200).json({
                success: false,
                message: "Validation error"
            })
        }
        const validatedValues = validateValue.value;
        const updateValues = changeCaseObject.snakeCase(validatedValues);
        User.findOne({where: {email: updateValues.email}}).then(async data => {
            if (!data) {
            return res.status(401).json({
                success: false,
                message: 'Authentication failed. User not found.'
            });
            
        }
        const isMatch = await bcrypt.compare(updateValues.password, data.password);
            if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Authentication failed. Incorrect password.'
            });
            
        }
        const SECRET_KEY = process.env.SECRET_KEY;
        const token = jwt.sign(
            {
                id: data.id,
                email: data.email
            },
            SECRET_KEY,
            { expiresIn: '1h' } // optional: token expiry
        );
         return res.status(200).json({
            success: true,
            message: 'Login successful',
            token: token
        });
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: `exception ${error}`
        })
    }
}







