const jwt = require("jsonwebtoken");
const authorModel = require("../models/authorModel");
const blogModel = require("../models/blogModel");
const mongoose = require('mongoose')

const isValidObjectId = function (ObjectId) { return mongoose.Types.ObjectId.isValid(ObjectId) }

// ________________________________MIDDLEWARE FOR AUTHENTICATION_________________________________

const authentication = async function (req, res, next) {
    try {


        let token = req.headers['x-api-key']
        if (!token) { return res.status(400).send({ status: false, msg: "Token must be present" }) }


        jwt.verify(token, "project1-secrete-key", function (err, decodedToken) {

            if (!err) {

                return res.status(401).send({ status: false, msg: "Token is invalid" })

            }
            else {
                req.token = decodedToken
                console.log(req.token)

                next()

            }
        })

    }
    catch (error) {

        res.status(500).send({ status: false, msg: error.message })
    }
}

// ________________________________MIDDLEWARE FOR AUTHORIZATION_________________________________

const authorization = async function (req, res, next) {
    try {
        let token = req.headers["x-api-key"]; //uthaying token from header
        token = req.headers["x-api-key"];
        let decodedToken = jwt.verify(token, "Project1-Group45"); //verify token with secret key 
        let loginInUser = decodedToken.authorId; //log in by token
        let blogId = req.params.blogId
        
        let checkBlogId = await blogModel.findById({ _id: blogId })
        if (!checkBlogId)
        return res.status(404).send({ status: false, msg: "No blog exists, Enter a valid Object Id" });
        
        if (checkBlogId.authorId != loginInUser) {
            return res.status(403).send({ status: false, msg: "Authorization failed" })
        }
        next(); //if auther is same then go to your page

    } catch (err) {
        res.status(500).send({ status: false, msg: err.message });
    }

}

module.exports = { authentication, authorization }