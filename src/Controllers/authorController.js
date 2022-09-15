const authorModel = require("../models/authorModel")
const jwt = require("jsonwebtoken");

const isValidreqbody = function (body) {
    return Object.keys(body).length > 0
}

const isValid = function (value) {
    if (typeof value === "undefined" || value === null) return false
    if (typeof value === "string" && value.trim().length === 0) return false
    return true
}

// ________________________________CREATE AUTHORS_________________________________

const authors = async function (req, res) {
    try {
        let authorsData = req.body
        if (!isValidreqbody(authorsData)) {
            return res.status(400).send({ status: false, Msg: "please provide auther details" })
        }

        const { fname, lname, title, email, password } = authorsData

        if (!isValid(fname) || !isValid(lname)) {
            return res.status(400).send({ status: false, msg: "fname or lname required" })
        }

        if (!(/^[a-zA-Z\\s]*$/.test(fname))) {
            return res.status(400).send({ status: false, msg: "Please Provide Valid Name" })
        }

        // __________________________________TITLE VALIDATION_______________________________________________________

        if (!title) {
            return res.status(400).send({ status: false, msg: "title is required" })
        }

        let validTitle = ['Mr', 'Mrs', 'Miss']; //validating the title
        //checking if the title is valid
        if (!validTitle.includes(authorsData.title)) return res.status(400).send({ status: false, msg: "Title should be one of Mr, Mrs, Miss" });

        // ______________________________Email VALIDATION______________________________________________

        if (!email) {
            return res.status(400).send({ status: false, msg: "PLEASE PROVIDE EMAIL" })
        }
        if (!(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email))) {
            return res.status(400).send({ status: false, msg: "PLEASE PROVIDE VALID EMAIL" })
        }

        let uniqueEmail = await authorModel.findOne({ email: email })
        if (uniqueEmail) {
            return res.status(400).send({ status: false, msg: "email address is already registered" })
        }

        // ___________________________________PASSWORD VALIDATION (regex)________________________________

        if (!password) {
            return res.status(400).send({ status: false, msg: "please provide password" })
        }

        if (!(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/.test(password))) {
            return res.status(400).send({ status: false, msg: "password must be Minimum eight characters, at least one letter and one number" })
        }

        let authorCreated = await authorModel.create(authorsData)
        res.status(201).send({status: true, data: authorCreated })

    }
    catch (err) { 
        res.status(500).send({ status: false, Error: err.message });
    }
}

// ________________________________LOGIN SYSTEM FOR AUTHOR_________________________________

const authorLogin = async function (req, res) {
    try{
    let { email, password } = req.body;

    let author = await authorModel.findOne({ email: email, password: password });
    if (!author) return res.status(400).send({ status: false, msg: "username or the password is not corerct" });

    let token = jwt.sign(
        {
            authorId: author._id.toString(),
            batch: "plutonium",
            organisation: "FunctionUp",
        },
        "Project1-Group45"
    );
    res.setHeader("x-auth-token", token);
    res.status(200).send({ status: true, token: token });
    }
    catch (err) {
        res.status(500).send({ status: false, Error: err.message });
    }
}

module.exports.authorLogin = authorLogin
module.exports.authors = authors
