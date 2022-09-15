const mongoose = require('mongoose')
const authorModel = require("../models/authorModel")
const blogModel = require("../models/blogModel")
const jwt = require("jsonwebtoken");
const moment = require("moment")

const isValidObjectId = function (ObjectId) { return mongoose.Types.ObjectId.isValid(ObjectId) }

const isValidreqbody = function (body) {
  return Object.keys(body).length > 0
};
 
const isValid = function (value) {
  if (typeof value === "undefined" || value === null) return false
  if (typeof value === "string" && value.trim().length === 0) return false
  return true
}
// __________CREATE BLOG_________

const createBlog = async function (req, res) {
  try {
    let data = req.body

    if (!isValidreqbody(data)) {
      return res.status(400).send({ status: false, msg: "Please Provide Blog Datails" })
    }
    const { title, body, authorId, tags, category, subcategory } = req.body

    let author = await authorModel.findById(authorId)

    if (!isValid(title) || !isValid(body)) {
      return res.status(400).send({ status: false, msg: "Please Enter Some data In title Or body" })
    }
    if (!isValidObjectId(authorId)) {
      return res.status(400).send({ status: false, msg: "Please Provide authorId" })
    }
    if (!author) {
      return res.status(400).send({ status: false, msg: "Please Provide Valid authorId" })
    }
    if (!data.tags) {
      return res.status(400).send({ status: false, msg: "Please Provide tags to the blog" })
    }
    if (!isValid(category)) {
      return res.status(400).send({ satust: false, msg: "Please Provide Categary" })
    }
    if (!isValid(subcategory)) {
      return res.status(400).send({ status: false, msg: "Please provide Subcategary" })
    }

    let savedBlog = await blogModel.create(data)
    res.status(201).send({ status:true, msg: savedBlog })
  }
  catch (err) {
    res.status(500).send({ status: false, Error: err.message })
  }
}

// ___________GET BLOG DATA USING QUERY PARAMS____________

const getBlog = async function (req, res) {
  try {

    let { ...data } = req.query
    // check whether the authorId is present or not 
    if (data.hasOwnProperty('authorId')) {
      let { ...deleteData } = data;
      delete (deleteData.authorId);
    }

    //finding the data for empty values 
    if (Object.keys(data).length == 0) {
      return res.status(400).send({ status: false, msg: "Please Provide data for filter!!" });
    }

    let getAllBlogs = await blogModel.find({ isDeleted: false, isPublished: true }).populate('authorId');

    //check that the getAllBlogs is empty or not

    if (getAllBlogs.length == 0) {
      return res.status(404).send({ status: false, msg: "No such blog exists" });
    }

    data.isDeleted = false;
    data.isPublished = true;

    // data  are not deleted and are published 

    let getBlogs = await blogModel.find(data).populate('authorId');

    // getBlogs is empty or not

    if (getBlogs.length == 0)
      return res.status(404).send({ status: false, msg: "No such blog exist" });
    res.status(200).send({ status: true, data: getBlogs })

  } catch (err) {
    res.status(500).send({ status: false, error: err.message });
  }
};

// __________UPDATE BLOG DATA USING PATH PARAMS________________

const updateBlog = async function (req, res) {
  try {
    let getBlogId = req.params.blogId;  // blog id will be taken from request param

    //blogId is valid or not
    if (!isValidObjectId(getBlogId))
      return res.status(404).send({ status: false, msg: "Enter a valid Object Id" });

    //Finding the blogid in data base
    let findBlogId = await blogModel.findById(getBlogId)
    if (!findBlogId)
      return res.status(404).send({ status: false, msg: "No blog exists" });

    // //finding the data is delted or not
    if (findBlogId.isDeleted == true)
      return res.status(404).send({ status: false, msg: "This blog has been deleted, Try another!!" });

    let { ...data } = req.body;

    // if data value is empty
    if (Object.keys(data).length == 0)
      return res.status(400).send({ status: false, msg: "data is requierd to update" });

    //update the blog data in data base by blog id

    let updatedBlog = await blogModel.findOneAndUpdate({ $and: [{ isDeleted: false }, { _id: getBlogId },] }, {
      $push: { tags: data.tags, category: data.category, subcategory: data.subcategory },
      title: data.title,
      body: data.body,
      isPublished: data.isPublished
      , publishedAt: moment(new Date()).format('DD/MM/YYYY h:mma')
    }, { new: true, upsert: true })

    return res.status(200).send({ status: true, data: updatedBlog })

  } catch (err) {
    res.status(500).send({ status: false, Error: err.message });
  }
};

// ___________DELETE BLOG USING PATH PARAMS____________

const deleteBlogByPathParams = async function (req, res) {
  try {
    let blogId = req.params.blogId;

    let blog = await blogModel.findById(blogId)
    //check the blog is present or not
    if (!blog) {
      return res.status(404).send({ status: false, msg: "No such user exists" });
    }

    //check isDeleted status is true
    if (blog.isDeleted == true) {
      return res.status(400).send({ status: false, msg: "Blog is already Deleted" });
    }

    // let timeStamp = new Date()
    //update the status of Isdeleted to true
    let updatedData = await blogModel.findOneAndUpdate({ _id: blogId }, { isDeleted: true, isPublished: false, deletedAt: moment(new Date()).format('DD/MM/YYYY h:mma') })
    console.log(updatedData)
    return res.status(200).send({ status: true, msg: "Successfully Deleted!!" });
  }
  catch (err) {
    res.status(500).send({ status: false, Error: err.message })
  }
}

// __________DELETE USING QUERY PARAMS________________

const deletedBlogByQueryParam = async function (req, res) {
  try {
    let { ...data } = req.query;
    let token = req.headers["x-api-key"];
    let decodedToken = jwt.verify(token, "Project1-Group45");

    //validating the data for empty values
    if (Object.keys(data).length == 0) return res.status(400).send({ status: false, msg: "Please Provide filter for performing deletion!!" });

    if (data.hasOwnProperty('authorId')) { // authorId is present or not
      if (!isValidObjectId(data.authorId))
        return res.status(400).send({ status: false, msg: "Enter a valid author Id" });

      if (decodedToken.authorId !== data.authorId)
        return res.status(403).send({ status: false, msg: "Action not allow" })

      let { ...oldData } = data;
      delete (oldData.authorId);
    }

    //let timeStamps = moment(new Date()).format('DD/MM/YYYY  h:mma') //getting the current timeStamps

    let getBlogData = await blogModel.find({ authorId: decodedToken.authorId, data });

    //blog doesnt match with  query data
    if (getBlogData.length == 0) {
      return res.status(404).send({ status: false, msg: "No blog found" });
    }

    const getNotDeletedBlog = getBlogData.filter(item => item.isDeleted === false);

    if (getNotDeletedBlog.length == 0) {
      return res.status(404).send({ status: false, msg: "The Blog is already deleted" });
    }

    data.authorId = decodedToken.authorId;

    let updatedData = await blogModel.updateMany({ authorId: data.authorId }, { $set: { isDeleted: true, deletedAt: Date.now() } }, { new: true })
    return res.status(200).send({ status: true, data: updatedData })

  } catch (err) {
    res.status(500).send({ status: false, error: err.message });
  }
};

module.exports = { createBlog, getBlog, updateBlog, deleteBlogByPathParams, deletedBlogByQueryParam }