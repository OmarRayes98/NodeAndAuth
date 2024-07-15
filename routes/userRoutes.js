const express = require("express");
const router = express.Router();
const usersController = require("../controllers/usersController");
const verifyJWT = require("../middleware/verifyJWT");

//to protect the url "/users" (user has to login before reuest /user)
router.use(verifyJWT);

//domain or url is /user
router.route("/").get(usersController.getAllUsers);

module.exports = router;
