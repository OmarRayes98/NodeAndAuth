const User = require("../models/User");
const getAllUsers = async (req, res) => {

  //return all properties except password , lean() to say will not retrun all properties
  const users = await User.find().select("-password").lean();
  if (!users.length) {
    return res.status(400).json({ message: "No users found" });
  }
  res.json(users);
};
module.exports = {
  getAllUsers,
};
