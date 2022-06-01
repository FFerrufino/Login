const mongoose = require("mongoose");

const userCollection = "user";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, max: 100 },
  password: { type: String, required: true, max: 100 },
  email: { type: String, required: true, max: 100 },
});

module.exports = mongoose.model(userCollection, userSchema);
