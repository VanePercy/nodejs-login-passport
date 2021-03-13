const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const { Schema } = mongoose;

const userSchema = new Schema({
  email: String,
  password: String,
});

userSchema.methods.encryptPassword = (password) => {
    bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

module.exports = mongoose.model("users", userSchema);