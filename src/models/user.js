const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const { Schema } = mongoose;

const userSchema = new Schema({
  email: String,
  password: String,
});

// Encript password
userSchema.methods.encryptPassword = (password) => {
   return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

// Compare passwords
userSchema.method.comparePassword = function (password) {
  return bcrypt.compareSync(password, this.password);

};
module.exports = mongoose.model("users", userSchema);
