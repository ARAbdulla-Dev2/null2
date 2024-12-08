const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  googleId: String,
  name: String,
  email: String,
  username: String,
  phone: String,
  profilePic: String,
  apiKey: String,
  ipAddress: String,
  requestLimit: { type: Number, default: 1000 },
  requestsMade: { type: Number, default: 0 },
});

module.exports = mongoose.model('User', userSchema);
