const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    twoFASecret: String,
    is2FAEnabled: { type: Boolean, default: false }
});

module.exports = mongoose.model('User', UserSchema);
