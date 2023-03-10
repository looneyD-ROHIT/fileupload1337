const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
	{
		username: { type: String, required: true, unique: true },
		password: { type: String, required: true },
        salt: String,
        admin: Boolean
	},
	{ collection: 'users' }
);

const model = mongoose.model('UserSchema', userSchema);

module.exports = model;

