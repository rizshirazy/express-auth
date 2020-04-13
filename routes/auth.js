const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../model/User');
const {registerValidation, loginValidation} = require('../validation');

router.post('/register', async (req, res) => {
	const {name, email, password} = req.body;

	// Validation input
	const {error} = registerValidation(req.body);
	if (error) return res.status(400).send({error: error.details[0].message});

	// Checking if the user is already in the database
	const emailExist = await User.findOne({email});
	if (emailExist)
		return res.status(400).send({error: 'Email already exists'});

	// Hash the password
	const salt = await bcrypt.genSalt(10);
	const hashPassword = await bcrypt.hash(password, salt);

	const user = new User({
		name,
		email,
		password: hashPassword,
	});

	try {
		const savedUser = await user.save();
		res.send({user: user._id});
	} catch (error) {
		res.status(400).send(error);
	}
});

router.post('/login', async (req, res) => {
	const {email, password} = req.body;

	// Validation input
	const {error} = loginValidation(req.body);
	if (error) return res.status(400).send({error: error.details[0].message});

	// Checking if the email exists
	const user = await User.findOne({email});
	if (!user) return res.status(400).send({error: `User not found`});

	// Checking if the password is correct
	const validPassword = await bcrypt.compare(password, user.password);
	if (!validPassword)
		return res.status(400).send({error: `Invalid password`});

	// Create and assign a token
	const token = jwt.sign(
		{_id: user._id, name: user.name, email: user.email},
		process.env.ACCESS_TOKEN_SECRET,
		{expiresIn: process.env.TOKEN_EXPIRES_IN}
	);
	res.send({accessToken: token});
});

module.exports = router;
