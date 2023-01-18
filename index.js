const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const { User } = require("./db");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", async (req, res, next) => {
	try {
		res.send(
			"<h1>Welcome to Loginopolis!</h1><p>Log in via POST /login or register via POST /register</p>"
		);
	} catch (error) {
		console.error(error);
		next(error);
	}
});

const SALT_ROUNDS = 10;

// POST /register
// TODO - takes req.body of {username, password} and creates a new user with the hashed password
app.post("/register", async (req, res) => {
	const hash = await bcrypt.hash(req.body.password, SALT_ROUNDS);
	const user = await User.create({
		username: req.body.username,
		password: hash,
	});
	res.send(`successfully created user ${req.body.username}`);
});

// POST /login
// TODO - takes req.body of {username, password}, finds user by username, and compares the password with the hashed version from the DB
app.post("/login", async (req, res) => {
	const user = await User.findOne({
		where: {
			username: req.body.username,
		},
	});
	if (!user) {
		res.status(401).send("incorrect username or password");
	}

	const match = await bcrypt.compare(
		req.body.password,
		user.getDataValue("password")
	);
	if (match) {
		res.send(
			`successfully logged in user ${user.getDataValue("username")}`
		);
	} else {
		res.status(401).send("incorrect username or password");
	}
});

// we export the app, not listening in here, so that we can run tests
module.exports = app;
