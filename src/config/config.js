require("dotenv").config({
	path: "./src/.env",
	debug: process.env.NODE_ENV === "development" ? true : false,
});

const { REFRESH_SECRET, ACCESS_SECRET, DB_URL, PORT, NODE_ENV, RABBITMQ_URL } =
	process.env;

module.exports = {
	REFRESH_SECRET,
	ACCESS_SECRET,
	RABBITMQ_URL,
	DB_URL,
	PORT,
	NODE_ENV,
};
