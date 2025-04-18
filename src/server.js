const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const mongoose = require("mongoose");
const router = require("./routes/routes.js");
const cookieParser = require("cookie-parser");

const { DB_URL, PORT, NODE_ENV } = require("./config/config.js");

mongoose.set("strictQuery", false);

mongoose
	.connect(DB_URL, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
		authSource: "admin",
	})
	.then(() => {
		const app = express();

		app.use(express.json());
		app.use(cookieParser());
		app.use(
			cors({
				origin: [
					"http://localhost:3000",
					"http://localhost:5000",
					"http://localhost:8080",
					"http://localhost:5173",
				],
				credentials: true,
			}),
		);

		// Logs
		NODE_ENV === "production"
			? app.use(morgan("common"))
			: app.use(morgan("dev"));

		// routes(app);
		app.use("/api/v1", router);
		app.use("/", (req, res) => {
			res.status(200).json({
				success: true,
				message: "Auth API",
				description: "Auth API | Version 1",
			});
		});

		// Service initiated...
		app.listen(PORT, () => {
			console.log(`> Auth service listening: ${PORT}`);
		});
	});
