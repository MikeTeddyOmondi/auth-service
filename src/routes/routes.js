const express = require("express");
const router = express.Router();

const {
	ApiInfo,
	AuthenticatedUser,
	Login,
	Logout,
	Refresh,
	Register,
} = require("../controllers/auth.js");

router.get("/", ApiInfo);
router.post("/register", Register);
router.post("/login", Login);
router.get("/user", AuthenticatedUser);
router.post("/refresh", Refresh);
router.post("/logout", Logout);

module.exports = router;
