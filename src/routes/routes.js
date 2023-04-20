const express = require("express");
const router = express.Router();

const {
  ApiInfo,
  AuthenticatedUser,
  Login,
  Logout,
  Refresh,
  Register,
  activateAccount,
} = require("../controllers/auth.js");

router.get("/", ApiInfo);
router.post("/register", Register);
router.get("/account/activate/:token", activateAccount);
router.post("/login", Login);
router.get("/user", AuthenticatedUser);
router.post("/refresh", Refresh);
router.post("/logout", Logout);

module.exports = router;
