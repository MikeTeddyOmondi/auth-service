const bcryptjs = require("bcryptjs");
const { sign, verify } = require("jsonwebtoken");
const amqplib = require("amqplib/callback_api");

const User = require("../models/User.js");
const Token = require("../models/Token.js");

const {
  REFRESH_SECRET,
  ACCESS_SECRET,
  RABBITMQ_URL,
} = require("../config/config.js");

exports.ApiInfo = async (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Auth API",
    description: "Auth API | Version 1",
  });
};

exports.Register = async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res
      .status(500)
      .json({ success: false, message: `Please enter all fields!` });
  }

  const userExists = await User.findOne({ email });
  const usernameTaken = await User.findOne({ username });

  if (userExists) {
    return res.status(500).json({
      success: false,
      message: "User already exists!",
    });
  }

  if (usernameTaken) {
    return res.status(500).json({
      success: false,
      message: "Username already taken!",
    });
  }

  const user = await User({
    username,
    email,
    password: await bcryptjs.hash(password, 12),
  });

  user
    .save()
    .then((doc) => {
      const { password, isAdmin, isActive, isVerified, ...otherData } =
        doc._doc;
      res.status(201).json({
        success: true,
        data: {
          message:
            "User registered successfully. Please verify your email by clicking on the link sent to activate your account.",
        },
      });

      const token = sign(
        {
          id: otherData._id,
        },
        ACCESS_SECRET,
        { expiresIn: "30m" }
      );

      const CLIENT_URL = `${req.protocol}://${req.headers.host}`;

      const data = {
        username: otherData.username,
        email: otherData.email,
        url: `${CLIENT_URL}/api/v1/account/activate/${token}`,
      };

      // Create RabbitMQ Connection
      amqplib.connect(RABBITMQ_URL, (connError, connection) => {
        if (connError) {
          console.log({ error: connError.message });
          throw connError;
        }
        // Create Channel
        connection.createChannel((channelError, channel) => {
          if (channelError) {
            throw channelError;
          }

          // Assert the queue exists
          const QUEUE = "mails";
          channel.assertQueue(QUEUE);

          // Send message to the queue
          channel.sendToQueue(
            QUEUE,
            Buffer.from(JSON.stringify(data), {
              headers: { "Content-Type": "application/json" },
            })
          );
          console.log(`Message sent to: ${QUEUE} queue`);

          //   // Receiving messages from the queue
          //   channel.consume(
          //     QUEUE,
          //     (msg) => {
          //       console.log(`Message received: ${msg.content.toString()}`);
          //     },
          //     {
          //       noAck: true,
          //     }
          //   );
        });
      });
    })
    .catch((err) => {
      console.log({ err });
      return res.status(500).json({
        success: false,
        message: `Error occurred while registering user!`,
      });
    });
};

exports.activateAccount = async (req, res) => {
  try {
    const { token } = req.params;

    let payload;

    verify(token, ACCESS_SECRET, (err, data) => {
      if (err) {
        throw Error("Invalid token!");
      }
      payload = data;
    });

    if (!payload) {
      return res.status(403).send({
        success: false,
        data: {
          message: "Invalid token!",
        },
      });
    }

    const userVerified = await User.findOne({ _id: payload.id });
    const { isActive, isVerified } = userVerified._doc;

    if (isVerified && isActive) {
      return res.status(500).send({
        success: false,
        data: {
          message: `User already verified`,
        },
      });
    }

    const user = await User.findOneAndUpdate(
      { _id: payload.id },
      {
        isActive: true,
        isVerified: true,
      },
      { new: true }
    );

    if (!user) {
      return res.status(403).send({
        success: false,
        data: {
          message: "Invalid token!",
        },
      });
    }

    const { _id, username, ...data } = user._doc;

    res.status(200).json({
      success: true,
      data: {
        user: { _id, username },
        message: "Account activated",
      },
    });
  } catch (err) {
    return res.status(500).send({
      success: false,
      data: {
        message: `${err.message}`,
      },
    });
  }
};

exports.Login = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).json({
      success: false,
      message: "Invalid credentials!",
    });
  }

  const isCorrect = await bcryptjs.compare(password, user.password);
  if (!isCorrect) {
    return res.status(400).json({
      success: false,
      message: "Invalid credentials!",
    });
  }

  const refreshToken = sign(
    {
      id: user._id,
    },
    REFRESH_SECRET,
    { expiresIn: "1w" }
    // { expiresIn: "1w", header: { kid: KID } },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  const expired_at = new Date();
  expired_at.setDate(expired_at.getDate() + 7);

  // Upsert the refreshToken instead of saving
  // to avoid duplicate tokens with the same id

  await Token.updateOne(
    {
      user_id: user._id,
    },
    {
      $set: { token: refreshToken, expired_at },
    },
    { upsert: true }
  )
    .then(() => {
      const access_token = sign(
        {
          id: user._id,
        },
        ACCESS_SECRET,
        { expiresIn: "30m" }
      );

      // Create RabbitMQ Connection
      amqplib.connect(RABBITMQ_URL, (connError, connection) => {
        if (connError) {
          console.log({ error: connError.message });
          throw connError;
        }
        // Create Channel
        connection.createChannel((channelError, channel) => {
          if (channelError) {
            throw channelError;
          }

          // Assert the queue exists
          const QUEUE = "sms";
          channel.assertQueue(QUEUE);

          // Send message to the queue
          const data = {
            token: access_token,
          };

          channel.sendToQueue(
            QUEUE,
            Buffer.from(JSON.stringify(data), {
              headers: { "Content-Type": "application/json" },
            })
          );
          console.log(`Message sent to: ${QUEUE} queue`);

          //   // Receiving messages from the queue
          //   channel.consume(
          //     QUEUE,
          //     (msg) => {
          //       console.log(`Message received: ${msg.content.toString()}`);
          //     },
          //     {
          //       noAck: true,
          //     }
          //   );
        });
      });

      res.status(200).json({
        success: true,
        data: {
          token: access_token,
        },
      });
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        success: false,
        message: "Error signing in!",
      });
    });
};

exports.AuthenticatedUser = async (req, res) => {
  try {
    const reqHeaders = req.get("Authorization");
    if (!reqHeaders) {
      return res.status(401).send({
        success: false,
        data: {
          message: "Unauthenticated!",
        },
      });
    }

    const accessToken = reqHeaders.split(" ")[1];
    if (!accessToken) {
      return res.status(401).send({
        success: false,
        data: {
          message: "Unauthenticated!",
        },
      });
    }

    // const payload = verify(accessToken, ACCESS_SECRET);
    let payload;

    verify(accessToken, ACCESS_SECRET, (err, data) => {
      if (err) {
        throw Error("Invalid token");
      }
      payload = data;
    });

    if (!payload) {
      return res.status(403).send({
        success: false,
        data: {
          message: "Invalid token",
        },
      });
    }

    const user = await User.findOne({ _id: payload.id });

    if (!user) {
      return res.status(403).send({
        success: false,
        data: {
          message: "Invalid token!",
        },
      });
    }

    const { password, ...data } = user._doc;

    res.status(200).json({
      success: true,
      data: {
        user: data,
      },
    });
  } catch (err) {
    return res.status(500).send({
      success: false,
      data: {
        message: `${err.message}`,
      },
    });
  }
};

exports.Refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies["refreshToken"];

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Unauthenticated!",
      });
    }
    const payload = verify(refreshToken, REFRESH_SECRET);

    if (!payload) {
      return res.status(401).json({
        success: false,
        message: "Unauthenticated!",
      });
    }

    const refreshtokenSaved = await Token.findOne({
      user_id: payload.id,
    });

    if (!refreshtokenSaved) {
      return res.status(401).json({
        success: false,
        message: "Unauthenticated!",
      });
    }

    const token = sign(
      {
        id: payload.id,
      },
      ACCESS_SECRET,
      { expiresIn: "30m" }
    );

    res.status(200).json({
      success: true,
      data: {
        token,
      },
    });
  } catch (err) {
    console.log(err);
    return res.status(401).json({
      success: false,
      message: "Unauthenticated!",
    });
  }
};

exports.Logout = async (req, res) => {
  const refreshToken = req.cookies["refreshToken"];

  try {
    if (refreshToken) {
      await Token.findOneAndDelete({ token: refreshToken });

      res.cookie("refreshToken", "", { maxAge: 0 });

      res.status(200).json({
        success: true,
        message: "Sign out successfull!",
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Unauthenticated!",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Error signing out!",
    });
  }
};
