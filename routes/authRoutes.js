const express = require("express");
const jwt = require("jsonwebtoken");
const router = express.Router();
const secretKey = "randomSecret";

let users = [];

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token not provided" });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  const accessToken = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: "1h",
  });
  user.accessToken = accessToken;
  res.json({ accessToken });
});

router.post("/signup", (req, res) => {
  const { username, password } = req.body;
  const userExists = users.some((user) => user.username === username);

  if (userExists) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const newUser = {
    id: users.length + 1,
    username,
    password,
    accessToken: null,
  };
  users.push(newUser);

  res.status(201).json({ message: "User created successfully" });
});

router.post("/logout", (req, res) => {
  const { username } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.accessToken = null;
  res.json({ message: "Logged out successfully" });
});

router.get("/users", (req, res) => {
  res.status(201).json(users);
});

router.delete("/user/:id", (req, res) => {
  const userId = parseInt(req.params.id);

  const userIndex = users.findIndex((user) => user.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({ message: "User not found" });
  }

  users = users.filter((user) => user.id !== userId);

  res.json({ message: "User deleted successfully" });
});

router.get("/protected-route", authenticateToken, (req, res) => {
  console.log(req.user);
  res.json({ message: "You accessed the protected route", user: req.user });
});
module.exports = router;
