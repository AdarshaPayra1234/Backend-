// api/index.js

require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

// MongoDB Schema and Model for Users
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  status: { type: String, default: 'Active' },
  lastLogin: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// MongoDB connection setup
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB:', err));

// API route to signup
app.post('/signup', async (req, res) => {
  const { email, password, name, phone } = req.body;
  const lowercaseEmail = email.toLowerCase();

  const existingUser = await User.findOne({ email: lowercaseEmail });
  if (existingUser) {
    return res.status(400).json({ message: 'Email already registered.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({
    email: lowercaseEmail,
    password: hashedPassword,
    name,
    phone,
  });

  await newUser.save();
  res.status(200).json({ message: 'User registered successfully.' });
});

// API route to login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const lowercaseEmail = email.toLowerCase();

  const user = await User.findOne({ email: lowercaseEmail });
  if (!user) {
    return res.status(400).json({ message: 'User not found.' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ message: 'Invalid password.' });
  }

  user.lastLogin = Date.now();
  await user.save();

  const token = jwt.sign({ email: lowercaseEmail, userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ message: 'Login successful.', token });
});

// Export the Express app as a serverless function for Render
module.exports = (req, res) => app(req, res);

