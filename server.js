// server.js

require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Create the Express app
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection setup
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB:', err));

// MongoDB Schema and Model for Users
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  status: { type: String, default: 'Active' },  // Account status (Active/Inactive)
  lastLogin: { type: Date, default: Date.now }, // Last login timestamp
});

const User = mongoose.model('User', userSchema);

// Sample API route
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

// Server listener (for Render)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
