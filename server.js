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
app.use(cors({ origin: 'https://jokercreation.netlify.app' })); // Allowing Netlify frontend to access backend
app.use(bodyParser.json()); // Parse incoming JSON requests

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
  status: { type: String, default: 'Active' },
  lastLogin: { type: Date, default: Date.now },
  otp: { type: String }, // Store OTP temporarily
  otpExpiration: { type: Date }, // OTP expiration time
});

const User = mongoose.model('User', userSchema);

// Helper function to generate JWT token
const generateJWT = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, name: user.name },
    process.env.JWT_SECRET_KEY,
    { expiresIn: '1h' }
  );
};

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { email, password, name, phone } = req.body;
  const lowercaseEmail = email.toLowerCase();

  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Forget Password Route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    user.otp = otp;
    user.otpExpiration = Date.now() + 3600000; // OTP expires in 1 hour
    await user.save();

    // Send OTP via email (Nodemailer setup)
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                background-color: #f4f7f6;
                color: #333;
                padding: 20px;
              }
              .email-container {
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
                padding: 20px;
                max-width: 600px;
                margin: 0 auto;
              }
              .header {
                background-color: #2980b9;
                color: white;
                text-align: center;
                padding: 15px;
                border-radius: 8px;
              }
              .header h2 {
                margin: 0;
                font-size: 24px;
              }
              .otp {
                font-size: 22px;
                text-align: center;
                padding: 20px;
                border-radius: 5px;
                background-color: #ecf0f1;
              }
            </style>
          </head>
          <body>
            <div class="email-container">
              <div class="header">
                <h2>OTP for Password Reset</h2>
              </div>
              <p>Hello,</p>
              <p>Use the following OTP to reset your password:</p>
              <div class="otp">
                <strong>${otp}</strong>
              </div>
              <p>This OTP will expire in 1 hour.</p>
            </div>
          </body>
        </html>
      `
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: 'Error sending OTP. Please try again later.' });
      } else {
        res.status(200).json({ message: 'OTP sent to email.' });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Verify OTP Route
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    if (Date.now() > user.otpExpiration) {
      return res.status(400).json({ message: 'OTP has expired.' });
    }

    res.status(200).json({ message: 'OTP verified.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Reset Password Route
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Server setup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
