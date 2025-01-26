const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
});
const User = mongoose.model('User', UserSchema);

const ReportSchema = new mongoose.Schema({
  reportType: { type: String, required: true }, // e.g., 'stock', 'issue', 'decompose'
  data: { type: Array, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Report = mongoose.model('Report', ReportSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Create Report
app.post('/api/reports', authenticateToken, async (req, res) => {
  const { reportType, data } = req.body;
  try {
    const newReport = new Report({ reportType, data });
    await newReport.save();
    res.status(201).json({ message: 'Report created successfully', report: newReport });
  } catch (err) {
    res.status(500).json({ message: 'Error creating report', error: err.message });
  }
});

// Get All Reports
app.get('/api/reports', authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find();
    res.status(200).json(reports);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching reports', error: err.message });
  }
});

// Delete Report
app.delete('/api/reports/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await Report.findByIdAndDelete(id);
    res.status(200).json({ message: 'Report deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting report', error: err.message });
  }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
