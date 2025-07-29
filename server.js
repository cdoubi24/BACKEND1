const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const users = require('./users');
const verifyToken = require('./middleware/verifyToken');

const app = express();
const SECRET = 'supersecretkey';

app.use(cors());
app.use(express.json());

// Register new user
app.post('/api/user', async (req, res) => {
  const { username, password, status } = req.body;
  if (!username || !password || !status) {
    return res.status(400).json({ message: 'All fields required' });
  }

  const existing = users.find(u => u.username === username);
  if (existing) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, status });
  res.json({ message: 'User registered' });
});

// Login and return token
app.post('/api/auth', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: 'Invalid password' });

  const token = jwt.sign({ username: user.username }, SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Protected route: get user status
app.get('/api/status', verifyToken, (req, res) => {
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.json({ status: user.status });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
