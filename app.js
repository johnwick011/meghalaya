require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON data
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Admin credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// Uploads directory
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Configure multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const newFileName = req.body.newFileName; // Ensure this is populated
    if (!newFileName) {
      return cb(new Error('The new file name is missing.'));
    }
    const sanitizedFileName = newFileName.trim() + path.extname(file.originalname);
    cb(null, sanitizedFileName);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed!'));
    }
  }
});

// Middleware to protect admin routes
function isAuthenticated(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  } else {
    res.redirect('/login');
  }
}

// Routes
// Public Page: View and Download PDFs
app.get('/', (req, res) => {
  const files = fs.readdirSync(UPLOADS_DIR).map(file => ({
    name: file,
    path: `/uploads/${file}`
  }));
  res.render('index', { files });
});

// Admin Login Page
app.get('/login', (req, res) => {
  res.render('admin-login', { error: null });
});

// Admin Login Submission
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('admin-login', { error: 'Invalid credentials. Try again.' });
  }
});

// Admin Panel
app.get('/admin', isAuthenticated, (req, res) => {
  res.render('admin-panel', { uploadError: null });
});

// Handle PDF Upload
app.post('/upload', isAuthenticated, (req, res) => {
  // Use upload.single to handle the file and parse fields
  upload.single('pdf')(req, res, (err) => {
    if (err) {
      console.error('Upload Error:', err.message);
      return res.render('admin-panel', { uploadError: err.message });
    }

    const newFileName = req.body.newFileName && req.body.newFileName.trim();
    if (!newFileName) {
      return res.render('admin-panel', { uploadError: 'New file name is missing.' });
    }

    if (!req.file) {
      return res.render('admin-panel', { uploadError: 'No file was uploaded.' });
    }

    res.redirect('/admin');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.redirect('/admin');
    }
    res.redirect('/login');
  });
});

// Start the Server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});