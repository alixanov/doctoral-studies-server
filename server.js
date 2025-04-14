// Server-side (backend) - server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Cloudinary Storage for multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'doctoral_documents',
    allowed_formats: ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx', 'xls', 'xlsx'],
    transformation: [{ width: 1000, height: 1000, crop: 'limit' }]
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://doctoral-studies.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/doctoral', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Data models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['doctoral', 'reviewer'], default: 'doctoral' },
  createdAt: { type: Date, default: Date.now }
});

const DocumentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  recipient: { type: String, required: true },
  content: { type: String, required: true },
  files: [{
    fieldName: { type: String, required: true },
    originalName: { type: String, required: true },
    cloudinaryUrl: { type: String, required: true },
    publicId: { type: String, required: true },
    size: { type: Number },
    mimetype: { type: String }
  }],
  status: { type: String, enum: ['pending', 'reviewed', 'approved', 'rejected'], default: 'pending' },
  decisionComment: { type: String },
  reviewedAt: { type: Date },
  reviewerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Document = mongoose.model('Document', DocumentSchema);

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Reviewer role check middleware
const checkReviewerRole = (req, res, next) => {
  if (req.user.role !== 'reviewer') {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

// Doctoral registration
app.post('/register-doctoral', async (req, res) => {
  try {
    const { firstName, lastName, login, password } = req.body;

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      login,
      password: hashedPassword,
      role: 'doctoral'
    });

    await newUser.save();

    res.status(201).json({ message: 'Doctoral student registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Reviewer registration
app.post('/register-reviewer', async (req, res) => {
  try {
    const { firstName, lastName, login, password } = req.body;

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      login,
      password: hashedPassword,
      role: 'reviewer'
    });

    await newUser.save();



    
    res.status(201).json({ message: 'Reviewer registered successfully' });
  } catch (error) {
    console.error('Reviewer registration error:', error);
    res.status(500).json({ error: 'Reviewer registration failed' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { login, password, role } = req.body;

    const user = await User.findOne({ login, role });
    if (!user) {
      return res.status(401).json({ error: 'Invalid login or role' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign(
      {
        id: user._id,
        login: user.login,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    const userData = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      login: user.login,
      role: user.role
    };

    res.json({ token, user: userData });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Document submission
app.post('/submit-documents', authenticateJWT, upload.any(), async (req, res) => {
  try {
    const { subject, recipient, content } = req.body;
    const userId = req.user.id;

    // Validation
    if (!subject || !recipient || !content) {
      return res.status(400).json({
        error: 'All fields are required',
        details: {
          subject: !subject ? 'Subject is required' : null,
          recipient: !recipient ? 'Recipient is required' : null,
          content: !content ? 'Content is required' : null
        }
      });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        error: 'At least one file is required'
      });
    }

    const maxFileSize = 10 * 1024 * 1024; // 10MB
    const oversizedFiles = req.files.filter(file => file.size > maxFileSize);
    if (oversizedFiles.length > 0) {
      return res.status(400).json({
        error: 'Some files exceed maximum size (10MB)',
        oversizedFiles: oversizedFiles.map(f => f.originalname)
      });
    }

    const files = req.files.map(file => ({
      fieldName: file.fieldname,
      originalName: file.originalname,
      cloudinaryUrl: file.path,
      publicId: file.filename,
      size: file.size,
      mimetype: file.mimetype
    }));

    const newDocument = new Document({
      userId,
      subject,
      recipient,
      content,
      files,
      status: 'pending'
    });

    await newDocument.save();

    res.status(201).json({
      message: 'Documents submitted successfully',
      documentId: newDocument._id,
      filesCount: files.length
    });

  } catch (error) {
    console.error('Document submission error:', error);

    if (req.files && req.files.length > 0) {
      try {
        await Promise.all(
          req.files.map(file =>
            cloudinary.uploader.destroy(file.filename)
          ))
      } catch (cloudinaryError) {
        console.error('Error cleaning up files:', cloudinaryError);
      }
    }

    res.status(500).json({
      error: 'Document submission failed',
      details: error.message
    });
  }
});

// Get applications for reviewer
app.get('/applications', authenticateJWT, checkReviewerRole, async (req, res) => {
  try {
    const documents = await Document.find({ status: { $in: ['pending', 'reviewed'] } })
      .populate('userId', 'firstName lastName login')
      .sort({ createdAt: -1 });

    const formattedDocs = documents.map(doc => ({
      ...doc.toObject(),
      applicantName: `${doc.userId.firstName} ${doc.userId.lastName}`
    }));

    res.json(formattedDocs);
  } catch (error) {
    console.error('Get applications error:', error);
    res.status(500).json({ error: 'Failed to get applications' });
  }
});

// Update application status
app.put('/applications/:id/decision', authenticateJWT, checkReviewerRole, async (req, res) => {
  try {
    const { status, comment } = req.body;
    const { id } = req.params;

    if (!status || !['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const updatedDoc = await Document.findByIdAndUpdate(
      id,
      {
        status,
        decisionComment: comment,
        reviewedAt: new Date(),
        reviewerId: req.user.id
      },
      { new: true }
    ).populate('userId', 'firstName lastName login');

    if (!updatedDoc) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const responseDoc = {
      ...updatedDoc.toObject(),
      applicantName: `${updatedDoc.userId.firstName} ${updatedDoc.userId.lastName}`
    };

    res.json(responseDoc);
  } catch (error) {
    console.error('Decision error:', error);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Get user documents
app.get('/user-documents', authenticateJWT, async (req, res) => {
  try {
    const documents = await Document.find({ userId: req.user.id })
      .sort({ createdAt: -1 });

    res.json(documents);
  } catch (error) {
    console.error('Get documents error:', error);
    res.status(500).json({ error: 'Failed to get documents' });
  }
});

// Get file URL
app.get('/file/:documentId/:fileId', authenticateJWT, async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.documentId,
      $or: [
        { userId: req.user.id },
        { reviewerId: req.user.id },
        { status: { $ne: 'pending' } }
      ]
    });

    if (!document) {
      return res.status(404).json({ error: 'Document not found or access denied' });
    }

    const file = document.files.find(f => f._id.toString() === req.params.fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.json({ url: file.cloudinaryUrl, name: file.originalName });
  } catch (error) {
    console.error('Get file error:', error);
    res.status(500).json({ error: 'Failed to get file' });
  }
});

// Get user data
app.get('/me', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

// Get reviewers list
app.get('/reviewers', authenticateJWT, async (req, res) => {
  try {
    const reviewers = await User.find({ role: 'reviewer' })
      .select('firstName lastName login _id')
      .sort({ lastName: 1, firstName: 1 });

    const formattedReviewers = reviewers.map(reviewer => ({
      id: reviewer._id,
      firstName: reviewer.firstName,
      lastName: reviewer.lastName,
      email: reviewer.login,
    }));

    res.json(formattedReviewers);
  } catch (error) {
    console.error('Get reviewers error:', error);
    res.status(500).json({ error: 'Failed to get reviewers list' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});