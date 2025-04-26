const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
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

// Cloudinary Storage configurations
const documentStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'doctoral_documents',
    allowed_formats: ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx', 'xls', 'xlsx'],
    transformation: [{ width: 1000, height: 1000, crop: 'limit' }]
  }
});

const profilePhotoStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'doctoral_profile_photos',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [{ width: 500, height: 500, crop: 'fill', gravity: 'face' }]
  }
});

const uploadDocuments = multer({
  storage: documentStorage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

const uploadProfilePhoto = multer({
  storage: profilePhotoStorage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
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
  .then(() => console.log('Подключено к MongoDB'))
  .catch(err => console.error('Ошибка подключения MongoDB:', err));

// Data models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['doctoral', 'reviewer'], default: 'doctoral' },
  profilePhoto: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const AssessmentSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  questions: [{
    question: { type: String, required: true },
    answer: { type: String, default: '' },
    rating: { type: Number, min: 0, default: 0 },
    subRatings: [{ type: Number, min: 0 }], // Sub-ratings for specific questions
    feedback: { type: String, default: '' }
  }],
  status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
  feedback: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
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
const Assessment = mongoose.model('Assessment', AssessmentSchema);
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
    return res.status(403).json({ error: 'Доступ запрещен' });
  }
  next();
};

// Error handling wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Routes
// Upload profile photo
app.post('/upload-profile-photo',
  authenticateJWT,
  uploadProfilePhoto.single('profilePhoto'),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'Ни один файл не загружен' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { profilePhoto: req.file.path },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json({
      message: 'Фотография профиля успешно загружена',
      profilePhotoUrl: user.profilePhoto
    });
  })
);

// Doctoral registration
app.post('/register-doctoral', asyncHandler(async (req, res) => {
  const { firstName, lastName, login, password } = req.body;

  const existingUser = await User.findOne({ login });
  if (existingUser) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
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
  res.status(201).json({ message: 'Докторант успешно зарегистрирован' });
}));

// Reviewer registration
app.post('/register-reviewer', asyncHandler(async (req, res) => {
  const { firstName, lastName, login, password } = req.body;

  const existingUser = await User.findOne({ login });
  if (existingUser) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
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
  res.status(201).json({ message: 'Рецензент успешно зарегистрирован' });
}));

// Login
app.post('/login', asyncHandler(async (req, res) => {
  const { login, password, role } = req.body;

  const user = await User.findOne({ login, role });
  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или роль' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Неверный пароль' });
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
    role: user.role,
    profilePhoto: user.profilePhoto
  };

  res.json({ token, user: userData });
}));

// Submit assessment (questions)
app.post('/submit-assessment',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    const { recipient, answers } = req.body;
    const senderId = req.user.id;

    if (!recipient || !answers || !Array.isArray(answers)) {
      return res.status(400).json({ error: 'Получатель и ответы обязательны' });
    }

    // Find recipient by email (login)
    const recipientUser = await User.findOne({ login: recipient, role: 'reviewer' });
    if (!recipientUser) {
      return res.status(404).json({ error: 'Рецензент не найден' });
    }

    const newAssessment = new Assessment({
      senderId,
      recipientId: recipientUser._id,
      questions: answers
    });

    await newAssessment.save();

    res.status(201).json({ message: 'Оценка успешно отправлена' });
  })
);

// Get submitted assessments
app.get('/submitted-assessments',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    try {
      const assessments = await Assessment.find({
        senderId: req.user.id,
        status: 'pending'
      })
        .populate('recipientId', 'firstName lastName profilePhoto')
        .sort({ createdAt: -1 });

      const formattedAssessments = assessments.map(assessment => ({
        _id: assessment._id,
        reviewerInfo: {
          firstName: assessment.recipientId.firstName,
          lastName: assessment.recipientId.lastName,
          profilePhoto: assessment.recipientId.profilePhoto
        },
        questions: assessment.questions,
        status: assessment.status,
        createdAt: assessment.createdAt,
        completedAt: assessment.completedAt
      }));

      res.json(formattedAssessments);
    } catch (error) {
      console.error('Error fetching submitted assessments:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  })
);

// Get reviewers list
app.get('/reviewers',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    const reviewers = await User.find({ role: 'reviewer' })
      .select('firstName lastName login profilePhoto _id')
      .sort({ lastName: 1, firstName: 1 });

    const formattedReviewers = reviewers.map(reviewer => ({
      id: reviewer._id,
      firstName: reviewer.firstName,
      lastName: reviewer.lastName,
      email: reviewer.login,
      profilePhoto: reviewer.profilePhoto
    }));

    res.json(formattedReviewers);
  })
);

// Document submission
app.post('/submit-documents',
  authenticateJWT,
  uploadDocuments.any(),
  asyncHandler(async (req, res) => {
    const { subject, recipient, content } = req.body;
    const userId = req.user.id;

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
      return res.status(400).json({ error: 'At least one file is required' });
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
  })
);

// Get applications for reviewer
app.get('/applications',
  authenticateJWT,
  checkReviewerRole,
  asyncHandler(async (req, res) => {
    const documents = await Document.find({ status: { $in: ['pending', 'reviewed'] } })
      .populate('userId', 'firstName lastName login profilePhoto')
      .sort({ createdAt: -1 });

    const formattedDocs = documents.map(doc => ({
      ...doc.toObject(),
      applicantName: `${doc.userId.firstName} ${doc.userId.lastName}`,
      applicantPhoto: doc.userId.profilePhoto
    }));

    res.json(formattedDocs);
  })
);

// Update application status
app.put('/applications/:id/decision',
  authenticateJWT,
  checkReviewerRole,
  asyncHandler(async (req, res) => {
    const { status, comment } = req.body;
    const { id } = req.params;

    if (!status || !['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Неверный статус' });
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
    ).populate('userId', 'firstName lastName login profilePhoto');

    if (!updatedDoc) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const responseDoc = {
      ...updatedDoc.toObject(),
      applicantName: `${updatedDoc.userId.firstName} ${updatedDoc.userId.lastName}`,
      applicantPhoto: updatedDoc.userId.profilePhoto
    };

    res.json(responseDoc);
  })
);

// Get user documents
app.get('/user-documents',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    const documents = await Document.find({ userId: req.user.id })
      .sort({ createdAt: -1 });

    res.json(documents);
  })
);

// Get file URL
app.get('/file/:documentId/:fileId',
  authenticateJWT,
  asyncHandler(async (req, res) => {
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
  })
);

// Get reviewer assessments
app.get('/reviewer-assessments',
  authenticateJWT,
  checkReviewerRole,
  asyncHandler(async (req, res) => {
    try {
      const assessments = await Assessment.find({
        recipientId: req.user.id,
        status: 'pending'
      })
        .populate('senderId', 'firstName lastName profilePhoto')
        .sort({ createdAt: -1 });

      const formattedAssessments = assessments.map(assessment => ({
        _id: assessment._id,
        userInfo: {
          firstName: assessment.senderId.firstName,
          lastName: assessment.senderId.lastName,
          profilePhoto: assessment.senderId.profilePhoto
        },
        answers: assessment.questions.map(q => ({
          question: q.question,
          answer: q.answer,
          rating: q.rating || 0,
          subRatings: q.subRatings || [],
          feedback: q.feedback || '',
          _id: q._id
        })),
        status: assessment.status,
        createdAt: assessment.createdAt
      }));

      res.json(formattedAssessments);
    } catch (error) {
      console.error('Error fetching reviewer assessments:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  })
);

// Submit review for assessment
app.post('/submit-review',
  authenticateJWT,
  checkReviewerRole,
  asyncHandler(async (req, res) => {
    const { assessmentId, answers, feedback } = req.body;

    console.log('Received review data:', req.body);

    if (!assessmentId) {
      return res.status(400).json({ error: 'Assessment ID is required' });
    }

    if (!answers || !Array.isArray(answers)) {
      return res.status(400).json({
        error: 'Answers are required',
        details: {
          hasAnswers: !!answers,
          isArray: Array.isArray(answers),
          receivedData: req.body
        }
      });
    }

    const assessment = await Assessment.findById(assessmentId);
    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    if (assessment.recipientId.toString() !== req.user.id) {
      return res.status(403).json({ error: 'You are not assigned to review this assessment' });
    }

    if (assessment.questions.length !== answers.length) {
      return res.status(400).json({
        error: 'Number of answers does not match number of questions',
        expected: assessment.questions.length,
        received: answers.length
      });
    }

    // Update questions with ratings, sub-ratings, and feedback
    assessment.questions = assessment.questions.map((question, index) => ({
      question: question.question,
      answer: question.answer,
      rating: answers[index].rating,
      subRatings: answers[index].subRatings || [],
      feedback: answers[index].feedback || ''
    }));

    assessment.feedback = feedback;
    assessment.status = 'completed';
    assessment.completedAt = new Date();

    await assessment.save();

    res.json({
      message: 'Review submitted successfully',
      assessment: {
        _id: assessment._id,
        status: assessment.status,
        feedback: assessment.feedback,
        completedAt: assessment.completedAt
      }
    });
  })
);

// Get completed assessments for doctoral student
app.get('/completed-assessments',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    const assessments = await Assessment.find({
      senderId: req.user.id,
      status: 'completed'
    })
      .populate('recipientId', 'firstName lastName profilePhoto')
      .sort({ completedAt: -1 });

    const formattedAssessments = assessments.map(assessment => ({
      _id: assessment._id,
      reviewerInfo: {
        firstName: assessment.recipientId.firstName,
        lastName: assessment.recipientId.lastName,
        profilePhoto: assessment.recipientId.profilePhoto
      },
      questions: assessment.questions,
      feedback: assessment.feedback,
      completedAt: assessment.completedAt
    }));

    res.json(formattedAssessments);
  })
);

// Get completed assessments for reviewer
app.get('/completed-assessments-reviewer',
  authenticateJWT,
  checkReviewerRole,
  asyncHandler(async (req, res) => {
    const assessments = await Assessment.find({
      recipientId: req.user.id,
      status: 'completed'
    })
      .populate('senderId', 'firstName lastName profilePhoto')
      .sort({ completedAt: -1 });

    const formattedAssessments = assessments.map(assessment => ({
      _id: assessment._id,
      userInfo: {
        firstName: assessment.senderId.firstName,
        lastName: assessment.senderId.lastName,
        profilePhoto: assessment.senderId.profilePhoto
      },
      questions: assessment.questions,
      feedback: assessment.feedback,
      completedAt: assessment.completedAt,
      status: assessment.status
    }));

    res.json(formattedAssessments);
  })
);

// Get user data
app.get('/me',
  authenticateJWT,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  })
);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});