const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Настройка Multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://your-production-domain.com']
    : ['http://localhost:3001'],
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/doctoral', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Модели данных
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
    path: { type: String, required: true },
    size: { type: Number, required: true },
    mimetype: { type: String, required: true }
  }],
  status: { type: String, enum: ['pending', 'reviewed', 'approved', 'rejected'], default: 'pending' },
  decisionComment: { type: String },
  reviewedAt: { type: Date },
  reviewerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Document = mongoose.model('Document', DocumentSchema);

// Middleware для проверки JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Middleware для проверки роли проверяющего
const checkReviewerRole = (req, res, next) => {
  if (req.user.role !== 'reviewer') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }
  next();
};

// Регистрация докторанта
app.post('/register-doctoral', async (req, res) => {
  try {
    const { firstName, lastName, login, password } = req.body;

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким логином уже существует' });
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
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка при регистрации' });
  }
});

// Регистрация проверяющего
app.post('/register-reviewer', async (req, res) => {
  try {
    const { firstName, lastName, login, password } = req.body;

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким логином уже существует' });
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

    res.status(201).json({ message: 'Проверяющий успешно зарегистрирован' });
  } catch (error) {
    console.error('Reviewer registration error:', error);
    res.status(500).json({ error: 'Ошибка при регистрации проверяющего' });
  }
});

// Авторизация
app.post('/login', async (req, res) => {
  try {
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
      role: user.role
    };

    res.json({ token, user: userData });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка при авторизации' });
  }
});

// Отправка документов докторантом
app.post('/submit-documents', authenticateJWT, upload.any(), async (req, res) => {
  try {
    const { subject, recipient, content } = req.body;
    const userId = req.user.id;

    if (!subject || !recipient || !content) {
      return res.status(400).json({ error: 'Все текстовые поля обязательны' });
    }

    // Обработка загруженных файлов
    const files = req.files.map(file => ({
      fieldName: file.fieldname,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    }));

    const newDocument = new Document({
      userId,
      subject,
      recipient,
      content,
      files
    });

    await newDocument.save();

    res.status(201).json({
      message: 'Документы успешно отправлены',
      documentId: newDocument._id
    });
  } catch (error) {
    console.error('Document submission error:', error);
    res.status(500).json({ error: 'Ошибка при отправке документов' });
  }
});

// Получение всех заявок для проверяющего
app.get('/applications', authenticateJWT, checkReviewerRole, async (req, res) => {
  try {
    const documents = await Document.find({ status: { $in: ['pending', 'reviewed'] } })
      .populate('userId', 'firstName lastName login')
      .sort({ createdAt: -1 })
      .select('-files.path');

    const formattedDocs = documents.map(doc => ({
      ...doc.toObject(),
      applicantName: `${doc.userId.firstName} ${doc.userId.lastName}`
    }));

    res.json(formattedDocs);
  } catch (error) {
    console.error('Get applications error:', error);
    res.status(500).json({ error: 'Ошибка при получении заявок' });
  }
});

// Обновление статуса заявки проверяющим
app.put('/applications/:id/decision', authenticateJWT, checkReviewerRole, async (req, res) => {
  try {
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
    ).populate('userId', 'firstName lastName login');

    if (!updatedDoc) {
      return res.status(404).json({ error: 'Документ не найден' });
    }

    const responseDoc = {
      ...updatedDoc.toObject(),
      applicantName: `${updatedDoc.userId.firstName} ${updatedDoc.userId.lastName}`
    };

    res.json(responseDoc);
  } catch (error) {
    console.error('Decision error:', error);
    res.status(500).json({ error: 'Ошибка при обновлении статуса' });
  }
});

// Получение документов пользователя
app.get('/user-documents', authenticateJWT, async (req, res) => {
  try {
    const documents = await Document.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select('-files.path');

    res.json(documents);
  } catch (error) {
    console.error('Get documents error:', error);
    res.status(500).json({ error: 'Ошибка при получении документов' });
  }
});

// Скачивание файла
app.get('/download-file/:documentId/:fileId', authenticateJWT, async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.documentId,
      $or: [
        { userId: req.user.id }, // Докторант может скачать свои файлы
        { reviewerId: req.user.id } // Проверяющий может скачать файлы заявок, которые он проверял
      ]
    });

    if (!document) {
      return res.status(404).json({ error: 'Документ не найден или нет доступа' });
    }

    const file = document.files.id(req.params.fileId);
    if (!file) {
      return res.status(404).json({ error: 'Файл не найден' });
    }

    res.download(file.path, file.originalName);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Ошибка при скачивании файла' });
  }
});

// Получение данных пользователя
app.get('/me', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Ошибка при получении данных пользователя' });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});