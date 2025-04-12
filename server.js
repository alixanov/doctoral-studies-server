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
    const uploadPath = 'uploads/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath);
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  origin: 'https://doctoral-studies.vercel.app',

  credentials: true,
}));
app.use(express.json());
// Статическая папка для доступа к загруженным файлам
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Подключено к MongoDB'))
  .catch((error) => console.error('Ошибка подключения к MongoDB:', error));

// Схема для учителей
const TeacherSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'teacher' },
});

const Teacher = mongoose.model('Teacher', TeacherSchema);

// Схема для учеников
const StudentSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'student' },
});

const Student = mongoose.model('Student', StudentSchema);

// Схема для документов
const DocumentSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  role: { type: String, required: true },
  subject: { type: String, required: true },
  recipient: { type: String, required: true },
  content: { type: String, required: true },
  files: [{
    fieldName: String,
    filePath: String,
    fileName: String,
  }],
  createdAt: { type: Date, default: Date.now },
});

const Document = mongoose.model('Document', DocumentSchema);

// Схема для заданий
const TaskSchema = new mongoose.Schema({
  studentId: { type: String, required: true },
  studentName: { type: String, required: true },
  teacherId: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, default: 'sent' },
  createdAt: { type: Date, default: Date.now },
});

const Task = mongoose.model('Task', TaskSchema);

// Схема для решений
const SolutionSchema = new mongoose.Schema({
  taskId: { type: String, required: true },
  studentId: { type: String, required: true },
  studentName: { type: String, required: true },
  solution: { type: String, required: true },
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

const Solution = mongoose.model('Solution', SolutionSchema);

// Регистрация учителя
app.post('/register-teacher', async (req, res) => {
  const { firstName, lastName, login, password } = req.body;

  if (!firstName || !lastName || !login || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
  }

  try {
    const existingTeacher = await Teacher.findOne({ login });
    if (existingTeacher) {
      return res.status(400).json({ error: 'Учитель с таким логином уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newTeacher = new Teacher({
      firstName,
      lastName,
      login,
      password: hashedPassword,
      role: 'teacher',
    });

    await newTeacher.save();
    res.status(201).json({ message: 'Учитель успешно зарегистрирован' });
  } catch (error) {
    console.error('Ошибка регистрации учителя:', error);
    res.status(500).json({ error: 'Ошибка при регистрации учителя: ' + error.message });
  }
});

// Регистрация ученика
app.post('/register-student', async (req, res) => {
  const { firstName, lastName, login, password } = req.body;

  if (!firstName || !lastName || !login || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
  }

  try {
    const existingStudent = await Student.findOne({ login });
    if (existingStudent) {
      return res.status(400).json({ error: 'Ученик с таким логином уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newStudent = new Student({
      firstName,
      lastName,
      login,
      password: hashedPassword,
      role: 'student',
    });

    await newStudent.save();
    res.status(201).json({ message: 'Ученик успешно зарегистрирован' });
  } catch (error) {
    console.error('Ошибка регистрации ученика:', error);
    res.status(500).json({ error: 'Ошибка при регистрации ученика: ' + error.message });
  }
});

// Авторизация (общая для учителя и ученика)
app.post('/login', async (req, res) => {
  const { login, password, role } = req.body;

  if (!login || !password || !role) {
    return res.status(400).json({ error: 'Логин, пароль и роль обязательны' });
  }

  try {
    let user;
    if (role === 'teacher') {
      user = await Teacher.findOne({ login });
    } else if (role === 'student') {
      user = await Student.findOne({ login });
    } else {
      return res.status(400).json({ error: 'Неверная роль' });
    }

    if (!user) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Авторизация успешна',
      token: `Bearer ${token}`,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        login: user.login,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Ошибка авторизации:', error);
    res.status(500).json({ error: 'Ошибка при авторизации: ' + error.message });
  }
});

// Middleware для проверки токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен не предоставлен' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.user = user;
    next();
  });
};

// Отправка документов
app.post('/submit-documents', authenticateToken, upload.fields([
  { name: 'file' },
  { name: 'malumotnoma' },
  { name: 'photo' },
  { name: 'passport' },
  { name: 'kengashBayyonomma' },
  { name: 'dekanatTaqdimnoma' },
  { name: 'sinovNatijalari' },
  { name: 'ilmiyIshlar' },
  { name: 'annotatsiya' },
  { name: 'maqolalar' },
  { name: 'xulosa' },
  { name: 'testBallari' },
  { name: 'tarjimaiXol' },
  { name: 'reytingDaftarcha' },
  { name: 'guvohnoma' },
  { name: 'yutuqlar' },
  { name: 'boshqa' },
]), async (req, res) => {
  const { subject, recipient, content } = req.body;

  if (!subject || !recipient || !content) {
    return res.status(400).json({ error: 'Все текстовые поля обязательны' });
  }

  try {
    const files = [];
    Object.keys(req.files).forEach((key) => {
      req.files[key].forEach((file) => {
        files.push({
          fieldName: key,
          filePath: file.path,
          fileName: file.originalname,
        });
      });
    });

    const newDocument = new Document({
      userId: req.user.id,
      role: req.user.role,
      subject,
      recipient,
      content,
      files,
    });

    await newDocument.save();
    res.status(200).json({ message: 'Документы успешно отправлены' });
  } catch (error) {
    console.error('Ошибка отправки документов:', error);
    res.status(500).json({ error: 'Ошибка при отправке документов: ' + error.message });
  }
});

// Получение списка учеников (для учителя)
app.get('/students', authenticateToken, async (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  try {
    const students = await Student.find();
    res.status(200).json(students);
  } catch (error) {
    console.error('Ошибка получения учеников:', error);
    res.status(500).json({ error: 'Ошибка при получении учеников' });
  }
});

// Отправка задания ученику (для учителя)
app.post('/send-task', authenticateToken, async (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  const { studentId, studentName, message } = req.body;

  if (!studentId || !studentName || !message) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  try {
    const newTask = new Task({
      studentId,
      studentName,
      teacherId: req.user.id,
      message,
    });

    await newTask.save();
    res.status(200).json({ message: 'Задание успешно отправлено!', task: newTask });
  } catch (error) {
    console.error('Ошибка отправки задания:', error);
    res.status(500).json({ error: 'Ошибка при отправке задания: ' + error.message });
  }
});

// Получение списка заданий учителя
app.get('/tasks', authenticateToken, async (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  try {
    const tasks = await Task.find({ teacherId: req.user.id });
    res.status(200).json(tasks);
  } catch (error) {
    console.error('Ошибка получения заданий:', error);
    res.status(500).json({ error: 'Ошибка при получении заданий' });
  }
});

// Получение заданий для ученика
app.get('/student-tasks', authenticateToken, async (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  try {
    const tasks = await Task.find({ studentId: req.user.id });
    res.status(200).json(tasks);
  } catch (error) {
    console.error('Ошибка получения заданий:', error);
    res.status(500).json({ error: 'Ошибка при получении заданий' });
  }
});

// Отправка решения (для ученика)
app.post('/send-solution', authenticateToken, async (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  const { taskId, solution } = req.body;

  if (!taskId || !solution) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  try {
    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({ error: 'Задание не найдено' });
    }

    if (task.studentId !== req.user.id) {
      return res.status(403).json({ error: 'Это задание не предназначено для вас' });
    }

    task.status = 'completed';
    await task.save();

    const student = await Student.findById(req.user.id);
    const newSolution = new Solution({
      taskId,
      studentId: req.user.id,
      studentName: `${student.firstName} ${student.lastName}`,
      solution,
    });

    await newSolution.save();
    res.status(200).json({ message: 'Решение успешно отправлено!' });
  } catch (error) {
    console.error('Ошибка отправки решения:', error);
    res.status(500).json({ error: 'Ошибка при отправке решения: ' + error.message });
  }
});

// Получение списка решений (для учителя)
app.get('/solutions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  try {
    const tasks = await Task.find({ teacherId: req.user.id });
    const taskIds = tasks.map(task => task._id);
    const solutions = await Solution.find({ taskId: { $in: taskIds } });
    res.status(200).json(solutions);
  } catch (error) {
    console.error('Ошибка получения решений:', error);
    res.status(500).json({ error: 'Ошибка при получении решений' });
  }
});

// Отметка решения как проверенного (для учителя)
app.post('/check-solution', authenticateToken, async (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  const { solutionId } = req.body;

  if (!solutionId) {
    return res.status(400).json({ error: 'solutionId обязателен' });
  }

  try {
    const solution = await Solution.findById(solutionId);
    if (!solution) {
      return res.status(404).json({ error: 'Решение не найдено' });
    }

    solution.status = 'checked';
    await solution.save();
    res.status(200).json({ message: 'Решение отмечено как проверенное' });
  } catch (error) {
    console.error('Ошибка проверки решения:', error);
    res.status(500).json({ error: 'Ошибка при проверке решения: ' + error.message });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});