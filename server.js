require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const path = require('path');
const multer = require("multer");

const app = express();
const PORT = 3000;
const uri = process.env.MONGODB_URI;

if (!uri) {
    console.error("Error: MONGODB_URI is undefined. Check your .env file.");
    process.exit(1);
}

const client = new MongoClient(uri, { tls: true });

async function connectDB() {
    try {
        await client.connect();
        console.log("Connected to MongoDB Atlas!");
    } catch (err) {
        console.error("MongoDB Connection Error:", err);
        process.exit(1);
    }
}

//еxpress
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/css', express.static(path.join(__dirname, "public/css")));
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");
app.use(express.static("public"));

// Middleware для сессий
app.use(session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Функция проверки аутентификации
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}

// 📌 Функция валидации пароля
function validatePassword(password) {
    return /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/.test(password);
}

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    const { username, password, house } = req.body;

    if (!username || !password || !house) {
        return res.render("register", { error: "All fields are required!" });
    }

    if (!validatePassword(password)) {
        return res.render("register", { error: "Password must be at least 6 characters long, contain at least one letter and one number." });
    }

    const usersCollection = client.db("testDB").collection("users");

    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
        return res.render("register", { error: "Username is already taken. Please choose another one!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({ username, password: hashedPassword, house });


    res.redirect('/login');
});


// 📌 Страница логина (GET) — автозаполнение полей
app.get('/login', (req, res) => {
    res.render('login', {error: null});
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const usersCollection = client.db("testDB").collection("users");

    try {
        const user = await usersCollection.findOne({ username });
        if (!user) {
            return res.render("login", { error: "Incorrect username or password!" }); 
        }

        // Проверяем пароль
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.render("login", { error: "Incorrect username or password!" });
        }

        // Если всё правильно — создаем сессию
        req.session.user = { username: user.username, house: user.house };
        console.log("✅ Session after login:", req.session); // Лог для проверки

        res.redirect('/dashboard');
    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).send("Internal Server Error");
    }
});


// 📌 Страница пользователя (Dashboard)
app.get("/dashboard", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    try {
        const usersCollection = client.db("testDB").collection("users");
        const user = await usersCollection.findOne({ username: req.session.user.username });

        if (!user) {
            req.session.destroy(); // Удаляем сессию, если пользователь не найден
            return res.redirect("/login");
        }

        console.log("✅ Session on dashboard:",{ user: req.session.user }); // Проверяем сессию

        res.render("dashboard", {
            username: user.username,
            house: user.house || "Unknown",
            avatarUrl: user.avatarUrl || "/images/default-avatar.jpg", // Убедись, что путь корректен
            students: await usersCollection.find({}, { projection: { username: 1, house: 1, avatarUrl: 1 } }).toArray(),
        });

    } catch (error) {
        console.error("❌ Error loading dashboard:", error);
        res.status(500).send("Internal Server Error");
    }
});


// 📌 Настройка хранения файлов (загрузим в папку "uploads")
const storage = multer.diskStorage({
    destination: "public/uploads/", // Папка для сохранения аватаров
    filename: (req, file, cb) => {
        cb(null, req.session.user.username + path.extname(file.originalname)); // Уникальное имя
    }
});
const upload = multer({ storage });

// 📌 Обработчик загрузки аватарки
app.post("/upload-avatar", upload.single("avatar"), async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const avatarPath = "/uploads/" + req.file.filename; // Путь к загруженному файлу

    const usersCollection = client.db("testDB").collection("users");
    await usersCollection.updateOne(
        { username: req.session.user.username },
        { $set: { avatarUrl: avatarPath } }
    );

    res.redirect("/dashboard"); // Перезагрузим страницу профиля
});

// 📌 Выход из системы
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// 📌 Обновление пароля
app.post('/change-password', isAuthenticated, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const database = client.db("testDB");
    const users = database.collection("users");

    const user = await users.findOne({ username: req.session.user.username });

    if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
        return res.status(400).send("Incorrect old password.");
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).send("New password must be at least 6 characters long, contain at least one letter and one number.");
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await users.updateOne({ username: user.username }, { $set: { password: hashedNewPassword } });

    req.session.successMessage = "Password updated successfully!";
    res.redirect('/change-password');
});

// 📌 Страница смены пароля (обновленная)
app.get('/change-password', isAuthenticated, (req, res) => {
    const successMessage = req.session.successMessage;
    req.session.successMessage = null; // Очистим сообщение после показа
    res.render('change-password', { successMessage });
});


// Старт сервера
app.listen(PORT, async () => {
    await connectDB();
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
// 📌 Маршрут для отображения страницы редактирования профиля
app.get('/edit-profile', isAuthenticated, async (req, res) => {
    const database = client.db("testDB");
    const users = database.collection("users");

    const user = await users.findOne({ username: req.session.user.username });

    if (!user) {
        return res.redirect('/dashboard'); // Если пользователя нет, вернуть на главную
    }

    res.render('edit-profile', { user });
});

// 📌 Маршрут для обновления данных профиля
app.post('/edit-profile', isAuthenticated, async (req, res) => {
    const { username, age, house } = req.body;
    const database = client.db("testDB");
    const users = database.collection("users");

    await users.updateOne(
        { username: req.session.user.username },
        { $set: { username, age: parseInt(age), house } }
    );

    // Обновляем сессию, чтобы изменения отразились сразу
    req.session.user.username = username;
    req.session.user.age = age;
    req.session.user.house = house;

    res.redirect('/dashboard'); // Перенаправляем обратно в профиль
});

app.post('/delete-account', isAuthenticated, async (req, res) => {
    const database = client.db("testDB");
    const users = database.collection("users");

    try {
        // Удаляем пользователя из базы
        await users.deleteOne({ username: req.session.user.username });

        // Удаляем сессию
        req.session.destroy((err) => {
            if (err) {
                console.error("Ошибка удаления сессии:", err);
                return res.status(500).send("Ошибка удаления аккаунта.");
            }
            res.clearCookie("connect.sid", { path: '/' }); // Очистка cookie сессии
            console.log("Redirecting to /register");

            res.redirect('/register'); // Перенаправляем пользователя
        });

    } catch (error) {
        console.error("Ошибка удаления аккаунта:", error);
        res.status(500).send("Ошибка удаления аккаунта.");
    }
});



