const express = require("express");
require("dotenv").config();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const cron = require("node-cron");
const { ToDo } = require("./models/ToDo");
const authRoutes = require("./routes/authRoute");

const connectToMongo = require("./db");

connectToMongo();
const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "https://todolisttopujhilam.netlify.app/#/auth",
  "https://todolisttopujhilam.netlify.app",
  "https://gj43d6f4-3000.inc1.devtunnels.ms",
   "https://gj43d6f4-3000.inc1.devtunnels.ms/#/auth"
];
// app.use(
//   cors({
//     origin: "http://localhost:3000", // Match frontend base URL
//     credentials: true, // Allow cookies to be sent/received
//   })
// );
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // Allow cookies to be sent/received
  })
);

app.use(express.json());
app.use(cookieParser());

app.use("/auth", require("./routes/auth"));
app.use("/user", require("./routes/user"));
app.use("/todolist", require("./routes/toDoList"));
app.use("/todo", require("./routes/toDo"));
app.use("/edit", require("./routes/edit"));
app.use("/deleteuser", require("./routes/deleteUser"));
// Routes
app.use("/api/auth", authRoutes);

// Schedule a task to run daily at midnight to update "My Day"
cron.schedule(
  "0 0 * * *",
  async () => {
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Set time to the beginning of the day
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999); // Set time to the end of the day

    try {
      // Find all todos with a due date within the current day
      const todos = await ToDo.find({
        dueAt: {
          $gte: today, // Greater than or equal to the beginning of the day
          $lte: endOfDay, // Less than or equal to the end of the day
        },
      });

      await ToDo.updateMany(
        { _id: { $in: todos.map((todo) => todo._id) } }, //Update the todos whose Ids are in the array of Ids (the array created from the map function)
        { $set: { inMyDay: true } }
      );
    } catch (error) {
      console.error('Error updating "My Day" section:', error);
    }
  },
  {
    timezone: "Asia/Kolkata",
  }
);

// Schedule a task to run daily just before midnight to clear "My Day"
cron.schedule(
  "59 23 * * *",
  async () => {
    try {
      const todosInMyDay = await ToDo.find({ inMyDay: true });

      await ToDo.updateMany(
        { _id: { $in: todosInMyDay.map((todo) => todo._id) } },
        { $set: { inMyDay: false } }
      );
    } catch (error) {
      console.error('Error clearing "My Day" section:', error);
    }
  },
  {
    timezone: "Asia/Kolkata",
  }
);

app.listen(port, () => {
  console.log(`Taskmaster Backend listening on port ${port}...`);
});
