const mongoose = require("mongoose");

let isConnected = false;

const connectDB = async (mongoUri) => {
  if (isConnected) {
    console.log("MongoDB already connected");
    return;
  }

  try {
    console.log("Connecting to MongoDB...", mongoUri);
    await mongoose.connect(mongoUri);
    isConnected = true;
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection error", err);
    process.exit(1);
  }
};

module.exports = connectDB;
