const mongoose = require('mongoose');
// const logger = require('./logger');

const connectDB = async (mongoUri) => {
    try {
        console.log('Connecting to MongoDB...', mongoUri);

        console.log('Connecting to MongoDB...');
        // await mongoose.connect(mongoUri, {
        //     useNewUrlParser: true,
        //     useUnifiedTopology: true,
        // });
        await mongoose.connect(mongoUri);

        console.log('MongoDB connected');
    } catch (err) {
        console.error('MongoDB connection error', err);
        process.exit(1);
    }
};

module.exports = connectDB;
