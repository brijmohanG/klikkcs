// app.js
require('dotenv').config();
const express = require('express');
const db = require('./db'); // Sequelize DB config
const sequelize = db.sequelize; // ✅ correctly extract the instance
const appRoutes = require('./routes/index');
const cors = require('cors');


const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use('/api', appRoutes);
app.use(cors());


// Test route
app.get('/', (req, res) => {
  res.send('🚀 Quipo Backend is running!');
});

// Start server & connect to DB
(async () => {
  try {
    await sequelize.authenticate(); // ✅ this now works
    console.log('✅ Connected to Supabase DB via Sequelize');
    app.listen(PORT, () => {
      console.log(`🌐 Server is running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ Failed to connect to the database:', err.message);
  }
})();
