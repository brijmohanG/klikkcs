// config.js
require('dotenv').config();
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false, // Supabase requires this for SSL
    },
  },
});

// ✅ Export as an object with `sequelize` property
module.exports = {
  sequelize,
  Sequelize, // optional, useful if you want to use Sequelize.DataTypes elsewhere
};

