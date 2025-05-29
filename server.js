require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { sequelize } = require('./models');
const authRoutes = require('./routes/auth');
const logger = require('./utils/logger');

const app = express();
app.use(express.json());

app.use(session({
  store: new pgSession({
    pool: sequelize.connectionManager.pool,
    tableName: 'user_sessions',
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

app.use('/api/auth', authRoutes);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
sequelize.sync().then(() => {
  app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
});

module.exports = app;
