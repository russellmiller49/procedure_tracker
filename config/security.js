module.exports = {
  sessionTimeout: parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30', 10),
};
