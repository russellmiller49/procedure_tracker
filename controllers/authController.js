// controllers/authController.js - HIPAA-compliant authentication
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { validationResult } = require('express-validator');
const { User, AuditLog } = require('../models');
const logger = require('../utils/logger');
const { sendEmail } = require('../services/emailService');
const { generateSecureToken, hashPassword } = require('../utils/crypto');

class AuthController {
  // User login with security checks
  async login(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { username, password, twoFactorCode } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get('user-agent');

      // Find user with security checks
      const user = await User.findOne({
        where: { username, is_active: true }
      });

      if (!user) {
        await this.logFailedLogin(username, ipAddress, 'User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check if account is locked
      if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
        await this.logFailedLogin(username, ipAddress, 'Account locked');
        return res.status(401).json({ 
          error: 'Account locked. Please contact administrator.' 
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        await this.handleFailedLogin(user, ipAddress);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check 2FA if enabled
      if (user.two_factor_enabled) {
        if (!twoFactorCode) {
          return res.status(200).json({ 
            requiresTwoFactor: true,
            message: 'Please provide 2FA code' 
          });
        }

        const isValid2FA = speakeasy.totp.verify({
          secret: user.two_factor_secret,
          encoding: 'base32',
          token: twoFactorCode,
          window: 2
        });

        if (!isValid2FA) {
          await this.logFailedLogin(username, ipAddress, 'Invalid 2FA code');
          return res.status(401).json({ error: 'Invalid 2FA code' });
        }
      }

      // Check if password needs to be changed
      const passwordAge = new Date() - new Date(user.last_password_change);
      const maxPasswordAge = 90 * 24 * 60 * 60 * 1000; // 90 days
      
      if (passwordAge > maxPasswordAge) {
        return res.status(200).json({
          requiresPasswordChange: true,
          message: 'Password expired. Please change your password.'
        });
      }

      // Check training and BAA compliance
      if (!user.training_completed || !user.baa_signed) {
        return res.status(200).json({
          requiresCompliance: true,
          training_required: !user.training_completed,
          baa_required: !user.baa_signed,
          message: 'Please complete compliance requirements'
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: user.role,
          sessionId: req.sessionID
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE || '30m',
          issuer: 'procedure-tracker',
          audience: 'medical-staff'
        }
      );

      // Update user login info
      await user.update({
        last_login: new Date(),
        failed_login_attempts: 0,
        account_locked_until: null
      });

      // Create session
      req.session.userId = user.id;
      req.session.userRole = user.role;
      req.session.loginTime = new Date();

      // Log successful login
      await AuditLog.create({
        user_id: user.id,
        username: user.username,
        user_role: user.role,
        action: 'LOGIN',
        resource_type: 'auth',
        ip_address: ipAddress,
        user_agent: userAgent,
        session_id: req.sessionID,
        success: true,
        metadata: {
          two_factor_used: user.two_factor_enabled
        }
      });

      logger.info(`User ${username} logged in successfully`, {
        userId: user.id,
        ipAddress,
        sessionId: req.sessionID
      });

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          firstName: user.first_name,
          lastName: user.last_name,
          email: user.email
        },
        sessionTimeout: 30 // minutes
      });

    } catch (error) {
      logger.error('Login error:', error);
      next(error);
    }
  }

  // Logout with session cleanup
  async logout(req, res, next) {
    try {
      const userId = req.session.userId;
      const sessionId = req.sessionID;

      // Log logout
      if (userId) {
        await AuditLog.create({
          user_id: userId,
          action: 'LOGOUT',
          resource_type: 'auth',
          session_id: sessionId,
          ip_address: req.ip,
          user_agent: req.get('user-agent'),
          success: true
        });
      }

      // Destroy session
      req.session.destroy((err) => {
        if (err) {
          logger.error('Session destruction error:', err);
        }
      });

      res.json({ success: true, message: 'Logged out successfully' });

    } catch (error) {
      logger.error('Logout error:', error);
      next(error);
    }
  }

  // Setup 2FA
  async setup2FA(req, res, next) {
    try {
      const userId = req.user.id;
      const user = await User.findByPk(userId);

      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `ProcedureTracker (${user.username})`,
        issuer: process.env['2FA_ISSUER'] || 'Hospital'
      });

      // Generate QR code
      const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

      // Store secret temporarily (should be confirmed before saving)
      req.session.temp2FASecret = secret.base32;

      res.json({
        success: true,
        secret: secret.base32,
        qrCode: qrCodeUrl
      });

    } catch (error) {
      logger.error('2FA setup error:', error);
      next(error);
    }
  }

  // Verify and enable 2FA
  async verify2FA(req, res, next) {
    try {
      const { token } = req.body;
      const userId = req.user.id;
      const tempSecret = req.session.temp2FASecret;

      if (!tempSecret) {
        return res.status(400).json({ error: 'No 2FA setup in progress' });
      }

      // Verify token
      const isValid = speakeasy.totp.verify({
        secret: tempSecret,
        encoding: 'base32',
        token: token,
        window: 2
      });

      if (!isValid) {
        return res.status(400).json({ error: 'Invalid verification code' });
      }

      // Update user with 2FA secret
      await User.update(
        { 
          two_factor_enabled: true,
          two_factor_secret: tempSecret
        },
        { where: { id: userId } }
      );

      // Clean up session
      delete req.session.temp2FASecret;

      // Log 2FA enablement
      await AuditLog.create({
        user_id: userId,
        action: 'ENABLE_2FA',
        resource_type: 'auth',
        session_id: req.sessionID,
        success: true
      });

      res.json({ 
        success: true, 
        message: '2FA enabled successfully' 
      });

    } catch (error) {
      logger.error('2FA verification error:', error);
      next(error);
    }
  }

  // Change password
  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      const user = await User.findByPk(userId);

      // Verify current password
      const isValid = await bcrypt.compare(currentPassword, user.password_hash);
      if (!isValid) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      // Check password requirements
      const passwordErrors = this.validatePassword(newPassword);
      if (passwordErrors.length > 0) {
        return res.status(400).json({ errors: passwordErrors });
      }

      // Check password history (prevent reuse)
      // This would check against a password_history table in production

      // Hash new password
      const hashedPassword = await hashPassword(newPassword);

      // Update password
      await user.update({
        password_hash: hashedPassword,
        last_password_change: new Date(),
        password_reset_token: null,
        password_reset_expires: null
      });

      // Log password change
      await AuditLog.create({
        user_id: userId,
        action: 'CHANGE_PASSWORD',
        resource_type: 'auth',
        session_id: req.sessionID,
        success: true
      });

      // Send notification email
      await sendEmail({
        to: user.email,
        subject: 'Password Changed',
        template: 'password-changed',
        data: {
          name: user.first_name,
          timestamp: new Date().toISOString()
        }
      });

      res.json({ 
        success: true, 
        message: 'Password changed successfully' 
      });

    } catch (error) {
      logger.error('Password change error:', error);
      next(error);
    }
  }

  // Request password reset
  async requestPasswordReset(req, res, next) {
    try {
      const { email } = req.body;

      const user = await User.findOne({ where: { email, is_active: true } });
      
      // Always return success to prevent email enumeration
      if (!user) {
        logger.warn(`Password reset requested for non-existent email: ${email}`);
        return res.json({ 
          success: true, 
          message: 'If the email exists, a reset link has been sent.' 
        });
      }

      // Generate reset token
      const resetToken = generateSecureToken();
      const resetExpires = new Date(Date.now() + 3600000); // 1 hour

      // Save token
      await user.update({
        password_reset_token: resetToken,
        password_reset_expires: resetExpires
      });

      // Send reset email
      await sendEmail({
        to: user.email,
        subject: 'Password Reset Request',
        template: 'password-reset',
        data: {
          name: user.first_name,
          resetLink: `${process.env.APP_URL}/reset-password?token=${resetToken}`,
          expiresIn: '1 hour'
        }
      });

      // Log password reset request
      await AuditLog.create({
        user_id: user.id,
        action: 'PASSWORD_RESET_REQUEST',
        resource_type: 'auth',
        ip_address: req.ip,
        success: true
      });

      res.json({ 
        success: true, 
        message: 'If the email exists, a reset link has been sent.' 
      });

    } catch (error) {
      logger.error('Password reset request error:', error);
      next(error);
    }
  }

  // Helper methods
  async handleFailedLogin(user, ipAddress) {
    const attempts = user.failed_login_attempts + 1;
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
    
    const updateData = {
      failed_login_attempts: attempts
    };

    if (attempts >= maxAttempts) {
      const lockoutMinutes = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 30;
      updateData.account_locked_until = new Date(Date.now() + lockoutMinutes * 60000);
      
      logger.warn(`Account locked for user ${user.username} after ${attempts} failed attempts`);
      
      // Send security alert
      await sendEmail({
        to: user.email,
        subject: 'Security Alert: Account Locked',
        template: 'account-locked',
        data: {
          name: user.first_name,
          attempts: attempts,
          lockoutMinutes: lockoutMinutes,
          ipAddress: ipAddress
        }
      });
    }

    await user.update(updateData);
    await this.logFailedLogin(user.username, ipAddress, 'Invalid password');
  }

  async logFailedLogin(username, ipAddress, reason) {
    await AuditLog.create({
      username: username,
      action: 'LOGIN_FAILED',
      resource_type: 'auth',
      ip_address: ipAddress,
      success: false,
      metadata: { reason }
    });
  }

  validatePassword(password) {
    const errors = [];
    const minLength = parseInt(process.env.PASSWORD_MIN_LENGTH) || 12;

    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }
    if (process.env.PASSWORD_REQUIRE_UPPERCASE === 'true' && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    
