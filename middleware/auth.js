// middleware/auth.js - JWT and session authentication middleware
const jwt = require('jsonwebtoken');
const { User, AuditLog } = require('../models');
const logger = require('../utils/logger');

// JWT authentication middleware
const authenticateJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'procedure-tracker',
      audience: 'medical-staff'
    });

    // Check if session is still valid
    if (!req.session || req.session.userId !== decoded.id) {
      await logUnauthorizedAccess(req, 'Session mismatch');
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Check session timeout
    const sessionAge = Date.now() - new Date(req.session.loginTime).getTime();
    const maxAge = (process.env.SESSION_TIMEOUT_MINUTES || 30) * 60 * 1000;
    
    if (sessionAge > maxAge) {
      await logUnauthorizedAccess(req, 'Session timeout');
      req.session.destroy();
      return res.status(401).json({ error: 'Session expired' });
    }

    // Get user from database
    const user = await User.findByPk(decoded.id, {
      attributes: ['id', 'username', 'role', 'is_active', 'training_completed', 'baa_signed']
    });

    if (!user || !user.is_active) {
      await logUnauthorizedAccess(req, 'User inactive or not found');
      return res.status(401).json({ error: 'User account inactive' });
    }

    // Check compliance requirements
    if (!user.training_completed || !user.baa_signed) {
      return res.status(403).json({ 
        error: 'Compliance requirements not met',
        training_required: !user.training_completed,
        baa_required: !user.baa_signed
      });
    }

    // Attach user to request
    req.user = user;
    req.userId = user.id;
    
    // Update session activity
    req.session.lastActivity = Date.now();
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      await logUnauthorizedAccess(req, 'Invalid JWT token');
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    if (error.name === 'TokenExpiredError') {
      await logUnauthorizedAccess(req, 'JWT token expired');
      return res.status(401).json({ error: 'Token expired' });
    }
    
    logger.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// Role-based access control middleware
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logUnauthorizedAccess(req, `Insufficient role: ${req.user.role}`);
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: allowedRoles,
        current: req.user.role
      });
    }

    next();
  };
};

// Check if user can access specific resource
const checkResourceAccess = (resourceType) => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params.id;
      const userId = req.user.id;
      const userRole = req.user.role;

      // Admins have full access
      if (userRole === 'admin') {
        return next();
      }

      let hasAccess = false;

      switch (resourceType) {
        case 'procedure':
          const { Procedure } = require('../models');
          const procedure = await Procedure.findByPk(resourceId);
          
          if (!procedure) {
            return res.status(404).json({ error: 'Procedure not found' });
          }

          // Check if user is performer or supervisor
          hasAccess = procedure.performer_id === userId || 
                     procedure.supervisor_id === userId ||
                     (procedure.assistants && procedure.assistants.includes(userId));
          break;

        case 'user':
          // Users can only access their own profile unless admin
          hasAccess = resourceId === userId;
          break;

        case 'pathology':
          const { PathologySample, Procedure: Proc } = require('../models');
          const sample = await PathologySample.findByPk(resourceId, {
            include: [{
              model: Proc,
              as: 'procedure',
              attributes: ['performer_id', 'supervisor_id']
            }]
          });
          
          if (!sample) {
            return res.status(404).json({ error: 'Pathology sample not found' });
          }

          hasAccess = sample.collected_by === userId ||
                     sample.procedure.performer_id === userId ||
                     sample.procedure.supervisor_id === userId;
          break;

        default:
          hasAccess = false;
      }

      if (!hasAccess) {
        await logUnauthorizedAccess(req, `Unauthorized ${resourceType} access attempt`);
        return res.status(403).json({ error: 'Access denied to this resource' });
      }

      next();
    } catch (error) {
      logger.error('Resource access check error:', error);
      res.status(500).json({ error: 'Access check failed' });
    }
  };
};

// API key authentication for external services
const authenticateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }

    // In production, validate against database or secure key management service
    const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
    
    if (!validApiKeys.includes(apiKey)) {
      await logUnauthorizedAccess(req, 'Invalid API key');
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Set a system user for API requests
    req.user = {
      id: 'system',
      role: 'api',
      username: 'api-client'
    };

    next();
  } catch (error) {
    logger.error('API key authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// Session validation middleware
const validateSession = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'No active session' });
  }

  // Check for session hijacking
  const currentIP = req.ip;
  const sessionIP = req.session.ipAddress;
  
  if (sessionIP && sessionIP !== currentIP) {
    logger.warn('Possible session hijacking detected', {
      userId: req.session.userId,
      sessionIP,
      currentIP
    });
    
    req.session.destroy();
    return res.status(401).json({ error: 'Session security violation' });
  }

  next();
};

// Helper function to log unauthorized access
async function logUnauthorizedAccess(req, reason) {
  try {
    await AuditLog.create({
      user_id: req.user?.id || null,
      username: req.user?.username || 'anonymous',
      action: 'UNAUTHORIZED_ACCESS',
      resource_type: 'auth',
      method: req.method,
      endpoint: req.originalUrl,
      ip_address: req.ip,
      user_agent: req.get('user-agent'),
      success: false,
      error_message: reason,
      metadata: {
        headers: req.headers,
        query: req.query
      }
    });
  } catch (error) {
    logger.error('Failed to log unauthorized access:', error);
  }
}

module.exports = {
  authenticateJWT,
  requireRole,
  checkResourceAccess,
  authenticateAPIKey,
  validateSession
};
