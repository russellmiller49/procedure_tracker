# Pulmonary & Critical Care Procedure Tracker

A HIPAA-compliant web application for tracking medical procedures and pathology samples in pulmonary and critical care settings.

## Features

### Core Functionality
- **Procedure Logging**: Track bronchoscopies, thoracentesis, intubations, and other procedures
- **Pathology Tracking**: Monitor samples from collection through final results
- **User Management**: Role-based access control for fellows, attendings, and administrators
- **Audit Trail**: Comprehensive logging of all system activities
- **Reporting**: Generate compliance and performance reports

### Security & Compliance
- **HIPAA Compliant**: Built with healthcare privacy regulations in mind
- **Data Encryption**: AES-256 encryption for PHI at rest
- **TLS 1.2+**: Secure data transmission
- **Two-Factor Authentication**: Optional 2FA for enhanced security
- **Session Management**: Automatic timeouts and session security
- **Audit Logging**: Immutable audit trail with 7-year retention

### Technical Features
- **RESTful API**: Well-documented API endpoints
- **Real-time Updates**: WebSocket support for live notifications
- **Responsive Design**: Mobile-friendly interface
- **Offline Capability**: Service worker for offline access
- **Automated Backups**: Scheduled encrypted backups
- **Monitoring**: Prometheus metrics and Grafana dashboards

## Quick Start

### Prerequisites
- Node.js 18+ 
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/procedure-tracker.git
cd procedure-tracker
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
# Create database
createdb procedure_tracker

# Run migrations
npm run migrate

# Seed initial data (development only)
npm run seed
```

5. Start the application:
```bash
# Development
npm run dev

# Production
npm start
```

### Docker Deployment

1. Build and start all services:
```bash
docker-compose up -d
```

2. Access the application:
- Web Interface: https://localhost
- API: https://localhost/api
- Monitoring: https://localhost:3001 (Grafana)

## Configuration

### Environment Variables

Key configuration options:

```bash
# Application
NODE_ENV=production
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=procedure_tracker
DB_USER=postgres
DB_PASSWORD=secure_password

# Security
SESSION_SECRET=very_long_random_string
JWT_SECRET=another_long_random_string
ENCRYPTION_KEY=32_character_hex_string

# Email
SMTP_HOST=smtp.sendgrid.net
SMTP_USER=apikey
SMTP_PASSWORD=your_api_key

# Compliance
AUDIT_RETENTION_DAYS=2555
SESSION_TIMEOUT_MINUTES=30
ENABLE_2FA=true
```

See `.env.example` for complete configuration options.

## API Documentation

### Authentication

All API endpoints require authentication except `/api/auth/login`.

```bash
# Login
POST /api/auth/login
{
  "username": "demo",
  "password": "demo123",
  "twoFactorCode": "123456" // If 2FA enabled
}

# Response
{
  "token": "JWT_TOKEN",
  "user": { ... },
  "sessionTimeout": 30
}
```

Use the JWT token in subsequent requests:
```bash
Authorization: Bearer YOUR_JWT_TOKEN
```

### Core Endpoints

#### Procedures
```bash
# List procedures
GET /api/procedures

# Create procedure
POST /api/procedures

# Get procedure details
GET /api/procedures/:id

# Update procedure
PUT /api/procedures/:id

# Delete procedure (soft delete)
DELETE /api/procedures/:id
```

#### Pathology
```bash
# List pathology samples
GET /api/pathology

# Update pathology results
PUT /api/pathology/:id

# Get pending samples
GET /api/pathology/pending
```

#### Reports
```bash
# Generate procedure report
GET /api/reports/procedures?start=2025-01-01&end=2025-12-31

# Export audit log
GET /api/reports/audit?format=csv
```

## Development

### Project Structure
```
├── config/         # Configuration files
├── controllers/    # Request handlers
├── middleware/     # Express middleware
├── models/         # Database models
├── routes/         # API routes
├── services/       # Business logic
├── utils/          # Utility functions
├── public/         # Frontend files
└── tests/          # Test suites
```

### Running Tests
```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# Coverage report
npm run test:coverage
```

### Code Style
```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

## Security Considerations

### PHI Protection
- All PHI is encrypted using AES-256-GCM
- Patient identifiers are de-identified
- No SSN or MRN patterns allowed
- Encrypted backups with key rotation

### Access Control
- Role-based permissions (RBAC)
- Resource-level access checks
- API rate limiting
- Session security with IP validation

### Audit Requirements
- All data access is logged
- Immutable audit trail
- 7-year retention policy
- Regular audit exports

## Deployment

### Production Checklist

1. **Environment Setup**
   - [ ] Configure all environment variables
   - [ ] Set up SSL certificates
   - [ ] Configure firewall rules
   - [ ] Enable SELinux/AppArmor

2. **Database**
   - [ ] Enable SSL connections
   - [ ] Set up replication
   - [ ] Configure automated backups
   - [ ] Test restore procedures

3. **Security**
   - [ ] Run security scan
   - [ ] Configure WAF
   - [ ] Set up intrusion detection
   - [ ] Enable 2FA for all users

4. **Monitoring**
   - [ ] Configure Prometheus
   - [ ] Set up Grafana dashboards
   - [ ] Configure alerts
   - [ ] Set up log aggregation

5. **Compliance**
   - [ ] Complete security assessment
   - [ ] Document procedures
   - [ ] Train staff
   - [ ] Sign BAAs with vendors

### Scaling

The application supports horizontal scaling:

1. **Load Balancer**: Use Nginx or HAProxy
2. **Application**: Run multiple Node.js instances
3. **Database**: PostgreSQL with read replicas
4. **Sessions**: Redis cluster for session storage
5. **Files**: S3-compatible object storage

## Maintenance

### Backup Procedures
```bash
# Manual backup
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh backup_file.enc
```

### Database Migrations
```bash
# Create new migration
npm run migrate:create -- --name add_new_feature

# Run pending migrations
npm run migrate

# Rollback last migration
npm run migrate:undo
```

### Monitoring

Access Grafana dashboards:
- System Metrics: CPU, Memory, Disk
- Application Metrics: Response times, Error rates
- Business Metrics: Procedures logged, Pending pathology

## Support

### Troubleshooting

Common issues and solutions:

1. **Login failures**
   - Check account lock status
   - Verify training/BAA compliance
   - Review audit logs

2. **Performance issues**
   - Check database indexes
   - Review slow query log
   - Monitor Redis memory

3. **Data sync problems**
   - Verify network connectivity
   - Check replication lag
   - Review error logs

### Getting Help

- Documentation: `/docs` directory
- Issue Tracker: GitHub Issues
- Email: support@hospital.com
- Emergency: Call IT helpdesk

## License

Copyright (c) 2024 Your Hospital System. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

## Acknowledgments

Built with:
- Node.js & Express
- PostgreSQL & Sequelize
- Redis
- Docker
- React (frontend)

Special thanks to the medical staff who provided requirements and feedback.
