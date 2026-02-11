# NEXUS KYC Pro

Enterprise-grade KYC (Know Your Customer) compliance platform competing with companyinfo.de.

## Features

- 6-Step Visual KYC Pipeline
- German Register Integration (Handelsregister, Transparenzregister)
- Document Upload with OCR & AI Analysis
- PEP/Sanctions Compliance Checks
- UBO Visualization
- Real-time Dashboard

## Tech Stack

- **Backend**: Node.js, Express, PostgreSQL
- **Frontend**: React, TypeScript, Tailwind CSS
- **APIs**: bundesAPI Handelsregister, Transparenzregister

## Deployment

Deployed on Railway with automatic CI/CD.

## API Endpoints

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/companies/search-handelsregister` - Search German companies
- `POST /api/cases` - Create KYC case
- `POST /api/documents` - Upload documents
- `POST /api/compliance/check` - Run compliance checks

## License

Proprietary - NEXUS Compliance AI GmbH
