# Authentication Feature Design

## Overview

This document describes the authentication system for our web application. The system supports email/password login, OAuth2 social login (Google, GitHub), and optional MFA via TOTP.

## Components

### Frontend (React SPA)
- Single Page Application hosted on CDN
- Communicates with backend via REST API
- Stores access token in memory, refresh token in HttpOnly cookie
- Uses React Query for API state management

### API Gateway (Kong)
- Entry point for all API traffic
- Handles rate limiting (100 req/min per IP)
- Validates JWT tokens before forwarding
- Terminates TLS (Let's Encrypt certificates)

### Auth Service (Node.js)
- Handles login, registration, password reset
- Issues JWT access tokens (15 min expiry)
- Issues refresh tokens (7 day expiry)
- Integrates with OAuth2 providers
- Sends transactional emails via SendGrid

### User Database (PostgreSQL)
- Stores user accounts, hashed passwords (bcrypt)
- Stores OAuth connections
- Stores MFA secrets (encrypted with AES-256)
- Located in private subnet, not internet-accessible

### Redis Session Cache
- Stores active session metadata
- Used for rate limiting counters
- Token blacklist for revoked tokens

## Authentication Flows

### Email/Password Login
1. User submits email/password to `/api/auth/login`
2. Auth service validates credentials against database
3. If valid, generates JWT access + refresh tokens
4. Returns access token in response body
5. Sets refresh token as HttpOnly cookie

### OAuth2 Login (Google)
1. Frontend redirects to `/api/auth/google`
2. Auth service redirects to Google OAuth consent
3. User approves, Google redirects back with code
4. Auth service exchanges code for tokens
5. Fetches user profile, creates/links account
6. Issues JWT tokens as above

### Token Refresh
1. Frontend detects expired access token
2. Calls `/api/auth/refresh` with refresh token cookie
3. Auth service validates refresh token
4. Issues new access token

### MFA Setup
1. User navigates to security settings
2. Frontend requests TOTP secret from backend
3. Backend generates secret, returns QR code data
4. User scans with authenticator app
5. User enters verification code
6. Backend validates and enables MFA

## Data Types

- User credentials (email, hashed password)
- OAuth tokens (encrypted at rest)
- TOTP secrets (encrypted with AES-256)
- JWT tokens (contain user ID, roles, expiry)
- Session metadata (IP, user agent, last active)

## External Integrations

- **Google OAuth2**: For social login
- **GitHub OAuth2**: For social login
- **SendGrid**: Transactional email (password reset, etc.)

## Security Considerations

- Passwords hashed with bcrypt (cost factor 12)
- All traffic over HTTPS
- CORS restricted to known origins
- Rate limiting on authentication endpoints
- Refresh tokens can be revoked
- MFA secrets encrypted at rest

## Open Questions

- Should we implement device fingerprinting?
- What is the session timeout policy?
- Do we need to support SAML for enterprise customers?



