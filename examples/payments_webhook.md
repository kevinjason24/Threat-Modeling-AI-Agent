# Payment Webhook Integration Design

## Overview

This document describes the integration with Stripe for payment processing in our SaaS platform. The system handles subscription management, webhook events for payment status updates, and provides billing information to users.

## System Context

Our SaaS platform allows users to subscribe to monthly or annual plans. We use Stripe as our payment processor. Users manage their subscriptions through our dashboard, while Stripe handles the actual payment collection.

## Components

### Billing Service (Python/FastAPI)
- Manages subscription lifecycle
- Processes Stripe webhook events
- Exposes billing API to frontend
- Syncs subscription status with user database
- Technology: Python 3.11, FastAPI, SQLAlchemy

### PostgreSQL Database
- Stores subscription records
- Stores invoice history
- Stores payment method metadata (no card numbers)
- Located in private subnet

### Billing Dashboard (React)
- Shows current subscription status
- Lists invoice history
- Allows plan upgrades/downgrades
- Manages payment methods (via Stripe Elements)

### Background Worker (Celery)
- Processes async billing tasks
- Sends billing-related emails
- Retries failed webhook processing

## Data Flows

### Subscription Creation
1. User selects plan in dashboard
2. Frontend loads Stripe Elements for payment input
3. Stripe.js tokenizes card, returns payment method ID
4. Frontend calls `/api/billing/subscribe` with plan + payment method
5. Billing service creates Stripe subscription
6. Stripe returns subscription object
7. Billing service stores subscription in database
8. Returns success to frontend

### Webhook Processing
1. Stripe sends webhook to `/api/webhooks/stripe`
2. Billing service validates webhook signature (HMAC)
3. Parses event type and payload
4. Updates local subscription status
5. Triggers any follow-up actions (email, feature access)
6. Returns 200 OK to Stripe

### Subscription Cancellation
1. User clicks "Cancel Subscription"
2. Frontend calls `/api/billing/cancel`
3. Billing service calls Stripe to cancel at period end
4. Updates local database
5. User retains access until period ends

## Stripe Integration Details

### API Endpoints Used
- `POST /v1/subscriptions` - Create subscription
- `POST /v1/subscriptions/:id` - Update subscription
- `DELETE /v1/subscriptions/:id` - Cancel subscription
- `GET /v1/invoices` - List invoices

### Webhook Events Handled
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.paid`
- `invoice.payment_failed`
- `payment_method.attached`

### Authentication
- API calls use Stripe secret key (sk_live_...)
- Webhook signature verified using webhook secret (whsec_...)
- Keys stored in environment variables

## Security Considerations

### Webhook Security
- Signature verification required for all webhooks
- Replay protection via timestamp validation
- Idempotency handling for duplicate events

### Data Handling
- No raw card numbers stored (Stripe tokenization)
- Payment method IDs and last 4 digits only
- Stripe customer IDs for reference

### Access Control
- Only authenticated users can view their billing
- Admin role can view all subscriptions
- Service-to-service auth for internal APIs

## Environment Configuration

```
STRIPE_API_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
DATABASE_URL=postgres://...
```

## Failure Scenarios

### Webhook Delivery Failure
- Stripe retries with exponential backoff
- Events stored for manual replay if needed
- Alert on repeated failures

### Payment Failure
- User notified via email
- Grace period before access revocation
- Automatic retry by Stripe

## Open Questions

- What is the grace period for failed payments?
- Should we support multiple payment methods per customer?
- Do we need to handle 3D Secure for European customers?
- What PCI compliance level do we need?



