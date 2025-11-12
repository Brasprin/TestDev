# Distributed Enrollment System — Skeleton

This repository contains a multi-node skeleton for a distributed, role-based online enrollment system using React (frontend), Node.js/Express (backend services), and MongoDB. Each service runs on its own port to simulate distribution/fault isolation.

## Nodes/Ports
- Frontend (React): http://localhost:3000
- Auth Service: http://localhost:8001
- User/RBAC Service: http://localhost:8002
- Course Service: http://localhost:8003
- Grade Service: http://localhost:8004
- Audit Service: http://localhost:8005
- (Optional) API Gateway: http://localhost:8000

## Prerequisites
- Node.js 18+
- npm or yarn
- MongoDB running locally or via Docker

## Quick Start
1. Copy `.env.example` to `.env` in each service and adjust values as needed.
2. Install dependencies in root to set up workspaces: `npm install`.
3. Start MongoDB locally or via Docker (see `infra/docker-compose.mongo.yml`).
4. In separate terminals, run each service: `npm run dev` from each service directory.
5. Run frontend: `npm start` from `frontend`.

## Fault Isolation
If a service (e.g., Grades) is stopped, only related features will be unavailable. Other services continue to function.

## Structure
- `frontend/` React app with vanilla CSS and role-guarded route placeholders.
- `services/` Node/Express microservices with TypeScript-ready configuration (currently JS for simplicity), basic health endpoints, and shared middleware scaffolding.
- `packages/common/` Shared code: types, auth utilities (JWT verify), error helpers.
- `infra/` Docker compose for MongoDB.

## Scripts
- Root: `npm run install:all` (installs across workspaces)
- Each service: `npm run dev`, `npm test`
- Frontend: `npm start`

## Notes
- This is a skeleton. Implement business logic, validation, and database models per the plan.
- JWT keys: generate dev keys and set env vars or file paths.
