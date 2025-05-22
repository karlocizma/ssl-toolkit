# 🔐 SSL Toolkit Web App

A full-featured web application for working with SSL/TLS certificates. Built with **FastAPI** (backend) and **React + Vite + TailwindCSS** (frontend). Runs seamlessly in Docker.

## ✨ Features

- 🔍 **SSL Certificate Checker** – Verify validity, issuer, expiration.
- 🧬 **CSR Decoder** – Decode Certificate Signing Requests.
- 📜 **SSL Decoder** – Decode PEM/CRT certificates into readable fields.
- 🛠️ **CSR Generator** – Generate CSRs by filling in organization details.
- 🔄 **SSL Converter** – Convert SSL certificates:
  - `PEM ⇄ PFX` (with password-protected PFX support)
  - Upload full certificate files for conversion

## 📦 Technologies Used

- 🐍 **FastAPI** – Python backend with endpoints for decoding/conversion
- ⚛️ **React + Vite** – Fast and responsive frontend
- 🎨 **Tailwind CSS** – Dark-mode friendly UI
- 🐳 **Docker** – Easy to containerize and deploy

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/yourusername/ssl-toolkit.git
cd ssl-toolkit

### 2. Build and Run with Docker

```bash
docker-compose up --build -d

# This will:
- Build the backend and frontend containers
- Start both services using Docker Compose
- Serve the app at: http://localhost:3000

## 🧪 Available Endpoints (Backend API)
- POST /api/ssl-check – Check SSL for a domain
- POST /api/csr-decode – Decode a CSR
- POST /api/ssl-decode – Decode a certificate
- POST /api/generate-csr – Generate a new CSR
- POST /api/convert-ssl – Convert SSL cert to another format (PEM/PFX)

## 🗂 Project Structure

```bash
.
├── backend/
│   ├── main.py             # FastAPI app
│   └── requirements.txt    # Python deps
│
├── frontend/
│   ├── src/
│   │   ├── components/     # React components (CSRDecoder, SSLDecoder, etc.)
│   │   └── App.jsx
│   ├── tailwind.config.js
│   └── package.json
│
├── docker-compose.yml
├── Dockerfile
└── nginx.conf

## 📥 Uploads & File Conversion Notes
- Certificate files should be .pem, .crt, or .pfx
- Private keys must be included if converting to PFX
- For password-protected PFX export, input your desired password before converting

## 🛠 Development Notes
- Frontend dev: cd frontend && npm run dev
- Backend dev: cd backend && uvicorn main:app --reload