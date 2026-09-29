# Independent Cloud & Web Deployment Guide

This guide explains how to publish **PhishShield** as an independent, publicly accessible website on the internet so that anyone (professors, recruiters, colleagues) can access it from their phone or laptop without needing Python running locally.

---

## 🌐 Option 1: Deploy to GitHub Pages (Fastest & 100% Free)
Because PhishShield includes an autonomous in-browser forensic and ML engine (`client_engine.js`), the frontend can be hosted directly on GitHub Pages with **zero backend servers required**.

### Steps:
1. Push your project to GitHub (see [`docs/GITHUB_STRATEGY.md`](GITHUB_STRATEGY.md)).
2. Go to your GitHub repository in your web browser.
3. Click **Settings** (top right) &rarr; Click **Pages** (left sidebar under "Code and automation").
4. Under **Build and deployment**:
   - **Source:** Select **GitHub Actions**.
5. The included workflow (`.github/workflows/deploy-pages.yml`) will automatically trigger!
6. Within 60 seconds, your site is live at:  
   👉 `https://<YOUR_GITHUB_USERNAME>.github.io/Phishing-Email-Detection-Awareness-Dashboard/`

---

## ⚡ Option 2: Deploy to Vercel (Instant Global CDN)
Vercel hosts the standalone frontend globally with automatic HTTPS certificates.

### Steps:
1. Go to [vercel.com](https://vercel.com) and sign in with your GitHub account.
2. Click **Add New...** &rarr; **Project**.
3. Select your `Phishing-Email-Detection-Awareness-Dashboard` repository.
4. Leave all settings at default (Vercel automatically detects [`vercel.json`](../vercel.json)).
5. Click **Deploy**.
6. Your live website is instantly available at:  
   👉 `https://phishshield-<unique-id>.vercel.app`

---

## 🐳 Option 3: Deploy Full-Stack to Render.com (Free FastAPI Backend + Frontend)
If you want the live website to run both the FastAPI Python backend and the web console on a public cloud server:

### Steps:
1. Sign up for a free account at [render.com](https://render.com).
2. In the Render Dashboard, click **New +** &rarr; **Blueprint**.
3. Connect your GitHub repository.
4. Render will automatically read [`render.yaml`](../render.yaml) from your repository root!
5. Click **Apply**.
6. Render will automatically:
   - Build the Python environment.
   - Run dataset generation & ML model training.
   - Seed the SQLite database with 30 audit records.
   - Start the production Uvicorn web server.
7. Your full-stack live service will be accessible globally at:  
   👉 `https://phishshield-dashboard.onrender.com`

---

## 📦 Option 4: Run via Docker Container
You can also run the pre-configured production Docker container locally or on any cloud VPS (DigitalOcean, AWS EC2, Google Cloud Run):

```bash
# Build the Docker image
docker build -t phishshield:latest .

# Run the container exposing port 8000
docker run -d -p 8000:8000 --name phishshield-app phishshield:latest

# Open in browser:
http://localhost:8000
```
