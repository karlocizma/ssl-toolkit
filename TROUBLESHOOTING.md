# Troubleshooting Guide

## Seeing Apache2 or Default Web Page (CRITICAL)

### Problem
When accessing `http://localhost`, you see an Apache2 default page, nginx welcome page, or other default web server page instead of the SSL Toolkit application.

### Root Cause
**The nginx container was not exposing port 80 to the host machine.** This was a critical bug in `docker-compose.yml` that prevented the application from being accessible.

### Solution - FIXED in latest version

**This issue was fixed in commit `d46d7bd`.** Pull the latest changes and restart:

```bash
# Pull the latest changes
git pull origin main

# Stop all containers
docker compose down

# Start with new configuration
docker compose up -d

# Or use the run script
./run.sh
```

The `docker-compose.yml` now includes the required port mappings:
```yaml
nginx:
  ports:
    - "80:80"
    - "443:443"
```

If you still see issues after updating, follow the frontend rebuild steps below.

## Frontend Shows Default/Nginx Page

### Problem
After fixing the port mapping issue, you might still see a default nginx page if the frontend wasn't built correctly.

### Why This Happens
The frontend container serves a static build of the React application. If you see a default page, it means:

1. **The frontend container hasn't been built yet** - The React app needs to be compiled into static files
2. **The build failed during initial setup** - npm build errors weren't visible
3. **The container is using cached layers** - An incomplete build is cached

### Quick Fix

Run the provided script:

```bash
./rebuild-frontend.sh
```

Or manually:

```bash
# Stop all containers
docker compose down

# Rebuild frontend without cache
docker compose build frontend --no-cache

# Start everything
docker compose up -d
```

### Verify the Build

After rebuilding, verify the containers are running:

```bash
docker compose ps
```

You should see all three containers (backend, frontend, nginx) with status "Up".

Check frontend logs for any errors:

```bash
docker compose logs frontend
```

You should see:
- npm install output
- npm run build output
- nginx starting

### Common Build Issues

#### 1. Node/npm version issues

**Error**: `npm ERR! code EBADENGINE`

**Solution**: The Dockerfile uses `node:18-alpine`. If you need a different version, edit `frontend/Dockerfile`:

```dockerfile
FROM node:20-alpine as build  # Change to node:20-alpine
```

#### 2. Out of memory during build

**Error**: `FATAL ERROR: Reached heap limit`

**Solution**: Increase Docker memory limit in Docker Desktop settings, or build with more memory:

```bash
docker compose build frontend --memory=4g
```

#### 3. Missing dependencies

**Error**: `Module not found` errors

**Solution**: Delete node_modules and reinstall:

```bash
cd frontend
rm -rf node_modules package-lock.json
docker compose build frontend --no-cache
```

## Backend Import Errors

### Problem: "Could not import module 'main'"

**Fixed in**: Commit `6bcdd31`

This was caused by trying to run Flask with an ASGI server. The backend now correctly uses Gunicorn WSGI server.

**Solution**: Pull latest changes and rebuild:

```bash
git pull origin main
docker compose build backend
docker compose up -d
```

## Nginx SSL Certificate Error

### Problem: Cannot load certificate "/etc/nginx/ssl/cert.pem"

**Fixed in**: Commit `f7cf54d`

HTTPS is now disabled by default for development.

**Solution**: Already fixed in main branch. Pull and restart:

```bash
git pull origin main
docker compose restart nginx
```

To enable HTTPS, see [README.md - SSL/HTTPS Configuration](README.md#sslhttps-configuration).

## Python Syntax Error in ssl_checker.py

### Problem: `SyntaxError: f-string: unmatched '('`

**Fixed in**: Commit `20ecb42`

This was a Python 3.11 f-string syntax issue.

**Solution**: Already fixed in main branch:

```bash
git pull origin main
docker compose build backend
docker compose up -d
```

## Port Conflicts

### Problem: "port is already allocated"

Another service is using port 80, 443, or 5000.

**Solution 1**: Stop the conflicting service

Find what's using the port:

```bash
# On Linux/Mac
sudo lsof -i :80
sudo lsof -i :5000

# On Windows
netstat -ano | findstr :80
netstat -ano | findstr :5000
```

**Solution 2**: Use different ports

Edit `docker-compose.yml`:

```yaml
nginx:
  ports:
    - "8080:80"  # Use 8080 instead of 80
```

Then access at `http://localhost:8080`

## Container Restart Loops

### Problem: Containers keep restarting

Check logs to identify the specific error:

```bash
# View all logs
docker compose logs

# View specific container
docker compose logs backend
docker compose logs frontend
docker compose logs nginx

# Follow logs in real-time
docker compose logs -f backend
```

Then follow the specific troubleshooting steps for the error you see.

## Health Check Failures

### Problem: Container shows as "unhealthy"

Check health status:

```bash
docker compose ps
```

Inspect health check logs:

```bash
docker inspect ssl-toolkit-backend | grep -A 10 Health
docker inspect ssl-toolkit-frontend | grep -A 10 Health
```

### Backend health check failing

The backend health check tests `http://localhost:5000/api/health`.

Verify it manually:

```bash
docker compose exec backend curl http://localhost:5000/api/health
```

If it fails, check backend logs:

```bash
docker compose logs backend
```

### Frontend health check failing

The frontend health check tests `http://localhost:80`.

Verify manually:

```bash
docker compose exec frontend curl http://localhost:80
```

## Network Issues

### Problem: Containers can't communicate

Verify all containers are on the same network:

```bash
docker network ls
docker network inspect ssl-toolkit_ssl-toolkit-network
```

All three containers should be listed under "Containers".

### Problem: Cannot access from host

Check Docker networking mode:

```bash
docker compose ps
```

Verify port mappings show `0.0.0.0:80->80/tcp`.

## Complete Reset

If all else fails, completely reset:

```bash
# Stop and remove everything
docker compose down -v

# Remove all images
docker compose down --rmi all

# Clean Docker build cache
docker builder prune -a

# Rebuild from scratch
docker compose build --no-cache

# Start fresh
docker compose up -d
```

## Getting Help

If you're still having issues:

1. **Check logs**: `docker compose logs`
2. **Check container status**: `docker compose ps`
3. **Verify Docker**: `docker --version` and `docker compose version`
4. **Check this guide**: Make sure you've tried the relevant solutions
5. **Create an issue**: Include logs and error messages

## Useful Commands

```bash
# View all containers
docker compose ps

# View logs for all services
docker compose logs

# View logs for specific service
docker compose logs backend
docker compose logs frontend
docker compose logs nginx

# Follow logs in real-time
docker compose logs -f

# Restart specific service
docker compose restart backend

# Rebuild and restart specific service
docker compose up -d --build frontend

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v

# Check Docker disk usage
docker system df

# Clean up unused resources
docker system prune
```
