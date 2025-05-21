FROM node:20-alpine

WORKDIR /app

COPY frontend/package*.json ./
RUN npm install

COPY frontend /app

RUN npm run build

# Use NGINX to serve build
FROM nginx:alpine
COPY --from=0 /app/dist /usr/share/nginx/html
EXPOSE 80

COPY nginx.conf /etc/nginx/conf.d/default.conf
