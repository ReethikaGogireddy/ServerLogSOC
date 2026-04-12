FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy frontend source code
COPY frontend/ ./

# Build the frontend
EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]