# ---- Frontend build stage ----
FROM node:22-slim AS frontend-build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

# ---- Production stage (Python/FastAPI) ----
FROM python:3.12-slim AS production
WORKDIR /app
ENV NODE_ENV=production
ENV PYTHONUNBUFFERED=1

COPY python-server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY python-server/app ./app
COPY --from=frontend-build /app/dist ./dist

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
