FROM node:22 AS build
WORKDIR /app


COPY package.json package-lock.json ./


RUN npm ci --include=dev


RUN npm install -g vite@5.2.0


COPY . .


RUN npm pkg set scripts.build="vite build"


RUN vite build


FROM node:22 AS runner
WORKDIR /app


RUN npm install -g serve

COPY --from=build /app/dist ./dist

EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
