import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
      "/health": "http://localhost:8000",
      "/chat": "http://localhost:8000",
      "/rag": "http://localhost:8000",
      "/tools": "http://localhost:8000",
      "/eval": "http://localhost:8000",
      "/reports": "http://localhost:8000",
      "/v1": "http://localhost:8000",
    },
  },
});
