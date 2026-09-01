import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        // Workbench API is served by FastAPI on port 8000; keeping the proxy here
        // makes frontend requests such as /api/llms resolve to the active backend.
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
