import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules/react')) return 'react';
            if (id.includes('node_modules/d3')) return 'visualization';
            if (id.includes('node_modules/motion')) return 'motion';
            if (id.includes('node_modules/lucide-react')) return 'icons';
            if (id.includes('/src/components/pages/AIPages')) return 'ai-pages';
            if (id.includes('/src/components/pages/IntelPages')) return 'intel-pages';
            if (id.includes('/src/components/pages/MalwareIntelPages')) return 'malware-pages';
            if (id.includes('/src/components/pages/OperationsPages')) return 'operations-pages';
            if (id.includes('/src/components/pages/InvestigationPages')) return 'investigation-pages';
            if (id.includes('/src/components/pages/AccountPages')) return 'account-pages';
            if (id.includes('/src/components/pages/SupportPages')) return 'support-pages';
            if (id.includes('/src/components/pages/UXStatesShowcasePage')) return 'ux-pages';
            if (id.includes('/src/components/pages/ToolsPages')) return 'tools-pages';
            if (id.includes('/src/components/modals/') || id.includes('/src/components/command-center/')) return 'interactive-components';
            if (id.includes('/src/components/dashboard/')) return 'dashboard-components';
            if (id.includes('/src/components/voice/')) return 'voice-components';
          },
        },
      },
    },
    preview: {
      host: '0.0.0.0',
      port: 3000,
    },
    server: {
      host: '0.0.0.0',
      port: 3000,
      allowedHosts: true,
      // HMR can be disabled with DISABLE_HMR=true.
      // Do not modify -- file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU.
      //
      // IMPORTANT: the Python backend's SQLite database lives at
      // python-server/data/nexsus.sqlite (plus its -wal/-shm journal
      // files). Every upload/write to that DB touches those files. If
      // Vite's watcher isn't told to ignore them, it sees them as
      // "unknown" file changes with no module-graph owner and falls back
      // to a FULL PAGE RELOAD -- wiping all in-memory React state (every
      // uploaded case/evidence reverts to mock data) even though nothing
      // in the frontend actually changed. The frontend never needs to
      // watch the backend's runtime data directory, so it's excluded here.
      watch: process.env.DISABLE_HMR === 'true' ? null : {
        ignored: [
          // The backend is a separate process. None of its source or runtime
          // files are frontend modules, so watching them can only cause noisy
          // HMR invalidations or full-page fallback reloads.
          '**/python-server/**',
          '**/python-server/data/**',
          '**/python-server/.venv/**',
          '**/*.sqlite',
          '**/*.sqlite-wal',
          '**/*.sqlite-shm',
        ],
      },
      // Proxy API calls to the Python (FastAPI) backend, which runs as a
      // separate process in development. See python-server/README.md.
      //
      // IMPORTANT: `configure` attaches an error handler on the proxy.
      // Without it, if the Python backend isn't running (or drops a
      // connection mid-request — e.g. during a file/sample upload), the
      // underlying http-proxy module emits an unhandled 'error' event that
      // CRASHES the whole Vite dev server process. If anything supervises
      // and restarts Vite on crash, the browser's HMR websocket reconnects
      // to the fresh instance and does a full page reload — wiping every
      // bit of in-memory React state (uploaded evidence, cases, etc. all
      // revert to the mock initial data) even though nothing in the React
      // code itself did anything wrong. This turns that hard crash into an
      // ordinary failed fetch the app's existing try/catch already handles.
      proxy: {
        '/api': {
          target: process.env.PY_API_URL || 'http://localhost:8000',
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on('error', (err, _req, res) => {
              console.error(
                `[vite proxy] Python backend unreachable at ${process.env.PY_API_URL || 'http://localhost:8000'} — is python-server running? (${err.message})`,
              );
              if (res && 'writeHead' in res && !res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
              }
              if (res && 'end' in res && res.writable) {
                res.end(JSON.stringify({
                  success: false,
                  error: 'Backend API server is unreachable. Start python-server (see python-server/README.md) and try again.',
                  code: 'BACKEND_UNREACHABLE',
                }));
              }
            });
          },
        },
      },
    },
  };
});
