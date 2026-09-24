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
      hmr: process.env.DISABLE_HMR !== 'true',
    },
  };
});
