import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import PublicApp from './components/PublicApp.tsx';
import { isPublicRoute } from './utils/publicRouter';
import './index.css';

const Root = isPublicRoute(window.location.pathname) ? PublicApp : App;

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
