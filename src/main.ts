import { createApp } from 'vue'
import App from './App.vue'
import ElementPlus from 'element-plus'
import { Init } from "./scripts/ipc"
import { GetConfig } from "./scripts/ipc/config"
// If you want use Node.js, the`nodeIntegration` needs to be enabled in the Main process.
// import './demos/node'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

import './assets/style/base.css'
import './style.css'

const app = createApp(App)
app.use(ElementPlus);
app.mount('#app')
Init();
GetConfig().then(config =>{console.log("[CONFIG]: ", JSON.stringify(config));});
postMessage({ payload: 'removeLoading' }, '*');
