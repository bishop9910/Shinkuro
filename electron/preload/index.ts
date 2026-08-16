import { ipcRenderer, contextBridge } from 'electron'

// --------- Expose some API to the Renderer process ---------
contextBridge.exposeInMainWorld('ipcRenderer', {
  on(...args: Parameters<typeof ipcRenderer.on>) {
    const [channel, listener] = args
    return ipcRenderer.on(channel, (event, ...args) => listener(event, ...args))
  },
  off(...args: Parameters<typeof ipcRenderer.off>) {
    const [channel, ...omit] = args
    return ipcRenderer.off(channel, ...omit)
  },
  send(...args: Parameters<typeof ipcRenderer.send>) {
    const [channel, ...omit] = args
    return ipcRenderer.send(channel, ...omit)
  },
  invoke(...args: Parameters<typeof ipcRenderer.invoke>) {
    const [channel, ...omit] = args
    return ipcRenderer.invoke(channel, ...omit)
  },
})

// --------- Preload scripts loading ---------
//检测页面是否加载完成
function domReady(condition: DocumentReadyState[] = ['complete', 'interactive']) {
  return new Promise((resolve) => {
    if (condition.includes(document.readyState)) {
      resolve(true);
    } else {
      document.addEventListener('readystatechange', () => {
        if (condition.includes(document.readyState)) {
          resolve(true);
        }
      })
    }
  })
}

//进行更安全DOM添加和删除操作的对象
const safeDOM = {
  append(parent: HTMLElement, child: HTMLElement) {
    if (!Array.from(parent.children).find(e => e === child)) {
      return parent.appendChild(child);
    }
  },
  remove(parent: HTMLElement, child: HTMLElement) {
    if (Array.from(parent.children).find(e => e === child)) {
      return parent.removeChild(child);
    }
  },
}

/**
 * https://tobiasahlin.com/spinkit
 * https://connoratherton.com/loaders
 * https://projects.lukehaas.me/css-loaders
 * https://matejkustec.github.io/SpinThatShit
 */
function useLoading() {
  const className = `element-loading-spinner`;
  const styleContent = `
  @keyframes loading-rotate {
    100% {
      transform: rotate(360deg);
    }
  }
  @keyframes loading-dash {
    0% {
      stroke-dasharray: 1, 200;
      stroke-dashoffset: 0;
    }
    50% {
      stroke-dasharray: 90, 150;
      stroke-dashoffset: -40px;
    }
    100% {
      stroke-dasharray: 90, 150;
      stroke-dashoffset: -120px;
    }
  }
  .${className} {
    position: relative;
    width: 42px;
    height: 42px;
  }
  .${className} .circular {
    animation: loading-rotate 2s linear infinite;
    height: 100%;
    width: 100%;
  }
  .${className} .path {
    animation: loading-dash 1.5s ease-in-out infinite;
    stroke-dasharray: 90, 150;
    stroke-dashoffset: 0;
    stroke-width: 3;
    stroke: #409eff;
    stroke-linecap: round;
  }
  .${className} .text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    margin: 0;
    color: #409eff;
    font-size: 12px;
  }
  .app-loading-wrap {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.7);
    z-index: 9999;
    backdrop-filter: blur(2px);
  }
  .loading-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
  }
  .loading-text {
    color: #fff;
    font-size: 14px;
    font-weight: 400;
    letter-spacing: 0.5px;
    text-align: center;
    margin-top: 8px;
  }
  `;

  const oStyle = document.createElement('style');
  const oDiv = document.createElement('div');

  oStyle.id = 'app-loading-style';
  oStyle.innerHTML = styleContent;
  oDiv.className = 'app-loading-wrap';

  const svgLoader = `
  <svg class="circular" viewBox="25 25 50 50">
    <circle class="path" cx="50" cy="50" r="20" fill="none"/>
  </svg>
  `;

  oDiv.innerHTML = `
  <div class="loading-content">
    <div class="${className}">
      ${svgLoader}
    </div>
    <div class="loading-text">加载中...</div>
  </div>
  `;

  return {
    appendLoading() {
      safeDOM.append(document.head, oStyle);
      safeDOM.append(document.body, oDiv);
    },
    removeLoading() {
      safeDOM.remove(document.head, oStyle);
      safeDOM.remove(document.body, oDiv);
    },
  }
}

// ----------------------------------------------------------------------

//引入
const { appendLoading, removeLoading } = useLoading();
//没加载好的时候使用加载页面
domReady().then(appendLoading);
//收到remove消息立即移除加载页面
window.onmessage = (ev: { data: { payload: string } }) => {
  ev.data.payload === 'removeLoading' && setTimeout(removeLoading, 200);
}
//兜底 5s后自动移除页面
setTimeout(removeLoading, 4999);