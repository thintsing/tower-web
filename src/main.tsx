import { createRoot } from 'react-dom/client'
import { App } from './App'
import { captureAPIKeyFromURL } from './util/apiAuth'
import { enterDemoMode, initWorkspaceSync } from './workspaceSync'
import { DEMO_MODE } from './demo/demoMode'
import './styles.css'

captureAPIKeyFromURL()
// 示例工作区只读本机演示命名空间，绝不连接服务端或覆盖真实工作区。
if (DEMO_MODE) enterDemoMode()
// 服务器模式要在首屏交给 React 之前就开始拉工作区，避免本机缓存先写回。
// local 模式只会多发一次 /api/auth-status，行为与原来一致。
else void initWorkspaceSync()
createRoot(document.getElementById('root')!).render(<App />)
