import { createRoot } from 'react-dom/client'
import { App } from './App'
import { captureAPIKeyFromURL } from './util/apiAuth'
import { initWorkspaceSync } from './workspaceSync'
import './styles.css'

captureAPIKeyFromURL()
// 服务器模式要在首屏交给 React 之前就开始拉工作区，避免本机缓存先写回。
// local 模式只会多发一次 /api/auth-status，行为与原来一致。
void initWorkspaceSync()
createRoot(document.getElementById('root')!).render(<App />)
