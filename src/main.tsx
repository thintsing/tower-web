import { createRoot } from 'react-dom/client'
import { App } from './App'
import { captureAPIKeyFromURL } from './util/apiAuth'
import './styles.css'

captureAPIKeyFromURL()
createRoot(document.getElementById('root')!).render(<App />)
