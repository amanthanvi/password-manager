import { contextBridge } from 'electron'

contextBridge.exposeInMainWorld('npw', {
  ping: () => 'pong'
})
