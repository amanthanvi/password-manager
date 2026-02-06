declare global {
  interface Window {
    npw: {
      ping: () => string
    }
  }
}

export {}
