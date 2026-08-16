import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Owns the WebSocket connection and the list of messages/system events
 * received over it. Talks to the SAME backend routes the old vanilla-JS
 * frontend did (`/ws?name=...&room=...`) -- only the client changed.
 */
export function useChatSocket() {
  const [messages, setMessages] = useState([])
  const [connected, setConnected] = useState(false)
  const socketRef = useRef(null)

  const connect = useCallback((name, room) => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url =
      `${proto}://${location.host}/ws` +
      `?name=${encodeURIComponent(name)}&room=${encodeURIComponent(room)}`

    const socket = new WebSocket(url)

    socket.onopen = () => setConnected(true)
    socket.onclose = () => setConnected(false)
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      setMessages((prev) => [...prev, { ...data, id: crypto.randomUUID() }])
    }

    socketRef.current = socket
  }, [])

  const sendMessage = useCallback((text) => {
    const socket = socketRef.current
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(text)
    }
  }, [])

  // Close the socket if the component using this hook unmounts.
  useEffect(() => {
    return () => socketRef.current?.close()
  }, [])

  return { messages, connected, connect, sendMessage }
}
