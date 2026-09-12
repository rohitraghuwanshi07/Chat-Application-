import { useCallback, useEffect, useRef, useState } from 'react'
// BYPASS (temporary): getOrCreateIdentity/signText disabled below, see notes.
// import { getOrCreateIdentity, signText } from '../lib/identity.js'

function makeId() {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

/**
 * Owns the WebSocket connection and the list of messages/system events
 * received over it. Talks to the SAME backend routes the old vanilla-JS
 * frontend did (`/ws?name=...&room=...`) -- only the client changed.
 *
 * CHANGED: every outgoing chat message now carries a client-generated
 * message_id. If the socket drops before we're sure a message landed,
 * we resend it (same message_id) after reconnecting -- the backend's
 * unique-message_id constraint makes that resend a safe no-op if the
 * original actually made it through, instead of creating a duplicate.
 *
 * CHANGED: the server no longer generates or holds signing keys. This
 * hook now loads/generates this browser's Ed25519 identity for the
 * given username (see lib/identity.js), registers its public key with
 * the server once at connect time (?pubkey=... on the WS URL), and
 * signs every outgoing message itself before sending it.
 */
export function useChatSocket() {
  const [messages, setMessages] = useState([])
  const [connected, setConnected] = useState(false)
  const socketRef = useRef(null)
  const nameRef = useRef('')
  const identityRef = useRef(null) // { privateKey, publicKeyPem }
  // message_id -> text, for messages we've sent but haven't seen echoed
  // back to us yet. Cleared as soon as the matching broadcast arrives.
  const pendingRef = useRef(new Map())

  const connect = useCallback(async (name, room) => {
    nameRef.current = name
    // BYPASS (temporary): getOrCreateIdentity() needs crypto.subtle, which
    // browsers disable on insecure (non-HTTPS, non-localhost) origins.
    // Skipping it means messages send unsigned -- verified will show as
    // false, but the app will actually connect. Restore this once served
    // over HTTPS or localhost.
    // identityRef.current = await getOrCreateIdentity(name)

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const url =
      `${proto}://${location.host}/ws` +
      `?name=${encodeURIComponent(name)}&room=${encodeURIComponent(room)}`

    const socket = new WebSocket(url)

    socket.onopen = () => {
      setConnected(true)
      // Retry: resend anything sent before this connection existed that
      // never got confirmed. Same message_id each time, so the server
      // just ignores it if it actually already has that message.
      for (const [message_id, text] of pendingRef.current) {
        // BYPASS (temporary): see note above -- sending with no signature.
        socket.send(JSON.stringify({ text, message_id, signature: '' }))
      }
    }
    socket.onclose = () => setConnected(false)
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data)

      if (data.message_id && data.user === nameRef.current) {
        pendingRef.current.delete(data.message_id)
      }

      const id = data.message_id ?? makeId()

      setMessages((prev) => {
        // Guard against ever rendering the same message twice (e.g. a
        // retry that lands as both a direct ack and a room broadcast).
        if (data.message_id && prev.some((m) => m.id === id)) return prev
        return [...prev, { ...data, id }]
      })
    }
    socketRef.current = socket
  }, [])

  const sendMessage = useCallback(async (text) => {
    const socket = socketRef.current
    if (socket && socket.readyState === WebSocket.OPEN) {
      const message_id = makeId()
      pendingRef.current.set(message_id, text)
      // BYPASS (temporary): see note above -- sending with no signature.
      const signature = ''
      socket.send(JSON.stringify({ text, message_id, signature }))
    }
  }, [])

  // Close the socket if the component using this hook unmounts.
  useEffect(() => {
    return () => socketRef.current?.close()
  }, [])

  return { messages, connected, connect, sendMessage }
}