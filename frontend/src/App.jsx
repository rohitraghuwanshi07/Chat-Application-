import { useState } from 'react'
import JoinScreen from './components/JoinScreen.jsx'
import ChatRoom from './components/ChatRoom.jsx'
import { useChatSocket } from './hooks/useChatSocket.js'

export default function App() {
  const [session, setSession] = useState(null) // { name, room } | null
  const { messages, connected, connect, sendMessage } = useChatSocket()

  function handleJoin(name, room) {
    setSession({ name, room })
    connect(name, room)
  }

  if (!session) {
    return <JoinScreen onJoin={handleJoin} />
  }

  return (
    <ChatRoom
      room={session.room}
      myName={session.name}
      messages={messages}
      onSend={sendMessage}
      connected={connected}
    />
  )
}
