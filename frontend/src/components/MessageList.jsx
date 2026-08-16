import { useEffect, useRef } from 'react'
import Message from './Message.jsx'

export default function MessageList({ messages, myName }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'end' })
  }, [messages])

  return (
    <ul className="message-list">
      {messages.map((m) => (
        <Message key={m.id} message={m} isMe={m.user === myName} />
      ))}
      <li ref={bottomRef} className="scroll-anchor" />
    </ul>
  )
}
