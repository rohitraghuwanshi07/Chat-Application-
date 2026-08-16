import MessageList from './MessageList.jsx'
import MessageInput from './MessageInput.jsx'

export default function ChatRoom({ room, myName, messages, onSend, connected }) {
  return (
    <div className="screen">
      <div className="chat-shell">
        <header className="chat-header">
          <div>
            <p className="eyebrow">room</p>
            <h2>{room}</h2>
          </div>
          <span className={`status${connected ? ' live' : ''}`}>
            <span className="status-dot" />
            {connected ? 'connected' : 'reconnecting…'}
          </span>
        </header>

        <MessageList messages={messages} myName={myName} />
        <MessageInput onSend={onSend} disabled={!connected} />
      </div>
    </div>
  )
}
