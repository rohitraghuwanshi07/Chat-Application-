export default function Message({ message, isMe }) {
  if (message.type === 'system') {
    return <li className="system-line">{message.text}</li>
  }

  return (
    <li className={`bubble${isMe ? ' me' : ''}`}>
      {!isMe && <span className="sender">{message.user}</span>}
      <p className="body">{message.text}</p>
      <span className="meta">
        <span className="time">{message.time}</span>
        <VerifiedChip verified={message.verified} />
      </span>
    </li>
  )
}

function VerifiedChip({ verified }) {
  if (verified === undefined) return null
  return (
    <span className={`chip${verified ? ' chip-ok' : ' chip-bad'}`}>
      <span className="chip-dot" />
      {verified ? 'signed' : 'unverified'}
    </span>
  )
}
