import { useState } from 'react'

export default function MessageInput({ onSend, disabled }) {
  const [value, setValue] = useState('')

  function submit() {
    const trimmed = value.trim()
    if (!trimmed) return
    onSend(trimmed)
    setValue('')
  }

  return (
    <div className="input-row">
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && submit()}
        placeholder="Type a message…"
        disabled={disabled}
      />
      <button onClick={submit} disabled={disabled}>
        Send
      </button>
    </div>
  )
}
