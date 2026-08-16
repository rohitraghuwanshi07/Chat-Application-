import { useState } from 'react'

export default function JoinScreen({ onJoin }) {
  const [name, setName] = useState('')
  const [room, setRoom] = useState('')

  function handleSubmit(e) {
    e.preventDefault()
    const trimmedName = name.trim()
    if (!trimmedName) return
    onJoin(trimmedName, room.trim() || 'general')
  }

  return (
    <div className="screen">
      <form className="join-card" onSubmit={handleSubmit}>
        <p className="eyebrow">encrypted at rest &middot; signed in transit</p>
        <h1>Enter the room</h1>

        <label>
          Name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. asha"
            autoFocus
          />
        </label>

        <label>
          Room
          <input
            value={room}
            onChange={(e) => setRoom(e.target.value)}
            placeholder="general"
          />
        </label>

        <button type="submit">Join chat</button>
      </form>
    </div>
  )
}
