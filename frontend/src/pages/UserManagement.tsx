import { useEffect, useState } from 'react'
import { Users, Trash2, UserPlus } from 'lucide-react'
import { listUsers, createUser, deleteUser, getMe, UserRecord } from '../api'

export default function UserManagement() {
  const [users, setUsers] = useState<UserRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [me, setMe] = useState<{ id: number; username: string } | null>(null)

  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [formError, setFormError] = useState('')
  const [formLoading, setFormLoading] = useState(false)

  async function load() {
    const [u, m] = await Promise.all([listUsers(), getMe()])
    setUsers(u)
    setMe(m)
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')

    if (!newUsername.trim()) {
      setFormError('Username cannot be empty.')
      return
    }
    if (newPassword.length < 8) {
      setFormError('Password must be at least 8 characters.')
      return
    }

    setFormLoading(true)
    try {
      const created = await createUser(newUsername.trim(), newPassword)
      setUsers((prev) => [...prev, created])
      setNewUsername('')
      setNewPassword('')
    } catch (err: any) {
      if (err.response?.status === 409) {
        setFormError('Username already taken.')
      } else {
        setFormError(err.response?.data?.detail ?? 'Failed to create user.')
      }
    } finally {
      setFormLoading(false)
    }
  }

  async function handleDelete(user: UserRecord) {
    if (!confirm(`Delete user "${user.username}"? This cannot be undone.`)) return
    await deleteUser(user.id)
    setUsers((prev) => prev.filter((u) => u.id !== user.id))
  }

  const inputClass =
    'border border-gray-300 rounded-lg px-3 py-2 text-sm ' +
    'focus:outline-none focus:ring-2 focus:ring-navy-700 focus:border-transparent'

  if (loading) {
    return <div className="p-8 text-gray-500 text-sm">Loading users...</div>
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
        <p className="text-gray-500 text-sm mt-1">
          {users.length} user{users.length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Create user form */}
      <div className="card">
        <h2 className="font-semibold text-gray-800 mb-4">Add New User</h2>
        <form onSubmit={handleCreate} className="flex items-end gap-3 flex-wrap">
          <div className="flex-1 min-w-[160px]">
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              className={inputClass + ' w-full'}
              placeholder="new_user"
            />
          </div>
          <div className="flex-1 min-w-[160px]">
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className={inputClass + ' w-full'}
              placeholder="Min 8 characters"
            />
          </div>
          <button
            type="submit"
            disabled={formLoading}
            className="btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <UserPlus size={16} />
            {formLoading ? 'Creating...' : 'Add User'}
          </button>
        </form>
        {formError && (
          <p className="text-red-600 text-sm bg-red-50 border border-red-200 rounded-lg px-3 py-2 mt-3">
            {formError}
          </p>
        )}
      </div>

      {/* Users table */}
      {users.length === 0 ? (
        <div className="card text-center py-16">
          <Users size={48} className="mx-auto text-gray-300 mb-4" />
          <p className="text-gray-400 text-sm">No users found.</p>
        </div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 text-gray-500 text-left">
                <th className="px-6 py-3 font-medium">Username</th>
                <th className="px-6 py-3 font-medium">Created</th>
                <th className="px-6 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-gray-50 hover:bg-gray-50">
                  <td className="px-6 py-3 font-medium text-gray-900">
                    {user.username}
                    {me?.id === user.id && (
                      <span className="ml-2 text-xs text-gray-400 font-normal">(you)</span>
                    )}
                  </td>
                  <td className="px-6 py-3 text-gray-500">
                    {new Date(user.created_at + 'Z').toLocaleDateString('en-AU', {
                      dateStyle: 'medium',
                    })}
                  </td>
                  <td className="px-6 py-3 text-right">
                    {me?.id !== user.id && (
                      <button
                        onClick={() => handleDelete(user)}
                        className="text-red-400 hover:text-red-600 transition-colors"
                        title={`Delete ${user.username}`}
                      >
                        <Trash2 size={15} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
