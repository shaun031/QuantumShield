import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth.js'

const emptyForm = {
  name: '',
  email: '',
  password: '',
  confirmPassword: '',
}

export default function RegisterPage() {
  const navigate = useNavigate()
  const { register } = useAuth()
  const [form, setForm] = useState(emptyForm)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  function updateField(event) {
    setForm((current) => ({
      ...current,
      [event.target.name]: event.target.value,
    }))
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')

    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setSubmitting(true)
    try {
      const user = await register({
        name: form.name.trim(),
        email: form.email.trim(),
        password: form.password,
      })
      navigate('/login', {
        replace: true,
        state: {
          email: user.email,
          message: 'Account created. You can now sign in.',
        },
      })
    } catch (requestError) {
      setError(requestError.message || 'Registration failed. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-intro">
        <div className="phase-badge">Research prototype · Server-managed keys</div>
        <p className="eyebrow">Create your account</p>
        <h1>QuantumShield</h1>
        <p className="subtitle">A secure identity foundation</p>
        <p className="scope-note">
          Passwords are protected with Argon2id. Registration provisions
          ML-KEM-512/768/1024, X25519, and ML-DSA-65 keys protected by the
          server. It does not automatically sign you in.
        </p>
      </section>

      <section className="auth-card" aria-labelledby="register-title">
        <p className="eyebrow">Get started</p>
        <h2 id="register-title">Register</h2>

        {error && (
          <p className="form-message form-message--error" role="alert">
            {error}
          </p>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            Name
            <input
              type="text"
              name="name"
              autoComplete="name"
              required
              maxLength={100}
              value={form.name}
              onChange={updateField}
            />
          </label>

          <label>
            Email
            <input
              type="email"
              name="email"
              autoComplete="email"
              required
              value={form.email}
              onChange={updateField}
            />
          </label>

          <label>
            Password
            <input
              type="password"
              name="password"
              autoComplete="new-password"
              required
              minLength={8}
              maxLength={128}
              value={form.password}
              onChange={updateField}
            />
            <span className="field-hint">8–128 characters</span>
          </label>

          <label>
            Confirm password
            <input
              type="password"
              name="confirmPassword"
              autoComplete="new-password"
              required
              minLength={8}
              maxLength={128}
              value={form.confirmPassword}
              onChange={updateField}
            />
          </label>

          <button className="button-primary" type="submit" disabled={submitting}>
            {submitting ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <p className="auth-switch">
          Already registered? <Link to="/login">Login</Link>
        </p>
      </section>
    </main>
  )
}

