const { createApp, ref, reactive, computed } = Vue

// api calls the JSON API and throws its error message on failure.
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body && JSON.stringify(body),
  })
  const data = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) throw Object.assign(new Error(data?.error || `Request failed (${res.status})`), { status: res.status })
  return data
}

const icons = {
  key: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
}

const app = createApp({
  setup() {
    const ready = ref(false)
    const me = ref(null)
    const error = ref('')
    const busy = ref(false)
    const certs = ref([])
    const users = ref([])
    const signed = ref(null)
    const enrolled = ref(null)
    const copied = ref('')
    const editing = ref('')
    const loginForm = reactive({ user: '', password: '', code: '' })
    const signForm = reactive({ identity: '', pubkey: '', days: 7 })
    const userForm = reactive({ name: '', principals: '', admin: false })
    const editForm = reactive({ name: '', principals: '', admin: false })

    const route = () => location.hash.slice(1) || 'dashboard'
    const view = ref(route())
    addEventListener('hashchange', () => (view.value = route()))

    const tabs = computed(() => [
      { id: 'dashboard', label: 'Dashboard' },
      ...(me.value?.admin ? [{ id: 'users', label: 'Users' }] : []),
      { id: 'about', label: 'About' },
    ])
    const dayChoices = computed(() => [1, 7, 14, me.value?.maxDays ?? 30])
    const stats = computed(() => ({
      active: certs.value.filter(c => !c.revoked && !c.expired).length,
      expired: certs.value.filter(c => !c.revoked && c.expired).length,
      revoked: certs.value.filter(c => c.revoked).length,
    }))
    const enrolFields = [
      { key: 'name', label: 'Username' },
      { key: 'password', label: 'Password' },
      { key: 'secret', label: 'Authenticator secret' },
      { key: 'url', label: 'otpauth link' },
    ]

    // run wraps every action: one at a time, errors shown in the banner,
    // and a 401 (session expired or account removed) drops back to the login form.
    async function run(fn) {
      busy.value = true
      error.value = ''
      try {
        await fn()
      } catch (e) {
        if (e.status === 401 && me.value) me.value = null
        error.value = e.message
      } finally {
        busy.value = false
      }
    }

    async function load() {
      try {
        me.value = await api('GET', '/api/me')
        certs.value = await api('GET', '/api/certs')
        if (me.value.admin) users.value = await api('GET', '/api/users')
      } catch (e) {
        me.value = null
        if (e.status !== 401) error.value = e.message
      }
      ready.value = true
    }

    const login = () => run(async () => {
      try {
        await api('POST', '/api/login', loginForm)
      } finally {
        loginForm.code = ''
      }
      loginForm.password = ''
      await load()
    })

    const logout = () => run(async () => {
      await api('POST', '/api/logout')
      me.value = null
      signed.value = enrolled.value = null
    })

    const sign = () => run(async () => {
      signed.value = await api('POST', '/api/certs', signForm)
      signForm.identity = signForm.pubkey = ''
      certs.value = await api('GET', '/api/certs')
      scrollTo({ top: 0, behavior: 'smooth' })
    })

    const revoke = c => {
      if (!confirm(`Revoke ${c.identity}? Every certificate for this key stops working, and the key can't be signed again.`)) return
      run(async () => {
        await api('POST', `/api/certs/${c.serial}/revoke`)
        certs.value = await api('GET', '/api/certs')
      })
    }

    const addUser = () => run(async () => {
      enrolled.value = await api('POST', '/api/users', userForm)
      Object.assign(userForm, { name: '', principals: '', admin: false })
      users.value = await api('GET', '/api/users')
      scrollTo({ top: 0, behavior: 'smooth' })
    })

    // startEdit fills the form from the row, so the list keeps whatever order it has.
    const startEdit = u => {
      Object.assign(editForm, { name: u.name, principals: u.principals.join(','), admin: u.admin })
      editing.value = u.name
    }

    // The row stays open when the save fails, so the message in the banner is
    // next to something that can be corrected.
    const saveUser = () => run(async () => {
      await api('PUT', `/api/users/${encodeURIComponent(editForm.name)}`, { principals: editForm.principals, admin: editForm.admin })
      editing.value = ''
      users.value = await api('GET', '/api/users')
    })

    const removeUser = u => {
      if (!confirm(`Remove ${u.name}? Their sessions end now, and every key they ever had signed is revoked.`)) return
      run(async () => {
        await api('DELETE', `/api/users/${encodeURIComponent(u.name)}`)
        users.value = await api('GET', '/api/users')
      })
    }

    async function copy(key, text) {
      await navigator.clipboard.writeText(text.trim() + '\n')
      copied.value = key
      setTimeout(() => copied.value === key && (copied.value = ''), 1500)
    }

    function download(name, text) {
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([text.trim() + '\n'], { type: 'text/plain' }))
      a.download = name
      a.click()
      URL.revokeObjectURL(a.href)
    }

    const isNew = c => signed.value?.serial === c.serial
    const when = t => new Date(t).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

    load()
    return {
      ready, me, error, busy, certs, users, signed, enrolled, copied, view, tabs, dayChoices, stats, enrolFields,
      loginForm, signForm, userForm, editing, editForm, login, logout, sign, revoke, addUser, startEdit, saveUser, removeUser, copy, download, isNew, when,
    }
  },
})

app.component('icon', {
  props: ['name'],
  setup: () => ({ icons }),
  template: `<svg class="size-[1em]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" v-html="icons[name]"></svg>`,
})
app.component('logo', {
  template: `<span class="grid size-9 place-items-center rounded-xl bg-neutral text-lg text-neutral-content"><icon name="key"></icon></span><span class="whitespace-nowrap text-xl font-bold tracking-tight max-[380px]:hidden">ssh-ca</span>`,
})
app.mount('#app')
