import { Outlet, NavLink } from 'react-router-dom'
import {
  MessageSquare,
  LayoutDashboard,
  Server,
  Shield,
  Eye,
  FileCheck,
  SlidersHorizontal,
  Settings,
  Wifi,
  WifiOff,
  Sun,
  Moon,
} from 'lucide-react'
import { useStatus } from '@powersync/react'
import { useState, useEffect } from 'react'

const navItems = [
  { to: '/', icon: MessageSquare, label: 'Chat' },
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview' },
  { to: '/instances', icon: Server, label: 'Instances' },
  { to: '/detections', icon: Eye, label: 'Detections' },
  { to: '/compliance', icon: FileCheck, label: 'Compliance' },
  { to: '/policies', icon: SlidersHorizontal, label: 'Policies' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

function SyncIndicator() {
  const status = useStatus()

  if (status.connected) {
    return (
      <div className="flex items-center gap-2 text-xs text-[var(--success)]">
        <Wifi className="w-3 h-3" />
        <span>Synced</span>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 text-xs text-[var(--warning)]">
      <WifiOff className="w-3 h-3" />
      <span>Offline</span>
    </div>
  )
}

function ThemeToggle() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('theme') || 'dark'
  })

  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light')
    } else {
      document.documentElement.removeAttribute('data-theme')
    }
    localStorage.setItem('theme', theme)
  }, [theme])

  return (
    <button
      onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
      className="p-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
    </button>
  )
}

export function Layout() {
  return (
    <div className="flex h-screen">
      <aside className="w-56 border-r border-[var(--border)] bg-[var(--card)] flex flex-col">
        <div className="px-5 py-4 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[var(--primary)]" />
            <span className="text-sm font-semibold tracking-tight">CloakPipe</span>
          </div>
        </div>

        <nav className="flex-1 px-3 py-3 space-y-0.5">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-1.5 text-[13px] transition-colors ${
                  isActive
                    ? 'bg-[var(--secondary)] text-[var(--foreground)] border-l-2 border-l-[var(--primary)]'
                    : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--secondary)] border-l-2 border-l-transparent'
                }`
              }
            >
              <item.icon className="w-3.5 h-3.5" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="px-5 py-3 border-t border-[var(--border)] flex items-center justify-between">
          <span className="text-[11px] text-[var(--muted-foreground)] font-mono">v0.6.0</span>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <SyncIndicator />
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-auto bg-[var(--background)]">
        <Outlet />
      </main>
    </div>
  )
}
