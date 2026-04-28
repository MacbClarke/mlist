import { useEffect, useMemo, useState } from "react"
import type { FormEvent, ReactNode } from "react"
import {
  AlertCircleIcon,
  ActivityIcon,
  ArrowLeftIcon,
  BanIcon,
  CheckCircleIcon,
  CircleOffIcon,
  CopyIcon,
  DownloadIcon,
  EyeIcon,
  FileIcon,
  FileMusicIcon,
  FilePlayIcon,
  FileTextIcon,
  FolderIcon,
  ImageIcon,
  KeyRoundIcon,
  LockIcon,
  LogOutIcon,
  RefreshCwIcon,
  SettingsIcon,
  ShieldIcon,
  Trash2Icon,
  UserPlusIcon,
} from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { toast } from "sonner"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "@/components/ui/context-menu"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

type EntryKind = "dir" | "file"

type ListEntry = {
  name: string
  path: string
  kind: EntryKind
  size?: number
  mtime?: number
  mime?: string
  requiresAuth: boolean
  authorized: boolean
}

type ListResponse = {
  path: string
  entries: ListEntry[]
  requiresAuth: boolean
  authorized: boolean
}

type UserRole = "admin" | "user"

type UserView = {
  id: number
  username: string
  role: UserRole
  enabled: boolean
  createdAt: number
  updatedAt: number
  lastLoginAt?: number | null
  lastSeenAt?: number | null
  totalBytesServed: number
}

type MeResponse = {
  authenticated: boolean
  user: UserView | null
  expiresAt: string | null
  needsBootstrap: boolean
}

type LoginResponse = {
  ok: boolean
  user: UserView
  expiresAt: string
}

type TotpBinding = {
  user: UserView
  secret: string
  otpauthUrl: string
  qrDataUrl: string
}

type BootstrapStartResponse = {
  username: string
  secret: string
  otpauthUrl: string
  qrDataUrl: string
}

type UsersResponse = {
  users: UserView[]
}

type ResourceAccessEvent = {
  id: number
  userId: number
  username: string
  resourceKind: "directory" | "file"
  path: string
  route: string
  status: number
  bytesServed: number
  fileSize?: number | null
  rangeStart?: number | null
  rangeEnd?: number | null
  createdAt: number
}

type ResourceUsage = {
  userId: number
  username: string
  path: string
  fileSize?: number | null
  accessCount: number
  totalBytesServed: number
  lastAccessAt: number
}

type AuditEventsResponse = {
  events: ResourceAccessEvent[]
  hasMore: boolean
}

type AuditResourcesResponse = {
  resources: ResourceUsage[]
  hasMore: boolean
}

type FileState = {
  path: string
  highlighted: boolean
  updatedAt: number
}

type FileStatesResponse = {
  files: FileState[]
}

type SignedFileLinkResponse = {
  url: string
  expiresAt: string
}

type ApiError = {
  code?: string
  message?: string
}

type LoadPathOptions = {
  updateUrl?: boolean
  replaceUrl?: boolean
  previewPath?: string | null
  allowPathAsFile?: boolean
}

const AUDIT_PAGE_SIZE = 50

function App() {
  const [authLoading, setAuthLoading] = useState(true)
  const [user, setUser] = useState<UserView | null>(null)
  const [needsBootstrap, setNeedsBootstrap] = useState(false)
  const [adminRoute, setAdminRoute] = useState(() => isAdminPath(window.location.pathname))
  const [currentPath, setCurrentPath] = useState("")
  const [entries, setEntries] = useState<ListEntry[]>([])
  const [previewEntry, setPreviewEntry] = useState<ListEntry | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [highlightedFiles, setHighlightedFiles] = useState<Set<string>>(() => new Set())

  const crumbs = useMemo(() => {
    if (!currentPath) return [{ label: "/", path: "" }]
    const parts = currentPath.split("/")
    return [
      { label: "/", path: "" },
      ...parts.map((part, index) => ({
        label: part,
        path: parts.slice(0, index + 1).join("/"),
      })),
    ]
  }, [currentPath])

  useEffect(() => {
    void bootstrapApp()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const handlePopState = () => {
      const nextIsAdmin = isAdminPath(window.location.pathname)
      setAdminRoute(nextIsAdmin)
      setPreviewEntry(null)
      if (!nextIsAdmin && user) {
        const nextPath = pathFromLocation(window.location.pathname)
        void loadPath(nextPath, { updateUrl: false })
      }
    }

    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  async function bootstrapApp() {
    setAuthLoading(true)
    try {
      const me = await fetchMe()
      applyMe(me)
      if (me.authenticated && me.user) {
        if (isAdminPath(window.location.pathname)) {
          setAdminRoute(true)
        } else {
          await loadPath(pathFromLocation(window.location.pathname), { replaceUrl: true })
          await loadHighlightedFilesFromServer()
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "认证状态加载失败")
    } finally {
      setAuthLoading(false)
    }
  }

  function applyMe(me: MeResponse) {
    setUser(me.user)
    setNeedsBootstrap(me.needsBootstrap)
  }

  async function loadPath(path: string, options: LoadPathOptions = {}) {
    const requestPath = normalizePath(path)
    const allowPathAsFile = options.allowPathAsFile !== false
    const requestedPreviewPath =
      options.previewPath === undefined ? undefined : normalizeOptionalPath(options.previewPath)
    setLoading(true)
    setError("")

    try {
      const response = await fetch(`/api/list?path=${encodeURIComponent(requestPath)}`, {
        credentials: "include",
      })

      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as ApiError
        if (response.status === 401 && payload.code === "AUTH_REQUIRED") {
          setUser(null)
          setError("请先登录。")
          return
        }

        const isPathFile =
          allowPathAsFile &&
          response.status === 400 &&
          payload.code === "BAD_REQUEST" &&
          payload.message?.includes("not a directory") &&
          requestPath.length > 0
        if (isPathFile) {
          const parentPath = parentPathOf(requestPath)
          await loadPath(parentPath, {
            updateUrl: options.updateUrl,
            replaceUrl: options.replaceUrl,
            previewPath: requestPath,
            allowPathAsFile: false,
          })
          return
        }

        throw new Error(payload.message ?? `加载目录失败（${response.status}）`)
      }

      const payload = (await response.json()) as ListResponse
      const safeEntries = payload.entries.filter((item) => item.name !== ".private")
      let resolvedPreviewPath: string | null = null
      if (requestedPreviewPath !== undefined) {
        const previewCandidate = requestedPreviewPath
          ? safeEntries.find(
              (item) => item.kind === "file" && normalizePath(item.path) === requestedPreviewPath,
            ) ?? null
          : null
        setPreviewEntry(previewCandidate)
        resolvedPreviewPath = previewCandidate?.path ?? null
      } else {
        setPreviewEntry(null)
      }

      setEntries(safeEntries)
      setCurrentPath(payload.path)
      if (options.updateUrl !== false) {
        syncBrowserState(payload.path, resolvedPreviewPath, options.replaceUrl === true)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "发生未知错误")
      setEntries([])
    } finally {
      setLoading(false)
    }
  }

  async function handleLogin(username: string, code: string) {
    const payload = await apiJson<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, code }),
    })
    setUser(payload.user)
    setNeedsBootstrap(false)
    setAdminRoute(false)
    await loadHighlightedFilesFromServer()
    await loadPath("", { replaceUrl: true })
  }

  async function handleBootstrapFinish(username: string, secret: string, code: string) {
    const payload = await apiJson<LoginResponse>("/api/bootstrap/finish", {
      method: "POST",
      body: JSON.stringify({ username, secret, code }),
    })
    setUser(payload.user)
    setNeedsBootstrap(false)
    setAdminRoute(false)
    await loadHighlightedFilesFromServer()
    await loadPath("", { replaceUrl: true })
  }

  async function logout() {
    await apiJson<{ ok: boolean }>("/api/auth/logout", { method: "POST" })
    setUser(null)
    setEntries([])
    setPreviewEntry(null)
    setCurrentPath("")
    setHighlightedFiles(new Set())
    setAdminRoute(false)
    window.history.replaceState(null, "", "/")
  }

  async function loadHighlightedFilesFromServer() {
    const payload = await apiJson<FileStatesResponse>("/api/file-states")
    setHighlightedFiles(
      new Set(
        payload.files
          .filter((item) => item.highlighted)
          .map((item) => normalizePath(item.path))
          .filter((path) => path.length > 0),
      ),
    )
  }

  function openAdmin() {
    setPreviewEntry(null)
    setAdminRoute(true)
    window.history.pushState(null, "", "/_mlist/admin")
  }

  function closeAdmin() {
    setAdminRoute(false)
    window.history.pushState(null, "", browserPath(currentPath))
    void loadPath(currentPath)
  }

  function goParent() {
    if (!currentPath) return
    const parts = currentPath.split("/")
    parts.pop()
    setPreviewEntry(null)
    void loadPath(parts.join("/"))
  }

  function openEntry(entry: ListEntry) {
    if (entry.kind === "dir") {
      setPreviewEntry(null)
      void loadPath(entry.path)
      return
    }
    void markFileHighlighted(entry.path)
    setPreviewEntry(entry)
    syncBrowserState(currentPath, entry.path, false)
  }

  async function copyDownloadAddress(entry: ListEntry) {
    try {
      const payload = await apiJson<SignedFileLinkResponse>("/api/file-link", {
        method: "POST",
        body: JSON.stringify({ path: entry.path }),
      })
      const url = toAbsoluteUrl(payload.url)
      await navigator.clipboard.writeText(url)
      await markFileHighlighted(entry.path)
      toast.success("7 天播放链接已复制")
    } catch {
      toast.error("复制失败，请检查浏览器剪贴板权限。")
    }
  }

  function downloadFile(entry: ListEntry) {
    void markFileHighlighted(entry.path)
    const anchor = document.createElement("a")
    anchor.href = fileUrl(entry.path)
    anchor.download = entry.name
    anchor.rel = "noreferrer"
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
  }

  function isFileHighlighted(path: string): boolean {
    return highlightedFiles.has(normalizePath(path))
  }

  async function markFileHighlighted(path: string) {
    const normalizedPath = normalizePath(path)
    if (!normalizedPath) return

    await setFileHighlighted(normalizedPath, true)
    setHighlightedFiles((previous) => {
      if (previous.has(normalizedPath)) return previous
      const next = new Set(previous)
      next.add(normalizedPath)
      return next
    })
  }

  async function unmarkFileHighlighted(path: string) {
    const normalizedPath = normalizePath(path)
    if (!normalizedPath) return

    await setFileHighlighted(normalizedPath, false)
    setHighlightedFiles((previous) => {
      if (!previous.has(normalizedPath)) return previous
      const next = new Set(previous)
      next.delete(normalizedPath)
      return next
    })
  }

  async function setFileHighlighted(path: string, highlighted: boolean) {
    await apiJson<FileState>("/api/file-states", {
      method: "POST",
      body: JSON.stringify({ path, highlighted }),
    })
  }

  if (authLoading) {
    return (
      <Shell>
        <p className="text-muted-foreground px-3 py-4 text-sm">正在加载...</p>
      </Shell>
    )
  }

  if (!user && needsBootstrap) {
    return (
      <Shell>
        <BootstrapView onFinish={handleBootstrapFinish} />
      </Shell>
    )
  }

  if (!user) {
    return (
      <Shell>
        <LoginView onLogin={handleLogin} />
      </Shell>
    )
  }

  if (adminRoute) {
    return (
      <Shell>
        <TopBar
          user={user}
          onAdmin={openAdmin}
          onLogout={() => void logout()}
          onBack={closeAdmin}
          adminMode
        />
        <AdminView currentUser={user} onUserChanged={setUser} />
      </Shell>
    )
  }

  if (previewEntry) {
    return (
      <Shell>
        <TopBar
          user={user}
          onAdmin={openAdmin}
          onLogout={() => void logout()}
        />
        <div className="mb-3 flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => {
              setPreviewEntry(null)
              syncBrowserState(currentPath, null, false)
            }}
            aria-label="返回列表"
            title="返回列表"
          >
            <ArrowLeftIcon className="size-4" />
          </Button>

          <div className="min-w-0 flex-1 overflow-x-auto">
            <PathBreadcrumbs
              crumbs={crumbs}
              currentFile={previewEntry.name}
              onNavigate={(path) => {
                setPreviewEntry(null)
                void loadPath(path)
              }}
            />
          </div>

          <Button
            variant="outline"
            size="icon"
            onClick={() => void copyDownloadAddress(previewEntry)}
            aria-label="复制链接"
            title="复制链接"
          >
            <CopyIcon className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={() => downloadFile(previewEntry)}
            aria-label="下载文件"
            title="下载文件"
          >
            <DownloadIcon className="size-4" />
          </Button>
        </div>

        {error ? (
          <Alert variant="destructive" className="mb-3">
            <AlertCircleIcon className="size-4" />
            <AlertTitle>请求失败</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        <Card className="py-1">
          <CardContent className="p-2">{renderPreview(previewEntry, fileUrl(previewEntry.path))}</CardContent>
        </Card>
      </Shell>
    )
  }

  return (
    <Shell>
      <TopBar
        user={user}
        onAdmin={openAdmin}
        onLogout={() => void logout()}
      />
      <div className="mb-3 flex items-center gap-2">
        <Button
          variant="outline"
          size="icon"
          onClick={goParent}
          disabled={!currentPath || loading}
          aria-label="上一级"
          title="上一级"
        >
          <ArrowLeftIcon className="size-4" />
        </Button>

        <div className="min-w-0 flex-1 overflow-x-auto">
          <PathBreadcrumbs
            crumbs={crumbs}
            onNavigate={(path) => {
              setPreviewEntry(null)
              void loadPath(path)
            }}
          />
        </div>

        <Button
          variant="outline"
          size="icon"
          onClick={() => void loadPath(currentPath)}
          disabled={loading}
          aria-label="刷新"
          title="刷新"
        >
          <RefreshCwIcon className={`size-4 ${loading ? "animate-spin" : ""}`} />
        </Button>
      </div>

      {error ? (
        <Alert variant="destructive" className="mb-3">
          <AlertCircleIcon className="size-4" />
          <AlertTitle>请求失败</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <Card className="py-1">
        <CardContent className="p-2">
          {loading ? (
            <p className="text-muted-foreground px-3 py-4 text-sm">正在加载目录内容...</p>
          ) : entries.length === 0 ? (
            <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center text-sm">
              当前目录为空
            </p>
          ) : (
            <ul className="space-y-1.5">
              {entries.map((entry) => {
                const highlighted = entry.kind === "file" && isFileHighlighted(entry.path)
                return (
                  <li key={entry.path}>
                    {entry.kind === "file" ? (
                      <ContextMenu>
                        <ContextMenuTrigger asChild>
                          <div className="w-full">
                            <EntryRow entry={entry} onOpen={openEntry} highlighted={highlighted} />
                          </div>
                        </ContextMenuTrigger>
                        <ContextMenuContent className="w-44">
                          <ContextMenuItem onSelect={() => openEntry(entry)}>
                            <EyeIcon className="mr-2 size-4" />
                            预览
                          </ContextMenuItem>
                          <ContextMenuItem onSelect={() => downloadFile(entry)}>
                            <DownloadIcon className="mr-2 size-4" />
                            下载
                          </ContextMenuItem>
                          <ContextMenuItem onSelect={() => void copyDownloadAddress(entry)}>
                            <CopyIcon className="mr-2 size-4" />
                            复制链接
                          </ContextMenuItem>
                          {highlighted ? (
                            <ContextMenuItem onSelect={() => void unmarkFileHighlighted(entry.path)}>
                              <CircleOffIcon className="mr-2 size-4" />
                              取消高亮
                            </ContextMenuItem>
                          ) : null}
                        </ContextMenuContent>
                      </ContextMenu>
                    ) : (
                      <EntryRow entry={entry} onOpen={openEntry} />
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </Shell>
  )
}

function Shell({ children }: { children: ReactNode }) {
  return <div className="mx-auto w-full max-w-6xl px-4 py-3">{children}</div>
}

function TopBar({
  user,
  adminMode = false,
  onAdmin,
  onLogout,
  onBack,
}: {
  user: UserView
  adminMode?: boolean
  onAdmin: () => void
  onLogout: () => void
  onBack?: () => void
}) {
  return (
    <div className="mb-3 flex items-center gap-2 border-b pb-3">
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium">{user.username}</span>
          {user.role === "admin" ? <Badge>管理员</Badge> : null}
          <Badge variant="outline" title="本用户累计流量">
            <DownloadIcon className="size-3" />
            {formatBytes(user.totalBytesServed, 2)}
          </Badge>
        </div>
      </div>
      {adminMode ? (
        <Button variant="outline" size="icon" onClick={onBack} aria-label="返回文件" title="返回文件">
          <ArrowLeftIcon className="size-4" />
        </Button>
      ) : user.role === "admin" ? (
        <Button variant="outline" size="icon" onClick={onAdmin} aria-label="用户管理" title="用户管理">
          <SettingsIcon className="size-4" />
        </Button>
      ) : null}
      <Button variant="outline" size="icon" onClick={onLogout} aria-label="退出登录" title="退出登录">
        <LogOutIcon className="size-4" />
      </Button>
    </div>
  )
}

function LoginView({ onLogin }: { onLogin: (username: string, code: string) => Promise<void> }) {
  const [username, setUsername] = useState("")
  const [code, setCode] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState("")

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError("")
    try {
      await onLogin(username, code)
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-sm pt-16">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRoundIcon className="size-5" />
            登录
          </CardTitle>
          <CardDescription>使用用户名和 6 位动态码访问文件。</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={(event) => void submit(event)}>
            <div className="space-y-2">
              <Label htmlFor="login-username">用户名</Label>
              <Input
                id="login-username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoFocus
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="login-code">动态码</Label>
              <Input
                id="login-code"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                required
              />
            </div>
            {error ? (
              <Alert variant="destructive">
                <AlertCircleIcon className="size-4" />
                <AlertTitle>登录失败</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? "登录中..." : "登录"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}

function BootstrapView({
  onFinish,
}: {
  onFinish: (username: string, secret: string, code: string) => Promise<void>
}) {
  const [username, setUsername] = useState("")
  const [code, setCode] = useState("")
  const [binding, setBinding] = useState<BootstrapStartResponse | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState("")

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError("")
    try {
      const payload = await apiJson<BootstrapStartResponse>("/api/bootstrap/start", {
        method: "POST",
        body: JSON.stringify({ username }),
      })
      setBinding(payload)
    } catch (err) {
      setError(err instanceof Error ? err.message : "初始化失败")
    } finally {
      setSubmitting(false)
    }
  }

  async function finish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!binding) return
    setSubmitting(true)
    setError("")
    try {
      await onFinish(binding.username, binding.secret, code)
    } catch (err) {
      setError(err instanceof Error ? err.message : "动态码验证失败")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-md pt-10">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldIcon className="size-5" />
            初始化管理员
          </CardTitle>
          <CardDescription>空库首次绑定的账号会成为管理员。</CardDescription>
        </CardHeader>
        <CardContent>
          {!binding ? (
            <form className="space-y-4" onSubmit={(event) => void start(event)}>
              <div className="space-y-2">
                <Label htmlFor="bootstrap-username">管理员用户名</Label>
                <Input
                  id="bootstrap-username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoFocus
                  required
                />
              </div>
              {error ? <FormError title="初始化失败" message={error} /> : null}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "生成中..." : "生成 TOTP"}
              </Button>
            </form>
          ) : (
            <form className="space-y-4" onSubmit={(event) => void finish(event)}>
              <TotpBindingPanel binding={binding} />
              <div className="space-y-2">
                <Label htmlFor="bootstrap-code">动态码</Label>
                <Input
                  id="bootstrap-code"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  required
                />
              </div>
              {error ? <FormError title="验证失败" message={error} /> : null}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "验证中..." : "完成初始化"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function AdminView({
  currentUser,
  onUserChanged,
}: {
  currentUser: UserView
  onUserChanged: (user: UserView) => void
}) {
  const [users, setUsers] = useState<UserView[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [createOpen, setCreateOpen] = useState(false)
  const [binding, setBinding] = useState<TotpBinding | null>(null)
  const [auditUserId, setAuditUserId] = useState("all")

  useEffect(() => {
    void loadUsers()
  }, [])

  async function loadUsers() {
    setLoading(true)
    setError("")
    try {
      const payload = await apiJson<UsersResponse>("/api/admin/users")
      setUsers(payload.users)
    } catch (err) {
      setError(err instanceof Error ? err.message : "用户加载失败")
    } finally {
      setLoading(false)
    }
  }

  async function toggleUser(target: UserView) {
    const action = target.enabled ? "disable" : "enable"
    try {
      const updated = await apiJson<UserView>(`/api/admin/users/${target.id}/${action}`, {
        method: "POST",
      })
      setUsers((previous) => previous.map((item) => (item.id === updated.id ? updated : item)))
      if (updated.id === currentUser.id) onUserChanged(updated)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "操作失败")
    }
  }

  async function resetTotp(target: UserView) {
    try {
      const payload = await apiJson<TotpBinding>(`/api/admin/users/${target.id}/reset-totp`, {
        method: "POST",
      })
      setBinding(payload)
      await loadUsers()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "重置失败")
    }
  }

  async function deleteUser(target: UserView) {
    if (target.id === currentUser.id) {
      toast.error("不能删除当前登录用户。")
      return
    }
    if (!window.confirm(`确定删除用户「${target.username}」？相关会话、审计和文件状态也会删除。`)) {
      return
    }

    try {
      await apiJson<{ ok: boolean }>(`/api/admin/users/${target.id}`, {
        method: "DELETE",
      })
      setUsers((previous) => previous.filter((item) => item.id !== target.id))
      if (auditUserId === String(target.id)) setAuditUserId("all")
      toast.success("用户已删除")
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "删除失败")
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <h1 className="text-lg font-semibold">管理</h1>
          <p className="text-muted-foreground text-sm">用户、资源访问审计和文件流量。</p>
        </div>
      </div>
      {error ? <FormError title="请求失败" message={error} /> : null}
      <Tabs defaultValue="users" className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <TabsList>
            <TabsTrigger value="users">
              <UserPlusIcon className="size-4" />
              用户
            </TabsTrigger>
            <TabsTrigger value="audit">
              <ActivityIcon className="size-4" />
              审计
            </TabsTrigger>
          </TabsList>
          <div className="flex-1" />
          <Button onClick={() => setCreateOpen(true)}>
            <UserPlusIcon className="size-4" />
            新建用户
          </Button>
        </div>
        <TabsContent value="users" className="space-y-3">
          <Card className="py-1">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>用户名</TableHead>
                    <TableHead>角色</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead className="hidden md:table-cell">最后登录</TableHead>
                    <TableHead className="hidden lg:table-cell">最后使用</TableHead>
                    <TableHead className="hidden sm:table-cell">总流量</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground py-6 text-center">
                        正在加载用户...
                      </TableCell>
                    </TableRow>
                  ) : users.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground py-6 text-center">
                        暂无用户
                      </TableCell>
                    </TableRow>
                  ) : (
                    users.map((item) => (
                      <TableRow key={item.id}>
                        <TableCell className="font-medium">{item.username}</TableCell>
                        <TableCell>
                          <Badge variant={item.role === "admin" ? "default" : "secondary"}>
                            {item.role === "admin" ? "管理员" : "用户"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={item.enabled ? "outline" : "destructive"}>
                            {item.enabled ? "启用" : "禁用"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground hidden md:table-cell">
                          {item.lastLoginAt ? formatDate(item.lastLoginAt) : "--"}
                        </TableCell>
                        <TableCell className="text-muted-foreground hidden lg:table-cell">
                          {item.lastSeenAt ? formatDate(item.lastSeenAt) : "--"}
                        </TableCell>
                        <TableCell className="text-muted-foreground hidden sm:table-cell">
                          {formatBytes(item.totalBytesServed)}
                        </TableCell>
                        <TableCell>
                          <div className="flex justify-end gap-1">
                            <Button
                              variant="outline"
                              size="icon-sm"
                              onClick={() => void resetTotp(item)}
                              aria-label="重置 TOTP"
                              title="重置 TOTP"
                            >
                              <KeyRoundIcon className="size-4" />
                            </Button>
                            <Button
                              variant="outline"
                              size="icon-sm"
                              onClick={() => void toggleUser(item)}
                              aria-label={item.enabled ? "禁用用户" : "启用用户"}
                              title={item.enabled ? "禁用用户" : "启用用户"}
                            >
                              {item.enabled ? (
                                <BanIcon className="size-4" />
                              ) : (
                                <CheckCircleIcon className="size-4" />
                              )}
                            </Button>
                            <Button
                              variant="outline"
                              size="icon-sm"
                              onClick={() => void deleteUser(item)}
                              aria-label="删除用户"
                              title="删除用户"
                              disabled={item.id === currentUser.id}
                            >
                              <Trash2Icon className="size-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="audit" className="space-y-3">
          <AuditView users={users} selectedUserId={auditUserId} onUserChange={setAuditUserId} />
        </TabsContent>
      </Tabs>
      <CreateUserDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(payload) => {
          setBinding(payload)
          setCreateOpen(false)
          void loadUsers()
        }}
      />
      <BindingDialog binding={binding} onClose={() => setBinding(null)} />
    </div>
  )
}

function AuditView({
  users,
  selectedUserId,
  onUserChange,
}: {
  users: UserView[]
  selectedUserId: string
  onUserChange: (value: string) => void
}) {
  const [events, setEvents] = useState<ResourceAccessEvent[]>([])
  const [resources, setResources] = useState<ResourceUsage[]>([])
  const [eventsPage, setEventsPage] = useState(0)
  const [resourcesPage, setResourcesPage] = useState(0)
  const [eventsHasMore, setEventsHasMore] = useState(false)
  const [resourcesHasMore, setResourcesHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    setEventsPage(0)
    setResourcesPage(0)
  }, [selectedUserId])

  useEffect(() => {
    void loadAudit()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedUserId, eventsPage, resourcesPage])

  async function loadAudit() {
    setLoading(true)
    setError("")
    try {
      const baseQuery = new URLSearchParams({ limit: String(AUDIT_PAGE_SIZE) })
      if (selectedUserId !== "all") {
        baseQuery.set("userId", selectedUserId)
      }
      const eventsQuery = new URLSearchParams(baseQuery)
      eventsQuery.set("offset", String(eventsPage * AUDIT_PAGE_SIZE))
      const resourcesQuery = new URLSearchParams(baseQuery)
      resourcesQuery.set("offset", String(resourcesPage * AUDIT_PAGE_SIZE))
      const [eventsPayload, resourcesPayload] = await Promise.all([
        apiJson<AuditEventsResponse>(`/api/admin/audit/events?${eventsQuery}`),
        apiJson<AuditResourcesResponse>(`/api/admin/audit/resources?${resourcesQuery}`),
      ])
      setEvents(eventsPayload.events)
      setResources(resourcesPayload.resources)
      setEventsHasMore(eventsPayload.hasMore)
      setResourcesHasMore(resourcesPayload.hasMore)
    } catch (err) {
      setError(err instanceof Error ? err.message : "审计数据加载失败")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={selectedUserId} onValueChange={onUserChange}>
          <SelectTrigger className="w-full sm:w-56">
            <SelectValue placeholder="选择用户" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部用户</SelectItem>
            {users.map((user) => (
              <SelectItem key={user.id} value={String(user.id)}>
                {user.username}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" onClick={() => void loadAudit()} disabled={loading}>
          <RefreshCwIcon className={`size-4 ${loading ? "animate-spin" : ""}`} />
          刷新
        </Button>
      </div>
      {error ? <FormError title="审计加载失败" message={error} /> : null}
      <Card>
        <CardHeader className="gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="flex flex-1 items-center gap-2 text-base">
              <DownloadIcon className="size-4" />
              文件流量
            </CardTitle>
            <AuditPager
              page={resourcesPage}
              hasMore={resourcesHasMore}
              disabled={loading}
              onPageChange={setResourcesPage}
            />
          </div>
          <CardDescription>按服务端实际流式发送的字节数累计。</CardDescription>
        </CardHeader>
        <CardContent>
          {loading && resources.length === 0 ? (
            <p className="text-muted-foreground py-6 text-center text-sm">正在加载文件流量...</p>
          ) : resources.length === 0 ? (
            <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center text-sm">
              暂无文件访问记录
            </p>
          ) : (
            <ul className="space-y-2">
              {resources.map((resource) => (
                <ResourceUsageRow
                  key={`${resource.userId}:${resource.path}`}
                  resource={resource}
                  showUser={selectedUserId === "all"}
                />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
      <Card className="py-1">
        <CardHeader className="gap-3 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="flex-1 text-base">最近访问</CardTitle>
            <AuditPager
              page={eventsPage}
              hasMore={eventsHasMore}
              disabled={loading}
              onPageChange={setEventsPage}
            />
          </div>
          <CardDescription>最近 90 天内成功访问的目录和文件。</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>用户</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>路径</TableHead>
                <TableHead className="hidden md:table-cell">Range</TableHead>
                <TableHead className="text-right">流量</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground py-6 text-center">
                    正在加载访问记录...
                  </TableCell>
                </TableRow>
              ) : events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground py-6 text-center">
                    暂无访问记录
                  </TableCell>
                </TableRow>
              ) : (
                events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      {formatDate(event.createdAt)}
                    </TableCell>
                    <TableCell>{event.username}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {event.resourceKind === "file" ? "文件" : "目录"}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[22rem] truncate font-mono text-xs">
                      {event.path || "/"}
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                      {formatRange(event.rangeStart, event.rangeEnd)}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">
                      {formatBytes(event.bytesServed)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

function ResourceUsageRow({
  resource,
  showUser,
}: {
  resource: ResourceUsage
  showUser: boolean
}) {
  return (
    <li
      className="overflow-hidden rounded-md border px-3 py-2"
      title={`${resource.path} · ${formatBytes(resource.totalBytesServed)}`}
    >
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <span className="min-w-0 flex-1 truncate font-mono text-xs">{resource.path}</span>
        <span className="text-sm font-medium">{formatBytes(resource.totalBytesServed)}</span>
      </div>
      <div className="text-muted-foreground mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
        {showUser ? <span>{resource.username}</span> : null}
        <span>{resource.accessCount} 次访问</span>
        <span>{formatDate(resource.lastAccessAt)}</span>
      </div>
    </li>
  )
}

function AuditPager({
  page,
  hasMore,
  disabled,
  onPageChange,
}: {
  page: number
  hasMore: boolean
  disabled: boolean
  onPageChange: (page: number) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <Button
        variant="outline"
        size="xs"
        onClick={() => onPageChange(Math.max(0, page - 1))}
        disabled={disabled || page === 0}
      >
        上一页
      </Button>
      <span className="text-muted-foreground min-w-12 text-center text-xs">第 {page + 1} 页</span>
      <Button
        variant="outline"
        size="xs"
        onClick={() => onPageChange(page + 1)}
        disabled={disabled || !hasMore}
      >
        下一页
      </Button>
    </div>
  )
}

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (binding: TotpBinding) => void
}) {
  const [username, setUsername] = useState("")
  const [role, setRole] = useState<UserRole>("user")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState("")

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError("")
    try {
      const payload = await apiJson<TotpBinding>("/api/admin/users", {
        method: "POST",
        body: JSON.stringify({ username, role }),
      })
      setUsername("")
      setRole("user")
      onCreated(payload)
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建失败")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>新建用户</DialogTitle>
          <DialogDescription>创建后会显示一次 TOTP 绑定二维码。</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={(event) => void submit(event)}>
          <div className="space-y-2">
            <Label htmlFor="create-username">用户名</Label>
            <Input
              id="create-username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoFocus
              required
            />
          </div>
          <div className="space-y-2">
            <Label>角色</Label>
            <Select value={role} onValueChange={(value) => setRole(value as UserRole)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="user">用户</SelectItem>
                <SelectItem value="admin">管理员</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error ? <FormError title="创建失败" message={error} /> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? "创建中..." : "创建"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function BindingDialog({ binding, onClose }: { binding: TotpBinding | null; onClose: () => void }) {
  return (
    <Dialog open={Boolean(binding)} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>TOTP 绑定</DialogTitle>
          <DialogDescription>该二维码和密钥只在本次操作后展示。</DialogDescription>
        </DialogHeader>
        {binding ? <TotpBindingPanel binding={binding} /> : null}
        <DialogFooter>
          <Button onClick={onClose}>完成</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function TotpBindingPanel({
  binding,
}: {
  binding: { username?: string; secret: string; otpauthUrl: string; qrDataUrl: string; user?: UserView }
}) {
  const label = binding.user?.username ?? binding.username ?? "user"

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(binding.secret)
      toast.success("密钥已复制")
    } catch {
      toast.error("复制失败，请检查浏览器剪贴板权限。")
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-center rounded-md border bg-white p-4">
        <img src={binding.qrDataUrl} alt={`${label} TOTP QR`} className="size-48" />
      </div>
      <div className="space-y-2">
        <Label>密钥</Label>
        <div className="flex gap-2">
          <Input value={binding.secret} readOnly className="font-mono text-xs" />
          <Button type="button" variant="outline" size="icon" onClick={() => void copySecret()}>
            <CopyIcon className="size-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}

function FormError({ title, message }: { title: string; message: string }) {
  return (
    <Alert variant="destructive">
      <AlertCircleIcon className="size-4" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

function PathBreadcrumbs({
  crumbs,
  onNavigate,
  currentFile,
}: {
  crumbs: Array<{ label: string; path: string }>
  onNavigate: (path: string) => void
  currentFile?: string
}) {
  return (
    <Breadcrumb>
      <BreadcrumbList>
        {crumbs.map((crumb, index) => {
          const isLastDirectory = index === crumbs.length - 1
          const showAsPage = isLastDirectory && !currentFile
          const showSeparator = !isLastDirectory || Boolean(currentFile)

          return (
            <div key={crumb.path || "root"} className="inline-flex items-center gap-1.5">
              <BreadcrumbItem>
                {showAsPage ? (
                  <BreadcrumbPage className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-md px-2">
                    {crumb.label}
                  </BreadcrumbPage>
                ) : (
                  <BreadcrumbLink asChild>
                    <button
                      type="button"
                      className="hover:bg-muted inline-flex min-h-8 min-w-8 cursor-pointer items-center justify-center rounded-md px-2 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
                      onClick={() => onNavigate(crumb.path)}
                    >
                      {crumb.label}
                    </button>
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
              {showSeparator ? <BreadcrumbSeparator /> : null}
            </div>
          )
        })}
        {currentFile ? (
          <BreadcrumbItem>
            <BreadcrumbPage className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-md px-2">
              {currentFile}
            </BreadcrumbPage>
          </BreadcrumbItem>
        ) : null}
      </BreadcrumbList>
    </Breadcrumb>
  )
}

function EntryRow({
  entry,
  onOpen,
  highlighted = false,
}: {
  entry: ListEntry
  onOpen: (entry: ListEntry) => void
  highlighted?: boolean
}) {
  return (
    <Button
      variant="ghost"
      className={`h-auto w-full justify-start gap-3 rounded-lg px-3 py-2.5 ${
        highlighted ? "bg-emerald-100/70 hover:bg-emerald-100" : ""
      }`}
      onClick={() => onOpen(entry)}
    >
      {entry.kind === "dir" ? (
        <FolderIcon className="text-muted-foreground size-4" />
      ) : isMarkdownFile(entry) || isPlainTextFile(entry) ? (
        <FileTextIcon className="text-muted-foreground size-4" />
      ) : isImageFile(entry) ? (
        <ImageIcon className="text-muted-foreground size-4" />
      ) : isAudioFile(entry) ? (
        <FileMusicIcon className="text-muted-foreground size-4" />
      ) : isVideoFile(entry) ? (
        <FilePlayIcon className="text-muted-foreground size-4" />
      ) : (
        <FileIcon className="text-muted-foreground size-4" />
      )}
      <span className="min-w-0 flex-1 truncate text-left">{entry.name}</span>
      {entry.requiresAuth && !entry.authorized ? (
        <span className="inline-flex shrink-0" aria-label="私有目录" title="私有目录">
          <LockIcon className="text-muted-foreground size-3.5" aria-hidden />
        </span>
      ) : null}
      <span className="text-muted-foreground hidden text-xs sm:inline">
        {entry.kind === "file" ? formatBytes(entry.size ?? 0) : "--"}
      </span>
      <span className="text-muted-foreground hidden text-xs md:inline">
        {entry.mtime ? formatDate(entry.mtime) : "--"}
      </span>
    </Button>
  )
}

async function fetchMe(): Promise<MeResponse> {
  return apiJson<MeResponse>("/api/me")
}

async function apiJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const response = await fetch(url, {
    ...init,
    headers,
    credentials: "include",
  })

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as ApiError
    throw new Error(payload.message ?? `请求失败（${response.status}）`)
  }

  return (await response.json()) as T
}

function isAdminPath(pathname: string): boolean {
  return normalizePath(pathname) === "_mlist/admin"
}

function fileUrl(path: string): string {
  const normalized = normalizePath(path)
  if (!normalized) return "/d"
  const encodedPath = normalized
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/")
  return `/d/${encodedPath}`
}

function normalizePath(path: string): string {
  return path
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/")
}

function normalizeOptionalPath(path: string | null | undefined): string | null {
  if (path == null) return null
  const normalized = normalizePath(path)
  return normalized || null
}

function parentPathOf(path: string): string {
  const normalized = normalizePath(path)
  if (!normalized) return ""
  const parts = normalized.split("/")
  parts.pop()
  return parts.join("/")
}

function pathFromLocation(pathname: string): string {
  const normalized = normalizePath(pathname)
  if (!normalized) return ""
  return normalized
    .split("/")
    .map((segment) => {
      try {
        return decodeURIComponent(segment)
      } catch {
        return segment
      }
    })
    .join("/")
}

function browserPath(relativePath: string): string {
  if (!relativePath) return "/"
  return `/${relativePath.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`
}

function syncBrowserState(relativePath: string, previewPath: string | null, replace: boolean) {
  if (typeof window === "undefined") return
  const normalizedPreview = normalizeOptionalPath(previewPath)
  const target = browserPath(normalizedPreview ?? relativePath)
  const current = window.location.pathname
  if (current === target) return
  if (replace) {
    window.history.replaceState(null, "", target)
    return
  }
  window.history.pushState(null, "", target)
}

function toAbsoluteUrl(url: string): string {
  if (typeof window === "undefined") return url
  return new URL(url, window.location.origin).toString()
}

function formatBytes(bytes: number, fractionDigits?: number): string {
  if (bytes < 1024) {
    return fractionDigits == null ? `${bytes} B` : `${bytes.toFixed(fractionDigits)} B`
  }
  const units = ["KB", "MB", "GB", "TB"]
  let size = bytes / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(fractionDigits ?? 1)} ${units[unit]}`
}

function formatRange(start: number | null | undefined, end: number | null | undefined): string {
  if (typeof start !== "number" || typeof end !== "number") return "--"
  return `${formatBytes(start)}-${formatBytes(end)}`
}

function formatDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString()
}

function renderPreview(entry: ListEntry, previewUrl: string) {
  const mime = entry.mime ?? ""
  const ext = entry.name.toLowerCase()

  if (isMarkdownFile(entry)) {
    return <MarkdownPreview previewUrl={previewUrl} />
  }

  if (isPlainTextFile(entry)) {
    return <TextPreview previewUrl={previewUrl} />
  }

  if (mime.startsWith("image/")) {
    return (
      <div className="bg-muted/30 flex min-h-[65vh] items-center justify-center overflow-hidden rounded-lg border">
        <img src={previewUrl} alt={entry.name} className="h-full w-full object-contain" />
      </div>
    )
  }

  if (mime.startsWith("audio/")) {
    return (
      <div className="bg-muted/30 flex min-h-[45vh] items-center justify-center rounded-lg border">
        <audio controls src={previewUrl} className="w-full max-w-2xl px-3">
          当前浏览器不支持音频播放。
        </audio>
      </div>
    )
  }

  if (mime.startsWith("video/")) {
    return (
      <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
        <video controls src={previewUrl} className="h-full w-full object-contain">
          当前浏览器不支持视频播放。
        </video>
      </div>
    )
  }

  if (mime === "application/pdf" || ext.endsWith(".pdf")) {
    return (
      <div className="bg-muted/30 min-h-[80vh] overflow-hidden rounded-lg border">
        <iframe src={previewUrl} title={entry.name} className="h-[80vh] w-full border-0" />
      </div>
    )
  }

  return (
    <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
      当前文件类型不支持预览。
    </div>
  )
}

function useRemoteTextContent(previewUrl: string) {
  const [content, setContent] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    async function loadText() {
      setLoading(true)
      setError("")
      try {
        const response = await fetch(previewUrl, {
          credentials: "include",
          signal: controller.signal,
        })
        if (!response.ok) {
          throw new Error(`加载文本失败（${response.status}）`)
        }
        const text = await response.text()
        if (!active) return
        setContent(text)
      } catch (err) {
        if (!active) return
        const abortError = err instanceof DOMException && err.name === "AbortError"
        if (abortError) return
        setError(err instanceof Error ? err.message : "加载文本失败。")
        setContent("")
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    void loadText()
    return () => {
      active = false
      controller.abort()
    }
  }, [previewUrl])

  return { content, loading, error }
}

function MarkdownPreview({ previewUrl }: { previewUrl: string }) {
  const { content, loading, error } = useRemoteTextContent(previewUrl)

  if (loading) {
    return (
      <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
        正在加载 Markdown...
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
        {error}
      </div>
    )
  }

  return (
    <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
      <div className="h-full w-full overflow-auto p-4">
        <article className="text-sm leading-6 [&_a]:text-sky-700 [&_a:hover]:underline [&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-4 [&_code]:rounded [&_code]:bg-muted [&_code]:px-1.5 [&_code]:py-0.5 [&_h1]:mt-6 [&_h1]:text-2xl [&_h1]:font-semibold [&_h2]:mt-5 [&_h2]:text-xl [&_h2]:font-semibold [&_h3]:mt-4 [&_h3]:text-lg [&_h3]:font-semibold [&_hr]:my-4 [&_hr]:border-border [&_li]:my-1 [&_ol]:list-decimal [&_ol]:pl-6 [&_p]:my-3 [&_pre]:my-3 [&_pre]:overflow-x-auto [&_pre]:rounded-md [&_pre]:border [&_pre]:bg-slate-900 [&_pre]:p-3 [&_pre]:text-slate-100 [&_table]:my-4 [&_table]:w-full [&_table]:border-collapse [&_td]:border [&_td]:border-border [&_td]:px-2 [&_td]:py-1 [&_th]:border [&_th]:border-border [&_th]:bg-muted/70 [&_th]:px-2 [&_th]:py-1 [&_th]:text-left [&_ul]:list-disc [&_ul]:pl-6">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
        </article>
      </div>
    </div>
  )
}

function TextPreview({ previewUrl }: { previewUrl: string }) {
  const { content, loading, error } = useRemoteTextContent(previewUrl)

  if (loading) {
    return (
      <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
        正在加载文本...
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
        {error}
      </div>
    )
  }

  return (
    <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
      <pre className="h-full w-full overflow-auto p-4 text-sm leading-6 whitespace-pre-wrap break-words">
        {content}
      </pre>
    </div>
  )
}

function fileExtension(name: string): string {
  const idx = name.lastIndexOf(".")
  if (idx === -1 || idx === name.length - 1) return ""
  return name.slice(idx + 1).toLowerCase()
}

function isMarkdownFile(entry: ListEntry): boolean {
  const mime = (entry.mime ?? "").toLowerCase()
  if (mime === "text/markdown" || mime === "text/x-markdown" || mime.endsWith("+markdown")) {
    return true
  }
  return ["md", "markdown", "mdown", "mkd", "mkdn", "mdx"].includes(fileExtension(entry.name))
}

function isPlainTextFile(entry: ListEntry): boolean {
  const mime = (entry.mime ?? "").toLowerCase()
  if (mime === "text/plain") return true
  return ["txt", "text", "log"].includes(fileExtension(entry.name))
}

function isImageFile(entry: ListEntry): boolean {
  const mime = entry.mime ?? ""
  if (mime.startsWith("image/")) return true
  return ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "avif", "heic", "heif"].includes(
    fileExtension(entry.name),
  )
}

function isAudioFile(entry: ListEntry): boolean {
  const mime = entry.mime ?? ""
  if (mime.startsWith("audio/")) return true
  return ["mp3", "flac", "aac", "m4a", "ogg", "wav", "opus", "wma"].includes(
    fileExtension(entry.name),
  )
}

function isVideoFile(entry: ListEntry): boolean {
  const mime = entry.mime ?? ""
  if (mime.startsWith("video/")) return true
  return ["mp4", "mkv", "mov", "avi", "wmv", "webm", "m4v", "ts", "m2ts"].includes(
    fileExtension(entry.name),
  )
}

export default App
