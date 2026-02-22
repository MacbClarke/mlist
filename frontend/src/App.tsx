import { useEffect, useMemo, useState } from "react"
import type { FormEvent } from "react"
import {
  AlertCircleIcon,
  ArrowLeftIcon,
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
  LockIcon,
  RefreshCwIcon,
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
import { Card, CardContent } from "@/components/ui/card"
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

const HIGHLIGHTED_FILES_STORAGE_KEY = "mlist.highlighted-files.v1"

function App() {
  const [currentPath, setCurrentPath] = useState("")
  const [entries, setEntries] = useState<ListEntry[]>([])
  const [previewEntry, setPreviewEntry] = useState<ListEntry | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [authPath, setAuthPath] = useState<string | null>(null)
  const [authPassword, setAuthPassword] = useState("")
  const [authError, setAuthError] = useState("")
  const [authSubmitting, setAuthSubmitting] = useState(false)
  const [pendingPreviewPath, setPendingPreviewPath] = useState<string | null>(null)
  const [highlightedFiles, setHighlightedFiles] = useState<Set<string>>(() =>
    loadHighlightedFiles(),
  )

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
    const initialPath = pathFromLocation(window.location.pathname)
    void loadPath(initialPath, { replaceUrl: true })
  }, [])

  useEffect(() => {
    const handlePopState = () => {
      const nextPath = pathFromLocation(window.location.pathname)
      setPreviewEntry(null)
      void loadPath(nextPath, { updateUrl: false })
    }

    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
  }, [])

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
          setAuthPath(requestPath)
          setAuthPassword("")
          setAuthError("")
          setPendingPreviewPath(requestedPreviewPath ?? null)
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
      const safeEntries = payload.entries.filter(
        (item) => item.name !== ".private" && item.name !== ".password",
      )
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
      setPendingPreviewPath(null)
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

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!authPath) return

    setAuthSubmitting(true)
    setAuthError("")
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ path: authPath, password: authPassword }),
      })

      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as ApiError
        throw new Error(payload.message ?? "密码校验失败。")
      }

      const targetPath = authPath
      const targetPreviewPath = pendingPreviewPath
      closeAuthDialog()
      await loadPath(targetPath, { previewPath: targetPreviewPath })
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "发生未知错误")
    } finally {
      setAuthSubmitting(false)
    }
  }

  function closeAuthDialog() {
    setAuthPath(null)
    setAuthPassword("")
    setAuthError("")
    setPendingPreviewPath(null)
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
    setPreviewEntry(entry)
    syncBrowserState(currentPath, entry.path, false)
  }

  async function copyDownloadAddress(entry: ListEntry) {
    const url = toAbsoluteUrl(fileUrl(entry.path))
    try {
      await navigator.clipboard.writeText(url)
      markFileHighlighted(entry.path)
      toast.success("链接已复制")
    } catch {
      toast.error("复制失败，请检查浏览器剪贴板权限。")
    }
  }

  function downloadFile(entry: ListEntry) {
    markFileHighlighted(entry.path)
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

  function markFileHighlighted(path: string) {
    const normalizedPath = normalizePath(path)
    if (!normalizedPath) return

    setHighlightedFiles((previous) => {
      if (previous.has(normalizedPath)) return previous
      const next = new Set(previous)
      next.add(normalizedPath)
      saveHighlightedFiles(next)
      return next
    })
  }

  function unmarkFileHighlighted(path: string) {
    const normalizedPath = normalizePath(path)
    if (!normalizedPath) return

    setHighlightedFiles((previous) => {
      if (!previous.has(normalizedPath)) return previous
      const next = new Set(previous)
      next.delete(normalizedPath)
      saveHighlightedFiles(next)
      return next
    })
  }

  if (previewEntry) {
    return (
      <div className="mx-auto w-full max-w-6xl px-4 py-2">
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

        <AuthDialog
          authPath={authPath}
          authPassword={authPassword}
          authError={authError}
          authSubmitting={authSubmitting}
          onPasswordChange={setAuthPassword}
          onClose={closeAuthDialog}
          onSubmit={submitPassword}
        />
      </div>
    )
  }

  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-2">
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
                            <ContextMenuItem onSelect={() => unmarkFileHighlighted(entry.path)}>
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

      <AuthDialog
        authPath={authPath}
        authPassword={authPassword}
        authError={authError}
        authSubmitting={authSubmitting}
        onPasswordChange={setAuthPassword}
        onClose={closeAuthDialog}
        onSubmit={submitPassword}
      />
    </div>
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

function AuthDialog({
  authPath,
  authPassword,
  authError,
  authSubmitting,
  onPasswordChange,
  onClose,
  onSubmit,
}: {
  authPath: string | null
  authPassword: string
  authError: string
  authSubmitting: boolean
  onPasswordChange: (value: string) => void
  onClose: () => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => Promise<void>
}) {
  return (
    <Dialog open={Boolean(authPath)} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent showCloseButton={false} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>私有目录</DialogTitle>
          <DialogDescription>
            <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{authPath || "/"}</code>
            {" 需要密码访问。"}
          </DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={(event) => void onSubmit(event)}>
          <Input
            type="password"
            value={authPassword}
            onChange={(event) => onPasswordChange(event.target.value)}
            placeholder="请输入密码"
            autoFocus
            required
          />
          {authError ? (
            <Alert variant="destructive">
              <AlertCircleIcon className="size-4" />
              <AlertTitle>认证失败</AlertTitle>
              <AlertDescription>{authError}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              取消
            </Button>
            <Button type="submit" disabled={authSubmitting}>
              {authSubmitting ? "验证中..." : "解锁"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
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

function loadHighlightedFiles(): Set<string> {
  if (typeof window === "undefined") return new Set()
  const raw = window.localStorage.getItem(HIGHLIGHTED_FILES_STORAGE_KEY)
  if (!raw) return new Set()

  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return new Set()

    const normalized = parsed
      .map((value) => (typeof value === "string" ? normalizePath(value) : ""))
      .filter((value) => value.length > 0)
    return new Set(normalized)
  } catch {
    return new Set()
  }
}

function saveHighlightedFiles(paths: Set<string>) {
  if (typeof window === "undefined") return
  window.localStorage.setItem(HIGHLIGHTED_FILES_STORAGE_KEY, JSON.stringify(Array.from(paths)))
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

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ["KB", "MB", "GB", "TB"]
  let size = bytes / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(1)} ${units[unit]}`
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
        if (!active) return
        setLoading(false)
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
