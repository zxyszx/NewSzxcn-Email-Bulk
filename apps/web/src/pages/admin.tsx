import * as React from "react"
import DOMPurify from "dompurify"
import Papa from "papaparse"
import { type Editor } from "@tiptap/core"
import { EditorContent, useEditor } from "@tiptap/react"
import StarterKit from "@tiptap/starter-kit"
import LinkExtension from "@tiptap/extension-link"
import ImageExtension from "@tiptap/extension-image"
import Placeholder from "@tiptap/extension-placeholder"
import TextAlign from "@tiptap/extension-text-align"
import { useSearchParams } from "react-router-dom"
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlignCenter, AlignLeft, AlignRight, AlertCircle, Bold, CheckCircle2, ChevronDown, ChevronRight, Circle, ClipboardList, Clock3, Cloud, Copy, Database, Download, Eraser, ExternalLink, Eye, EyeOff, FileUp, Globe2, HardDrive, Image as ImageIcon, Italic, KeyRound, Link, List, ListOrdered, Loader2, Mail, Maximize2, Megaphone, Minimize2, MoreHorizontal, Paperclip, Pause, Pencil, Play, Plus, Redo2, RefreshCcw, RotateCcw, Search, Send, Server, ShieldCheck, Strikethrough, Trash2, Underline, Undo2, UserRound, UsersRound, XCircle } from "lucide-react"
import { api, AdminOverview, AdminUser, Alias, Campaign, CampaignInput, CampaignRecipient, CampaignSuppression, DNSRecord, Domain, Mailbox as MailboxType, MailMessage, MailTemplate, MaildirSyncHealth, PermissionGroup, PermissionInfo, PermissionLimits, SystemSettings } from "@/lib/api"
import { cn, decodeMimeHeader, formatBytes, formatDate } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { useMe } from "@/hooks/use-me"
import { useToast } from "@/hooks/use-toast"
import { hasAnyPermission, hasPermission } from "@/lib/permissions"
import type { BackupTransfer, DeliverabilitySettings, PermissionKey, SMTPRelay, SMTPRelayPayload, TelegramPairing } from "@/lib/api-types"

type Section = "overview" | "users" | "permissionGroups" | "domains" | "mailboxes" | "aliases" | "messages" | "sendAudit" | "backups" | "settings"
type SettingsTab = "base" | "smtp" | "storage" | "mail" | "notifications" | "externalImap" | "templates" | "security"
type PendingConfirm = { title: string; description?: string; confirmText: string; onConfirm: () => void }

const sectionMeta: Record<Section, { label: string; description: string }> = {
  overview: { label: "仪表盘", description: "邮件运行、域名与系统状态集中查看。" },
  users: { label: "账号管理", description: "管理登录账号、身份状态、邮箱数量上限和共享存储容量。" },
  permissionGroups: { label: "权限配置", description: "配置自定义权限、发信频率、附件和邮箱创建额度。" },
  domains: { label: "域名管理", description: "维护邮件域名、DKIM 和 DNS 检测。" },
  mailboxes: { label: "邮箱管理", description: "按归属账号查看和管理子邮箱，默认邮箱受保护。" },
  aliases: { label: "邮件转发", description: "管理域名转发规则。" },
  messages: { label: "全部邮件", description: "按邮箱、文件夹和关键词查看全站邮件。" },
  sendAudit: { label: "发送队列", description: "查看发信投递、重试和失败记录。" },
  backups: { label: "备份与恢复", description: "创建、校验和下载可迁移的加密完整备份。" },
  settings: { label: "系统设置", description: "管理站点、发信、存储、注册、安全和邮件模板。" },
}
const sectionLabels = Object.fromEntries(Object.entries(sectionMeta).map(([key, value]) => [key, value.label])) as Record<Section, string>
const sectionKeys = Object.keys(sectionLabels) as Section[]
const sectionPermissions: Record<Section, PermissionKey[]> = {
  overview: ["admin.overview.view"],
  users: ["admin.users.view"],
  permissionGroups: ["admin.permission_groups.view"],
  domains: ["admin.domains.view", "admin.dns.view"],
  mailboxes: ["admin.mailboxes.view"],
  aliases: ["admin.aliases.view"],
  messages: ["admin.messages.view"],
  sendAudit: ["admin.messages.view"],
  backups: ["admin.settings.view"],
  settings: ["admin.settings.view", "admin.templates.view"],
}
const defaultPermissionLimits: PermissionLimits = { maxAttachmentMb: 25, maxMailboxCount: 9, smtpDailyLimit: 200, smtpMinuteLimit: 20, imapMinuteLimit: 200, pop3MinuteLimit: 150 }
const defaultMailboxLimitOverride = 9
const defaultUserStorageQuotaMb = 100
const defaultAdminStorageQuotaMb = 1024
const superAdminPermissionGroupId = "pg_super_admin"
const regularUserPermissionGroupId = "pg_regular_user"
const defaultStorageQuotaMb = (role: AdminUser["role"]) => role === "admin" ? defaultAdminStorageQuotaMb : defaultUserStorageQuotaMb
const accountPrimaryEmail = (user: Pick<AdminUser, "email" | "loginName">) => user.email || user.loginName || ""
function compareAdminUsers(left: AdminUser, right: AdminUser) {
  if (left.role === "admin" && right.role !== "admin") return -1
  if (left.role !== "admin" && right.role === "admin") return 1
  return accountPrimaryEmail(left).localeCompare(accountPrimaryEmail(right), "en", { sensitivity: "base" }) ||
    left.displayName.localeCompare(right.displayName, "en", { sensitivity: "base" }) ||
    left.createdAt.localeCompare(right.createdAt)
}

export function AdminPage() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const me = useMe()
  const user = me.data?.user
  const canOverview = hasPermission(user, "admin.overview.view")
  const canUsersView = hasPermission(user, "admin.users.view")
  const canPermissionGroupsView = hasPermission(user, "admin.permission_groups.view")
  const canDomainsView = hasPermission(user, "admin.domains.view")
  const canDNSView = hasPermission(user, "admin.dns.view")
  const canMailboxesView = hasPermission(user, "admin.mailboxes.view")
  const canAliasesView = hasPermission(user, "admin.aliases.view")
  const canMessagesView = hasPermission(user, "admin.messages.view")
  const canSettingsView = hasPermission(user, "admin.settings.view")
  const canTemplatesView = hasPermission(user, "admin.templates.view")
  const canLoadDomains = canUsersView || canDomainsView || canDNSView || canMailboxesView || canAliasesView || canSettingsView || canTemplatesView
  const canLoadMailboxes = canMailboxesView || canMessagesView || canSettingsView
  const overview = useQuery({ queryKey: ["admin", "overview"], queryFn: api.adminOverview, enabled: !!user && canOverview })
  const users = useQuery({ queryKey: ["admin", "users"], queryFn: api.users, enabled: !!user && (canUsersView || canMailboxesView) })
  const permissionGroups = useQuery({ queryKey: ["admin", "permission-groups"], queryFn: api.permissionGroups, enabled: !!user && (canPermissionGroupsView || canUsersView) })
  const domains = useQuery({ queryKey: ["admin", "domains"], queryFn: api.domains, enabled: !!user && canLoadDomains })
  const mailboxes = useQuery({ queryKey: ["admin", "mailboxes"], queryFn: api.mailboxes, enabled: !!user && canLoadMailboxes })
  const aliases = useQuery({ queryKey: ["admin", "aliases"], queryFn: api.aliases, enabled: !!user && canAliasesView })
  const settings = useQuery({ queryKey: ["admin", "settings"], queryFn: api.systemSettings, enabled: !!user && canSettingsView })
  const [params, setParams] = useSearchParams()
  const [refreshing, setRefreshing] = React.useState(false)

  const domainItems = domains.data?.items || []
  const mailboxItems = mailboxes.data?.items || []
  const aliasItems = aliases.data?.items || []
  const userItems = users.data?.items || []
  const assignablePermissionGroups = (permissionGroups.data?.items || []).filter((group) => group.id !== superAdminPermissionGroupId && group.id !== regularUserPermissionGroupId)
  const visibleSections = sectionKeys.filter((key) => hasAnyPermission(user, sectionPermissions[key]) && (key !== "backups" || user?.role === "admin"))
  const rawSection = params.get("section") as Section | null
  const section: Section = rawSection && visibleSections.includes(rawSection) ? rawSection : visibleSections[0] || "overview"
  const sectionQueries = section === "overview" ? [overview, ...(canLoadDomains ? [domains] : []), ...(canSettingsView ? [settings] : [])]
    : section === "users" ? [users, permissionGroups, domains]
      : section === "permissionGroups" ? [permissionGroups]
        : section === "domains" ? [domains]
          : section === "mailboxes" ? [mailboxes, users, domains]
            : section === "aliases" ? [aliases, domains]
              : section === "messages" || section === "sendAudit" ? [mailboxes]
                : section === "settings" ? [domains, ...(canLoadMailboxes ? [mailboxes] : []), ...(canSettingsView ? [settings] : [])]
                  : []
  const sectionLoading = sectionQueries.some((query) => query.isPending)
  const sectionError = sectionQueries.find((query) => query.isError)
  const sectionReady = !sectionLoading && !sectionError

  async function refreshAdminPage() {
    if (refreshing) return
    setRefreshing(true)
    try {
      await Promise.all([
        qc.invalidateQueries({ queryKey: ["admin"] }),
        qc.invalidateQueries({ queryKey: ["mailboxes"] }),
        qc.invalidateQueries({ queryKey: ["me"] }),
      ])
      toast({ title: "后台数据已刷新" })
    } catch (error) {
      toast({ title: "刷新失败", description: error instanceof Error ? error.message : "请稍后重试" })
    } finally {
      setRefreshing(false)
    }
  }

  const overviewChecklist = sectionReady && section === "overview" ? setupChecklist(overview.data, domainItems, settings.data).filter((item) => visibleSections.includes(item.section)) : undefined
  const changeSection = (next: Section) => setParams(next === "overview" ? {} : { section: next })

  return (
    <ScrollArea className="h-[calc(100svh-3rem)] md:h-svh">
      <main className="admin-page mx-auto w-full max-w-[1320px] px-3 pb-8 pt-3 sm:px-4 sm:pt-4">
        <AdminPageHeader section={section} refreshing={refreshing} onRefresh={refreshAdminPage} checklist={overviewChecklist} onSectionChange={changeSection} />

        {sectionError && <QueryFailure error={sectionError.error} onRetry={() => { void Promise.all(sectionQueries.map((query) => query.refetch())) }} />}
        {sectionLoading && <AdminSectionLoading overview={section === "overview"} />}

        {sectionReady && section === "overview" && canOverview && (
          <section className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={<UserRound />} tone="primary" label="账号" value={overview.data?.users || 0} detail={`${overview.data?.activeUsers || 0} 个活跃`} />
            <Stat icon={<Globe2 />} tone="cyan" label="邮件域名" value={overview.data?.domains || 0} detail={domainItems.some((domain) => domain.dnsStatus === "ok") ? `${domainItems.filter((domain) => domain.dnsStatus === "ok").length} 个 DNS 正常` : "待检测"} />
            <Stat icon={<Mail />} tone="sky" label="邮箱" value={overview.data?.mailboxes || 0} detail={`${overview.data?.activeMailboxes || 0} 个活跃`} />
            <Stat icon={<Database />} tone="violet" label="存储用量" value={formatBytes(overview.data?.storageBytes || 0)} detail={`${overview.data?.unreadMessages || 0} 封未读 · ${overview.data?.aliases || 0} 个转发`} />
          </section>
        )}

        {sectionReady && section === "overview" && <OverviewSection overview={overview.data} domains={domainItems} domainsAvailable={canLoadDomains} settings={settings.data} settingsAvailable={canSettingsView} visibleSections={visibleSections} onSectionChange={changeSection} />}
        {sectionReady && section === "users" && <UsersSection users={userItems} permissionGroups={assignablePermissionGroups} domains={domainItems} />}
        {sectionReady && section === "permissionGroups" && <PermissionGroupsSection groups={permissionGroups.data?.items || []} catalog={permissionGroups.data?.catalog || []} />}
        {sectionReady && section === "domains" && <DomainsSection domains={domainItems} />}
        {sectionReady && section === "mailboxes" && <MailboxesSection mailboxes={mailboxItems} users={userItems} domains={domainItems} />}
        {sectionReady && section === "aliases" && <AliasesSection aliases={aliasItems} domains={domainItems} />}
        {sectionReady && section === "messages" && <AdminMessagesSection mailboxes={mailboxItems} systemAdmin={user?.role === "admin"} />}
        {sectionReady && section === "sendAudit" && <AdminSendAuditSection mailboxes={mailboxItems} />}
        {sectionReady && section === "backups" && <BackupsSection />}
        {sectionReady && section === "settings" && <SystemSettingsSection settings={settings.data} domains={domainItems} mailboxes={mailboxItems} initialTab={params.get("settingsTab")} />}
      </main>
    </ScrollArea>
  )
}

function AdminSectionLoading({ overview = false }: { overview?: boolean }) {
  return (
    <div className="space-y-3" aria-label="正在加载后台数据" aria-busy="true">
      {overview && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">{Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-[88px] w-full" />)}</div>}
      <Skeleton className={cn("w-full", overview ? "h-[126px]" : "h-[360px]")} />
      {overview && <Skeleton className="h-[152px] w-full" />}
      <span className="sr-only">加载中...</span>
    </div>
  )
}

type SetupChecklistItem = ReturnType<typeof setupChecklist>[number]

function AdminPageHeader({ section, refreshing, onRefresh, checklist, onSectionChange }: { section: Section; refreshing: boolean; onRefresh: () => void; checklist?: SetupChecklistItem[]; onSectionChange: (section: Section) => void }) {
  const meta = sectionMeta[section]
  return (
    <div className="mb-4 border-b border-border/80 pb-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-[20px] font-semibold leading-7 tracking-tight">{meta.label}</h1>
          <p className="mt-1 text-sm leading-5 text-muted-foreground/80">{meta.description}</p>
        </div>
        <div className="flex items-center gap-2">
          {checklist && <SetupChecklistDialog checklist={checklist} onSectionChange={onSectionChange} />}
          <Button type="button" variant="outline" size="sm" className="h-9 gap-2 shadow-none" onClick={onRefresh} disabled={refreshing} aria-label="刷新后台数据" title="刷新后台数据">
            <RefreshCcw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            <span className="hidden sm:inline">刷新</span>
          </Button>
        </div>
      </div>
    </div>
  )
}

function SetupChecklistDialog({ checklist, onSectionChange }: { checklist: SetupChecklistItem[]; onSectionChange: (section: Section) => void }) {
  const [open, setOpen] = React.useState(false)
  const completed = checklist.filter((item) => item.done).length
  const complete = checklist.length > 0 && completed === checklist.length
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm" className="h-9 gap-2 shadow-none">
          {complete ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <Circle className="h-4 w-4 text-amber-600" />}
          <span>{complete ? "初始化完成" : `初始化 ${completed}/${checklist.length}`}</span>
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-xl gap-3 p-5">
        <DialogHeader><DialogTitle>首次配置</DialogTitle></DialogHeader>
        <div className="grid gap-2 sm:grid-cols-2">
          {checklist.map((item) => (
            <Button key={item.key} type="button" variant="outline" className="h-auto min-h-[62px] justify-start gap-3 px-3 py-2 text-left font-normal last:sm:col-span-2" onClick={() => { setOpen(false); onSectionChange(item.section) }}>
              {item.done ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" /> : <Circle className="h-4 w-4 shrink-0 text-muted-foreground" />}
              <span className="min-w-0 flex-1"><span className="block font-medium">{item.title}</span><span className="block truncate text-xs text-muted-foreground">{item.detail}</span></span>
              <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
            </Button>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}

function OverviewSection({ overview, domains, domainsAvailable, settings, settingsAvailable, visibleSections, onSectionChange }: { overview?: AdminOverview; domains: Domain[]; domainsAvailable: boolean; settings?: SystemSettings; settingsAvailable: boolean; visibleSections: Section[]; onSectionChange: (section: Section) => void }) {
  const { toast } = useToast()
  const dnsOK = domains.length > 0 && domains.every((domain) => domain.dnsStatus === "ok")
  const dnsWarning = domains.length > 0 && domains.some((domain) => domain.dnsStatus === "ok")
  return (
    <div className="space-y-3">
      <Card className="border-border/80">
        <CardHeader className="px-4 pb-2 pt-3 sm:px-4"><CardTitle className="text-base">邮件运行概览</CardTitle></CardHeader>
        <CardContent className="px-4 pb-3 sm:px-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <OverviewMetric icon={<Send />} label="今日发送" value={overview?.todaySent || 0} tone="primary" />
            <OverviewMetric icon={<Download />} label="今日接收" value={overview?.todayReceived || 0} tone="success" />
            <OverviewMetric icon={<CheckCircle2 />} label="发送成功" value={overview?.sendDelivered || 0} tone="success" />
            <OverviewMetric icon={<AlertCircle />} label="发送失败" value={overview?.sendFailed || 0} tone={(overview?.sendFailed || 0) > 0 ? "danger" : "muted"} />
            <OverviewMetric icon={<Clock3 />} label="队列邮件" value={overview?.queueMessages || 0} tone={(overview?.queueMessages || 0) > 0 ? "warning" : "muted"} />
            <OverviewMetric icon={<Mail />} label="未读邮件" value={overview?.unreadMessages || 0} tone={(overview?.unreadMessages || 0) > 0 ? "primary" : "muted"} />
          </div>
        </CardContent>
      </Card>

      <Card className="border-border/80">
        <CardHeader className="px-4 pb-2 pt-3"><CardTitle className="text-base">系统状态</CardTitle></CardHeader>
        <CardContent className="grid gap-2.5 px-4 pb-3 md:grid-cols-3">
          <div className="rounded-md border border-border/80 px-3 py-2">
            <DashboardGroupTitle>系统健康</DashboardGroupTitle>
            <div className="grid grid-cols-3 gap-2">
              <DashboardStatusItem label="系统" status={<LightStatus state="success" label="运行中" />} />
              <DashboardStatusItem label="DNS" status={!domainsAvailable ? <LightStatus state="muted" label="不可查看" /> : <LightStatus state={dnsOK ? "success" : dnsWarning ? "warning" : "muted"} label={dnsOK ? "正常" : dnsWarning ? "部分正常" : domains.length ? "未检测" : "未配置"} />} />
              <DashboardStatusItem label="SMTP" status={!settingsAvailable ? <LightStatus state="muted" label="不可查看" /> : <LightStatus state={settings?.smtpHost ? "success" : "warning"} label={settings?.smtpHost ? "已配置" : "未配置"} />} />
            </div>
          </div>
          <div className="rounded-md border border-border/80 px-3 py-2">
            <DashboardGroupTitle>服务信息</DashboardGroupTitle>
            <div className="grid grid-cols-2 gap-3">
              <DashboardInfoItem label="公网地址" value={!settingsAvailable ? "不可查看" : settings?.publicBaseUrl || "-"} onCopy={settings?.publicBaseUrl ? () => copyOverviewValue(settings.publicBaseUrl, "公网地址", toast) : undefined} />
              <DashboardInfoItem label="SMTP" value={!settingsAvailable ? "不可查看" : settings?.smtpHost ? `${settings.smtpHost}:${settings.smtpPort}` : "未配置"} onCopy={settings?.smtpHost ? () => copyOverviewValue(`${settings.smtpHost}:${settings.smtpPort}`, "SMTP 地址", toast) : undefined} />
            </div>
          </div>
          <div className="rounded-md border border-border/80 px-3 py-2">
            <DashboardGroupTitle>功能状态</DashboardGroupTitle>
            <div className="grid grid-cols-2 gap-3">
              <DashboardStatusItem label="注册" status={!settingsAvailable ? <LightStatus state="muted" label="不可查看" /> : <LightStatus state={settings?.openRegistration ? "success" : "muted"} label={settings?.openRegistration ? "已开放" : "关闭"} />} />
              <DashboardStatusItem label="自助申请邮箱" status={!settingsAvailable ? <LightStatus state="muted" label="不可查看" /> : <LightStatus state={settings?.userMailboxApplyEnabled ? "success" : "muted"} label={settings?.userMailboxApplyEnabled ? "已启用" : "关闭"} />} />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-border/80">
        <CardHeader className="flex-row items-center justify-between space-y-0 px-4 pb-2 pt-3"><div className="flex items-baseline gap-2"><CardTitle className="text-base">域名状态</CardTitle><span className="text-xs text-muted-foreground">{domains.length} 个域名</span></div>{visibleSections.includes("domains") && <Button type="button" variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={() => onSectionChange("domains")}>管理域名<ChevronRight className="h-3.5 w-3.5" /></Button>}</CardHeader>
        <CardContent className="px-4 pb-3">
          {!domainsAvailable ? <Empty text="没有权限查看域名详情" /> : domains.length > 0 ? <div className="overflow-hidden rounded-md border border-border/80">
            <div className="hidden grid-cols-[minmax(0,1fr)_120px_140px_150px_24px] items-center gap-3 border-b bg-muted/20 px-3 py-1.5 text-[11px] font-medium text-muted-foreground md:grid"><span>邮件域名</span><span>使用状态</span><span>DNS 状态</span><span>最近检测</span><span /></div>
            <div className="divide-y">{domains.slice(0, 5).map((domain) => {
              const dnsDisplay = dnsStatusDisplay(domain.dnsStatus)
              return <Button key={domain.id} type="button" variant="ghost" className="grid h-auto min-h-12 w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-none px-3 py-2 text-left font-normal transition-colors hover:bg-muted/35 md:grid-cols-[minmax(0,1fr)_120px_140px_150px_24px]" onClick={() => onSectionChange("domains")}>
                <span className="min-w-0 truncate text-sm font-medium">{domain.name}</span>
                <span className="hidden md:block"><LightStatus state={domain.status === "active" ? "success" : "muted"} label={domain.status === "active" ? "已启用" : "已停用"} /></span>
                <span className="justify-self-end md:justify-self-start"><LightStatus state={dnsDisplay.state} label={dnsDisplay.label} /></span>
                <span className="hidden text-xs text-muted-foreground md:block">{domain.dnsCheckedAt ? formatDate(domain.dnsCheckedAt) : "尚未检测"}</span>
                <ChevronRight className="hidden h-4 w-4 text-muted-foreground md:block" />
                <span className="col-span-2 flex items-center gap-2 text-[11px] text-muted-foreground md:hidden"><span>{domain.status === "active" ? "已启用" : "已停用"}</span><span>·</span><span>{domain.dnsCheckedAt ? `检测于 ${formatDate(domain.dnsCheckedAt)}` : "尚未检测"}</span></span>
              </Button>
            })}</div>
            {domains.length > 5 && <Button type="button" variant="ghost" className="h-auto w-full justify-start rounded-none border-t px-3 py-2 text-left text-xs font-normal text-muted-foreground transition-colors hover:bg-muted/35 hover:text-foreground" onClick={() => onSectionChange("domains")}>还有 {domains.length - 5} 个域名，查看全部</Button>}
          </div> : <Empty text="暂无邮件域名" />}
        </CardContent>
      </Card>
    </div>
  )
}

function setupChecklist(overview: AdminOverview | undefined, domains: Domain[], settings?: SystemSettings) {
  const hasDomain = domains.length > 0
  const dnsReady = domains.some((domain) => domain.dnsStatus === "ok")
  const hasMailbox = (overview?.activeMailboxes || 0) > 0
  const hasMail = (overview?.messages || 0) > 0
  return [
    { key: "domain", title: "添加邮件域名", detail: hasDomain ? `${domains.length} 个域名已添加` : "先添加 example.com 这样的邮件域名", done: hasDomain, section: "domains" as Section },
    { key: "dns", title: "完成 DNS 检测", detail: dnsReady ? "至少一个域名 DNS 正常" : "配置 MX、SPF、DKIM、DMARC 后执行检测", done: dnsReady, section: "domains" as Section },
    { key: "mailbox", title: "创建邮箱", detail: hasMailbox ? `${overview?.activeMailboxes || 0} 个活跃邮箱` : "给管理员或普通账号创建第一个邮箱", done: hasMailbox, section: "mailboxes" as Section },
    { key: "smtp", title: "确认发信链路", detail: settings?.smtpHost ? `内置 Postfix：${settings.smtpHost}:${settings.smtpPort}` : "默认使用内置 Postfix", done: true, section: "settings" as Section },
    { key: "mail", title: "完成收发测试", detail: hasMail ? `${overview?.messages || 0} 封邮件已入库` : "发送或接收一封测试邮件", done: hasMail, section: "messages" as Section },
  ]
}

function OverviewMetric({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: number; tone: "primary" | "success" | "warning" | "danger" | "muted" }) {
  return <div className="flex min-h-[50px] items-center gap-2 rounded-md border border-border/80 px-2 py-1"><div className={cn("grid h-7 w-7 shrink-0 place-items-center rounded-full [&>svg]:h-3.5 [&>svg]:w-3.5", tone === "primary" && "bg-primary/5 text-primary", tone === "success" && "bg-emerald-500/10 text-emerald-600", tone === "warning" && "bg-amber-500/10 text-amber-600", tone === "danger" && "bg-destructive/10 text-destructive", tone === "muted" && "bg-muted text-muted-foreground")}>{icon}</div><div className="min-w-0"><div className="truncate text-[10px] leading-3 text-muted-foreground">{label}</div><div className={cn("text-base font-semibold leading-5 tabular-nums", tone === "success" && "text-emerald-700 dark:text-emerald-400", tone === "warning" && "text-amber-700 dark:text-amber-400", tone === "danger" && "text-destructive")}>{value}</div></div></div>
}

function dnsStatusDisplay(status: string): { state: "success" | "warning" | "danger" | "muted"; label: string } {
  if (status === "ok") return { state: "success", label: "DNS 正常" }
  if (status === "error") return { state: "danger", label: "DNS 异常" }
  if (!status || status === "unchecked") return { state: "muted", label: "未检测" }
  return { state: "warning", label: "需检查" }
}

function LightStatus({ state, label }: { state: "success" | "warning" | "danger" | "muted"; label: string }) {
  return <span className={cn("inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full px-1.5 text-xs font-medium", state === "success" && "bg-emerald-500/[0.07] text-emerald-700 dark:text-emerald-400", state === "warning" && "bg-amber-500/[0.07] text-amber-700 dark:text-amber-400", state === "danger" && "bg-destructive/[0.07] text-destructive", state === "muted" && "bg-muted/70 text-muted-foreground")}><span className={cn("h-1.5 w-1.5 rounded-full", state === "success" && "bg-emerald-600", state === "warning" && "bg-amber-500", state === "danger" && "bg-destructive", state === "muted" && "bg-muted-foreground/60")} />{label}</span>
}

function DashboardGroupTitle({ children }: { children: React.ReactNode }) {
  return <div className="mb-1.5 text-[11px] font-medium text-muted-foreground">{children}</div>
}

function DashboardStatusItem({ label, status }: { label: string; status: React.ReactNode }) {
  return <div className="min-w-0"><div className="mb-0.5 truncate text-[10px] text-muted-foreground">{label}</div>{status}</div>
}

function DashboardInfoItem({ label, value, onCopy }: { label: string; value: string; onCopy?: () => void }) {
  return <div className="flex min-w-0 items-end gap-1"><div className="min-w-0 flex-1"><div className="text-[10px] text-muted-foreground">{label}</div><div className="truncate text-xs font-medium" title={value}>{value}</div></div>{onCopy && <Button type="button" variant="ghost" size="icon" className="h-6 w-6 shrink-0" onClick={onCopy} title={`复制${label}`} aria-label={`复制${label}`}><Copy className="h-3 w-3" /></Button>}</div>
}

async function copyOverviewValue(value: string, label: string, toast: ReturnType<typeof useToast>["toast"]) {
  await navigator.clipboard.writeText(value)
  toast({ title: `${label}已复制` })
}

function InfoLine({ label, value }: { label: string; value: React.ReactNode }) {
  return <div className="grid min-h-10 grid-cols-[auto_minmax(0,1fr)] items-center gap-3 rounded-md border px-3 py-2"><span className="whitespace-nowrap">{label}</span><span className="min-w-0 break-all text-right font-medium text-foreground">{value}</span></div>
}

function generateBackupPassword(length = 24) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
  const values = new Uint32Array(length)
  crypto.getRandomValues(values)
  return Array.from(values, (value) => alphabet[value % alphabet.length]).join("")
}

function BackupsSection() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const backups = useQuery({
    queryKey: ["admin", "backups"],
    queryFn: api.backups,
    refetchInterval: (query) => query.state.data?.job?.status === "running" || query.state.data?.transfers?.some((item) => item.status === "running" || item.status === "queued") ? 2000 : false,
  })
  const [createOpen, setCreateOpen] = React.useState(false)
  const [password, setPassword] = React.useState("")
  const [confirmPassword, setConfirmPassword] = React.useState("")
  const [showCreatePassword, setShowCreatePassword] = React.useState(false)
  const [sendAfterCreate, setSendAfterCreate] = React.useState(true)
  const [driveAfterCreate, setDriveAfterCreate] = React.useState(false)
  const [deleteName, setDeleteName] = React.useState("")

  const [scheduleEnabled, setScheduleEnabled] = React.useState(false)
  const [scheduleDays, setScheduleDays] = React.useState("7")
  const [customDays, setCustomDays] = React.useState("14")
  const [schedulePassword, setSchedulePassword] = React.useState("")
  const [scheduleConfirmPassword, setScheduleConfirmPassword] = React.useState("")
  const [showSchedulePassword, setShowSchedulePassword] = React.useState(false)
  const [backupChatId, setBackupChatId] = React.useState("")
  const [telegramMode, setTelegramMode] = React.useState<"system" | "custom">("system")
  const [telegramEnabled, setTelegramEnabled] = React.useState(true)
  const [googleDriveEnabled, setGoogleDriveEnabled] = React.useState(false)
  const [googleClientId, setGoogleClientId] = React.useState("")
  const [googleClientSecret, setGoogleClientSecret] = React.useState("")
  const [googleFolderName, setGoogleFolderName] = React.useState("NewSzxcn Backups")
  const [telegramConfigOpen, setTelegramConfigOpen] = React.useState(false)
  const [backupGroupPairing, setBackupGroupPairing] = React.useState<TelegramPairing | null>(null)
  const [discoveredBackupGroups, setDiscoveredBackupGroups] = React.useState<{ chatId: string; displayName: string }[]>([])
  const [googleConfigOpen, setGoogleConfigOpen] = React.useState(false)
  const [passwordConfigOpen, setPasswordConfigOpen] = React.useState(false)
  React.useEffect(() => {
    if (!backups.data) return
    const days = backups.data.schedule.days || 7
    setScheduleEnabled(backups.data.schedule.enabled)
    setScheduleDays([3, 5, 7, 30].includes(days) ? String(days) : "custom")
    setCustomDays(String(days))
    setBackupChatId(backups.data.schedule.chatId || "")
    setTelegramMode(backups.data.schedule.telegramMode === "custom" ? "custom" : "system")
    setTelegramEnabled(backups.data.schedule.telegramEnabled)
    setGoogleDriveEnabled(backups.data.schedule.googleDriveEnabled)
    setGoogleClientId(backups.data.googleDrive.clientId || "")
    setGoogleFolderName(backups.data.googleDrive.folderName || "NewSzxcn Backups")
    setDriveAfterCreate(backups.data.googleDrive.connected)
    setSendAfterCreate(backups.data.telegramSet)
  }, [backups.data])
  React.useEffect(() => {
    const drive = new URLSearchParams(window.location.search).get("drive")
    if (!drive) return
    toast({ title: drive === "connected" ? "Google 云端硬盘已连接" : "Google 授权未完成" })
    window.history.replaceState({}, "", "/admin?section=backups")
  }, [toast])
  const create = useMutation({
    mutationFn: () => api.createBackup(password, confirmPassword, sendAfterCreate, driveAfterCreate),
    onSuccess: async () => {
      setCreateOpen(false); setPassword(""); setConfirmPassword("")
      await qc.invalidateQueries({ queryKey: ["admin", "backups"] })
      toast({ title: "备份任务已开始", description: "可以留在此页面查看进度。" })
    },
    onError: (error) => toast({ title: "无法创建备份", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const saveSchedule = useMutation({
    mutationFn: () => api.updateBackupSettings({ enabled: scheduleEnabled, days: scheduleDays === "custom" ? Number(customDays) : Number(scheduleDays), password: "", confirmPassword: "", serverIp: "", chatId: backupChatId, telegramMode, telegramEnabled, googleDriveEnabled, googleClientId, googleClientSecret, googleFolderName }),
    onSuccess: async () => { setGoogleClientSecret(""); await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "备份设置已保存" }) },
    onError: (error) => toast({ title: "保存失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const savePassword = useMutation({
    mutationFn: () => api.updateBackupPassword(schedulePassword, scheduleConfirmPassword),
    onSuccess: async () => { setPasswordConfigOpen(false); setSchedulePassword(""); setScheduleConfirmPassword(""); setShowSchedulePassword(false); await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "统一备份密码已保存", description: "以后创建的手动和定时备份都会使用新密码。" }) },
    onError: (error) => toast({ title: "密码保存失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const verify = useMutation({
    mutationFn: api.verifyBackup,
    onSuccess: (result) => toast({ title: result.ok ? "备份校验通过" : "备份校验失败", description: result.ok ? `SHA-256：${result.sha256.slice(0, 16)}...` : "文件可能已损坏，请勿用于恢复。" }),
    onError: (error) => toast({ title: "校验失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const sendTelegram = useMutation({
    mutationFn: api.sendBackupTelegram,
    onSuccess: async () => { await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "已开始发送到 Telegram" }) },
    onError: (error) => toast({ title: "发送失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const testBackupTelegram = useMutation({
    mutationFn: () => api.testBackupTelegram({ mode: telegramMode, chatId: backupChatId }),
    onSuccess: () => toast({ title: "Telegram 测试通知已发送" }),
    onError: (error) => toast({ title: "测试失败", description: error instanceof Error ? error.message : "请检查机器人和 Chat ID" }),
  })
  const createBackupGroupPairing = useMutation({
    mutationFn: () => api.createTelegramPairing(""),
    onSuccess: (pairing) => { setBackupGroupPairing(pairing); setDiscoveredBackupGroups([]); toast({ title: "群组查询码已生成" }) },
    onError: (error) => toast({ title: "无法生成查询码", description: error instanceof Error ? error.message : "请先绑定 Telegram 机器人" }),
  })
  const discoverBackupGroup = useMutation({
    mutationFn: () => api.discoverBackupTelegramGroup(backupGroupPairing?.code || ""),
    onSuccess: ({ items }) => {
      setDiscoveredBackupGroups(items)
      if (items.length === 1) setBackupChatId(items[0].chatId)
      toast({ title: `找到 ${items.length} 个群组`, description: items.length === 1 ? "已自动选中" : "请选择备份群组" })
    },
    onError: (error) => toast({ title: "未找到群组", description: error instanceof Error ? error.message : "请在群组发送查询命令后重试" }),
  })
  const sendDrive = useMutation({
    mutationFn: api.sendBackupGoogleDrive,
    onSuccess: async () => { await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "已开始上传到 Google 云端硬盘" }) },
    onError: (error) => toast({ title: "上传失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const connectDrive = useMutation({
    mutationFn: async () => {
      await api.updateBackupSettings({ enabled: scheduleEnabled, days: scheduleDays === "custom" ? Number(customDays) : Number(scheduleDays), password: "", confirmPassword: "", serverIp: "", chatId: backupChatId, telegramMode, telegramEnabled, googleDriveEnabled: false, googleClientId, googleClientSecret, googleFolderName })
      return api.connectGoogleDrive()
    },
    onSuccess: ({ url }) => { window.location.href = url },
    onError: (error) => toast({ title: "无法连接 Google 云端硬盘", description: error instanceof Error ? error.message : "请检查 OAuth 配置" }),
  })
  const disconnectDrive = useMutation({
    mutationFn: api.disconnectGoogleDrive,
    onSuccess: async () => { setGoogleDriveEnabled(false); await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "已断开 Google 云端硬盘" }) },
  })
  const remove = useMutation({
    mutationFn: api.deleteBackup,
    onSuccess: async () => { setDeleteName(""); await qc.invalidateQueries({ queryKey: ["admin", "backups"] }); toast({ title: "备份已删除" }) },
    onError: (error) => toast({ title: "删除失败", description: error instanceof Error ? error.message : "请稍后重试" }),
  })
  const job = backups.data?.job
  const canCreate = backups.data?.enabled && job?.status !== "running"
  function submitCreate() {
    if (!backups.data?.schedule.passwordSet && password.length < 8) { toast({ title: "密码至少需要 8 个字符" }); return }
    if (!backups.data?.schedule.passwordSet && password !== confirmPassword) { toast({ title: "两次输入的密码不一致" }); return }
    create.mutate()
  }
  function generateCreatePassword() {
    const generated = generateBackupPassword()
    setPassword(generated)
    setConfirmPassword(generated)
    setShowCreatePassword(true)
    toast({ title: "已生成 24 位备份密码", description: "请将密码保存到密码管理器，恢复时必须使用。" })
  }
  function generateSchedulePassword() {
    const generated = generateBackupPassword()
    setSchedulePassword(generated)
    setScheduleConfirmPassword(generated)
    setShowSchedulePassword(true)
    toast({ title: "已生成 24 位备份密码", description: "保存设置前，请先将密码存入密码管理器。" })
  }
  async function copyBackupPassword(value: string) {
    if (!value) return
    await navigator.clipboard.writeText(value)
    toast({ title: "备份密码已复制" })
  }
  function downloadBackupPassword(value: string) {
    if (!value) return
    const createdAt = new Date().toLocaleString("zh-CN", { hour12: false })
    const content = `NewSzxcn Email 备份恢复密码\n\n密码：${value}\n生成时间：${createdAt}\n\n请妥善保管。恢复备份时必须输入此密码，系统无法找回。\n`
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }))
    const link = document.createElement("a")
    link.href = url
    link.download = `newszxcn-backup-password-${new Date().toISOString().slice(0, 10)}.txt`
    link.click()
    URL.revokeObjectURL(url)
    toast({ title: "密码文本已下载", description: "请导入密码管理器，不要与备份文件存放在一起。" })
  }
  function PasswordTools({ value, visible, onVisibleChange, onGenerate }: { value: string; visible: boolean; onVisibleChange: (visible: boolean) => void; onGenerate: () => void }) {
    return <div className="flex items-center gap-0.5">
      <Button type="button" variant="ghost" size="icon" className="h-7 w-7" title="生成 24 位密码" aria-label="生成 24 位密码" onClick={onGenerate}><KeyRound className="h-4 w-4" /></Button>
      <Button type="button" variant="ghost" size="icon" className="h-7 w-7" title={visible ? "隐藏密码" : "查看密码"} aria-label={visible ? "隐藏密码" : "查看密码"} disabled={!value} onClick={() => onVisibleChange(!visible)}>{visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</Button>
      <Button type="button" variant="ghost" size="icon" className="h-7 w-7" title="复制密码" aria-label="复制密码" disabled={!value} onClick={() => copyBackupPassword(value)}><Copy className="h-4 w-4" /></Button>
      <Button type="button" variant="ghost" size="icon" className="h-7 w-7" title="保存密码文件" aria-label="保存密码文件" disabled={!value} onClick={() => downloadBackupPassword(value)}><Download className="h-4 w-4" /></Button>
    </div>
  }
  function submitSchedule() {
    if (scheduleEnabled && !backups.data?.schedule.passwordSet) { setPasswordConfigOpen(true); toast({ title: "请先设置统一备份密码" }); return }
    saveSchedule.mutate()
  }
  function submitPassword() {
    if (schedulePassword.length < 8) { toast({ title: "备份密码至少需要 8 个字符" }); return }
    if (schedulePassword !== scheduleConfirmPassword) { toast({ title: "两次输入的备份密码不一致" }); return }
    savePassword.mutate()
  }
  const transferGroups = Object.values((backups.data?.transfers || []).reduce<Record<string, BackupTransfer[]>>((groups, transfer) => {
    ;(groups[transfer.name] ||= []).push(transfer)
    return groups
  }, {})).sort((left, right) => Date.parse(right[0]?.startedAt || "") - Date.parse(left[0]?.startedAt || ""))
  if (backups.isPending) return <AdminSectionLoading />
  if (backups.isError) return <QueryFailure error={backups.error} onRetry={() => { void backups.refetch() }} compact />
  return (
    <div className="space-y-3">
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1.35fr)_minmax(300px,.65fr)]">
        <Card>
          <CardHeader className="flex-row items-center justify-between gap-3 space-y-0 pb-3">
            <div><CardTitle>完整加密备份</CardTitle><p className="mt-1 text-sm text-muted-foreground">包含账号、邮件、附件、DKIM、证书和部署配置。</p></div>
            <Button type="button" disabled={!canCreate} onClick={() => setCreateOpen(true)}>
              {job?.status === "running" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <HardDrive className="mr-2 h-4 w-4" />}
              {job?.status === "running" ? "生成中" : "创建备份"}
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {!backups.data?.enabled && <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">当前版本缺少完整备份组件。请更新到最新修复版本，更新完成后刷新本页即可创建备份。</div>}
            {job?.status === "failed" && <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{job.error || "备份生成失败"}</div>}
            {job?.status === "success" && <div className="rounded-md border border-green-300 bg-green-50 px-3 py-2 text-sm text-green-800">最近一次备份已完成。</div>}
            {!job && <p className="text-sm text-muted-foreground">手动备份与定时备份共用同一个恢复密码，避免不同备份使用不同密码。</p>}
            {transferGroups.slice(0, 3).map((transfers) => <div key={transfers[0].name} className="space-y-3 rounded-md border px-3 py-3">
              <div className="truncate text-sm font-medium" title={transfers[0].name}>{transfers[0].name}</div>
              {transfers.sort((a, b) => (a.provider === "telegram" ? 0 : 1) - (b.provider === "telegram" ? 0 : 1)).map((transfer) => {
                const percent = transfer.total > 0 ? Math.min(100, Math.round(transfer.uploaded * 100 / transfer.total)) : 0
                const label = transfer.provider === "telegram" ? "Telegram" : "Google 云端硬盘"
                return <div key={transfer.provider} className="space-y-1.5">
                  <div className="flex items-center justify-between gap-3 text-xs"><span>{label}</span><span className={cn("shrink-0", transfer.status === "failed" ? "text-destructive" : "text-muted-foreground")}>{transfer.status === "queued" ? "等待上传" : transfer.status === "running" ? `${percent}% · ${formatBytes(transfer.uploaded)} / ${formatBytes(transfer.total)}` : transfer.status === "success" ? "上传完成" : "上传失败"}</span></div>
                  <div className="h-2 overflow-hidden rounded-full bg-muted"><div className={cn("h-full transition-[width]", transfer.status === "failed" ? "bg-destructive" : transfer.status === "success" ? "bg-green-600" : "bg-primary")} style={{ width: `${transfer.status === "success" ? 100 : percent}%` }} /></div>
                  {transfer.error && <p className="text-xs text-destructive">{transfer.error}</p>}
                </div>
              })}
            </div>)}
            <div className="border-t pt-3">
              <div className="mb-2 flex items-center justify-between"><span className="text-sm font-medium">本地备份</span><span className="text-xs text-muted-foreground">保留最近 10 份</span></div>
              <div className="divide-y rounded-md border">
                {(backups.data?.items || []).slice(0, 4).map((item) => (
                  <div key={item.name} className="flex items-center gap-2 px-3 py-2">
                    <div className="min-w-0 flex-1"><div className="truncate text-sm font-medium" title={item.name}>{item.name}</div><div className="text-xs text-muted-foreground">{formatDate(item.createdAt)} · {formatBytes(item.size)}</div></div>
                    <Button type="button" variant="ghost" size="icon" title="校验备份" disabled={verify.isPending} onClick={() => verify.mutate(item.name)}><ShieldCheck className="h-4 w-4" /></Button>
                    <DropdownMenu><DropdownMenuTrigger asChild><Button type="button" variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger><DropdownMenuContent align="end">
                      <DropdownMenuItem disabled={!backups.data?.telegramSet || item.size > (backups.data?.telegramLimit || 0)} onClick={() => sendTelegram.mutate(item.name)}><Send className="mr-2 h-4 w-4" />发送到 Telegram</DropdownMenuItem>
                      <DropdownMenuItem disabled={!backups.data?.googleDrive.connected} onClick={() => sendDrive.mutate(item.name)}><Cloud className="mr-2 h-4 w-4" />上传到 Google 云端硬盘</DropdownMenuItem>
                      <DropdownMenuItem asChild><a href={`/api/admin/backups/${encodeURIComponent(item.name)}/download`}><Download className="mr-2 h-4 w-4" />下载</a></DropdownMenuItem>
                      <DropdownMenuSeparator /><DropdownMenuItem className="text-destructive" onClick={() => setDeleteName(item.name)}><Trash2 className="mr-2 h-4 w-4" />删除</DropdownMenuItem>
                    </DropdownMenuContent></DropdownMenu>
                  </div>
                ))}
                {!backups.isLoading && (backups.data?.items.length || 0) === 0 && <div className="px-3 py-4 text-center text-sm text-muted-foreground">暂无完整备份</div>}
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3"><CardTitle>新服务器恢复</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p><strong className="text-foreground">1.</strong> 将原始加密备份上传到 <strong className="text-foreground">/root/</strong>，不要解压。</p>
            <p><strong className="text-foreground">2.</strong> 运行官方安装脚本，菜单输入 <strong className="text-foreground">2</strong>。</p>
            <p><strong className="text-foreground">3.</strong> 选择“本地上传”；多份备份会显示 1、2、3。</p>
            <p><strong className="text-foreground">4.</strong> 输入序号和备份密码开始恢复。</p>
            <div className="mt-3 rounded-md bg-muted/60 px-3 py-2 text-xs">恢复完成后可输入 <strong className="text-foreground">ns</strong> 打开管理菜单。运行中的服务器不会在网页内覆盖数据。</div>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-3"><div><CardTitle>定时备份</CardTitle><p className="mt-1 text-sm text-muted-foreground">按周期创建加密备份并保存到选定位置。</p></div><Switch checked={scheduleEnabled} onCheckedChange={setScheduleEnabled} /></CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <div className="space-y-2"><Label>备份周期</Label><div className={cn("grid gap-2", scheduleDays === "custom" && "grid-cols-[minmax(0,1fr)_5.5rem]")}><Select value={scheduleDays} onValueChange={setScheduleDays}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="3">每 3 天</SelectItem><SelectItem value="5">每 5 天</SelectItem><SelectItem value="7">每 7 天</SelectItem><SelectItem value="30">每 30 天</SelectItem><SelectItem value="custom">自定义</SelectItem></SelectContent></Select>{scheduleDays === "custom" && <Input id="backup-custom-days" aria-label="自定义天数" title="自定义天数" type="number" min={1} max={365} value={customDays} onChange={(event) => setCustomDays(event.target.value)} />}</div></div>
            <div className="space-y-2"><div className="flex h-7 items-center justify-between gap-2"><Label htmlFor="backup-server-ip">服务器 IP</Label><Button type="button" variant="ghost" size="icon" className="h-7 w-7" title="重新检测" aria-label="重新检测服务器 IP" disabled={backups.isFetching} onClick={() => backups.refetch()}><RefreshCcw className={cn("h-4 w-4", backups.isFetching && "animate-spin")} /></Button></div><Input id="backup-server-ip" readOnly value={backups.data?.schedule.serverIp || ""} placeholder={backups.isLoading ? "正在自动检测" : "未检测到，请检查邮局主机名 DNS"} /><p className="text-xs text-muted-foreground">根据当前邮局主机名的公网 DNS 自动识别。</p></div>
            <div className="space-y-2"><div className="flex h-7 items-center"><Label>恢复密码</Label></div><div className="flex h-10 items-center gap-3 rounded-md border bg-background px-3"><KeyRound className="h-4 w-4 shrink-0 text-muted-foreground" /><span className="min-w-0 flex-1 truncate font-mono text-sm">{backups.data?.schedule.passwordHint || "尚未设置"}</span><Button type="button" variant="ghost" size="sm" className="shrink-0" onClick={() => setPasswordConfigOpen(true)}>{backups.data?.schedule.passwordSet ? "更换" : "设置"}</Button></div><p className="text-xs text-muted-foreground">手动与定时备份共用。</p></div>
          </div>
          <div className="divide-y rounded-md border">
            <div className="flex items-center gap-3 p-3">
              <Send className="h-4 w-4 shrink-0" />
              <div className="min-w-0 flex-1"><div className="flex items-center gap-2 sm:grid sm:grid-cols-[8.5rem_auto]"><span className="text-sm font-medium">Telegram</span><Badge className="w-fit" variant={backups.data?.telegramSet ? "default" : "secondary"}>{backups.data?.telegramSet ? "已配置" : "未配置"}</Badge></div><p className="truncate text-xs text-muted-foreground">{telegramMode === "custom" ? "使用系统机器人推送到备份群组" : "沿用邮件通知接收方"}</p></div>
              <Button type="button" size="sm" variant="outline" onClick={() => setTelegramConfigOpen(true)}>配置</Button>
              <Switch checked={telegramEnabled} onCheckedChange={setTelegramEnabled} disabled={!backups.data?.telegramSet} />
            </div>
            <div className="flex items-center gap-3 p-3">
              <Cloud className="h-4 w-4 shrink-0" />
              <div className="min-w-0 flex-1"><div className="flex items-center gap-2 sm:grid sm:grid-cols-[8.5rem_auto]"><span className="text-sm font-medium">Google 云端硬盘</span><Badge className="w-fit" variant={backups.data?.googleDrive.connected ? "default" : "secondary"}>{backups.data?.googleDrive.connected ? "已连接" : "未连接"}</Badge></div><p className="truncate text-xs text-muted-foreground">{backups.data?.googleDrive.connected ? `保存到 ${googleFolderName}` : "长期保存加密备份"}</p></div>
              <Button type="button" size="sm" variant="outline" onClick={() => setGoogleConfigOpen(true)}>配置</Button>
              <Switch checked={googleDriveEnabled} onCheckedChange={setGoogleDriveEnabled} disabled={!backups.data?.googleDrive.connected} />
            </div>
          </div>
          <div className="flex justify-end border-t pt-3"><Button type="button" className="shrink-0" disabled={saveSchedule.isPending} onClick={submitSchedule}>{saveSchedule.isPending ? "保存中" : "保存设置"}</Button></div>
        </CardContent>
      </Card>
      <Dialog open={telegramConfigOpen} onOpenChange={setTelegramConfigOpen}>
        <DialogContent className="w-[calc(100vw-2rem)] max-w-md rounded-lg">
          <DialogHeader><DialogTitle>Telegram 备份</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2"><Label>备份接收位置</Label><Select value={telegramMode} onValueChange={(value) => setTelegramMode(value === "custom" ? "custom" : "system")}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="system">沿用邮件通知接收方</SelectItem><SelectItem value="custom">自定义备份群组</SelectItem></SelectContent></Select></div>
            {telegramMode === "system" ? <div className="rounded-md bg-muted/60 px-3 py-2 text-sm text-muted-foreground">使用系统已绑定机器人，备份发送到邮件通知的接收方。</div> : <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="backup-chat-id">备份群组</Label>
                <div className="flex gap-2"><Input id="backup-chat-id" inputMode="numeric" value={backupChatId} onChange={(event) => setBackupChatId(event.target.value)} placeholder="群组 Chat ID" /><Button type="button" variant="outline" className="shrink-0" disabled={createBackupGroupPairing.isPending} onClick={() => createBackupGroupPairing.mutate()}>{createBackupGroupPairing.isPending ? "生成中" : "查询群组"}</Button></div>
                <p className="text-xs text-muted-foreground">请先将系统机器人加入该群组。邮件继续推送到原接收方，备份通知和附件只推送到此群组。</p>
                {backupGroupPairing && <div className="space-y-3 rounded-md border px-3 py-3">
                  <p className="text-sm">在每个候选群组发送下面的命令，然后点击“完成查询”：</p>
                  <div className="flex items-center gap-2"><code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 font-mono text-sm">/newszxcn {backupGroupPairing.code}</code><Button type="button" variant="ghost" size="icon" aria-label="复制群组查询命令" title="复制群组查询命令" onClick={() => navigator.clipboard.writeText(`/newszxcn ${backupGroupPairing.code}`)}><Copy className="h-4 w-4" /></Button></div>
                  <Button type="button" size="sm" disabled={discoverBackupGroup.isPending} onClick={() => discoverBackupGroup.mutate()}>{discoverBackupGroup.isPending ? "查询中" : "完成查询"}</Button>
                  {discoveredBackupGroups.length > 0 && <div className="divide-y rounded-md border">{discoveredBackupGroups.map((group) => <Button key={group.chatId} type="button" variant="ghost" className={cn("h-auto w-full justify-start rounded-none px-3 py-2 text-left", backupChatId === group.chatId && "bg-muted")} onClick={() => { setBackupChatId(group.chatId); setBackupGroupPairing(null); setDiscoveredBackupGroups([]) }}><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{group.displayName}</span><span className="block font-mono text-xs font-normal text-muted-foreground">{group.chatId}</span></span>{backupChatId === group.chatId && <CheckCircle2 className="h-4 w-4 text-primary" />}</Button>)}</div>}
                </div>}
              </div>
            </div>}
          </div>
          <DialogFooter className="gap-2 sm:justify-between">
            <Button asChild type="button" variant="outline"><a href="/admin?section=settings&settingsTab=notifications">管理机器人</a></Button>
            <div className="flex gap-2">
              <Button type="button" variant="outline" disabled={testBackupTelegram.isPending || (telegramMode === "custom" && !backupChatId)} onClick={() => testBackupTelegram.mutate()}>{testBackupTelegram.isPending ? "发送中" : "测试发送"}</Button>
              <Button type="button" onClick={() => setTelegramConfigOpen(false)}>完成</Button>
            </div>
          </DialogFooter>
          <p className="text-xs text-muted-foreground">关闭后请点击页面下方“保存设置”使 Chat ID 生效。</p>
        </DialogContent>
      </Dialog>
      <Dialog open={googleConfigOpen} onOpenChange={setGoogleConfigOpen}>
        <DialogContent className="w-[calc(100vw-2rem)] max-w-lg rounded-lg">
          <DialogHeader><DialogTitle>Google 云端硬盘</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"><div className="font-medium">连接前必须启用 Google Drive API</div><p className="mt-1 text-xs">请在 OAuth 客户端所属的同一个 Google Cloud 项目中启用 API。启用后若仍提示无权限，请先断开连接，再重新授权。</p><Button asChild type="button" variant="link" className="mt-1 h-auto p-0 text-amber-900"><a href="https://console.cloud.google.com/apis/library/drive.googleapis.com" target="_blank" rel="noreferrer">打开 Google Drive API <ExternalLink className="ml-1 h-3.5 w-3.5" /></a></Button></div>
            <div className="space-y-2"><Label htmlFor="google-client-id">OAuth 客户端 ID</Label><Input id="google-client-id" value={googleClientId} onChange={(e) => setGoogleClientId(e.target.value)} /></div>
            <div className="space-y-2"><Label htmlFor="google-client-secret">OAuth 客户端密钥</Label><Input id="google-client-secret" type="password" value={googleClientSecret} onChange={(e) => setGoogleClientSecret(e.target.value)} placeholder={backups.data?.googleDrive.clientSecretSet ? "已安全保存，留空不变" : "请输入客户端密钥"} /></div>
            <div className="space-y-2"><Label htmlFor="google-folder-name">备份文件夹</Label><Input id="google-folder-name" value={googleFolderName} onChange={(e) => setGoogleFolderName(e.target.value)} /></div>
            <div className="space-y-2"><Label htmlFor="google-callback-url">Google Cloud 回调地址</Label><div className="flex gap-2"><Input id="google-callback-url" readOnly className="min-w-0 font-mono text-xs" value={`${window.location.origin}/api/admin/backups/google-drive/callback`} /><Button type="button" variant="outline" size="icon" className="shrink-0" title="复制回调地址" aria-label="复制 Google Cloud 回调地址" onClick={() => { navigator.clipboard.writeText(`${window.location.origin}/api/admin/backups/google-drive/callback`); toast({ title: "回调地址已复制" }) }}><Copy className="h-4 w-4" /></Button></div></div>
          </div>
          <DialogFooter className="gap-2 sm:justify-between">
            {backups.data?.googleDrive.connected ? <Button type="button" variant="outline" className="text-destructive" onClick={() => { disconnectDrive.mutate(); setGoogleConfigOpen(false) }}>断开连接</Button> : <span />}
            <div className="flex gap-2"><Button type="button" variant="outline" onClick={() => setGoogleConfigOpen(false)}>取消</Button><Button type="button" disabled={!googleClientId || (!googleClientSecret && !backups.data?.googleDrive.clientSecretSet) || connectDrive.isPending} onClick={() => connectDrive.mutate()}>{backups.data?.googleDrive.connected ? "重新连接" : "连接 Google"}</Button></div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={passwordConfigOpen} onOpenChange={(open) => { if (!savePassword.isPending) { setPasswordConfigOpen(open); if (!open) { setSchedulePassword(""); setScheduleConfirmPassword(""); setShowSchedulePassword(false) } } }}>
        <DialogContent className="w-[calc(100vw-2rem)] max-w-md rounded-lg">
          <DialogHeader><DialogTitle>{backups.data?.schedule.passwordSet ? "更换统一备份密码" : "设置统一备份密码"}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            {backups.data?.schedule.passwordSet && <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">当前密码：<span className="font-mono">{backups.data.schedule.passwordHint}</span>。更换只影响以后创建的备份，已有备份仍需原密码恢复。</div>}
            <div className="space-y-2"><div className="flex h-7 items-center justify-between gap-2"><Label htmlFor="backup-schedule-password">新备份密码</Label><PasswordTools value={schedulePassword} visible={showSchedulePassword} onVisibleChange={setShowSchedulePassword} onGenerate={generateSchedulePassword} /></div><Input id="backup-schedule-password" type={showSchedulePassword ? "text" : "password"} autoComplete="new-password" value={schedulePassword} onChange={(event) => setSchedulePassword(event.target.value)} placeholder="至少 8 个字符" /></div>
            <div className="space-y-2"><Label htmlFor="backup-schedule-confirm-password">确认新备份密码</Label><Input id="backup-schedule-confirm-password" type={showSchedulePassword ? "text" : "password"} autoComplete="new-password" value={scheduleConfirmPassword} onChange={(event) => setScheduleConfirmPassword(event.target.value)} placeholder="再次输入新备份密码" /></div>
            <p className="text-xs text-muted-foreground">生成密码后可查看、复制或下载密码文本。请存入密码管理器，并与备份文件分开保存。</p>
          </div>
          <DialogFooter><Button type="button" variant="outline" onClick={() => setPasswordConfigOpen(false)} disabled={savePassword.isPending}>取消</Button><Button type="button" onClick={submitPassword} disabled={savePassword.isPending}>{savePassword.isPending ? "保存中" : "保存密码"}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={createOpen} onOpenChange={(open) => { if (!create.isPending) setCreateOpen(open) }}>
        <DialogContent className="w-[calc(100vw-2rem)] max-w-md rounded-lg">
          <DialogHeader><DialogTitle>创建完整备份</DialogTitle></DialogHeader>
          <div className="space-y-4">
            {backups.data?.schedule.passwordSet ? <div className="rounded-md border bg-muted/40 px-3 py-3"><div className="text-sm font-medium">使用已保存的备份密码</div><div className="mt-1 font-mono text-sm text-muted-foreground">{backups.data.schedule.passwordHint || "密码已安全保存"}</div><p className="mt-1 text-xs text-muted-foreground">与定时备份共用同一个恢复密码。</p></div> : <><div className="space-y-2"><div className="flex h-7 items-center justify-between gap-2"><Label htmlFor="backup-password">首次设置备份密码</Label><PasswordTools value={password} visible={showCreatePassword} onVisibleChange={setShowCreatePassword} onGenerate={generateCreatePassword} /></div><Input id="backup-password" type={showCreatePassword ? "text" : "password"} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="自己输入或自动生成" /></div><div className="space-y-2"><Label htmlFor="backup-confirm-password">确认备份密码</Label><Input id="backup-confirm-password" type={showCreatePassword ? "text" : "password"} autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></div></>}
            <div className="flex items-center justify-between gap-4 rounded-md border px-3 py-2"><div><div className="text-sm font-medium">完成后发送到 Telegram</div><div className="text-xs text-muted-foreground">同时发送详细恢复说明和加密附件。</div></div><Switch checked={sendAfterCreate} onCheckedChange={setSendAfterCreate} disabled={!backups.data?.telegramSet} /></div>
            <div className="flex items-center justify-between gap-4 rounded-md border px-3 py-2"><div><div className="text-sm font-medium">上传到 Google 云端硬盘</div><div className="text-xs text-muted-foreground">保存加密备份到已连接的云端文件夹。</div></div><Switch checked={driveAfterCreate} onCheckedChange={setDriveAfterCreate} disabled={!backups.data?.googleDrive.connected} /></div>
            {!backups.data?.schedule.passwordSet && <p className="text-xs text-muted-foreground">首次设置后，手动和定时备份都会使用这个密码。请保存到密码管理器，不要与备份文件放在同一位置。</p>}
          </div>
          <DialogFooter><Button type="button" variant="outline" onClick={() => setCreateOpen(false)} disabled={create.isPending}>取消</Button><Button type="button" onClick={submitCreate} disabled={create.isPending}>{create.isPending ? "启动中" : "开始备份"}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog open={!!deleteName} onOpenChange={(open) => { if (!open) setDeleteName("") }} title="删除这个备份？" description="删除后无法恢复，请确认已经在其他位置保存副本。" confirmText="删除备份" destructive pending={remove.isPending} onConfirm={() => remove.mutate(deleteName)} />
    </div>
  )
}

function UsersSection({ users, permissionGroups, domains }: { users: AdminUser[]; permissionGroups: PermissionGroup[]; domains: Domain[] }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [query, setQuery] = React.useState("")
  const [roleFilter, setRoleFilter] = React.useState("all")
  const [statusFilter, setStatusFilter] = React.useState("all")
  const [pendingConfirm, setPendingConfirm] = React.useState<PendingConfirm | null>(null)
  const canCreate = hasPermission(user, "admin.users.create")
  const canDelete = hasPermission(user, "admin.users.delete")
  const filteredUsers = users
    .filter((user) => {
      const keyword = query.trim().toLowerCase()
      const primaryEmail = accountPrimaryEmail(user)
      const matchesKeyword = !keyword || [primaryEmail, user.email, user.displayName, ...(user.mailboxes || [])].some((value) => value.toLowerCase().includes(keyword))
      const matchesRole = roleFilter === "all" || user.role === roleFilter
      const matchesStatus = statusFilter === "all" || (statusFilter === "active" ? !user.disabled : user.disabled)
      return matchesKeyword && matchesRole && matchesStatus
    })
    .sort(compareAdminUsers)
  const remove = useMutation({ mutationFn: api.deleteUser, onSuccess: () => { setPendingConfirm(null); invalidateAdmin(qc); toast({ title: "账号已删除" }) }, onError: (e) => toast({ title: "删除失败", description: e.message }) })
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>账号管理</CardTitle>
          <div className="flex flex-wrap gap-2">
            {canCreate && <CreateUserDialog permissionGroups={permissionGroups} domains={domains} />}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索账号、邮箱、显示名称" className="pl-9" />
          </div>
          <Select value={roleFilter} onValueChange={setRoleFilter}>
            <SelectTrigger className="lg:w-36"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部角色</SelectItem>
              <SelectItem value="admin">管理员</SelectItem>
              <SelectItem value="user">普通用户</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="lg:w-36"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部状态</SelectItem>
              <SelectItem value="active">正常</SelectItem>
              <SelectItem value="disabled">停用</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-3 md:hidden">
          {filteredUsers.map((user) => (
            <div key={user.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{user.displayName}</div>
                  <div className="truncate text-xs text-muted-foreground">{accountPrimaryEmail(user)}</div>
                </div>
                <UserActions user={user} permissionGroups={permissionGroups} onDelete={canDelete ? () => setPendingConfirm({ title: "删除账号？", description: `将删除 ${accountPrimaryEmail(user)} 及其关联数据。`, confirmText: "删除账号", onConfirm: () => remove.mutate(user.id) }) : undefined} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <RoleBadge user={user} />
                <AccountStatus user={user} />
                <span className="text-xs text-muted-foreground">{new Date(user.createdAt).toLocaleDateString()}</span>
              </div>
              <div className="mt-3"><UserPermissionGroupsCell user={user} /></div>
              <div className="mt-3"><UserMailboxCell user={user} /></div>
            </div>
          ))}
        </div>
        <div className="hidden md:block">
          <Table>
            <TableHeader><TableRow><TableHead>账号</TableHead><TableHead>身份</TableHead><TableHead>权限配置</TableHead><TableHead className="w-[22rem]">邮箱</TableHead><TableHead>状态</TableHead><TableHead>创建</TableHead><TableHead className="w-16"></TableHead></TableRow></TableHeader>
            <TableBody>
              {filteredUsers.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <div className="font-medium">{user.displayName}</div>
                    <div className="text-xs text-muted-foreground">{accountPrimaryEmail(user)}</div>
                  </TableCell>
                  <TableCell><RoleBadge user={user} /></TableCell>
                  <TableCell><UserPermissionGroupsCell user={user} /></TableCell>
                  <TableCell className="w-[22rem] max-w-[22rem]"><UserMailboxCell user={user} /></TableCell>
                  <TableCell><AccountStatus user={user} /></TableCell>
                  <TableCell className="text-muted-foreground">{new Date(user.createdAt).toLocaleDateString()}</TableCell>
                  <TableCell><UserActions user={user} permissionGroups={permissionGroups} onDelete={canDelete ? () => setPendingConfirm({ title: "删除账号？", description: `将删除 ${accountPrimaryEmail(user)} 及其关联数据。`, confirmText: "删除账号", onConfirm: () => remove.mutate(user.id) }) : undefined} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {filteredUsers.length === 0 && <Empty text="没有匹配的账号" />}
      </CardContent>
      <ConfirmDialog open={!!pendingConfirm} title={pendingConfirm?.title || ""} description={pendingConfirm?.description} confirmText={pendingConfirm?.confirmText || "删除"} destructive pending={remove.isPending} onOpenChange={(open) => { if (!open) setPendingConfirm(null) }} onConfirm={() => pendingConfirm?.onConfirm()} />
    </Card>
  )
}

function PermissionGroupsSection({ groups, catalog }: { groups: PermissionGroup[]; catalog: PermissionInfo[] }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [query, setQuery] = React.useState("")
  const [editing, setEditing] = React.useState<PermissionGroup | null>(null)
  const [viewing, setViewing] = React.useState<PermissionGroup | null>(null)
  const [pendingConfirm, setPendingConfirm] = React.useState<PendingConfirm | null>(null)
  const canCreate = hasPermission(user, "admin.permission_groups.create")
  const canUpdate = hasPermission(user, "admin.permission_groups.update")
  const canDelete = hasPermission(user, "admin.permission_groups.delete")
  const remove = useMutation({
    mutationFn: api.deletePermissionGroup,
    onSuccess: () => {
      setPendingConfirm(null)
      invalidateAdmin(qc)
      toast({ title: "权限配置已删除" })
    },
    onError: (e) => toast({ title: "删除失败", description: e.message }),
  })
  const filtered = groups.filter((group) => {
    const keyword = query.trim().toLowerCase()
    if (!keyword) return true
    return [group.name, group.description, ...group.permissions].some((value) => value.toLowerCase().includes(keyword))
  })
  const isEditable = (group: PermissionGroup) => !group.system || group.id === regularUserPermissionGroupId
  const isDeletable = (group: PermissionGroup) => !group.system && group.userCount === 0
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>权限配置</CardTitle>
          <div className="flex flex-wrap gap-2">
            {canCreate && <PermissionGroupDialog catalog={catalog} />}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索权限配置、说明或权限键" className="pl-9" />
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          {filtered.map((group) => (
            <div key={group.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="font-medium">{group.name}</div>
                    <span className="text-xs text-muted-foreground">{group.system ? "系统配置" : "自定义配置"} · {group.userCount} 个账号</span>
                  </div>
                  <div className="mt-1 line-clamp-2 text-sm text-muted-foreground">{group.description || "未填写说明"}</div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button type="button" variant="outline" size="sm" onClick={() => setViewing(group)}>查看全部权限</Button>
                  {((isEditable(group) && canUpdate) || (isDeletable(group) && canDelete)) && <DropdownMenu>
                    <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label={`管理权限配置 ${group.name}`} title="更多操作"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {isEditable(group) && canUpdate && <DropdownMenuItem onSelect={() => setEditing(group)}>{group.id === regularUserPermissionGroupId ? "编辑普通用户权限" : "编辑权限配置"}</DropdownMenuItem>}
                      {isEditable(group) && canUpdate && isDeletable(group) && canDelete && <DropdownMenuSeparator />}
                      {isDeletable(group) && canDelete && <DropdownMenuItem className="text-destructive" onSelect={() => setPendingConfirm({ title: "删除权限配置？", description: `${group.name} 删除后不能再分配给账号。`, confirmText: "删除权限配置", onConfirm: () => remove.mutate(group.id) })}>删除权限配置</DropdownMenuItem>}
                    </DropdownMenuContent>
                  </DropdownMenu>}
                </div>
              </div>
              <PermissionBadges permissions={group.permissions} catalog={catalog} />
              <PermissionLimitBadges limits={group.limits} />
            </div>
          ))}
        </div>
        {filtered.length === 0 && <Empty text="暂无匹配的权限配置" />}
      </CardContent>
      {editing && <PermissionGroupDialog group={editing} catalog={catalog} open={!!editing} onOpenChange={(open) => { if (!open) setEditing(null) }} />}
      {viewing && <PermissionGroupDetailsDialog group={viewing} catalog={catalog} open={!!viewing} onOpenChange={(open) => { if (!open) setViewing(null) }} />}
      <ConfirmDialog open={!!pendingConfirm} title={pendingConfirm?.title || ""} description={pendingConfirm?.description} confirmText={pendingConfirm?.confirmText || "删除"} destructive pending={remove.isPending} onOpenChange={(open) => { if (!open) setPendingConfirm(null) }} onConfirm={() => pendingConfirm?.onConfirm()} />
    </Card>
  )
}

function PermissionGroupDialog({ group, catalog, open, onOpenChange }: { group?: PermissionGroup; catalog: PermissionInfo[]; open?: boolean; onOpenChange?: (open: boolean) => void }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [internalOpen, setInternalOpen] = React.useState(false)
  const dialogOpen = open ?? internalOpen
  const setDialogOpen = onOpenChange ?? setInternalOpen
  const fixedIdentity = group?.id === regularUserPermissionGroupId
  const defaultLimitsQuery = useQuery({ queryKey: ["admin", "permission-limits", "defaults"], queryFn: api.defaultPermissionLimits, enabled: dialogOpen })
  const defaultLimits = defaultLimitsQuery.data || defaultPermissionLimits
  const [permissions, setPermissions] = React.useState<PermissionKey[]>(group?.permissions || [])
  const [limits, setLimits] = React.useState<PermissionLimits>(group?.limits || defaultLimits)
  React.useEffect(() => {
    if (dialogOpen) {
      setPermissions(group?.permissions || [])
      setLimits(group?.limits || defaultLimits)
    }
  }, [defaultLimits, dialogOpen, group])
  const mutation = useMutation({
    mutationFn: (form: FormData) => {
      const payload = {
        name: String(form.get("name") || ""),
        description: String(form.get("description") || ""),
        permissions,
        limits,
      }
      return group ? api.updatePermissionGroup(group.id, payload) : api.createPermissionGroup(payload)
    },
    onSuccess: () => {
      invalidateAdmin(qc)
      setDialogOpen(false)
      toast({ title: group ? "权限配置已更新" : "权限配置已创建" })
    },
    onError: (e) => toast({ title: group ? "更新失败" : "创建失败", description: e.message }),
  })
  const trigger = group ? null : (
    <DialogTrigger asChild>
      <Button size="sm" className="self-start">添加权限配置</Button>
    </DialogTrigger>
  )
  return (
    <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
      {trigger}
      <DialogContent className="max-h-[86vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader><DialogTitle>{fixedIdentity ? "编辑普通用户权限" : group ? "编辑权限配置" : "创建权限配置"}</DialogTitle></DialogHeader>
        <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); mutation.mutate(new FormData(event.currentTarget)) }}>
          <div className="grid gap-4 md:grid-cols-2">
            <Field name="name" label="名称" defaultValue={group?.name || ""} placeholder="例如：客服主管" readOnly={fixedIdentity} />
            <Field name="description" label="说明" defaultValue={group?.description || ""} required={false} readOnly={fixedIdentity} />
          </div>
          <PermissionLimitEditor value={limits} onChange={setLimits} />
          <PermissionPicker catalog={catalog} value={permissions} onChange={setPermissions} />
          <DialogFooter><Button disabled={mutation.isPending}>{mutation.isPending ? "保存中..." : "保存"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function PermissionGroupDetailsDialog({ group, catalog, open, onOpenChange }: { group: PermissionGroup; catalog: PermissionInfo[]; open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[86vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader><DialogTitle>{group.name}的全部权限</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">共 {group.permissions.length} 项权限。{group.id === superAdminPermissionGroupId ? "管理员权限由账号身份决定，不能修改。" : ""}</p>
        <PermissionLimitBadges limits={group.limits} />
        <PermissionPicker catalog={catalog} value={group.permissions} onChange={() => undefined} readOnly />
      </DialogContent>
    </Dialog>
  )
}

function PermissionPicker({ catalog, value, onChange, readOnly = false }: { catalog: PermissionInfo[]; value: PermissionKey[]; onChange: (value: PermissionKey[]) => void; readOnly?: boolean }) {
  const grouped = groupPermissionCatalog(catalog)
  function toggle(permission: PermissionKey, checked: boolean) {
    onChange(checked ? Array.from(new Set([...value, permission])) : value.filter((item) => item !== permission))
  }
  function toggleCategory(items: PermissionInfo[], checked: boolean) {
    const keys = items.map((item) => item.key)
    onChange(checked ? Array.from(new Set([...value, ...keys])) : value.filter((item) => !keys.includes(item)))
  }
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <Label>菜单与操作权限</Label>
        <span className="text-xs tabular-nums text-muted-foreground">已选 {value.length} 项</span>
      </div>
      <div className="space-y-3">
        {grouped.map(({ category, items }) => {
          const allChecked = items.every((item) => value.includes(item.key))
          const selectedCount = items.filter((item) => value.includes(item.key)).length
          return (
            <div key={category} className="rounded-lg border">
              <div className="flex items-center justify-between gap-3 border-b px-3 py-2">
                <label className={cn("flex items-center gap-2 font-medium", readOnly && "cursor-default")}>
                  <Checkbox className={cn(readOnly && "disabled:opacity-100")} disabled={readOnly} checked={allChecked ? true : selectedCount > 0 ? "indeterminate" : false} onCheckedChange={(next) => toggleCategory(items, next === true)} />
                  {category}
                </label>
                <span className="text-xs text-muted-foreground">{selectedCount}/{items.length}</span>
              </div>
              <div className="grid gap-2 p-3 md:grid-cols-2">
                {items.map((item) => (
                  <label key={item.key} className={cn("flex min-h-16 items-start gap-3 rounded-md border px-3 py-2", readOnly && "cursor-default")}>
                    <Checkbox className={cn(readOnly && "disabled:opacity-100")} disabled={readOnly} checked={value.includes(item.key)} onCheckedChange={(next) => toggle(item.key, next === true)} />
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{item.label}</span>
                      <span className="line-clamp-2 text-xs text-muted-foreground">{item.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PermissionLimitEditor({ value, onChange }: { value: PermissionLimits; onChange: (value: PermissionLimits) => void }) {
  function update(key: keyof PermissionLimits, raw: string) {
    const next = Number(raw)
    onChange({ ...value, [key]: Number.isFinite(next) && next > 0 ? Math.floor(next) : 0 })
  }
  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <Label>使用限制</Label>
        <span className="text-xs text-muted-foreground">填 0 表示不限制</span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <div className="space-y-2">
          <Label>邮箱数量上限</Label>
          <Input type="number" min={0} value={value.maxMailboxCount} onChange={(event) => update("maxMailboxCount", event.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>附件上限 MB</Label>
          <Input type="number" min={0} value={value.maxAttachmentMb} onChange={(event) => update("maxAttachmentMb", event.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>SMTP 每日封数</Label>
          <Input type="number" min={0} value={value.smtpDailyLimit} onChange={(event) => update("smtpDailyLimit", event.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>SMTP 每分钟封数</Label>
          <Input type="number" min={0} value={value.smtpMinuteLimit} onChange={(event) => update("smtpMinuteLimit", event.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>IMAP 每分钟命令数</Label>
          <Input type="number" min={0} value={value.imapMinuteLimit} onChange={(event) => update("imapMinuteLimit", event.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>POP3 每分钟命令数</Label>
          <Input type="number" min={0} value={value.pop3MinuteLimit} onChange={(event) => update("pop3MinuteLimit", event.target.value)} />
        </div>
      </div>
    </div>
  )
}

function PermissionBadges({ permissions, catalog }: { permissions: PermissionKey[]; catalog: PermissionInfo[] }) {
  const labelByKey = new Map(catalog.map((item) => [item.key, item.label]))
  if (permissions.length === 0) return <div className="mt-3 text-sm text-muted-foreground">无后台权限</div>
  const visible = permissions.slice(0, 5).map((permission) => labelByKey.get(permission) || permission)
  return <div className="mt-3 line-clamp-2 text-sm leading-6 text-muted-foreground">权限：{visible.join("、")}{permissions.length > visible.length ? ` 等 ${permissions.length} 项` : ""}</div>
}

function PermissionLimitBadges({ limits }: { limits?: PermissionLimits }) {
  const defaultLimitsQuery = useQuery({ queryKey: ["admin", "permission-limits", "defaults"], queryFn: api.defaultPermissionLimits })
  const value = limits || defaultLimitsQuery.data || defaultPermissionLimits
  return <div className="mt-2 text-xs leading-5 text-muted-foreground">限制：邮箱 {limitText(value.maxMailboxCount, "个")} · 附件 {limitText(value.maxAttachmentMb, "MB")} · SMTP {limitText(value.smtpDailyLimit, "封/日")} · IMAP {limitText(value.imapMinuteLimit, "次/分钟")} · POP3 {limitText(value.pop3MinuteLimit, "次/分钟")}</div>
}

function limitText(value: number, unit: string) {
  return value > 0 ? `${value} ${unit}` : "不限"
}

function groupPermissionCatalog(catalog: PermissionInfo[]) {
  const order: string[] = []
  const grouped = new Map<string, PermissionInfo[]>()
  for (const item of catalog) {
    if (!grouped.has(item.category)) {
      grouped.set(item.category, [])
      order.push(item.category)
    }
    grouped.get(item.category)!.push(item)
  }
  return order.map((category) => ({ category, items: grouped.get(category)! }))
}

function DomainsSection({ domains }: { domains: Domain[] }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [pendingConfirm, setPendingConfirm] = React.useState<PendingConfirm | null>(null)
  const canCreate = hasPermission(user, "admin.domains.create")
  const canUpdate = hasPermission(user, "admin.domains.update")
  const canDelete = hasPermission(user, "admin.domains.delete")
  const canViewDNS = hasPermission(user, "admin.dns.view")
  const update = useMutation({ mutationFn: ({ id, status }: { id: string; status: string }) => api.updateDomain(id, { status }), onSuccess: () => { invalidateAdmin(qc); toast({ title: "域名已更新" }) }, onError: (e) => toast({ title: "更新失败", description: e.message }) })
  const remove = useMutation({ mutationFn: api.deleteDomain, onSuccess: () => { setPendingConfirm(null); invalidateAdmin(qc); toast({ title: "域名已删除" }) }, onError: (e) => toast({ title: "删除失败", description: e.message }) })
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>域名管理</CardTitle>
          {canCreate && <CreateDomainDialog />}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {domains.map((domain) => (
          <div key={domain.id} className="flex flex-col gap-3 rounded-lg border p-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="font-medium">{domain.name}</div>
              <div className="text-xs text-muted-foreground">DKIM 选择器：{domain.dkimSelector}</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <StatusText active={domain.status === "active"} activeLabel="启用" inactiveLabel="停用" />
              <LightStatus state={dnsStatusDisplay(domain.dnsStatus).state} label={dnsStatusDisplay(domain.dnsStatus).label} />
              {canViewDNS && <DomainDNSDialog domain={domain} />}
              {canUpdate && <Button variant="outline" size="sm" onClick={() => update.mutate({ id: domain.id, status: domain.status === "active" ? "disabled" : "active" })}>{domain.status === "active" ? "停用" : "启用"}</Button>}
              {canDelete && <Button variant="outline" size="sm" onClick={() => setPendingConfirm({ title: "删除域名？", description: `将删除 ${domain.name}，相关邮箱、转发和邮件也可能受影响。`, confirmText: "删除域名", onConfirm: () => remove.mutate(domain.id) })}><Trash2 className="h-4 w-4" />删除</Button>}
            </div>
          </div>
        ))}
        {domains.length === 0 && <Empty text="暂无域名" />}
      </CardContent>
      <ConfirmDialog open={!!pendingConfirm} title={pendingConfirm?.title || ""} description={pendingConfirm?.description} confirmText={pendingConfirm?.confirmText || "删除"} destructive pending={remove.isPending} onOpenChange={(open) => { if (!open) setPendingConfirm(null) }} onConfirm={() => pendingConfirm?.onConfirm()} />
    </Card>
  )
}

function DomainDNSDialog({ domain }: { domain: Domain }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">DNS</Button>
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100svh-1.5rem)] overflow-y-auto p-4 sm:max-w-[calc(100vw-2rem)] sm:p-5 lg:max-w-5xl">
        <DialogHeader><DialogTitle>{domain.name} DNS</DialogTitle></DialogHeader>
        <DNSPanel domain={domain} embedded />
      </DialogContent>
    </Dialog>
  )
}

function MailboxesSection({ mailboxes, users, domains }: { mailboxes: MailboxType[]; users: AdminUser[]; domains: Domain[] }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [query, setQuery] = React.useState("")
  const [expandedOwners, setExpandedOwners] = React.useState<string[]>([])
  const [pendingConfirm, setPendingConfirm] = React.useState<PendingConfirm | null>(null)
  const canCreate = hasPermission(user, "admin.mailboxes.create")
  const canUpdate = hasPermission(user, "admin.mailboxes.update")
  const canDelete = hasPermission(user, "admin.mailboxes.delete")
  const update = useMutation({
    mutationFn: ({ mailbox, status }: { mailbox: MailboxType; status: "active" | "disabled" }) => api.updateMailbox(mailbox.id, { userId: mailbox.userId, displayName: mailbox.displayName || mailbox.address, quotaMb: mailbox.quotaMb, status }),
    onSuccess: (mailbox) => { invalidateAdmin(qc); toast({ title: mailbox.status === "active" ? "邮箱已启用" : "邮箱已停用" }) },
    onError: (e) => toast({ title: "状态更新失败", description: e.message }),
  })
  const remove = useMutation({ mutationFn: api.deleteMailbox, onSuccess: () => { setPendingConfirm(null); invalidateAdmin(qc); toast({ title: "邮箱已删除" }) }, onError: (e) => toast({ title: "删除失败", description: e.message }) })
  const keyword = query.trim().toLowerCase()
  const knownOwnerIDs = new Set(users.map((item) => item.id))
  const compareMailboxes = (left: MailboxType, right: MailboxType) => {
    if (left.primary !== right.primary) return left.primary ? -1 : 1
    return left.address.localeCompare(right.address, "en", { sensitivity: "base" })
  }
  const orphanMailboxes = new Map<string, MailboxType[]>()
  for (const mailbox of mailboxes.filter((item) => !knownOwnerIDs.has(item.userId))) {
    orphanMailboxes.set(mailbox.userId, [...(orphanMailboxes.get(mailbox.userId) || []), mailbox])
  }
  const mailboxGroups: Array<{ owner?: AdminUser; mailboxes: MailboxType[] }> = [
    ...users.slice().sort(compareAdminUsers).map((owner) => ({ owner, mailboxes: mailboxes.filter((mailbox) => mailbox.userId === owner.id).sort(compareMailboxes) })),
    ...Array.from(orphanMailboxes.values()).map((items) => ({ owner: undefined, mailboxes: items.sort(compareMailboxes) })),
  ]
    .filter((group) => group.mailboxes.length > 0)
    .filter((group) => !keyword || [group.owner ? accountPrimaryEmail(group.owner) : "", group.owner?.displayName || "", ...group.mailboxes.map((mailbox) => mailbox.address)].some((value) => value.toLowerCase().includes(keyword)))
  const toggleOwner = (ownerID: string) => setExpandedOwners((current) => current.includes(ownerID) ? current.filter((id) => id !== ownerID) : [...current, ownerID])
  return (
    <Card className="min-w-0">
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>邮箱管理</CardTitle>
          <div className="flex items-center gap-2">
            <span className="text-sm tabular-nums text-muted-foreground">{mailboxes.length} 个邮箱</span>
            {canCreate && <CreateMailboxDialog domains={domains} users={users} />}
          </div>
        </div>
      </CardHeader>
      <CardContent className="min-w-0 space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索账号或邮箱" className="pl-9" />
        </div>
        <div className="divide-y overflow-hidden rounded-md border">
          <div className="hidden grid-cols-[1rem_minmax(0,1fr)_9rem_8rem] gap-3 bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground sm:grid">
            <span aria-hidden="true" />
            <span>归属账号</span>
            <span className="text-center">权限管理</span>
            <span className="text-center">子邮箱</span>
          </div>
          {mailboxGroups.map((group) => {
            const ownerID = group.owner?.id || group.mailboxes[0].userId
            const expanded = expandedOwners.includes(ownerID) || !!keyword
            return (
              <div key={ownerID}>
                <Button type="button" variant="ghost" className="grid h-auto min-h-16 w-full grid-cols-[auto_minmax(0,1fr)_auto] gap-3 rounded-none px-4 py-3 text-left font-normal sm:grid-cols-[auto_minmax(0,1fr)_9rem_8rem]" onClick={() => toggleOwner(ownerID)} aria-expanded={expanded}>
                  <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", !expanded && "-rotate-90")} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{group.owner ? accountPrimaryEmail(group.owner) : group.mailboxes[0].userEmail || "未知账号"}</div>
                    <div className="truncate text-xs text-muted-foreground">{group.owner?.displayName || "账号信息不可用"}</div>
                  </div>
                  <span className="hidden items-center justify-center sm:flex">{group.owner ? <RoleBadge user={group.owner} /> : "-"}</span>
                  <span className="flex items-center justify-center gap-2 text-sm tabular-nums text-muted-foreground"><span>{group.mailboxes.length} 个</span><span className="hidden text-xs lg:inline">查看邮箱</span></span>
                </Button>
                {expanded && (
                  <div className="border-t bg-muted/20 px-4 py-2 sm:pl-11">
                    {group.mailboxes.map((mailbox) => (
                      <div key={mailbox.id} className="flex min-h-14 items-center gap-3 border-b py-2 last:border-b-0">
                        <Mail className="hidden h-4 w-4 shrink-0 text-muted-foreground sm:block" />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium">{mailbox.address}</div>
                          <div className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                            <span className="truncate">{mailbox.displayName || "未命名"}</span>
                            {mailbox.primary && <span className="shrink-0">默认邮箱</span>}
                          </div>
                        </div>
                        <span className={cn("w-10 shrink-0 text-right text-xs font-medium", mailbox.status === "active" ? "text-emerald-600 dark:text-emerald-400" : "text-destructive")}>{mailbox.status === "active" ? "启用" : "停用"}</span>
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center">
                          {!mailbox.primary && (canUpdate || canDelete) && (
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild><Button type="button" variant="ghost" size="icon" className="h-8 w-8" aria-label={`管理邮箱 ${mailbox.address}`} title="更多操作"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {canUpdate && <DropdownMenuItem disabled={mailbox.status === "active" || update.isPending} onSelect={() => update.mutate({ mailbox, status: "active" })}>启用</DropdownMenuItem>}
                                {canUpdate && <DropdownMenuItem disabled={mailbox.status === "disabled" || update.isPending} onSelect={() => update.mutate({ mailbox, status: "disabled" })}>停用</DropdownMenuItem>}
                                {canUpdate && canDelete && !mailbox.primary && <DropdownMenuSeparator />}
                                {canDelete && !mailbox.primary && <DropdownMenuItem className="text-destructive" onSelect={() => setPendingConfirm({ title: "删除邮箱？", description: `将删除 ${mailbox.address} 和其中邮件。此操作无法撤销。`, confirmText: "确认删除", onConfirm: () => remove.mutate(mailbox.id) })}>删除邮箱</DropdownMenuItem>}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
        {mailboxGroups.length === 0 && <Empty text={query ? "没有匹配的账号或邮箱" : "暂无邮箱"} />}
      </CardContent>
      <ConfirmDialog open={!!pendingConfirm} title={pendingConfirm?.title || ""} description={pendingConfirm?.description} confirmText={pendingConfirm?.confirmText || "删除"} destructive pending={remove.isPending} onOpenChange={(open) => { if (!open) setPendingConfirm(null) }} onConfirm={() => pendingConfirm?.onConfirm()} />
    </Card>
  )
}

function AliasesSection({ aliases, domains }: { aliases: Alias[]; domains: Domain[] }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [pendingConfirm, setPendingConfirm] = React.useState<PendingConfirm | null>(null)
  const canCreate = hasPermission(user, "admin.aliases.create")
  const canUpdate = hasPermission(user, "admin.aliases.update")
  const canDelete = hasPermission(user, "admin.aliases.delete")
  const update = useMutation({ mutationFn: ({ id, payload }: { id: string; payload: { source: string; destination: string; enabled: boolean } }) => api.updateAlias(id, payload), onSuccess: () => { invalidateAdmin(qc); toast({ title: "转发已更新" }) }, onError: (e) => toast({ title: "更新失败", description: e.message }) })
  const remove = useMutation({ mutationFn: api.deleteAlias, onSuccess: () => { setPendingConfirm(null); invalidateAdmin(qc); toast({ title: "转发已删除" }) }, onError: (e) => toast({ title: "删除失败", description: e.message }) })
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>邮件转发</CardTitle>
          {canCreate && <CreateAliasDialog domains={domains} />}
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 md:hidden">
          {aliases.map((alias) => (
            <div key={alias.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{alias.source}</div>
                  <div className="truncate text-xs text-muted-foreground">{alias.destination}</div>
                </div>
                <AliasActions alias={alias} onToggle={canUpdate ? () => update.mutate({ id: alias.id, payload: { source: alias.source, destination: alias.destination, enabled: !alias.enabled } }) : undefined} onDelete={canDelete ? () => setPendingConfirm({ title: "删除转发？", description: `${alias.source} 将不再转发到 ${alias.destination}。`, confirmText: "删除转发", onConfirm: () => remove.mutate(alias.id) }) : undefined} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <StatusText active={alias.enabled} activeLabel="启用" inactiveLabel="停用" />
                <Badge variant="outline">{domains.find((d) => d.id === alias.domainId)?.name || alias.domainId}</Badge>
              </div>
            </div>
          ))}
        </div>
        <div className="hidden md:block">
          <Table>
            <TableHeader><TableRow><TableHead>来源</TableHead><TableHead>目标</TableHead><TableHead>域名</TableHead><TableHead>状态</TableHead><TableHead className="w-16"></TableHead></TableRow></TableHeader>
            <TableBody>
              {aliases.map((alias) => (
                <TableRow key={alias.id}>
                  <TableCell className="font-medium">{alias.source}</TableCell>
                  <TableCell>{alias.destination}</TableCell>
                  <TableCell className="text-muted-foreground">{domains.find((d) => d.id === alias.domainId)?.name || alias.domainId}</TableCell>
                  <TableCell><StatusText active={alias.enabled} activeLabel="启用" inactiveLabel="停用" /></TableCell>
                  <TableCell><AliasActions alias={alias} onToggle={canUpdate ? () => update.mutate({ id: alias.id, payload: { source: alias.source, destination: alias.destination, enabled: !alias.enabled } }) : undefined} onDelete={canDelete ? () => setPendingConfirm({ title: "删除转发？", description: `${alias.source} 将不再转发到 ${alias.destination}。`, confirmText: "删除转发", onConfirm: () => remove.mutate(alias.id) }) : undefined} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {aliases.length === 0 && <Empty text="暂无邮件转发" />}
      </CardContent>
      <ConfirmDialog open={!!pendingConfirm} title={pendingConfirm?.title || ""} description={pendingConfirm?.description} confirmText={pendingConfirm?.confirmText || "删除"} destructive pending={remove.isPending} onOpenChange={(open) => { if (!open) setPendingConfirm(null) }} onConfirm={() => pendingConfirm?.onConfirm()} />
    </Card>
  )
}

function AdminMessagesSection({ mailboxes, systemAdmin }: { mailboxes: MailboxType[]; systemAdmin: boolean }) {
  const [query, setQuery] = React.useState("")
  const [mailboxId, setMailboxId] = React.useState("all")
  const [folder, setFolder] = React.useState("all")
  const [selectedId, setSelectedId] = React.useState<string | null>(null)
  const messages = useInfiniteQuery({
    queryKey: ["admin", "messages", mailboxId, folder, query],
    queryFn: ({ pageParam }) => api.adminMessages({
      mailboxId: mailboxId === "all" ? "" : mailboxId,
      folder: folder === "all" ? "" : folder,
      q: query,
      cursor: typeof pageParam === "string" ? pageParam : "",
    }),
    initialPageParam: "",
    getNextPageParam: (lastPage) => lastPage.nextCursor || undefined,
  })
  const detail = useQuery({ queryKey: ["admin", "message", selectedId], queryFn: () => api.adminMessage(selectedId!), enabled: !!selectedId })
  const items = messages.data?.pages.flatMap((page) => page.items || []) || []
  return (
    <Card className="min-w-0">
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle>全部邮件</CardTitle>
          <Button variant="outline" size="sm" onClick={() => messages.refetch()} disabled={messages.isFetching}>
            <RefreshCcw className={cn("h-4 w-4", messages.isFetching && "animate-spin")} />{messages.isFetching ? "刷新中" : "刷新"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="min-w-0 space-y-4">
        <div className="flex flex-col gap-3 xl:flex-row">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索主题、发件人、收件人、邮箱" className="pl-9" />
          </div>
          <Select value={mailboxId} onValueChange={setMailboxId}>
            <SelectTrigger className="xl:w-72"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部邮箱</SelectItem>
              {systemAdmin && <SelectItem value="unregistered">未知收件</SelectItem>}
              {mailboxes.map((mailbox) => <SelectItem key={mailbox.id} value={mailbox.id}>{mailbox.address}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={folder} onValueChange={setFolder}>
            <SelectTrigger className="xl:w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部文件夹</SelectItem>
              <SelectItem value="Inbox">收件箱</SelectItem>
              <SelectItem value="Sent">已发送</SelectItem>
              <SelectItem value="Archive">归档</SelectItem>
              <SelectItem value="Spam">垃圾邮件</SelectItem>
              <SelectItem value="Trash">回收站</SelectItem>
              {systemAdmin && <SelectItem value="Unregistered">未知收件</SelectItem>}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-3 md:hidden">
          {items.map((message) => (
            <div key={message.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{message.subject}</div>
                  <div className="mt-1 line-clamp-2 text-xs text-muted-foreground">{message.snippet}</div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setSelectedId(message.id)}>查看</Button>
              </div>
              <div className="mt-3 space-y-2 text-sm">
                <div className="truncate text-muted-foreground">邮箱：{message.mailboxAddress || message.recipientAddress || "-"}</div>
                <div className="truncate text-muted-foreground">发件人：{adminSenderDisplayName(message)}</div>
                <div className="truncate text-muted-foreground">收件人：{message.recipientAddress || message.to?.join(", ") || ""}</div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Badge variant="secondary">{folderName(message.folder)}</Badge>
                <Badge variant="outline">{formatDate(message.receivedAt)}</Badge>
              </div>
            </div>
          ))}
        </div>
        <div className="min-w-0 overflow-hidden md:block max-md:hidden">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-[25%]">邮件</TableHead>
                <TableHead className="w-[17%]">邮箱</TableHead>
                <TableHead className="w-[15%]">发件人</TableHead>
                <TableHead className="w-[17%]">收件人</TableHead>
                <TableHead className="w-[9%]">文件夹</TableHead>
                <TableHead className="w-[10%]">时间</TableHead>
                <TableHead className="w-[7%]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((message) => (
                <TableRow key={message.id}>
                  <TableCell className="max-w-[360px]">
                    <div className="truncate font-medium">{message.subject}</div>
                    <div className="truncate text-xs text-muted-foreground">{message.snippet}</div>
                  </TableCell>
                  <TableCell className="min-w-0">
                    <div className="truncate font-medium" title={message.mailboxAddress || message.recipientAddress || "-"}>{message.mailboxAddress || message.recipientAddress || "-"}</div>
                    {message.ownerEmail && <div className="truncate text-xs text-muted-foreground" title={message.ownerEmail}>{message.ownerEmail}</div>}
                  </TableCell>
                  <TableCell className="max-w-[220px] truncate" title={adminSenderTitle(message)}>{adminSenderDisplayName(message)}</TableCell>
                  <TableCell className="max-w-[220px] truncate">{message.recipientAddress || message.to?.join(", ") || ""}</TableCell>
                  <TableCell><Badge variant="secondary">{folderName(message.folder)}</Badge></TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(message.receivedAt)}</TableCell>
                  <TableCell><Button variant="ghost" size="sm" onClick={() => setSelectedId(message.id)}>查看</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {messages.isLoading && <Empty text="加载中..." />}
        {messages.isError && <QueryFailure error={messages.error} onRetry={() => { void messages.refetch() }} compact />}
        {!messages.isLoading && !messages.isError && items.length === 0 && <Empty text="暂无邮件" />}
        {!messages.isLoading && messages.hasNextPage && (
          <div className="flex justify-center">
            <Button variant="outline" size="sm" disabled={messages.isFetchingNextPage} onClick={() => messages.fetchNextPage()}>
              {messages.isFetchingNextPage ? "加载中..." : "加载更多"}
            </Button>
          </div>
        )}
      </CardContent>
      <AdminMessageDialog message={detail.data} loading={detail.isLoading} open={!!selectedId} onOpenChange={(open) => { if (!open) setSelectedId(null) }} />
    </Card>
  )
}

function AdminSendAuditSection({ mailboxes }: { mailboxes: MailboxType[] }) {
  const [mailboxId, setMailboxId] = React.useState("all")
  const [event, setEvent] = React.useState("all")
  const [messageId, setMessageId] = React.useState("")
  const [from, setFrom] = React.useState("")
  const [to, setTo] = React.useState("")
  const audit = useInfiniteQuery({
    queryKey: ["admin", "send-audit", mailboxId, event, messageId, from, to],
    queryFn: ({ pageParam }) => api.adminSendAudit({
      mailboxId: mailboxId === "all" ? "" : mailboxId,
      event: event === "all" ? "" : event,
      messageId: messageId.trim(),
      from,
      to,
      cursor: typeof pageParam === "string" ? pageParam : "",
    }),
    initialPageParam: "",
    getNextPageParam: (lastPage) => lastPage.nextCursor || undefined,
  })
  const items = audit.data?.pages.flatMap((page) => page.items || []) || []
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <CardTitle className="flex items-center gap-2"><ClipboardList className="h-5 w-5" />发送队列</CardTitle>
          <Button variant="outline" size="sm" onClick={() => audit.refetch()} disabled={audit.isFetching}>
            <RefreshCcw className={cn("h-4 w-4", audit.isFetching && "animate-spin")} />{audit.isFetching ? "刷新中" : "刷新"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_180px_180px_160px_160px]">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={messageId} onChange={(event) => setMessageId(event.target.value)} placeholder="Message-ID 或已发送邮件 ID" className="pl-9" />
          </div>
          <Select value={mailboxId} onValueChange={setMailboxId}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部邮箱</SelectItem>
              {mailboxes.map((mailbox) => <SelectItem key={mailbox.id} value={mailbox.id}>{mailbox.address}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={event} onValueChange={setEvent}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部事件</SelectItem>
              {sendAuditEvents.map((item) => <SelectItem key={item} value={item}>{sendAuditEventLabel(item)}</SelectItem>)}
            </SelectContent>
          </Select>
          <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} aria-label="开始日期" />
          <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} aria-label="结束日期" />
        </div>
        <div className="space-y-3 md:hidden">
          {items.map((item) => (
            <div key={item.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-medium">{sendAuditEventLabel(item.event || "")}</div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">{item.mailboxAddress || item.mailboxId || "-"}</div>
                </div>
                <Badge variant={sendAuditBadgeVariant(item.event)}>{item.status || item.event || "-"}</Badge>
              </div>
              <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                <div className="truncate">收件人：{(item.recipients || []).join(", ") || "-"}</div>
                <div className="truncate">Message-ID：{item.messageId || item.sentMessageId || "-"}</div>
                {item.error && <div className="line-clamp-2 text-destructive">错误：{item.error}</div>}
              </div>
              <div className="mt-3 text-xs text-muted-foreground">{formatDate(item.createdAt)}</div>
            </div>
          ))}
        </div>
        <div className="hidden md:block">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>事件</TableHead>
                <TableHead>邮箱</TableHead>
                <TableHead>收件人</TableHead>
                <TableHead>Message-ID</TableHead>
                <TableHead>错误</TableHead>
                <TableHead>时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell><Badge variant={sendAuditBadgeVariant(item.event)}>{sendAuditEventLabel(item.event || "")}</Badge></TableCell>
                  <TableCell className="max-w-[220px] truncate">{item.mailboxAddress || item.mailboxId || "-"}</TableCell>
                  <TableCell className="max-w-[260px] truncate" title={(item.recipients || []).join(", ")}>{(item.recipients || []).join(", ") || "-"}</TableCell>
                  <TableCell className="max-w-[240px] truncate" title={item.messageId || item.sentMessageId || ""}>{item.messageId || item.sentMessageId || "-"}</TableCell>
                  <TableCell className="max-w-[260px] truncate text-destructive" title={item.error || ""}>{item.error || "-"}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDate(item.createdAt)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {audit.isLoading && <Empty text="加载中..." />}
        {audit.isError && <QueryFailure error={audit.error} onRetry={() => { void audit.refetch() }} compact />}
        {!audit.isLoading && !audit.isError && items.length === 0 && <Empty text="暂无发送记录" />}
        {!audit.isLoading && audit.hasNextPage && (
          <div className="flex justify-center">
            <Button variant="outline" size="sm" disabled={audit.isFetchingNextPage} onClick={() => audit.fetchNextPage()}>
              {audit.isFetchingNextPage ? "加载中..." : "加载更多"}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function SystemSettingsSection({ settings, domains, mailboxes, initialTab }: { settings?: SystemSettings; domains: Domain[]; mailboxes: MailboxType[]; initialTab?: string | null }) {
  const me = useMe()
  const user = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const canSettingsView = hasPermission(user, "admin.settings.view")
  const canUpdateSettings = hasPermission(user, "admin.settings.update")
  const canTestSMTP = hasPermission(user, "admin.settings.test_smtp")
  const canViewTemplates = hasPermission(user, "admin.templates.view")
  const canUpdateTemplates = hasPermission(user, "admin.templates.update")
  const canResetTemplates = hasPermission(user, "admin.templates.reset")
  const templates = useQuery({ queryKey: ["admin", "mail-templates"], queryFn: api.mailTemplates, enabled: canViewTemplates })
  const requestedTab = initialTab as SettingsTab | undefined
  const [settingsTab, setSettingsTab] = React.useState<SettingsTab>(() => requestedTab && ["base", "smtp", "storage", "mail", "notifications", "externalImap", "templates", "security"].includes(requestedTab) ? requestedTab : "base")
  const maildirHealth = useQuery({ queryKey: ["admin", "maildir-sync", "health"], queryFn: api.maildirSyncHealth, enabled: canSettingsView && settingsTab === "storage" })
  const [smtpRequireTls, setSmtpRequireTls] = React.useState(() => settings?.smtpRequireTls ?? false)
  const [allowInsecureHttp, setAllowInsecureHttp] = React.useState(() => settings?.allowInsecureHttp ?? true)
  const [openRegistration, setOpenRegistration] = React.useState(() => settings?.openRegistration ?? false)
  const [twoFactorEnabled, setTwoFactorEnabled] = React.useState(() => settings?.twoFactorEnabled ?? false)
  const [turnstileEnabled, setTurnstileEnabled] = React.useState(() => settings?.turnstileEnabled ?? false)
  const [catchAllEnabled, setCatchAllEnabled] = React.useState(() => settings?.catchAllEnabled ?? false)
  const [mailAutoRefresh, setMailAutoRefresh] = React.useState(() => settings?.mailAutoRefresh ?? true)
  const [userMailboxApplyEnabled, setUserMailboxApplyEnabled] = React.useState(() => settings?.userMailboxApplyEnabled ?? false)
  const [userMailboxDomainIds, setUserMailboxDomainIds] = React.useState<string[]>(() => settings?.userMailboxDomainIds || [])
  const [externalImapEnabled, setExternalImapEnabled] = React.useState(() => settings?.externalImapEnabled ?? false)
  const [externalImapAllowPrivateHosts, setExternalImapAllowPrivateHosts] = React.useState(() => settings?.externalImapAllowPrivateHosts ?? false)
  const [telegramMailEnabled, setTelegramMailEnabled] = React.useState(() => settings?.telegramMailEnabled ?? false)
  const [telegramBotToken, setTelegramBotToken] = React.useState("")
  const [telegramPrivateChatId, setTelegramPrivateChatId] = React.useState(() => settings?.telegramPrivateChatId || "")
  const [telegramBodyMode, setTelegramBodyMode] = React.useState<"summary" | "full">(() => settings?.telegramBodyMode === "full" ? "full" : "summary")
  const [telegramMailboxIds, setTelegramMailboxIds] = React.useState<string[]>(() => settings?.telegramMailboxIds || [])
  const [telegramIncludeUnregistered, setTelegramIncludeUnregistered] = React.useState(() => settings?.telegramIncludeUnregistered ?? false)
  const [telegramPairing, setTelegramPairing] = React.useState<TelegramPairing | null>(null)
  React.useEffect(() => {
    if (!settings) return
    setSmtpRequireTls(settings.smtpRequireTls)
    setAllowInsecureHttp(settings.allowInsecureHttp)
    setOpenRegistration(settings.openRegistration)
    setTwoFactorEnabled(settings.twoFactorEnabled)
    setTurnstileEnabled(settings.turnstileEnabled)
    setCatchAllEnabled(settings.catchAllEnabled)
    setMailAutoRefresh(settings.mailAutoRefresh)
    setUserMailboxApplyEnabled(settings.userMailboxApplyEnabled)
    setUserMailboxDomainIds(settings.userMailboxDomainIds || [])
    setExternalImapEnabled(settings.externalImapEnabled)
    setExternalImapAllowPrivateHosts(settings.externalImapAllowPrivateHosts)
    setTelegramMailEnabled(settings.telegramMailEnabled)
    setTelegramBotToken("")
    setTelegramPrivateChatId(settings.telegramPrivateChatId || "")
    setTelegramBodyMode(settings.telegramBodyMode === "full" ? "full" : "summary")
    setTelegramMailboxIds(settings.telegramMailboxIds || [])
    setTelegramIncludeUnregistered(settings.telegramIncludeUnregistered)
    setTelegramPairing(null)
  }, [settings])
  const createTelegramPairing = useMutation({
    mutationFn: () => api.createTelegramPairing(telegramBotToken),
    onSuccess: (pairing) => {
      setTelegramPairing(pairing)
      toast({ title: "Telegram 绑定码已生成" })
    },
    onError: (error) => toast({ title: "生成失败", description: error.message }),
  })
  const discoverTelegram = useMutation({
    mutationFn: () => api.discoverTelegramChat(telegramBotToken, telegramPairing?.code || ""),
    onSuccess: (chat) => {
      setTelegramPrivateChatId(chat.chatId)
      setTelegramPairing(null)
      toast({ title: "已获取 Telegram 私聊", description: chat.displayName || chat.chatId })
    },
    onError: (error) => toast({ title: "获取失败", description: error.message }),
  })
  const testTelegram = useMutation({
    mutationFn: () => api.testTelegram(telegramBotToken, telegramPrivateChatId),
    onSuccess: () => toast({ title: "Telegram 测试通知已发送" }),
    onError: (error) => toast({ title: "发送失败", description: error.message }),
  })
  const save = useMutation({
    mutationFn: (form: FormData) => api.updateSystemSettings({
      publicHostname: fieldValue(form, "publicHostname", settings?.publicHostname || ""),
      publicBaseUrl: fieldValue(form, "publicBaseUrl", settings?.publicBaseUrl || ""),
      smtpHost: fieldValue(form, "smtpHost", settings?.smtpHost || ""),
      smtpPort: fieldValue(form, "smtpPort", settings?.smtpPort || "25"),
      smtpUsername: fieldValue(form, "smtpUsername", settings?.smtpUsername || ""),
      smtpPassword: fieldValue(form, "smtpPassword", ""),
      smtpRequireTls,
      maildirRoot: fieldValue(form, "maildirRoot", settings?.maildirRoot || ""),
      maildirScanSeconds: fieldNumber(form, "maildirScanSeconds", settings?.maildirScanSeconds || 30),
      sessionTtlHours: fieldNumber(form, "sessionTtlHours", settings?.sessionTtlHours || 168),
      allowInsecureHttp,
      openRegistration,
      twoFactorEnabled,
      turnstileEnabled,
      turnstileSiteKey: fieldValue(form, "turnstileSiteKey", settings?.turnstileSiteKey || ""),
      turnstileSecretKey: fieldValue(form, "turnstileSecretKey", ""),
      catchAllEnabled,
      mailAutoRefresh,
      mailRefreshSeconds: fieldNumber(form, "mailRefreshSeconds", settings?.mailRefreshSeconds || 30),
      userMailboxApplyEnabled,
      userMailboxDomainIds,
      reservedMailboxPrefixes: fieldValue(form, "reservedMailboxPrefixes", settings?.reservedMailboxPrefixes || ""),
      externalImapEnabled,
      externalImapSecretKey: fieldValue(form, "externalImapSecretKey", ""),
      externalImapSyncSeconds: fieldNumber(form, "externalImapSyncSeconds", settings?.externalImapSyncSeconds || 300),
      externalImapAllowPrivateHosts,
      externalImapGmailClientId: fieldValue(form, "externalImapGmailClientId", settings?.externalImapGmailClientId || ""),
      externalImapGmailClientSecret: fieldValue(form, "externalImapGmailClientSecret", ""),
      externalImapOutlookClientId: fieldValue(form, "externalImapOutlookClientId", settings?.externalImapOutlookClientId || ""),
      externalImapOutlookClientSecret: fieldValue(form, "externalImapOutlookClientSecret", ""),
      telegramMailEnabled,
      telegramBotToken,
      telegramPrivateChatId,
      telegramBodyMode,
      telegramMailboxIds,
      telegramIncludeUnregistered,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "settings"] })
      qc.invalidateQueries({ queryKey: ["admin", "maildir-sync", "health"] })
      qc.invalidateQueries({ queryKey: ["dns-records"] })
      qc.invalidateQueries({ queryKey: ["public-settings"] })
      toast({ title: "系统设置已保存" })
    },
    onError: (e) => toast({ title: "保存失败", description: e.message }),
  })
  const formKey = settings ? [
    settings.publicHostname,
    settings.publicBaseUrl,
    settings.smtpHost,
    settings.smtpPort,
    settings.smtpUsername,
    settings.smtpPasswordSet,
    settings.smtpRequireTls,
    settings.maildirRoot,
    settings.maildirScanSeconds,
    settings.sessionTtlHours,
    settings.allowInsecureHttp,
    settings.openRegistration,
    settings.twoFactorEnabled,
    settings.turnstileEnabled,
    settings.turnstileSiteKey,
    settings.turnstileSecretSet,
    settings.catchAllEnabled,
    settings.mailAutoRefresh,
    settings.mailRefreshSeconds,
    settings.userMailboxApplyEnabled,
    (settings.userMailboxDomainIds || []).join(","),
    settings.reservedMailboxPrefixes,
    settings.externalImapEnabled,
    settings.externalImapSecretSet,
    settings.externalImapSyncSeconds,
    settings.externalImapAllowPrivateHosts,
    settings.externalImapGmailClientId,
    settings.externalImapGmailClientSecretSet,
    settings.externalImapOutlookClientId,
    settings.externalImapOutlookClientSecretSet,
    settings.telegramMailEnabled,
    settings.telegramBotTokenSet,
    settings.telegramPrivateChatId,
    settings.telegramBodyMode,
    (settings.telegramMailboxIds || []).join(","),
    settings.telegramIncludeUnregistered,
  ].join("|") : "loading"
  const tabs: { key: typeof settingsTab; label: string }[] = [
    ...(canSettingsView ? [
      { key: "base" as const, label: "基础" },
      { key: "smtp" as const, label: "SMTP" },
      { key: "storage" as const, label: "存储" },
      { key: "mail" as const, label: "邮件" },
      { key: "notifications" as const, label: "通知" },
      { key: "externalImap" as const, label: "外部 IMAP" },
    ] : []),
    ...(canViewTemplates ? [{ key: "templates" as const, label: "模板" }] : []),
    ...(canSettingsView ? [{ key: "security" as const, label: "安全" }] : []),
  ]
  React.useEffect(() => {
    if (tabs.some((tab) => tab.key === settingsTab)) return
    setSettingsTab(tabs[0]?.key || "base")
  }, [settingsTab, tabs])
  return (
    <form key={formKey} onSubmit={(event) => { event.preventDefault(); if (canUpdateSettings) save.mutate(new FormData(event.currentTarget)) }} className="space-y-6">
      <div className="flex flex-wrap gap-2 rounded-lg border bg-card p-2">
        {tabs.map((tab) => (
          <Button key={tab.key} type="button" variant={settingsTab === tab.key ? "default" : "ghost"} size="sm" onClick={() => setSettingsTab(tab.key)}>
            {tab.label}
          </Button>
        ))}
      </div>

      {settingsTab === "base" && <Card>
        <CardHeader><CardTitle>基础设置</CardTitle></CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Field name="publicHostname" label="公网主机名" defaultValue={settings?.publicHostname || ""} placeholder="mail.example.com" />
          <Field name="publicBaseUrl" label="访问地址" defaultValue={settings?.publicBaseUrl || ""} placeholder="https://mail.example.com" required={false} />
          <Field name="sessionTtlHours" label="登录有效期小时" type="number" defaultValue={String(settings?.sessionTtlHours || 168)} />
          <Field name="maildirScanSeconds" label="Maildir 扫描秒数" type="number" defaultValue={String(settings?.maildirScanSeconds || 30)} />
          <SwitchRow label="允许 HTTP 调试" checked={allowInsecureHttp} onCheckedChange={setAllowInsecureHttp} className="md:col-span-2" />
        </CardContent>
      </Card>}

      {settingsTab === "smtp" && <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <div>
              <CardTitle>发信通道</CardTitle>
            </div>
            {canTestSMTP && <TestSMTPDialog disabled={!settings} />}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">
            <div className="font-medium text-foreground">当前默认：内置 Postfix</div>
            <div>Host 填 127.0.0.1、端口 25、用户名/密码留空、强制 TLS 关闭。这里的“强制 TLS”仅用于外部 SMTP 中继（587 STARTTLS 或 465 TLS）。</div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Field name="smtpHost" label="发信主机" defaultValue={settings?.smtpHost || ""} placeholder="127.0.0.1" required={false} />
            <Field name="smtpPort" label="发信端口" defaultValue={settings?.smtpPort || "25"} />
            <Field name="smtpUsername" label="中继用户名（内置 Postfix 留空）" defaultValue={settings?.smtpUsername || ""} required={false} />
            <Field name="smtpPassword" label={settings?.smtpPasswordSet ? "中继密码（留空不变）" : "中继密码（内置 Postfix 留空）"} type="password" required={false} />
            <SwitchRow label="外部中继强制 TLS" checked={smtpRequireTls} onCheckedChange={setSmtpRequireTls} className="md:col-span-2" />
          </div>
          <Separator />
          <SMTPRelayManager domains={domains} mailboxes={mailboxes} canUpdate={canUpdateSettings} canTest={canTestSMTP} />
        </CardContent>
      </Card>}

      {settingsTab === "storage" && <div className="space-y-6">
        <Card>
          <CardHeader><CardTitle>存储设置</CardTitle></CardHeader>
          <CardContent>
            <Field name="maildirRoot" label="Maildir 根目录" defaultValue={settings?.maildirRoot || ""} required={false} />
          </CardContent>
        </Card>
        <MaildirSyncHealthCard health={maildirHealth.data} loading={maildirHealth.isLoading} error={maildirHealth.error} onRefresh={() => maildirHealth.refetch()} refreshing={maildirHealth.isFetching} fallbackRoot={settings?.maildirRoot || ""} />
      </div>}

      {settingsTab === "mail" && <Card>
        <CardHeader><CardTitle>邮件设置</CardTitle></CardHeader>
        <CardContent className="space-y-5">
          <SwitchRow label="无人收件" checked={catchAllEnabled} onCheckedChange={setCatchAllEnabled} />
          <Separator />
          <SwitchRow label="账号自助申请邮箱" checked={userMailboxApplyEnabled} onCheckedChange={setUserMailboxApplyEnabled} />
          {userMailboxApplyEnabled && (
            <div className="space-y-5 border-t pt-5">
              <div className="space-y-3">
                <Label>开放域名</Label>
                <div className="grid gap-2 md:grid-cols-2">
                  {domains.map((domain) => {
                    const checked = userMailboxDomainIds.includes(domain.id)
                    const disabled = domain.status !== "active"
                    return (
                      <label key={domain.id} className={cn("flex min-h-11 items-center gap-3 rounded-md border px-3 py-2", disabled && "cursor-not-allowed opacity-50")}>
                        <Checkbox
                          checked={checked}
                          disabled={disabled}
                          onCheckedChange={(value) => setUserMailboxDomainIds((items) => value === true ? Array.from(new Set([...items, domain.id])) : items.filter((id) => id !== domain.id))}
                        />
                        <span className="text-sm font-medium">{domain.name}</span>
                      </label>
                    )
                  })}
                </div>
                {domains.length === 0 && <Empty text="暂无域名" />}
              </div>
              <div className="space-y-2">
                <Label>禁止前缀</Label>
                <Textarea name="reservedMailboxPrefixes" defaultValue={settings?.reservedMailboxPrefixes || ""} className="min-h-28 font-mono text-sm" />
              </div>
            </div>
          )}
          <Separator />
          <SwitchRow label="自动刷新" checked={mailAutoRefresh} onCheckedChange={setMailAutoRefresh} />
          {mailAutoRefresh && (
            <div className="border-t pt-5">
              <Field name="mailRefreshSeconds" label="刷新间隔秒数" type="number" min={5} defaultValue={String(settings?.mailRefreshSeconds || 30)} />
            </div>
          )}
        </CardContent>
      </Card>}

      {settingsTab === "notifications" && <Card>
        <CardHeader><CardTitle>Telegram 邮件通知</CardTitle></CardHeader>
        <CardContent className="space-y-5">
          <SwitchRow label="私聊新邮件通知" checked={telegramMailEnabled} onCheckedChange={setTelegramMailEnabled} />
          {telegramMailEnabled && (
            <div className="space-y-5 border-t pt-5">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Bot Token</Label>
                  <Input type="password" value={telegramBotToken} onChange={(event) => setTelegramBotToken(event.target.value)} placeholder={settings?.telegramBotTokenSet ? "已保存，留空不变" : "123456789:..."} />
                </div>
                <div className="space-y-2">
                  <Label>私聊 Chat ID</Label>
                  <div className="flex gap-2">
                    <Input inputMode="numeric" value={telegramPrivateChatId} onChange={(event) => setTelegramPrivateChatId(event.target.value)} placeholder="123456789" />
                    <Button type="button" variant="outline" className="shrink-0" disabled={createTelegramPairing.isPending} onClick={() => createTelegramPairing.mutate()}>
                      <ShieldCheck className="mr-2 h-4 w-4" />{createTelegramPairing.isPending ? "生成中" : "安全绑定"}
                    </Button>
                  </div>
                  {telegramPairing && (
                    <div className="space-y-3 border-l-2 border-primary/50 py-1 pl-3">
                      <div className="flex items-center gap-2">
                        <code className="min-w-0 flex-1 font-mono text-sm font-semibold">{telegramPairing.code}</code>
                        <Button type="button" variant="ghost" size="icon" aria-label="复制绑定码" title="复制绑定码" onClick={() => navigator.clipboard.writeText(telegramPairing.code)}>
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button asChild type="button" variant="outline" size="sm">
                          <a href={telegramPairing.deepLink} target="_blank" rel="noreferrer"><ExternalLink className="mr-2 h-4 w-4" />打开机器人</a>
                        </Button>
                        <Button type="button" size="sm" disabled={discoverTelegram.isPending} onClick={() => discoverTelegram.mutate()}>
                          <CheckCircle2 className="mr-2 h-4 w-4" />{discoverTelegram.isPending ? "绑定中" : "完成绑定"}
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              <div className="space-y-3 border-t pt-5">
                <Label>通知邮箱</Label>
                <div className="grid gap-2 md:grid-cols-2">
                  {mailboxes.filter((mailbox) => mailbox.status === "active").map((mailbox) => (
                    <label key={mailbox.id} className="flex min-h-11 items-center gap-3 rounded-md border px-3 py-2">
                      <Checkbox
                        checked={telegramMailboxIds.includes(mailbox.id)}
                        onCheckedChange={(checked) => setTelegramMailboxIds((items) => checked === true ? Array.from(new Set([...items, mailbox.id])) : items.filter((id) => id !== mailbox.id))}
                      />
                      <span className="min-w-0 truncate text-sm font-medium">{mailbox.address}</span>
                    </label>
                  ))}
                  <label className="flex min-h-11 items-center gap-3 rounded-md border px-3 py-2">
                    <Checkbox checked={telegramIncludeUnregistered} onCheckedChange={(checked) => setTelegramIncludeUnregistered(checked === true)} />
                    <span className="text-sm font-medium">未知收件</span>
                  </label>
                </div>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>邮件正文</Label>
                  <Select value={telegramBodyMode} onValueChange={(value) => setTelegramBodyMode(value === "full" ? "full" : "summary")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="summary">正文摘要</SelectItem>
                      <SelectItem value="full">尽量显示完整正文</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-end">
                  <Button type="button" variant="outline" disabled={testTelegram.isPending || !telegramPrivateChatId} onClick={() => testTelegram.mutate()}>
                    <Mail className="mr-2 h-4 w-4" />{testTelegram.isPending ? "发送中" : "测试通知"}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>}

      {settingsTab === "externalImap" && <Card>
        <CardHeader>
          <CardTitle>外部 IMAP 接入</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">
            默认关闭。关闭后前台会隐藏外部 IMAP 接入，相关后端接口也会返回禁用。
          </div>
          <SwitchRow label="启用外部 IMAP" checked={externalImapEnabled} onCheckedChange={setExternalImapEnabled} />
          {externalImapEnabled && (
            <div className="space-y-5 border-t pt-5">
              <div className="grid gap-4 md:grid-cols-2">
                <Field name="externalImapSecretKey" label={settings?.externalImapSecretSet ? "密码加密密钥（留空不变）" : "密码加密密钥"} type="password" required={!settings?.externalImapSecretSet} />
                <Field name="externalImapSyncSeconds" label="后台同步间隔秒数" type="number" min={30} defaultValue={String(settings?.externalImapSyncSeconds || 300)} />
              </div>
              <SwitchRow label="允许 localhost / 内网 / link-local IMAP 主机" checked={externalImapAllowPrivateHosts} onCheckedChange={setExternalImapAllowPrivateHosts} />
              <Separator />
              <div className="space-y-3">
                <div>
                  <div className="font-medium">Gmail OAuth2</div>
                  <div className="text-xs text-muted-foreground">回调地址：{(settings?.publicBaseUrl || "${LANQIN_PUBLIC_BASE_URL}").replace(/\/$/, "")}/api/external-imap-oauth/gmail/callback</div>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field name="externalImapGmailClientId" label="Gmail Client ID" defaultValue={settings?.externalImapGmailClientId || ""} required={false} />
                  <Field name="externalImapGmailClientSecret" label={settings?.externalImapGmailClientSecretSet ? "Gmail Client Secret（留空不变）" : "Gmail Client Secret"} type="password" required={false} />
                </div>
              </div>
              <Separator />
              <div className="space-y-3">
                <div>
                  <div className="font-medium">Microsoft 365 / Outlook OAuth2</div>
                  <div className="text-xs text-muted-foreground">回调地址：{(settings?.publicBaseUrl || "${LANQIN_PUBLIC_BASE_URL}").replace(/\/$/, "")}/api/external-imap-oauth/outlook/callback</div>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field name="externalImapOutlookClientId" label="Outlook Client ID" defaultValue={settings?.externalImapOutlookClientId || ""} required={false} />
                  <Field name="externalImapOutlookClientSecret" label={settings?.externalImapOutlookClientSecretSet ? "Outlook Client Secret（留空不变）" : "Outlook Client Secret"} type="password" required={false} />
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>}

      {settingsTab === "templates" && canViewTemplates && templates.isError && <QueryFailure error={templates.error} onRetry={() => { void templates.refetch() }} />}
      {settingsTab === "templates" && canViewTemplates && !templates.isError && <MailTemplatesPanel templates={templates.data?.items || []} loading={templates.isLoading} canUpdate={canUpdateTemplates} canReset={canResetTemplates} />}

      {settingsTab === "security" && <Card>
        <CardHeader><CardTitle>安全设置</CardTitle></CardHeader>
        <CardContent className="space-y-5">
          <SwitchRow label="开放注册" checked={openRegistration} onCheckedChange={setOpenRegistration} />
          <Separator />
          <SwitchRow label="双因素认证 (2FA)" checked={twoFactorEnabled} onCheckedChange={setTwoFactorEnabled} />
          <Separator />
          <SwitchRow label="Turnstile" checked={turnstileEnabled} onCheckedChange={setTurnstileEnabled} />
          {turnstileEnabled && (
            <div className="grid gap-4 border-t pt-5 md:grid-cols-2">
              <Field name="turnstileSiteKey" label="Site Key" defaultValue={settings?.turnstileSiteKey || ""} required />
              <Field name="turnstileSecretKey" label={settings?.turnstileSecretSet ? "Secret Key（留空不变）" : "Secret Key"} type="password" required={!settings?.turnstileSecretSet} />
            </div>
          )}
        </CardContent>
      </Card>}

      {canUpdateSettings && <div className="flex justify-end">
        <Button disabled={save.isPending || !settings}>{save.isPending ? "保存中..." : "保存设置"}</Button>
      </div>}
    </form>
  )
}

function MaildirSyncHealthCard({ health, loading, error, onRefresh, refreshing, fallbackRoot }: { health?: MaildirSyncHealth; loading: boolean; error: Error | null; onRefresh: () => void; refreshing: boolean; fallbackRoot: string }) {
  const root = health?.root || fallbackRoot
  const configured = health?.configured ?? !!root
  const lastRun = health?.lastRun
  const counters = lastRun?.counts || health?.summary
  const recentErrors = health?.recentErrors || []
  const status = health?.running ? "running" : lastRun?.status || (configured ? "idle" : "disabled")
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <CardTitle>Maildir 同步健康</CardTitle>
            <div className="break-all text-xs text-muted-foreground">{root || "未配置 Maildir 根目录"}</div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={configured ? "default" : "secondary"}>{configured ? "已配置" : "未配置"}</Badge>
            <Badge variant={health?.running ? "default" : health?.workerStarted ? "outline" : "secondary"}>{health?.running ? "运行中" : health?.workerStarted ? "worker 已启动" : "worker 未启动"}</Badge>
            <Button type="button" variant="outline" size="sm" onClick={onRefresh} disabled={loading || refreshing}>
              <RefreshCcw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
              刷新
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{queryErrorMessage(error)}</div>}
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <InfoLine label="当前状态" value={<MaildirStatusBadge status={status} />} />
          <InfoLine label="最近开始" value={formatOptionalDate(lastRun?.startedAt)} />
          <InfoLine label="最近结束" value={formatOptionalDate(lastRun?.finishedAt)} />
          <InfoLine label="最近耗时" value={formatDuration(lastRun?.durationMs)} />
          <InfoLine label="扫描间隔" value={health?.scanSeconds ? `${health.scanSeconds} 秒` : "-"} />
          <InfoLine label="下次运行" value={formatOptionalDate(health?.nextRunAt)} />
          <InfoLine label="最后错误" value={lastRun?.error || health?.lastError || "-"} />
          <InfoLine label="错误数" value={counterValue(counters, "fileErrors")} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {maildirCounterRows(counters).map((item) => <InfoBox key={item.key} label={item.label} value={item.value} />)}
        </div>
        <div className="space-y-2">
          <div className="text-sm font-medium">最近错误</div>
          {recentErrors.length === 0 && <Empty text={loading ? "正在读取同步状态..." : "暂无同步错误"} />}
          {recentErrors.length > 0 && (
            <div className="space-y-2">
              {recentErrors.slice(0, 5).map((item, index) => (
                <div key={`${item}-${index}`} className="rounded-lg border px-3 py-2 text-sm">
                  <div className="break-words text-destructive">{item || "未知错误"}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function MaildirStatusBadge({ status }: { status: string }) {
	const normalized = status.toLowerCase()
	if (normalized === "running") return <Badge>运行中</Badge>
	if (["ok", "success", "succeeded", "idle"].includes(normalized)) return <Badge variant="outline">{normalized === "idle" ? "等待下次扫描" : "正常"}</Badge>
	if (normalized === "partial") return <Badge variant="secondary">部分成功</Badge>
	if (["error", "failed", "failure"].includes(normalized)) return <Badge variant="destructive">失败</Badge>
	if (["disabled", "not_configured"].includes(normalized)) return <Badge variant="secondary">未启用</Badge>
	return <Badge variant="secondary">{status || "-"}</Badge>
}

function maildirCounterRows(counters?: Record<string, number | undefined>) {
  return [
    { key: "filesScanned", label: "扫描文件", value: counterValue(counters, "filesScanned") },
    { key: "imported", label: "导入", value: counterValue(counters, "imported") },
    { key: "backfilled", label: "回填", value: counterValue(counters, "backfilled") },
    { key: "cleaned", label: "清理", value: counterValue(counters, "cleaned") },
    { key: "fileErrors", label: "文件错误", value: counterValue(counters, "fileErrors") },
  ]
}

function counterValue(counters: Record<string, number | undefined> | undefined, key: string) {
  return Number(counters?.[key] || 0)
}

function formatOptionalDate(value?: string) {
  return value ? formatDate(value) || "-" : "-"
}

function formatDuration(value?: number) {
  if (!value) return "-"
  if (value < 1000) return `${value} ms`
  return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)} 秒`
}

function queryErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "读取 Maildir 同步健康失败"
}

function TestSMTPDialog({ disabled }: { disabled?: boolean }) {
  const { toast } = useToast()
  const [open, setOpen] = React.useState(false)
  const test = useMutation({
    mutationFn: (form: FormData) => api.testSmtp(String(form.get("to") || "")),
    onSuccess: () => {
      setOpen(false)
      toast({ title: "测试邮件已发送" })
    },
    onError: (e) => toast({ title: "发送失败", description: e.message }),
  })
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm" disabled={disabled}>测试发送</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>SMTP 测试发送</DialogTitle></DialogHeader>
        <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); test.mutate(new FormData(event.currentTarget)) }}>
          <Field name="to" label="收件邮箱" type="email" placeholder="test@example.com" />
          <DialogFooter><Button disabled={test.isPending}>{test.isPending ? "发送中..." : "发送"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const emptyRelayPayload: SMTPRelayPayload = {
  name: "", host: "", port: 587, username: "", password: "", tlsMode: "starttls", enabled: true,
  priority: 100, minuteLimit: 30, dailyLimit: 1000, domainIds: [], mailboxIds: [],
}

function SMTPRelayManager({ domains, mailboxes, canUpdate, canTest }: { domains: Domain[]; mailboxes: MailboxType[]; canUpdate: boolean; canTest: boolean }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const me = useMe()
  const relays = useQuery({ queryKey: ["admin", "smtp-relays"], queryFn: api.smtpRelays })
  const protection = useQuery({ queryKey: ["admin", "deliverability-settings"], queryFn: api.deliverabilitySettings })
  const [editorOpen, setEditorOpen] = React.useState(false)
  const [editing, setEditing] = React.useState<SMTPRelay | null>(null)
  const [relayForm, setRelayForm] = React.useState<SMTPRelayPayload>(emptyRelayPayload)
  const [deleteTarget, setDeleteTarget] = React.useState<SMTPRelay | null>(null)
  const [testTarget, setTestTarget] = React.useState<SMTPRelay | null>(null)
  const [testAddress, setTestAddress] = React.useState("")
  const [protectionForm, setProtectionForm] = React.useState<DeliverabilitySettings | null>(null)
  React.useEffect(() => { if (protection.data) setProtectionForm(protection.data) }, [protection.data])
  React.useEffect(() => { if (!testAddress && me.data?.user.email) setTestAddress(me.data.user.email) }, [me.data?.user.email, testAddress])

  const saveRelay = useMutation({
    mutationFn: () => editing ? api.updateSmtpRelay(editing.id, relayForm) : api.createSmtpRelay(relayForm),
    onSuccess: () => {
      setEditorOpen(false)
      qc.invalidateQueries({ queryKey: ["admin", "smtp-relays"] })
      toast({ title: editing ? "中继已更新" : "中继已添加" })
    },
    onError: (error) => toast({ title: "保存失败", description: error.message }),
  })
  const removeRelay = useMutation({
    mutationFn: (id: string) => api.deleteSmtpRelay(id),
    onSuccess: () => {
      setDeleteTarget(null)
      qc.invalidateQueries({ queryKey: ["admin", "smtp-relays"] })
      toast({ title: "中继已删除" })
    },
    onError: (error) => toast({ title: "删除失败", description: error.message }),
  })
  const testRelay = useMutation({
    mutationFn: () => api.testSmtpRelay(testTarget!.id, testAddress),
    onSuccess: () => { setTestTarget(null); toast({ title: "中继测试邮件已发送" }) },
    onError: (error) => toast({ title: "测试失败", description: error.message }),
  })
  const saveProtection = useMutation({
    mutationFn: () => api.updateDeliverabilitySettings({
      autoPause: protectionForm!.autoPause,
      complaintThreshold: protectionForm!.complaintThreshold,
      bounceThreshold: protectionForm!.bounceThreshold,
      minimumSample: protectionForm!.minimumSample,
      circuitFailureThreshold: protectionForm!.circuitFailureThreshold,
      circuitMinutes: protectionForm!.circuitMinutes,
    }),
    onSuccess: (data) => {
      setProtectionForm(data)
      qc.invalidateQueries({ queryKey: ["admin", "deliverability-settings"] })
      toast({ title: "投递保护已保存" })
    },
    onError: (error) => toast({ title: "保存失败", description: error.message }),
  })
  const openEditor = (relay?: SMTPRelay) => {
    setEditing(relay || null)
    setRelayForm(relay ? {
      name: relay.name, host: relay.host, port: relay.port, username: relay.username, password: "", tlsMode: relay.tlsMode,
      enabled: relay.enabled, priority: relay.priority, minuteLimit: relay.minuteLimit, dailyLimit: relay.dailyLimit,
      domainIds: relay.domainIds || [], mailboxIds: relay.mailboxIds || [],
    } : { ...emptyRelayPayload, domainIds: [], mailboxIds: [] })
    setEditorOpen(true)
  }
  const updateRelayField = <K extends keyof SMTPRelayPayload>(key: K, value: SMTPRelayPayload[K]) => setRelayForm((current) => ({ ...current, [key]: value }))
  const toggleAssignment = (key: "domainIds" | "mailboxIds", id: string, checked: boolean) => updateRelayField(key, checked ? Array.from(new Set([...relayForm[key], id])) : relayForm[key].filter((item) => item !== id))
  const assignmentLabel = (relay: SMTPRelay) => {
    if (relay.mailboxIds.length) return `${relay.mailboxIds.length} 个发件人`
    if (relay.domainIds.length) return `${relay.domainIds.length} 个域名`
    return "全部发件人"
  }
  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <div className="flex items-center gap-2 font-semibold"><Server className="h-4 w-4" />中继池</div>
        <p className="mt-1 text-xs text-muted-foreground">按发件人、域名和优先级自动选择；故障时仅在确认尚未投递的阶段切换。</p>
      </div>
      {canUpdate && <Button type="button" size="sm" onClick={() => openEditor()}><Plus className="mr-2 h-4 w-4" />添加中继</Button>}
    </div>
    {!protection.data?.relaySecretConfigured && <div className="border-l-2 border-amber-500 bg-amber-500/5 px-3 py-2 text-sm">当前环境缺少中继密码加密密钥。使用新版一键安装或更新脚本后会自动生成。</div>}
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader><TableRow><TableHead>中继</TableHead><TableHead>状态</TableHead><TableHead>使用范围</TableHead><TableHead>额度</TableHead><TableHead className="w-32 text-right">操作</TableHead></TableRow></TableHeader>
        <TableBody>
          {(relays.data?.items || []).map((relay) => {
            const circuitOpen = !!relay.circuitOpenUntil && new Date(relay.circuitOpenUntil).getTime() > Date.now()
            return <TableRow key={relay.id}>
              <TableCell><div className="font-medium">{relay.name}</div><div className="text-xs text-muted-foreground">{relay.host}:{relay.port} · {relay.tlsMode === "tls" ? "TLS" : relay.tlsMode === "starttls" ? "STARTTLS" : "明文"} · 优先级 {relay.priority}</div></TableCell>
              <TableCell><Badge variant={!relay.enabled || circuitOpen ? "destructive" : relay.failureCount ? "secondary" : "default"}>{!relay.enabled ? "已停用" : circuitOpen ? "已熔断" : relay.failureCount ? `异常 ${relay.failureCount}` : "可用"}</Badge>{relay.lastError && <div className="mt-1 max-w-64 truncate text-xs text-muted-foreground" title={relay.lastError}>{relay.lastError}</div>}</TableCell>
              <TableCell className="text-sm">{assignmentLabel(relay)}</TableCell>
              <TableCell><div className="text-sm">{relay.minuteUsed}/{relay.minuteLimit || "不限"} 分钟</div><div className="text-xs text-muted-foreground">{relay.dailyUsed}/{relay.dailyLimit || "不限"} 今日</div></TableCell>
              <TableCell><div className="flex justify-end gap-1">
                {canTest && <Button type="button" variant="ghost" size="icon" title="测试中继" aria-label="测试中继" onClick={() => setTestTarget(relay)}><Send className="h-4 w-4" /></Button>}
                {canUpdate && <Button type="button" variant="ghost" size="icon" title="编辑中继" aria-label="编辑中继" onClick={() => openEditor(relay)}><Pencil className="h-4 w-4" /></Button>}
                {canUpdate && <Button type="button" variant="ghost" size="icon" title="删除中继" aria-label="删除中继" onClick={() => setDeleteTarget(relay)}><Trash2 className="h-4 w-4" /></Button>}
              </div></TableCell>
            </TableRow>
          })}
          {!relays.isPending && !(relays.data?.items || []).length && <TableRow><TableCell colSpan={5} className="h-20 text-center text-muted-foreground">暂无独立中继，仍会使用上方默认发信通道</TableCell></TableRow>}
        </TableBody>
      </Table>
    </div>

    <div className="border-t pt-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div><div className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-4 w-4" />退信与投诉保护</div><p className="mt-1 text-xs text-muted-foreground">硬退信和投诉立即加入全局禁止发送名单；样本达到设定数量后按比例自动暂停活动。</p></div>
        {canUpdate && <Button type="button" variant="outline" size="sm" disabled={!protectionForm || saveProtection.isPending} onClick={() => saveProtection.mutate()}>{saveProtection.isPending ? "保存中" : "保存保护设置"}</Button>}
      </div>
      {protectionForm && <div className="grid gap-4 md:grid-cols-3">
        <SwitchRow label="超标自动暂停" checked={protectionForm.autoPause} onCheckedChange={(value) => setProtectionForm({ ...protectionForm, autoPause: value })} />
        <div className="space-y-2"><Label>投诉率阈值（%）</Label><Input type="number" min="0.01" max="10" step="0.01" value={protectionForm.complaintThreshold} onChange={(event) => setProtectionForm({ ...protectionForm, complaintThreshold: Number(event.target.value) })} /></div>
        <div className="space-y-2"><Label>硬退信率阈值（%）</Label><Input type="number" min="0.1" max="50" step="0.1" value={protectionForm.bounceThreshold} onChange={(event) => setProtectionForm({ ...protectionForm, bounceThreshold: Number(event.target.value) })} /></div>
        <div className="space-y-2"><Label>最小统计样本</Label><Input type="number" min="1" max="100000" value={protectionForm.minimumSample} onChange={(event) => setProtectionForm({ ...protectionForm, minimumSample: Number(event.target.value) })} /></div>
        <div className="space-y-2"><Label>连续失败次数</Label><Input type="number" min="1" max="20" value={protectionForm.circuitFailureThreshold} onChange={(event) => setProtectionForm({ ...protectionForm, circuitFailureThreshold: Number(event.target.value) })} /></div>
        <div className="space-y-2"><Label>熔断时长（分钟）</Label><Input type="number" min="1" max="1440" value={protectionForm.circuitMinutes} onChange={(event) => setProtectionForm({ ...protectionForm, circuitMinutes: Number(event.target.value) })} /></div>
      </div>}
      <div className="mt-4 grid gap-2 border-l-2 border-border pl-3 text-xs text-muted-foreground sm:grid-cols-[auto_1fr]">
        <span>投递回调</span><div className="flex min-w-0 items-center gap-2"><code className="truncate">{protection.data?.callbackUrl || "请先配置外部访问地址"}</code>{protection.data?.callbackUrl && <Button type="button" variant="ghost" size="icon" className="h-7 w-7 shrink-0" title="复制回调地址" aria-label="复制回调地址" onClick={() => navigator.clipboard.writeText(protection.data!.callbackUrl)}><Copy className="h-3.5 w-3.5" /></Button>}</div>
        <span>签名密钥</span><span className={protection.data?.callbackConfigured ? "text-emerald-600" : "text-amber-600"}>{protection.data?.callbackConfigured ? "已配置，可接收送达/退信/投诉事件" : "未配置 LANQIN_DELIVERY_WEBHOOK_SECRET"}</span>
      </div>
    </div>

    <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
      <DialogContent className="max-h-[90svh] max-w-3xl overflow-y-auto">
        <DialogHeader><DialogTitle>{editing ? "编辑 SMTP 中继" : "添加 SMTP 中继"}</DialogTitle></DialogHeader>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>名称</Label><Input value={relayForm.name} onChange={(event) => updateRelayField("name", event.target.value)} placeholder="例如：营销线路 A" /></div>
          <div className="space-y-2"><Label>主机</Label><Input value={relayForm.host} onChange={(event) => updateRelayField("host", event.target.value)} placeholder="smtp.example.com" /></div>
          <div className="space-y-2"><Label>端口</Label><Input type="number" min="1" max="65535" value={relayForm.port} onChange={(event) => updateRelayField("port", Number(event.target.value))} /></div>
          <SelectField label="加密方式" value={relayForm.tlsMode} onValueChange={(value) => updateRelayField("tlsMode", value as SMTPRelayPayload["tlsMode"])} items={[["starttls", "STARTTLS（通常 587）"], ["tls", "TLS（通常 465）"], ["plain", "明文（仅可信内网）"]]} />
          <div className="space-y-2"><Label>用户名</Label><Input value={relayForm.username} onChange={(event) => updateRelayField("username", event.target.value)} /></div>
          <div className="space-y-2"><Label>{editing?.passwordSet ? "密码（留空不变）" : "密码"}</Label><Input type="password" value={relayForm.password} onChange={(event) => updateRelayField("password", event.target.value)} /></div>
          <div className="space-y-2"><Label>优先级</Label><Input type="number" min="1" max="9999" value={relayForm.priority} onChange={(event) => updateRelayField("priority", Number(event.target.value))} /><div className="text-xs text-muted-foreground">数字越小越优先。</div></div>
          <SwitchRow label="启用此中继" checked={relayForm.enabled} onCheckedChange={(value) => updateRelayField("enabled", value)} />
          <div className="space-y-2"><Label>每分钟额度</Label><Input type="number" min="0" value={relayForm.minuteLimit} onChange={(event) => updateRelayField("minuteLimit", Number(event.target.value))} /><div className="text-xs text-muted-foreground">填 0 表示不限额。</div></div>
          <div className="space-y-2"><Label>每日额度</Label><Input type="number" min="0" value={relayForm.dailyLimit} onChange={(event) => updateRelayField("dailyLimit", Number(event.target.value))} /><div className="text-xs text-muted-foreground">按 UTC 自然日统计，填 0 表示不限额。</div></div>
        </div>
        <div className="grid gap-4 border-t pt-4 md:grid-cols-2">
          <div><Label>指定域名</Label><p className="mb-2 text-xs text-muted-foreground">不选择域名和发件人时，对全部发件人可用。</p><div className="max-h-40 space-y-1 overflow-y-auto">{domains.map((domain) => <label key={domain.id} className="flex items-center gap-2 py-1 text-sm"><Checkbox checked={relayForm.domainIds.includes(domain.id)} onCheckedChange={(value) => toggleAssignment("domainIds", domain.id, value === true)} />{domain.name}</label>)}</div></div>
          <div><Label>指定发件人</Label><p className="mb-2 text-xs text-muted-foreground">发件人指定优先于域名指定。</p><div className="max-h-40 space-y-1 overflow-y-auto">{mailboxes.filter((item) => item.status === "active").map((mailbox) => <label key={mailbox.id} className="flex items-center gap-2 py-1 text-sm"><Checkbox checked={relayForm.mailboxIds.includes(mailbox.id)} onCheckedChange={(value) => toggleAssignment("mailboxIds", mailbox.id, value === true)} />{mailbox.address}</label>)}</div></div>
        </div>
        <DialogFooter><Button type="button" variant="outline" onClick={() => setEditorOpen(false)}>取消</Button><Button type="button" disabled={saveRelay.isPending || !relayForm.name || !relayForm.host || (!editing && !relayForm.password)} onClick={() => saveRelay.mutate()}>{saveRelay.isPending ? "保存中" : "保存中继"}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <Dialog open={!!testTarget} onOpenChange={(open) => { if (!open) setTestTarget(null) }}>
      <DialogContent><DialogHeader><DialogTitle>测试 {testTarget?.name}</DialogTitle></DialogHeader><div className="space-y-2"><Label>收件邮箱</Label><Input type="email" value={testAddress} onChange={(event) => setTestAddress(event.target.value)} /></div><DialogFooter><Button type="button" disabled={testRelay.isPending || !testAddress} onClick={() => testRelay.mutate()}>{testRelay.isPending ? "发送中" : "发送测试邮件"}</Button></DialogFooter></DialogContent>
    </Dialog>
    <ConfirmDialog open={!!deleteTarget} onOpenChange={(open) => { if (!open) setDeleteTarget(null) }} title="删除这个 SMTP 中继？" description="删除后，绑定到它的发件人会自动改用其他可用中继或默认通道。" confirmText="删除中继" destructive pending={removeRelay.isPending} onConfirm={() => deleteTarget && removeRelay.mutate(deleteTarget.id)} />
  </div>
}

function MailTemplatesPanel({ templates, loading, canUpdate, canReset }: { templates: MailTemplate[]; loading: boolean; canUpdate: boolean; canReset: boolean }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [selectedKey, setSelectedKey] = React.useState("")
  const selected = templates.find((template) => template.key === selectedKey) || templates[0]
  const [subject, setSubject] = React.useState("")
  const [bodyText, setBodyText] = React.useState("")
  const [bodyHtml, setBodyHtml] = React.useState("")
  React.useEffect(() => {
    if (!selectedKey && templates[0]) setSelectedKey(templates[0].key)
  }, [selectedKey, templates])
  React.useEffect(() => {
    if (!selected) return
    setSubject(selected.subject)
    setBodyText(selected.bodyText)
    setBodyHtml(selected.bodyHtml)
  }, [selected])
  const save = useMutation({
    mutationFn: () => api.updateMailTemplate(selected!.key, { subject, bodyText, bodyHtml }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "mail-templates"] })
      toast({ title: "模板已保存" })
    },
    onError: (e) => toast({ title: "保存失败", description: e.message }),
  })
  const reset = useMutation({
    mutationFn: () => api.resetMailTemplate(selected!.key),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "mail-templates"] })
      toast({ title: "模板已恢复" })
    },
    onError: (e) => toast({ title: "恢复失败", description: e.message }),
  })
  if (loading) return <Card><CardContent className="p-6"><Empty text="加载中..." /></CardContent></Card>
  if (!selected) return <Card><CardContent className="p-6"><Empty text="暂无模板" /></CardContent></Card>
  return (
    <Card>
      <CardHeader><CardTitle>邮件模板</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        <SelectField label="模板" value={selected.key} onValueChange={setSelectedKey} items={templates.map((template) => [template.key, template.name])} />
        <div className="space-y-2">
          <Label>主题</Label>
          <Input value={subject} onChange={(event) => setSubject(event.target.value)} />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <Label>纯文本</Label>
            <Textarea value={bodyText} onChange={(event) => setBodyText(event.target.value)} className="min-h-64 font-mono text-sm" />
          </div>
          <div className="space-y-2">
            <Label>HTML</Label>
            <Textarea value={bodyHtml} onChange={(event) => setBodyHtml(event.target.value)} className="min-h-64 font-mono text-sm" />
          </div>
        </div>
        {(canUpdate || canReset) && <div className="flex justify-end gap-2">
          {canReset && <Button type="button" variant="outline" disabled={reset.isPending || save.isPending} onClick={() => reset.mutate()}>
            {reset.isPending ? "恢复中..." : "恢复默认"}
          </Button>}
          {canUpdate && <Button type="button" disabled={save.isPending || reset.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "保存中..." : "保存模板"}
          </Button>}
        </div>}
      </CardContent>
    </Card>
  )
}

function AdminMessageDialog({ message, loading, open, onOpenChange }: { message?: MailMessage; loading: boolean; open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[86vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader><DialogTitle>{loading ? "加载中..." : message?.subject || "邮件详情"}</DialogTitle></DialogHeader>
        {message && (
          <div className="space-y-5">
            <div className="grid gap-3 rounded-lg border p-4 text-sm md:grid-cols-2">
              <MessageMeta label="所属邮箱" value={message.mailboxAddress || message.recipientAddress || ""} />
              <MessageMeta label="所属账号" value={message.ownerEmail || ""} />
              <MessageMeta label="发件人" value={adminSenderTitle(message)} />
              <MessageMeta label="收件人" value={message.recipientAddress || message.to?.join(", ") || ""} />
              <MessageMeta label="文件夹" value={folderName(message.folder)} />
              <MessageMeta label="时间" value={formatDate(message.receivedAt)} />
            </div>
            <div className="mail-html prose max-w-none rounded-lg border p-5 text-sm leading-7" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(message.bodyHtml || `<pre>${escapeHtml(message.bodyText || message.snippet || "")}</pre>`) }} />
            {message.attachments && message.attachments.length > 0 && (
              <div className="rounded-lg border p-4">
                <div className="mb-3 font-medium">附件</div>
                <div className="space-y-2">
                  {message.attachments.map((attachment) => (
                    <a className="flex items-center justify-between rounded-md border p-3 text-sm hover:bg-accent" href={`/api/admin/attachments/${attachment.id}`} key={attachment.id}>
                      <span className="truncate">{attachment.filename}</span>
                      <span className="text-muted-foreground">{formatBytes(attachment.sizeBytes)}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function MessageMeta({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><div className="text-xs text-muted-foreground">{label}</div><div className="truncate font-medium">{value || "-"}</div></div>
}

function folderName(folder: string) {
  const labels: Record<string, string> = { Inbox: "收件箱", Sent: "已发送", Drafts: "草稿箱", Archive: "归档", Spam: "垃圾邮件", Trash: "回收站", Unregistered: "未注册收件" }
  return labels[folder] || folder
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char)
}

function adminSenderDisplayName(message: MailMessage) {
  const fromName = decodeMimeHeader(message.fromName?.trim() || "")
  if (fromName) return fromName
  const text = decodeMimeHeader(message.from.trim())
  const namedAddress = text.match(/^"?([^"<]+?)"?\s*<[^>]+>$/)
  const name = namedAddress?.[1]?.trim()
  if (name) return name
  const address = text.match(/<([^>]+)>/)?.[1]?.trim() || text
  return address.split("@")[0]?.trim() || text || "未知发件人"
}

function adminSenderTitle(message: MailMessage) {
  const name = decodeMimeHeader(message.fromName?.trim() || "")
  const from = decodeMimeHeader(message.from)
  return name ? `${name} <${from}>` : from
}

const sendAuditEvents = ["accepted", "queued", "retry", "delivered", "failed", "canceled"]

function sendAuditEventLabel(event: string) {
  switch (event) {
    case "accepted": return "已接受"
    case "queued": return "已入队"
    case "retry": return "重试"
    case "delivered": return "已投递"
    case "failed": return "失败"
    case "canceled": return "已取消"
    default: return event || "-"
  }
}

function sendAuditBadgeVariant(event?: string) {
  if (event === "failed") return "destructive"
  if (event === "delivered" || event === "accepted") return "default"
  return "secondary"
}

function Stat({ icon, tone, label, value, detail }: { icon: React.ReactNode; tone: "primary" | "cyan" | "sky" | "violet"; label: string; value: React.ReactNode; detail: string }) {
  return <Card className="border-border/80"><CardContent className="flex min-h-[88px] items-center gap-3 p-3 !pt-3"><div className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-lg [&>svg]:h-5 [&>svg]:w-5", tone === "primary" && "bg-primary/5 text-primary", tone === "cyan" && "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400", tone === "sky" && "bg-sky-500/10 text-sky-600 dark:text-sky-400", tone === "violet" && "bg-violet-500/10 text-violet-600 dark:text-violet-400")}>{icon}</div><div className="min-w-0"><div className="truncate text-xs font-medium">{label}</div><div className="truncate text-2xl font-semibold leading-7 tabular-nums">{value}</div><div className="truncate text-[11px] text-muted-foreground">{detail}</div></div></CardContent></Card>
}
function InfoBox({ label, value }: { label: string; value: React.ReactNode }) { return <div className="rounded-lg border p-4"><div className="text-xl font-semibold tracking-tight sm:text-2xl">{value}</div><div className="text-xs text-muted-foreground">{label}</div></div> }
function Empty({ text }: { text: string }) { return <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">{text}</div> }

function QueryFailure({ error, onRetry, compact = false }: { error: unknown; onRetry: () => void; compact?: boolean }) {
  return (
    <div className={cn("mb-4 flex flex-col gap-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4 sm:flex-row sm:items-center sm:justify-between", compact && "mb-0")} role="alert">
      <div className="min-w-0">
        <div className="text-sm font-semibold text-destructive">数据读取失败</div>
        <div className="mt-1 break-words text-sm text-muted-foreground">{queryErrorMessage(error)}</div>
      </div>
      <Button type="button" variant="outline" size="sm" className="shrink-0" onClick={onRetry}><RefreshCcw className="h-4 w-4" />重试</Button>
    </div>
  )
}
function invalidateAdmin(qc: ReturnType<typeof useQueryClient>) { qc.invalidateQueries({ queryKey: ["admin"] }); qc.invalidateQueries({ queryKey: ["mailboxes"] }); qc.invalidateQueries({ queryKey: ["me"] }) }

function UserMailboxCell({ user }: { user: AdminUser }) {
  const { toast } = useToast()
  const loginAddress = accountPrimaryEmail(user)
  const mailboxes = user.mailboxes || []
  const [mailboxQuery, setMailboxQuery] = React.useState("")
  const normalizedQuery = mailboxQuery.trim().toLowerCase()
  const sortedMailboxes = React.useMemo(() => {
    return Array.from(new Set(mailboxes)).sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" }))
  }, [mailboxes])
  const [selectedAddress, setSelectedAddress] = React.useState(loginAddress)
  React.useEffect(() => {
    if (selectedAddress === loginAddress || sortedMailboxes.includes(selectedAddress)) return
    setSelectedAddress(loginAddress)
  }, [loginAddress, selectedAddress, sortedMailboxes])
  const filteredMailboxes = React.useMemo(() => {
    if (!normalizedQuery) return sortedMailboxes
    return sortedMailboxes.filter((mailbox) => mailbox.toLowerCase().includes(normalizedQuery))
  }, [normalizedQuery, sortedMailboxes])
  const limit = user.role === "admin" ? "不限" : limitText(user.limits?.maxMailboxCount ?? defaultMailboxLimitOverride, "个")
  const storage = formatBytes((user.storageQuotaMb || defaultStorageQuotaMb(user.role)) * 1024 * 1024)
  const quota = <div className="text-[11px] text-muted-foreground">邮箱 {user.mailboxCount}/{limit} · 共享存储容量 {storage}</div>
  async function copyMailbox(address: string) {
    if (!address) return
    await navigator.clipboard.writeText(address)
    toast({ title: "邮箱地址已复制", description: address })
  }
  return (
    <div className="w-full max-w-[21rem] space-y-1">
      <div className="flex min-w-0 items-center gap-1.5">
        <DropdownMenu onOpenChange={(open) => { if (!open) setMailboxQuery("") }}>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="outline"
              className="h-8 min-w-0 flex-1 justify-start gap-1.5 overflow-hidden rounded-md border-input bg-background px-2 text-left font-normal shadow-none hover:bg-background"
              title={selectedAddress}
            >
              <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{selectedAddress}</span>
              {sortedMailboxes.length > 0 && <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground">{sortedMailboxes.length} 个</span>}
              <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-[21rem] max-w-[calc(100vw-32px)] p-1">
            <div className="px-1 pb-1">
              <div className="relative">
                <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  autoFocus
                  value={mailboxQuery}
                  onChange={(event) => setMailboxQuery(event.target.value)}
                  onKeyDown={(event) => event.stopPropagation()}
                  placeholder="搜索邮箱..."
                  className="h-8 rounded-md bg-background pl-8 pr-2 text-[13px] shadow-none"
                />
              </div>
            </div>
            {filteredMailboxes.map((mailbox) => (
              <DropdownMenuItem
                key={mailbox}
                onSelect={() => setSelectedAddress(mailbox)}
                className={cn("h-8 min-w-0 gap-2 rounded-sm px-2 text-[13px] font-normal", selectedAddress === mailbox && "bg-accent text-accent-foreground")}
              >
                <span className="min-w-0 flex-1 truncate" title={mailbox}>{mailbox}</span>
              </DropdownMenuItem>
            ))}
            {sortedMailboxes.length === 0 && <DropdownMenuItem disabled className="h-8 px-2 text-[13px] font-normal">暂无创建邮箱</DropdownMenuItem>}
            {sortedMailboxes.length > 0 && filteredMailboxes.length === 0 && <DropdownMenuItem disabled className="h-8 px-2 text-[13px] font-normal">没有匹配邮箱</DropdownMenuItem>}
          </DropdownMenuContent>
        </DropdownMenu>
        <Button type="button" variant="outline" size="icon" className="h-8 w-8 shrink-0 rounded-md bg-background shadow-none hover:bg-background" disabled={!selectedAddress} onClick={() => copyMailbox(selectedAddress)} aria-label="复制邮箱地址" title="复制邮箱地址">
          <Copy className="h-3.5 w-3.5" />
        </Button>
      </div>
      {quota}
    </div>
  )
}

function UserPermissionGroupsCell({ user }: { user: AdminUser }) {
  const groups = (user.permissionGroups || []).filter((group) => group.id !== "pg_regular_user")
  if (user.role === "admin") return <span className="text-sm text-muted-foreground">全部权限</span>
  if (groups.length === 0) return <span className="text-muted-foreground">默认权限</span>
  return <span className="line-clamp-2 text-sm text-muted-foreground">{groups.map((group) => group.name).join("、")}</span>
}

function assignableUserGroupIDs(user: AdminUser) {
  return (user.permissionGroupIds || []).filter((id) => id !== "pg_super_admin" && id !== "pg_regular_user")
}

function PermissionGroupPicker({ groups, value, onChange }: { groups: PermissionGroup[]; value: string[]; onChange: (value: string[]) => void }) {
  if (groups.length === 0) return null
  function toggle(groupID: string, checked: boolean) {
    onChange(checked ? Array.from(new Set([...value, groupID])) : value.filter((id) => id !== groupID))
  }
  return (
    <div className="space-y-2">
      <Label>自定义权限配置</Label>
      <div className="grid gap-2 md:grid-cols-2">
        {groups.map((group) => {
          const checked = value.includes(group.id)
          return (
            <label key={group.id} className="flex min-h-16 items-start gap-3 rounded-md border px-3 py-2">
              <Checkbox checked={checked} onCheckedChange={(next) => toggle(group.id, next === true)} />
              <span className="min-w-0">
                <span className="block text-sm font-medium">{group.name}</span>
                <span className="line-clamp-2 text-xs text-muted-foreground">{group.description}</span>
              </span>
            </label>
          )
        })}
      </div>
    </div>
  )
}

function RoleBadge({ user }: { user: AdminUser }) {
  return <span className="text-sm font-medium">{user.role === "admin" ? "管理员" : "普通用户"}</span>
}

function AccountStatus({ user }: { user: AdminUser }) {
  return <StatusText active={!user.disabled} activeLabel="正常" inactiveLabel="停用" />
}

function StatusText({ active, activeLabel, inactiveLabel }: { active: boolean; activeLabel: string; inactiveLabel: string }) {
  return <span className="inline-flex items-center gap-2 whitespace-nowrap text-sm"><span className={cn("h-1.5 w-1.5 rounded-full", active ? "bg-emerald-600" : "bg-muted-foreground")} />{active ? activeLabel : inactiveLabel}</span>
}

function UserActions({ user, permissionGroups, onDelete }: { user: AdminUser; permissionGroups: PermissionGroup[]; onDelete?: () => void }) {
  const me = useMe()
  const currentUser = me.data?.user
  const qc = useQueryClient()
  const { toast } = useToast()
  const [editOpen, setEditOpen] = React.useState(false)
  const [passwordOpen, setPasswordOpen] = React.useState(false)
  const canUpdate = hasPermission(currentUser, "admin.users.update")
  const canResetPassword = hasPermission(currentUser, "admin.users.reset_password")
  const update = useMutation({
    mutationFn: (payload: { email: string; displayName: string; role: "admin" | "user"; disabled: boolean; permissionGroupIds?: string[] }) => api.updateUser(user.id, payload),
    onSuccess: () => { invalidateAdmin(qc); toast({ title: "账号已更新" }) },
    onError: (e) => toast({ title: "更新失败", description: e.message }),
  })
  function quickPatch(patch: Partial<{ disabled: boolean }>) {
    const role = user.role
    update.mutate({
      email: accountPrimaryEmail(user),
      displayName: user.displayName,
      role,
      disabled: patch.disabled ?? user.disabled,
      permissionGroupIds: role === "user" ? assignableUserGroupIDs(user) : [],
    })
  }
  if (!canUpdate && !canResetPassword && !onDelete) return null
  return <><DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label={`管理账号 ${accountPrimaryEmail(user)}`} title="更多操作"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger><DropdownMenuContent align="end">{canUpdate && <DropdownMenuItem onSelect={() => setEditOpen(true)}>编辑账号</DropdownMenuItem>}{canResetPassword && <DropdownMenuItem onSelect={() => setPasswordOpen(true)}>重置密码</DropdownMenuItem>}{!user.protected && user.role !== "admin" && canUpdate && <><DropdownMenuSeparator /><DropdownMenuItem onSelect={() => quickPatch({ disabled: !user.disabled })}>{user.disabled ? "启用账号" : "停用账号"}</DropdownMenuItem></>}{!user.protected && user.role !== "admin" && onDelete && <><DropdownMenuSeparator /><DropdownMenuItem className="text-destructive" onSelect={onDelete}>删除账号</DropdownMenuItem></>}</DropdownMenuContent></DropdownMenu>{canUpdate && <EditUserDialog user={user} permissionGroups={permissionGroups} open={editOpen} onOpenChange={setEditOpen} />}{canResetPassword && <ResetPasswordDialog user={user} open={passwordOpen} onOpenChange={setPasswordOpen} />}</>
}

function CreateUserDialog({ permissionGroups, domains }: { permissionGroups: PermissionGroup[]; domains: Domain[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [open, setOpen] = React.useState(false)
  const [domainId, setDomainId] = React.useState("")
  const [permissionGroupIds, setPermissionGroupIds] = React.useState<string[]>([])
  React.useEffect(() => { if (!domainId && domains[0]) setDomainId(domains[0].id) }, [domainId, domains])
  const create = useMutation({
    mutationFn: (form: FormData) => {
      const domain = domains.find((item) => item.id === domainId)
      if (!domain) throw new Error("请选择邮箱域名")
      const localPart = String(form.get("localPart") || "").trim()
      if (!localPart) throw new Error("请输入邮箱前缀")
      const email = `${localPart}@${domain.name}`
      const inputPassword = String(form.get("password") || "")
      const confirmPassword = String(form.get("confirmPassword") || "")
      if (inputPassword !== confirmPassword) throw new Error("两次输入的密码不一致")
      const password = inputPassword || email
      if (password.length < 6) throw new Error("密码至少需要 6 位")
      return api.createUser({ email, displayName: String(form.get("displayName") || ""), password, role: "user", disabled: false, mailboxLimitOverride: mailboxLimitFromForm(form), storageQuotaMb: Number(form.get("storageQuotaMb") || defaultUserStorageQuotaMb), permissionGroupIds })
    },
    onSuccess: () => { invalidateAdmin(qc); setOpen(false); toast({ title: "账号已创建" }) },
    onError: (e) => toast({ title: "创建失败", description: e.message }),
  })
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm">添加账号</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>创建用户账号</DialogTitle></DialogHeader>
        <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); create.mutate(new FormData(event.currentTarget)) }}>
          <DomainSelect domains={domains} value={domainId} onChange={setDomainId} />
          <div className="grid grid-cols-2 gap-3">
            <Field name="localPart" label="邮箱前缀" placeholder="user" />
            <Field name="displayName" label="显示名称" placeholder="例如：SZX" />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field name="password" label="密码（留空则使用邮箱账号）" type="password" required={false} autoComplete="new-password" />
            <Field name="confirmPassword" label="再次输入密码" type="password" required={false} autoComplete="new-password" />
          </div>
          <SelectField label="身份" value="user" onValueChange={() => undefined} items={[["user", "普通用户"]]} disabled />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <MailboxLimitField defaultValue={defaultMailboxLimitOverride} />
            <Field name="storageQuotaMb" label="共享存储容量（MB）" type="number" min={100} defaultValue={String(defaultUserStorageQuotaMb)} />
          </div>
          <PermissionGroupPicker groups={permissionGroups} value={permissionGroupIds} onChange={setPermissionGroupIds} />
          <DialogFooter><Button disabled={create.isPending || !domainId}>{create.isPending ? "创建中..." : "创建用户账号"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function AliasActions({ alias, onToggle, onDelete }: { alias: Alias; onToggle?: () => void; onDelete?: () => void }) {
  if (!onToggle && !onDelete) return null
  return <DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label={`管理转发 ${alias.source}`} title="更多操作"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger><DropdownMenuContent align="end">{onToggle && <DropdownMenuItem onSelect={onToggle}>{alias.enabled ? "停用" : "启用"}</DropdownMenuItem>}{onToggle && onDelete && <DropdownMenuSeparator />}{onDelete && <DropdownMenuItem className="text-destructive" onSelect={onDelete}>删除转发</DropdownMenuItem>}</DropdownMenuContent></DropdownMenu>
}

function EditUserDialog({ user, permissionGroups, open, onOpenChange }: { user: AdminUser; permissionGroups: PermissionGroup[]; open: boolean; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [role, setRole] = React.useState(user.role)
  const [disabled, setDisabled] = React.useState(user.disabled ? "disabled" : "active")
  const [permissionGroupIds, setPermissionGroupIds] = React.useState<string[]>(assignableUserGroupIDs(user))
  React.useEffect(() => {
    setRole(user.role)
    setDisabled(user.disabled ? "disabled" : "active")
    setPermissionGroupIds(assignableUserGroupIDs(user))
  }, [user, open])
  const mut = useMutation({
    mutationFn: (form: FormData) => api.updateUser(user.id, {
      email: String(form.get("email") || ""),
      displayName: String(form.get("displayName") || ""),
      role,
      disabled: disabled === "disabled",
      mailboxLimitOverride: role === "user" ? mailboxLimitFromForm(form, effectiveMailboxLimit(user)) : undefined,
      storageQuotaMb: Number(form.get("storageQuotaMb") || user.storageQuotaMb || defaultStorageQuotaMb(user.role)),
      permissionGroupIds: role === "user" ? permissionGroupIds : [],
    }),
    onSuccess: () => { invalidateAdmin(qc); onOpenChange(false); toast({ title: "账号已更新" }) },
    onError: (e) => toast({ title: "更新失败", description: e.message }),
  })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>编辑账号</DialogTitle></DialogHeader>
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); mut.mutate(new FormData(e.currentTarget)) }}>
          <Field name="email" label="主登录邮箱" defaultValue={accountPrimaryEmail(user)} type="email" autoComplete="off" />
          <Field name="displayName" label="显示名称" defaultValue={user.displayName} />
          <div className="grid grid-cols-2 gap-3">
            <SelectField label="身份" value={role} onValueChange={(value) => setRole(value as "admin" | "user")} items={user.role === "admin" ? [["admin", "管理员"]] : [["user", "普通用户"]]} disabled />
            <SelectField label="状态" value={disabled} onValueChange={setDisabled} items={[["active", "正常"], ["disabled", "停用"]]} disabled={user.protected || user.role === "admin"} />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {role === "user" && !user.protected && <MailboxLimitField defaultValue={effectiveMailboxLimit(user)} />}
            <Field name="storageQuotaMb" label="共享存储容量（MB）" type="number" min={100} defaultValue={String(user.storageQuotaMb || defaultStorageQuotaMb(user.role))} />
          </div>
          {role === "user" && !user.protected && <PermissionGroupPicker groups={permissionGroups} value={permissionGroupIds} onChange={setPermissionGroupIds} />}
          <DialogFooter><Button disabled={mut.isPending}>{mut.isPending ? "保存中..." : "保存"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({ user, open, onOpenChange }: { user: AdminUser; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { toast } = useToast(); const mut = useMutation({ mutationFn: (form: FormData) => api.resetUserPassword(user.id, String(form.get("password") || "")), onSuccess: () => { onOpenChange(false); toast({ title: "密码已重置" }) }, onError: (e) => toast({ title: "重置失败", description: e.message }) })
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogHeader><DialogTitle>重置密码</DialogTitle></DialogHeader><form className="space-y-4" onSubmit={(e) => { e.preventDefault(); mut.mutate(new FormData(e.currentTarget)); e.currentTarget.reset() }}><Field name="email" label="主登录邮箱" value={accountPrimaryEmail(user)} readOnly /><Field name="password" label="新密码" type="password" minLength={6} /><DialogFooter><Button disabled={mut.isPending}>{mut.isPending ? "重置中..." : "重置"}</Button></DialogFooter></form></DialogContent></Dialog>
}

function CreateDomainDialog() {
  const qc = useQueryClient(); const { toast } = useToast(); const [open, setOpen] = React.useState(false)
  const mut = useMutation({ mutationFn: (form: FormData) => api.createDomain(String(form.get("name"))), onSuccess: () => { invalidateAdmin(qc); setOpen(false); toast({ title: "域名已创建" }) }, onError: (e) => toast({ title: "创建失败", description: e.message }) })
  return <Dialog open={open} onOpenChange={setOpen}><DialogTrigger asChild><Button className="self-start">添加域名</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>添加域名</DialogTitle></DialogHeader><form className="space-y-4" onSubmit={(e) => { e.preventDefault(); mut.mutate(new FormData(e.currentTarget)) }}><Field name="name" label="域名" placeholder="example.com" /><DialogFooter><Button disabled={mut.isPending}>创建</Button></DialogFooter></form></DialogContent></Dialog>
}

function CreateMailboxDialog({ domains, users }: { domains: Domain[]; users: AdminUser[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [open, setOpen] = React.useState(false)
  const [domainId, setDomainId] = React.useState("")
  const [userId, setUserId] = React.useState("")
  React.useEffect(() => {
    if (!domainId && domains[0]) setDomainId(domains[0].id)
    if (!userId && users[0]) setUserId(users[0].id)
  }, [domains, domainId, users, userId])
  const mut = useMutation({
    mutationFn: (form: FormData) => api.createMailbox({
      domainId,
      localPart: String(form.get("localPart")),
      userId,
    }),
    onSuccess: () => { invalidateAdmin(qc); setOpen(false); toast({ title: "邮箱已创建" }) },
    onError: (e) => toast({ title: "创建失败", description: e.message }),
  })
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button>添加邮箱</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>创建邮箱</DialogTitle></DialogHeader>
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); mut.mutate(new FormData(e.currentTarget)) }}>
          <DomainSelect domains={domains} value={domainId} onChange={setDomainId} />
          <Field name="localPart" label="邮箱前缀" placeholder="alice" />
          <SelectField label="绑定用户账号" value={userId} onValueChange={setUserId} items={users.filter((item) => !item.disabled).sort(compareAdminUsers).map((item) => [item.id, accountPrimaryEmail(item)])} />
          <p className="text-xs text-muted-foreground">该邮箱使用绑定账号的登录密码；账号修改密码后会自动同步。</p>
          <DialogFooter><Button disabled={mut.isPending || !domainId || !userId}>{mut.isPending ? "创建中..." : "创建邮箱"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function CreateAliasDialog({ domains }: { domains: Domain[] }) {
  const qc = useQueryClient(); const { toast } = useToast(); const [open, setOpen] = React.useState(false); const [domainId, setDomainId] = React.useState("")
  React.useEffect(() => { if (!domainId && domains[0]) setDomainId(domains[0].id) }, [domains, domainId])
  const mut = useMutation({ mutationFn: (form: FormData) => api.createAlias({ domainId, source: String(form.get("source")), destination: String(form.get("destination")), enabled: true }), onSuccess: () => { invalidateAdmin(qc); setOpen(false); toast({ title: "转发已创建" }) }, onError: (e) => toast({ title: "创建失败", description: e.message }) })
  return <Dialog open={open} onOpenChange={setOpen}><DialogTrigger asChild><Button className="self-start">添加转发</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>创建邮件转发</DialogTitle></DialogHeader><form className="space-y-4" onSubmit={(e) => { e.preventDefault(); mut.mutate(new FormData(e.currentTarget)) }}><DomainSelect domains={domains} value={domainId} onChange={setDomainId} /><Field name="source" label="来源" placeholder="sales 或 sales@example.com" /><Field name="destination" label="目标邮箱" placeholder="alice@example.com" /><DialogFooter><Button disabled={mut.isPending || !domainId}>创建</Button></DialogFooter></form></DialogContent></Dialog>
}

function DNSPanel({ domain, embedded = false }: { domain?: Domain; embedded?: boolean }) {
  const me = useMe()
  const user = me.data?.user
  const canCheckDNS = hasPermission(user, "admin.dns.check")
  const { toast } = useToast(); const qc = useQueryClient(); const records = useQuery({ queryKey: ["dns-records", domain?.id], queryFn: () => api.dnsRecords(domain!.id), enabled: !!domain })
  const check = useMutation({ mutationFn: () => api.checkDns(domain!.id), onSuccess: (res) => { qc.invalidateQueries({ queryKey: ["admin", "domains"] }); toast({ title: res.status === "ok" ? "DNS 检测通过" : "DNS 检测未通过", description: Object.values(res.checks).map((c) => c.message).join("；") }) }, onError: (error) => toast({ title: "DNS 检测失败", description: error.message }) })
  if (!domain) return <Card><CardContent className="p-6 text-muted-foreground">请选择域名</CardContent></Card>
  const content = <>
    <p className="mb-3 text-sm text-muted-foreground">以下内容可直接填写到常见 DNS 控制台，根域名的主机记录使用 @。</p>
    {check.isPending && <DNSCheckPending />}
    {check.isError && <DNSCheckFailure error={check.error} />}
    {check.data && !check.isPending && <DNSCheckSummary checks={check.data.checks} />}
    {records.isError ? <QueryFailure error={records.error} onRetry={() => { void records.refetch() }} compact /> : <div className="grid gap-3 md:auto-rows-fr md:grid-cols-2">{records.data?.items.map((r) => <DNSRecordRow key={`${r.type}-${r.name}`} record={r} domainName={domain.name} />)}</div>}
  </>
  const checkButton = canCheckDNS ? <Button variant="outline" size="sm" onClick={() => check.mutate()} disabled={check.isPending}><RefreshCcw className={cn("h-4 w-4", check.isPending && "animate-spin")} />{check.isPending ? "检测中" : check.data ? "重新检测" : "检测"}</Button> : null
  const header = <div className="flex items-center justify-between"><CardTitle>DNS 记录</CardTitle>{checkButton}</div>
  if (embedded) return <div className="space-y-3"><div className="flex items-center justify-between"><div className="font-medium">DNS 记录</div>{checkButton}</div>{content}</div>
  return <Card><CardHeader>{header}</CardHeader><CardContent>{content}</CardContent></Card>
}

const dnsCheckMeta: Record<string, { label: string; description: string }> = {
  mx: { label: "MX", description: "收信地址" },
  spf: { label: "SPF", description: "发信授权" },
  dkim: { label: "DKIM", description: "邮件签名" },
  dmarc: { label: "DMARC", description: "防伪策略" },
  ptr: { label: "PTR", description: "反向 DNS" },
}
const dnsCheckOrder = ["mx", "spf", "dkim", "dmarc", "ptr"]
const requiredDNSCheckNames = ["mx", "spf", "dkim", "dmarc"]

function isRequiredDNSCheck(name: string) {
  return requiredDNSCheckNames.includes(name.toLowerCase())
}

function DNSCheckPending() {
  return <div className="mb-4 flex items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 p-4" role="status" aria-live="polite">
    <div className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-primary/10 text-primary"><Loader2 className="h-5 w-5 animate-spin" /></div>
    <div><div className="font-semibold text-foreground">正在检测 DNS</div><p className="mt-0.5 text-sm text-muted-foreground">正在查询最新解析结果，请稍候...</p></div>
  </div>
}

function DNSCheckFailure({ error }: { error: Error }) {
  return <div className="mb-4 flex items-start gap-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4" role="alert">
    <div className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-destructive/10 text-destructive"><AlertCircle className="h-5 w-5" /></div>
    <div className="min-w-0"><div className="font-semibold text-destructive">DNS 检测失败</div><p className="mt-0.5 break-words text-sm text-muted-foreground">{error.message || "暂时无法查询 DNS，请稍后重新检测。"}</p></div>
  </div>
}

function DNSCheckSummary({ checks }: { checks: Record<string, { ok: boolean; message: string; found?: string[] }> }) {
  const entries = Object.entries(checks).sort(([left], [right]) => {
    return dnsCheckOrder.indexOf(left) - dnsCheckOrder.indexOf(right)
  })
  const requiredEntries = entries.filter(([name]) => isRequiredDNSCheck(name))
  const requiredPassed = requiredEntries.filter(([, item]) => item.ok).length
  const allRequiredPassed = requiredEntries.length > 0 && requiredPassed === requiredEntries.length
  const hasOptionalWarning = entries.some(([name, item]) => !isRequiredDNSCheck(name) && !item.ok)
  return <section className={cn("mb-4 overflow-hidden rounded-lg border p-4", allRequiredPassed ? "border-emerald-500/40 bg-emerald-500/[0.07]" : "border-destructive/40 bg-destructive/5")} role={allRequiredPassed ? "status" : "alert"} aria-live="polite" aria-label="DNS 检测结果">
    <div className="flex items-start gap-3">
      <div className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-full", allRequiredPassed ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400" : "bg-destructive/10 text-destructive")}>
        {allRequiredPassed ? <CheckCircle2 className="h-5 w-5" /> : <AlertCircle className="h-5 w-5" />}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className={cn("text-base font-semibold", allRequiredPassed ? "text-emerald-800 dark:text-emerald-300" : "text-destructive")}>{allRequiredPassed ? "DNS 配置正常" : "DNS 配置需要处理"}</h3>
          <Badge variant="outline" className={cn("shrink-0 bg-background/70", allRequiredPassed ? "border-emerald-500/40 text-emerald-800 dark:text-emerald-300" : "border-destructive/40 text-destructive")}>{requiredPassed}/{requiredEntries.length} 必需项通过</Badge>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">{allRequiredPassed ? (hasOptionalWarning ? "MX、SPF、DKIM、DMARC 已通过；PTR 仅在本页提醒，使用中继时不影响发信。" : "邮件必需 DNS 记录均已正确解析，可以正常使用。") : "请处理下面标红的项目，修改 DNS 后再重新检测。"}</p>
      </div>
    </div>
    <div className="mt-3 grid gap-x-4 sm:grid-cols-2 lg:grid-cols-5">
      {entries.map(([name, item]) => <DNSCheckRow key={name} name={name} check={item} required={isRequiredDNSCheck(name)} />)}
    </div>
  </section>
}

function DNSCheckRow({ name, check, required }: { name: string; check: { ok: boolean; message: string; found?: string[] }; required: boolean }) {
  const visibleRecords = check.found?.filter(Boolean) ?? []
  const meta = dnsCheckMeta[name.toLowerCase()] || { label: name.toUpperCase(), description: "DNS 记录" }
  return <div className={cn("space-y-1 border-t py-2.5 text-sm", check.ok ? "border-emerald-500/20" : required ? "border-destructive/20" : "border-amber-500/25")}>
    <div className="flex items-start gap-2.5">
      {check.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" /> : <AlertCircle className={cn("mt-0.5 h-4 w-4 shrink-0", required ? "text-destructive" : "text-amber-600")} />}
      <div className="min-w-0 flex-1">
        <div className="shrink-0 font-medium text-foreground">{meta.label}<span className="ml-1 font-normal text-muted-foreground">({meta.description})</span></div>
        <div className={cn("mt-0.5", check.ok ? "text-muted-foreground" : required ? "font-medium text-destructive" : "font-medium text-amber-700 dark:text-amber-400")}>{check.message}</div>
      </div>
    </div>
    {!check.ok && visibleRecords.length > 0 && <div className="ml-6 rounded-md bg-background/70 px-3 py-2 font-mono text-xs text-muted-foreground">
      <div className="mb-1 font-sans text-foreground">当前解析</div>
      <div className="space-y-1">{visibleRecords.map((record, index) => <div key={`${name}-${index}`} className="break-all">{record}</div>)}</div>
    </div>}
  </div>
}

function dnsDescription(record: DNSRecord): string {
  if (record.type === "TXT" && record.name.startsWith("_dmarc")) return "声明域名的 DMARC 策略（如何处理未通过 SPF/DKIM 验证的邮件）。"
  if (record.type === "TXT" && record.value.includes("DKIM1")) return "DKIM 公钥。收件服务器用此密钥验证邮件是否由你发出。"
  if (record.type === "TXT" && record.value.includes("spf1")) return "声明哪些服务器有权使用你的域名发件，防止伪造。"
  if (record.type === "MX") {
    const mx = mxRecordParts(record.value)
    return `邮件由 ${mx.target} 接收，请确保它的 A 记录指向服务器 IP。优先级 ${mx.priority}，数值越小越优先。`
  }
  return ""
}

function mxRecordParts(value: string) {
  const [rawPriority = "10", ...rawTarget] = value.trim().split(/\s+/)
  const priority = /^\d+$/.test(rawPriority) ? rawPriority : "10"
  const target = (rawTarget.length > 0 ? rawTarget.join(" ") : value).replace(/\.$/, "")
  return { priority, target }
}

function dnsHostForProvider(recordName: string, domainName: string) {
  const name = recordName.replace(/\.$/, "")
  const domain = domainName.replace(/\.$/, "")
  if (name.toLowerCase() === domain.toLowerCase()) return "@"
  const suffix = `.${domain}`
  if (name.toLowerCase().endsWith(suffix.toLowerCase())) return name.slice(0, -suffix.length)
  return name
}

function DNSRecordRow({ record, domainName }: { record: DNSRecord; domainName: string }) {
  const { toast } = useToast()
  const desc = dnsDescription(record)
  const longValue = record.value.length > 180
  const mx = record.type === "MX" ? mxRecordParts(record.value) : null
  const displayHost = dnsHostForProvider(record.name, domainName)
  const displayValue = mx?.target || record.value
  const [valueExpanded, setValueExpanded] = React.useState(false)
  async function copyField(label: string, value: string) {
    await navigator.clipboard.writeText(value)
    toast({ title: `${label}已复制` })
  }
  return <div className="flex h-full flex-col rounded-lg border bg-card p-3">
    <div className="mb-2 flex min-h-7 items-center justify-between gap-2">
      <Badge variant="outline" className="font-mono">{record.type}</Badge>
      {longValue && <Button type="button" size="sm" variant="ghost" className="h-7 gap-1 px-2 text-xs text-muted-foreground" aria-expanded={valueExpanded} onClick={() => setValueExpanded((current) => !current)}><ChevronDown className={cn("h-3.5 w-3.5 transition-transform", valueExpanded && "rotate-180")} />{valueExpanded ? "收起完整内容" : "查看完整内容"}</Button>}
    </div>
    {desc && <p className="mb-2 line-clamp-2 min-h-9 text-xs leading-[1.125rem] text-muted-foreground">{desc}</p>}
    <div className="mt-auto space-y-1 font-mono text-xs text-muted-foreground">
      <div className="grid grid-cols-[4.5rem_minmax(0,1fr)_1.75rem] items-start gap-2">
        <span className="pt-1 text-foreground">主机记录</span>
        <code className="break-all pt-1 font-mono font-medium text-foreground">{displayHost}</code>
        <Button type="button" size="icon" variant="ghost" className="h-7 w-7" aria-label="复制主机记录" title="复制主机记录" onClick={() => copyField("主机记录", displayHost)}><Copy className="h-3.5 w-3.5" /></Button>
      </div>
      <div className="grid grid-cols-[4.5rem_minmax(0,1fr)_1.75rem] items-start gap-2">
        <span className="pt-1 text-foreground">记录值</span>
        <code className={cn("break-all pt-1 font-mono", longValue && !valueExpanded && "line-clamp-3")}>{displayValue}</code>
        <Button type="button" size="icon" variant="ghost" className="h-7 w-7" aria-label="复制记录值" title="复制记录值" onClick={() => copyField("记录值", displayValue)}><Copy className="h-3.5 w-3.5" /></Button>
      </div>
      <div className="grid grid-cols-2 gap-4">
        {mx && <div className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2"><span className="text-foreground">优先级</span><code className="font-mono font-medium text-foreground">{mx.priority}</code></div>}
        <div className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2"><span className="text-foreground">TTL</span><code className="font-mono">{record.ttl} 秒</code></div>
      </div>
    </div>
  </div>
}

function fieldValue(form: FormData, name: string, fallback: string) {
  const value = form.get(name)
  return value === null ? fallback : String(value)
}
function fieldNumber(form: FormData, name: string, fallback: number) {
  const value = form.get(name)
  if (value === null) return fallback
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? n : fallback
}
function SwitchRow({ label, checked, onCheckedChange, className = "" }: { label: string; checked: boolean; onCheckedChange: (checked: boolean) => void; className?: string }) {
  const id = React.useId()
  return (
    <div className={`flex min-h-14 items-center justify-between gap-4 ${className}`}>
      <Label htmlFor={id} className="text-base font-medium">{label}</Label>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  )
}
function Field({ label, required = true, id: suppliedId, ...props }: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const generatedId = React.useId()
  const id = suppliedId || generatedId
  return <div className="space-y-2"><Label htmlFor={id}>{label}</Label><Input id={id} required={required} {...props} /></div>
}
function MailboxLimitField({ defaultValue }: { defaultValue: number }) {
  const id = React.useId()
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>邮箱数量上限</Label>
      <Input id={id} name="mailboxLimitOverride" type="number" min={0} step={1} defaultValue={String(defaultValue)} />
      <div className="text-xs text-muted-foreground">普通用户默认 9 个，填 0 表示不限制。</div>
    </div>
  )
}
function mailboxLimitFromForm(form: FormData, fallback = defaultMailboxLimitOverride) {
  const value = Number(form.get("mailboxLimitOverride") || fallback)
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback
}
function effectiveMailboxLimit(user: AdminUser) {
  return user.mailboxLimitOverride ?? user.limits?.maxMailboxCount ?? defaultMailboxLimitOverride
}
function SelectField({ label, value, onValueChange, items, disabled = false }: { label: string; value: string; onValueChange: (value: string) => void; items: string[][]; disabled?: boolean }) {
  const id = React.useId()
  return <div className="space-y-2"><Label htmlFor={id}>{label}</Label><Select value={value} onValueChange={onValueChange} disabled={disabled}><SelectTrigger id={id}><SelectValue /></SelectTrigger><SelectContent>{items.map(([value, itemLabel]) => <SelectItem key={value} value={value}>{itemLabel}</SelectItem>)}</SelectContent></Select></div>
}
function DomainSelect({ domains, value, onChange }: { domains: Domain[]; value: string; onChange: (value: string) => void }) { return <div className="space-y-2"><Label>域名</Label><Select value={value} onValueChange={onChange}><SelectTrigger><SelectValue placeholder="选择域名" /></SelectTrigger><SelectContent>{domains.map((d) => <SelectItem key={d.id} value={d.id}>{d.name}</SelectItem>)}</SelectContent></Select></div> }

type CampaignPageTab = "campaigns" | "suppressions"
type RecipientTab = "sending" | "delivered" | "failed"
type CampaignStatusFilter = "all" | Campaign["status"]

export function CampaignsSection({ mailboxes }: { mailboxes: MailboxType[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const user = useMe().data?.user
  const canManage = hasPermission(user, "admin.campaigns.manage")
  const [tab, setTab] = React.useState<CampaignPageTab>("campaigns")
  const [createOpen, setCreateOpen] = React.useState(false)
  const [detailId, setDetailId] = React.useState("")
  const [campaignQuery, setCampaignQuery] = React.useState("")
  const [statusFilter, setStatusFilter] = React.useState<CampaignStatusFilter>("all")
  const campaigns = useQuery({ queryKey: ["admin", "campaigns"], queryFn: api.campaigns, refetchInterval: 5000 })
  const suppressions = useQuery({ queryKey: ["admin", "campaign-suppressions"], queryFn: api.campaignSuppressions, enabled: tab === "suppressions" })
  const action = useMutation({
    mutationFn: ({ id, kind }: { id: string; kind: "start" | "pause" | "resume" | "cancel" }) => kind === "start" ? api.startCampaign(id) : kind === "pause" ? api.pauseCampaign(id) : kind === "resume" ? api.resumeCampaign(id) : api.cancelCampaign(id),
    onSuccess: async (_, variables) => {
      await qc.invalidateQueries({ queryKey: ["admin", "campaigns"] })
      toast({ title: variables.kind === "start" ? "活动已启动" : variables.kind === "pause" ? "活动已暂停" : variables.kind === "resume" ? "活动已继续" : "活动已取消" })
    },
    onError: (error) => toast({ title: "操作失败", description: error.message }),
  })
  const items = campaigns.data?.items || []
  const totals = React.useMemo(() => items.reduce((sum, item) => ({ total: sum.total + item.totalCount, delivered: sum.delivered + item.deliveredCount, failed: sum.failed + item.failedCount, active: sum.active + (item.status === "running" || item.status === "scheduled" ? 1 : 0) }), { total: 0, delivered: 0, failed: 0, active: 0 }), [items])
  const filteredItems = React.useMemo(() => {
    const query = campaignQuery.trim().toLocaleLowerCase()
    return items.filter((item) => {
      if (statusFilter !== "all" && item.status !== statusFilter) return false
      if (!query) return true
      return [item.name, item.subject, item.mailboxAddress].some((value) => value?.toLocaleLowerCase().includes(query))
    })
  }, [items, campaignQuery, statusFilter])

  return <div className="space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3">
      <div className="inline-flex h-9 rounded-md border bg-muted/30 p-0.5">
        <Button type="button" size="sm" variant={tab === "campaigns" ? "secondary" : "ghost"} className="h-8" onClick={() => setTab("campaigns")}><Megaphone className="mr-2 h-4 w-4" />活动列表</Button>
        <Button type="button" size="sm" variant={tab === "suppressions" ? "secondary" : "ghost"} className="h-8" onClick={() => setTab("suppressions")}><ShieldCheck className="mr-2 h-4 w-4" />退订名单</Button>
      </div>
      {tab === "campaigns" && canManage && <Button type="button" onClick={() => setCreateOpen(true)}><Send className="mr-2 h-4 w-4" />新建群发</Button>}
    </div>

    {tab === "campaigns" && <>
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <CampaignMetric label="进行中" value={totals.active} icon={<Clock3 />} />
        <CampaignMetric label="收件人" value={totals.total} icon={<UsersRound />} />
        <CampaignMetric label="发送完成" value={totals.delivered} icon={<CheckCircle2 />} tone="success" />
        <CampaignMetric label="发送失败" value={totals.failed} icon={<AlertCircle />} tone={totals.failed > 0 ? "danger" : "default"} />
      </div>
      <div className="flex flex-col gap-2 rounded-md border bg-muted/[0.12] p-2 sm:flex-row sm:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={campaignQuery} onChange={(event) => setCampaignQuery(event.target.value)} placeholder="搜索活动名称、主题或发件人" className="h-9 bg-background pl-9" />
        </div>
        <Select value={statusFilter} onValueChange={(value) => setStatusFilter(value as CampaignStatusFilter)}>
          <SelectTrigger className="h-9 w-full bg-background sm:w-36" aria-label="筛选活动状态"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="draft">草稿</SelectItem>
            <SelectItem value="scheduled">待发送</SelectItem>
            <SelectItem value="running">发送中</SelectItem>
            <SelectItem value="paused">已暂停</SelectItem>
            <SelectItem value="completed">已完成</SelectItem>
            <SelectItem value="canceled">已取消</SelectItem>
          </SelectContent>
        </Select>
        <Button type="button" size="icon" variant="outline" className="h-9 w-9 shrink-0" title="刷新活动列表" aria-label="刷新活动列表" disabled={campaigns.isFetching} onClick={() => { void campaigns.refetch() }}><RefreshCcw className={cn("h-4 w-4", campaigns.isFetching && "animate-spin")} /></Button>
      </div>
      {campaigns.isPending && <Skeleton className="h-72 w-full" />}
      {campaigns.isError && <QueryFailure error={campaigns.error} onRetry={() => campaigns.refetch()} />}
      {!campaigns.isPending && !campaigns.isError && <div className="overflow-hidden rounded-lg border">
        <div className="hidden grid-cols-[minmax(180px,1.4fr)_minmax(140px,1fr)_92px_150px_132px_112px] gap-3 border-b bg-muted/40 px-3 py-2 text-xs font-medium text-muted-foreground lg:grid">
          <span>活动</span><span>发件人</span><span>状态</span><span>进度</span><span>发送速度</span><span className="text-right">操作</span>
        </div>
        {items.length === 0 && <div className="grid min-h-48 place-items-center px-4 text-sm text-muted-foreground">暂无群发活动</div>}
        {items.length > 0 && filteredItems.length === 0 && <div className="grid min-h-48 place-items-center px-4 py-8 text-center"><div><div className="font-medium">没有匹配的活动</div><Button type="button" variant="link" className="mt-1" onClick={() => { setCampaignQuery(""); setStatusFilter("all") }}>清除筛选</Button></div></div>}
        {filteredItems.map((item) => <div key={item.id} className="grid gap-3 border-b px-3 py-3 last:border-b-0 lg:grid-cols-[minmax(180px,1.4fr)_minmax(140px,1fr)_92px_150px_132px_112px] lg:items-center">
          <Button type="button" variant="ghost" className="h-auto min-w-0 justify-start p-0 text-left font-normal" onClick={() => setDetailId(item.id)}><span className="min-w-0"><span className="block truncate font-medium hover:underline">{item.name}</span><span className="block truncate text-xs text-muted-foreground">{item.subject}</span></span></Button>
          <div className="min-w-0"><div className="truncate text-sm">{item.senderCount > 1 ? `${item.senderCount} 个邮箱自动分配` : item.mailboxAddress}</div><div className="text-xs text-muted-foreground">共 {item.totalCount} 位收件人</div></div>
          <CampaignStatusBadge status={item.status} />
          <CampaignProgress item={item} />
          <div className="text-sm"><span className="font-medium">{item.ratePerMinute}</span> 封/分钟</div>
          <div className="flex justify-end gap-1">
            {canManage && item.status === "draft" && <Button type="button" size="icon" variant="ghost" title="开始发送" aria-label="开始发送" onClick={() => action.mutate({ id: item.id, kind: "start" })}><Play className="h-4 w-4" /></Button>}
            {canManage && (item.status === "running" || item.status === "scheduled") && <Button type="button" size="icon" variant="ghost" title="暂停" aria-label="暂停活动" onClick={() => action.mutate({ id: item.id, kind: "pause" })}><Pause className="h-4 w-4" /></Button>}
            {canManage && item.status === "paused" && <Button type="button" size="icon" variant="ghost" title="继续" aria-label="继续活动" onClick={() => action.mutate({ id: item.id, kind: "resume" })}><Play className="h-4 w-4" /></Button>}
            {canManage && ["draft", "scheduled", "running", "paused"].includes(item.status) && <Button type="button" size="icon" variant="ghost" className="text-destructive" title="取消" aria-label="取消活动" onClick={() => action.mutate({ id: item.id, kind: "cancel" })}><XCircle className="h-4 w-4" /></Button>}
            <Button type="button" size="icon" variant="ghost" title="查看明细" aria-label="查看活动明细" onClick={() => setDetailId(item.id)}><ChevronRight className="h-4 w-4" /></Button>
          </div>
        </div>)}
      </div>}
    </>}

    {tab === "suppressions" && <CampaignSuppressions items={suppressions.data?.items || []} loading={suppressions.isPending} canManage={canManage} />}
    <CampaignEditorDialog open={createOpen} onOpenChange={setCreateOpen} mailboxes={mailboxes.filter((mailbox) => mailbox.status === "active")} />
    <CampaignDetailDialog id={detailId} open={!!detailId} onOpenChange={(open) => { if (!open) setDetailId("") }} canManage={canManage} />
  </div>
}

function CampaignMetric({ label, value, icon, tone = "default" }: { label: string; value: number; icon: React.ReactNode; tone?: "default" | "success" | "danger" }) {
  return <div className={cn("flex min-h-[72px] items-center gap-3 rounded-lg border px-3 py-2", tone === "success" && "border-emerald-500/30 bg-emerald-500/[0.06]", tone === "danger" && "border-destructive/30 bg-destructive/5")}><span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground [&>svg]:h-4 [&>svg]:w-4", tone === "success" && "bg-emerald-500/10 text-emerald-700", tone === "danger" && "bg-destructive/10 text-destructive")}>{icon}</span><div><div className="text-xl font-semibold tabular-nums">{value}</div><div className="text-xs text-muted-foreground">{label}</div></div></div>
}

const campaignStatusText: Record<Campaign["status"], string> = { draft: "草稿", scheduled: "待发送", running: "发送中", paused: "已暂停", completed: "已完成", canceled: "已取消" }
function CampaignStatusBadge({ status }: { status: Campaign["status"] }) {
  return <Badge variant={status === "completed" ? "default" : status === "canceled" ? "destructive" : "outline"} className={cn("w-fit", status === "running" && "border-emerald-500/40 bg-emerald-500/10 text-emerald-700", status === "paused" && "border-amber-500/40 bg-amber-500/10 text-amber-700")}>{campaignStatusText[status]}</Badge>
}
function CampaignProgress({ item }: { item: Campaign }) {
  const done = item.deliveredCount + item.failedCount + item.suppressedCount
  const percent = item.totalCount ? Math.min(100, Math.round(done / item.totalCount * 100)) : 0
  return <div className="min-w-0"><div className="mb-1 flex justify-between text-xs"><span>{item.deliveredCount}/{item.totalCount}</span><span className="text-muted-foreground">{percent}%</span></div><div className="h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full bg-primary transition-[width] duration-300" style={{ width: `${percent}%` }} /></div></div>
}

function CampaignEditorDialog({ open, onOpenChange, mailboxes }: { open: boolean; onOpenChange: (open: boolean) => void; mailboxes: MailboxType[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const user = useMe().data?.user
  const csvFileRef = React.useRef<HTMLInputElement>(null)
  const [name, setName] = React.useState("")
  const [subject, setSubject] = React.useState("")
  const [body, setBody] = React.useState({ text: "", html: "" })
  const [recipientText, setRecipientText] = React.useState("")
  const [files, setFiles] = React.useState<File[]>([])
  const [mailboxIds, setMailboxIds] = React.useState<string[]>([])
  const [rate, setRate] = React.useState(30)
  const [scheduledAt, setScheduledAt] = React.useState("")
  const [consent, setConsent] = React.useState(false)
  const [sendersExpanded, setSendersExpanded] = React.useState(false)
  const [bodyExpanded, setBodyExpanded] = React.useState(false)
  const parsed = React.useMemo(() => parseCampaignRecipients(recipientText), [recipientText])
  const maxAttachmentBytes = campaignAttachmentLimitBytes(user?.limits)
  const maxAttachmentText = maxAttachmentBytes > 0 ? formatBytes(maxAttachmentBytes) : "不限"
  React.useEffect(() => { if (open && mailboxIds.length === 0 && mailboxes[0]) setMailboxIds([mailboxes[0].id]) }, [open, mailboxes, mailboxIds.length])
  const create = useMutation({
    mutationFn: async ({ start }: { start: boolean }) => {
      if (!attachmentsWithinLimit()) throw new Error("请移除超过上限的附件")
      const attachments = files.length ? await Promise.all(files.map(fileToCampaignAttachment)) : []
      const payload: CampaignInput = { mailboxIds, name, subject, text: body.text, html: body.html, ratePerMinute: rate, scheduledAt: scheduledAt ? new Date(scheduledAt).toISOString() : undefined, consentConfirmed: consent, attachments, recipients: parsed.items }
      const item = await api.createCampaign(payload)
      return start ? api.startCampaign(item.id) : item
    },
    onSuccess: async (item) => { await qc.invalidateQueries({ queryKey: ["admin", "campaigns"] }); toast({ title: item.status === "draft" ? "草稿已保存" : item.status === "scheduled" ? "活动已设置定时发送" : "活动已启动" }); onOpenChange(false); setName(""); setSubject(""); setBody({ text: "", html: "" }); setRecipientText(""); setFiles([]); setScheduledAt(""); setConsent(false) },
    onError: (error) => toast({ title: "保存失败", description: error.message }),
  })
  const ready = mailboxIds.length > 0 && name.trim() && subject.trim() && campaignHtmlContainsMeaningfulContent(body.html, body.text) && parsed.items.length > 0
  const visibleMailboxes = sendersExpanded ? mailboxes : mailboxes.slice(0, 4)
  const senderAllocation = (mailboxID: string) => {
    const index = mailboxIds.indexOf(mailboxID)
    if (index < 0 || mailboxIds.length === 0) return 0
    return Math.floor(parsed.items.length / mailboxIds.length) + (index < parsed.items.length % mailboxIds.length ? 1 : 0)
  }
  const toggleMailbox = (id: string, checked: boolean) => setMailboxIds((current) => checked ? [...new Set([...current, id])] : current.filter((item) => item !== id))
  function addAttachmentFiles(nextFiles: File[]) {
    if (!nextFiles.length) return
    const allowed = maxAttachmentBytes > 0 ? nextFiles.filter((file) => file.size <= maxAttachmentBytes) : nextFiles
    if (allowed.length < nextFiles.length) {
      toast({ title: "附件超过配额上限", description: `当前单个附件上限 ${maxAttachmentText}` })
    }
    if (allowed.length) {
      setFiles((current) => [...current, ...allowed])
    }
  }
  function attachmentsWithinLimit() {
    if (maxAttachmentBytes <= 0 || files.every((file) => file.size <= maxAttachmentBytes)) return true
    toast({ title: "附件超过配额上限", description: `当前单个附件上限 ${maxAttachmentText}` })
    return false
  }
  async function readCSV(file?: File) {
    if (!file) return
    try {
      const imported = parseCampaignRecipients(await file.text())
      setRecipientText(imported.items.map((item) => item.email).join("\n"))
      toast({ title: `已导入 ${imported.items.length} 个邮箱`, description: imported.duplicates || imported.invalid ? `已跳过 ${imported.duplicates} 个重复、${imported.invalid} 个无效地址` : undefined })
    } catch {
      toast({ title: "文件读取失败" })
    }
  }
  return <Dialog open={open} onOpenChange={(nextOpen) => { if (!nextOpen) { setBodyExpanded(false); setSendersExpanded(false) } onOpenChange(nextOpen) }}>
    <DialogContent className={cn("flex max-h-[88svh] w-[min(94vw,900px)] max-w-none flex-col overflow-hidden p-0", bodyExpanded && "h-[92svh] w-[min(98vw,1120px)]")}>
      <DialogHeader className="border-b px-4 py-3"><DialogTitle>新建群发活动</DialogTitle></DialogHeader>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className={cn("grid gap-4 p-4", bodyExpanded ? "grid-cols-1" : "lg:grid-cols-[minmax(0,1.08fr)_minmax(280px,0.92fr)]")}>
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="活动名称" value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：8 月产品通知" />
              <Field label="邮件主题" value={subject} onChange={(event) => setSubject(event.target.value)} placeholder="收件人看到的主题" />
            </div>
            <div className="space-y-2">
              <Label>邮件正文</Label>
              <CampaignBodyEditor value={body} expanded={bodyExpanded} files={files} maxAttachmentText={maxAttachmentText} onExpandedChange={setBodyExpanded} onChange={setBody} onPickFiles={addAttachmentFiles} onRemoveFile={(index) => setFiles((current) => current.filter((_, itemIndex) => itemIndex !== index))} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="每分钟发送" type="number" min={1} max={300} value={rate} onChange={(event) => setRate(Math.max(1, Math.min(300, Number(event.target.value) || 1)))} />
              <Field label="定时发送（可选）" required={false} type="datetime-local" value={scheduledAt} onChange={(event) => setScheduledAt(event.target.value)} />
            </div>
          </div>

          <div className={cn("space-y-4", bodyExpanded && "hidden")}>
            <div className="space-y-2">
              <div className="flex items-center justify-between"><Label>发件人</Label><Button type="button" size="sm" variant="ghost" onClick={() => setMailboxIds(mailboxIds.length === mailboxes.length ? [] : mailboxes.map((item) => item.id))}>{mailboxIds.length === mailboxes.length ? "取消全选" : "全选"}</Button></div>
              <div className={cn("grid grid-cols-1 gap-1 rounded-md border p-2", sendersExpanded && "max-h-44 overflow-y-auto")}>{visibleMailboxes.map((mailbox) => <label key={mailbox.id} className="flex min-h-10 cursor-pointer items-center gap-2 rounded px-2 text-sm hover:bg-muted"><Checkbox checked={mailboxIds.includes(mailbox.id)} onCheckedChange={(checked) => toggleMailbox(mailbox.id, checked === true)} /><span className="min-w-0 flex-1 truncate" title={mailbox.address}>{mailbox.address}</span>{mailboxIds.includes(mailbox.id) && <span className="shrink-0 text-xs tabular-nums text-muted-foreground">预计发送 {senderAllocation(mailbox.id)} 封</span>}</label>)}</div>
              {mailboxes.length > 4 && <Button type="button" size="sm" variant="ghost" className="h-8 w-full text-xs text-muted-foreground" aria-expanded={sendersExpanded} onClick={() => setSendersExpanded((current) => !current)}><ChevronDown className={cn("mr-1 h-3.5 w-3.5 transition-transform", sendersExpanded && "rotate-180")} />{sendersExpanded ? "收起发件人" : `查看全部发件人 (${mailboxes.length})`}</Button>}
              <div className="text-xs text-muted-foreground">已选 {mailboxIds.length} 位发件人，{parsed.items.length} 位收件人会自动均匀分配；余数按所选顺序每人多发 1 封。</div>
            </div>
            <div className="space-y-2">
              <div className="flex items-start justify-between gap-2"><div className="flex flex-col items-start"><Label htmlFor="campaign-recipients">收件人</Label><p className="mt-1 text-xs text-muted-foreground">每行只填写一个邮箱账号，无需姓名。</p></div><div><Input ref={csvFileRef} className="hidden" type="file" accept=".csv,text/csv" onChange={(event) => { void readCSV(event.target.files?.[0]); event.target.value = "" }} /><Button type="button" size="sm" variant="outline" onClick={() => csvFileRef.current?.click()}><FileUp className="mr-2 h-4 w-4" />导入 CSV</Button></div></div>
              <Textarea id="campaign-recipients" className="h-[238px] resize-none font-mono text-xs" value={recipientText} onChange={(event) => setRecipientText(event.target.value)} placeholder={'zhangsan@example.com\nlisi@example.com'} />
              <div className="grid grid-cols-3 gap-2 text-xs"><span className="rounded bg-emerald-500/10 px-2 py-1.5 text-emerald-700">有效 {parsed.items.length}</span><span className="rounded bg-muted px-2 py-1.5 text-muted-foreground">重复 {parsed.duplicates}</span><span className={cn("rounded px-2 py-1.5", parsed.invalid ? "bg-destructive/10 text-destructive" : "bg-muted text-muted-foreground")}>无效 {parsed.invalid}</span></div>
            </div>
            <label className="flex cursor-pointer items-start gap-3 rounded-md border border-amber-500/30 bg-amber-500/[0.06] p-3"><Checkbox checked={consent} onCheckedChange={(checked) => setConsent(checked === true)} /><span className="text-sm leading-5">确认名单中的收件人已明确同意接收此类邮件，并接受邮件自动附加退订链接。</span></label>
          </div>
        </div>
      </div>
      <DialogFooter className="border-t px-4 py-3"><Button type="button" variant="outline" onClick={() => onOpenChange(false)}>取消</Button><Button type="button" variant="secondary" disabled={!ready || create.isPending} onClick={() => create.mutate({ start: false })}>保存草稿</Button><Button type="button" disabled={!ready || !consent || create.isPending} onClick={() => create.mutate({ start: true })}>{create.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}开始发送</Button></DialogFooter>
    </DialogContent>
  </Dialog>
}

function CampaignBodyEditor({ value, expanded, files, maxAttachmentText, onExpandedChange, onChange, onPickFiles, onRemoveFile }: { value: { text: string; html: string }; expanded: boolean; files: File[]; maxAttachmentText: string; onExpandedChange: (expanded: boolean) => void; onChange: (value: { text: string; html: string }) => void; onPickFiles: (files: File[]) => void; onRemoveFile: (index: number) => void }) {
  const attachmentInputRef = React.useRef<HTMLInputElement>(null)
  const [viewMode, setViewMode] = React.useState<"content" | "preview" | "html">("content")
  const [insertContent, setInsertContent] = React.useState<CampaignInsertContentState | null>(null)
  const editor = useEditor({
    extensions: [
      StarterKit.configure({ link: false }),
      LinkExtension.configure({ openOnClick: false, HTMLAttributes: { target: "_blank", rel: "noopener noreferrer" } }),
      ImageExtension.configure({ allowBase64: true, HTMLAttributes: { style: "max-width:100%;height:auto;margin:12px 0;" } }),
      TextAlign.configure({ types: ["heading", "paragraph"] }),
      Placeholder.configure({ placeholder: "输入邮件正文，退订链接会自动添加到末尾。" }),
    ],
    content: value.html || "<p></p>",
    editorProps: {
      attributes: {
        class: "mail-html min-h-[160px] w-full px-3 py-3 text-sm leading-6 outline-none [overflow-wrap:anywhere] lg:min-h-0",
        "aria-label": "邮件正文",
        spellcheck: "true",
      },
    },
    onUpdate({ editor: current }) {
      const text = current.getText({ blockSeparator: "\n" }).replace(/\u00a0/g, " ").trimEnd()
      const html = sanitizeCampaignHtml(current.getHTML())
      onChange({ text, html: campaignHtmlContainsMeaningfulContent(html, text) ? html : "" })
    },
  })

  function openInsertDialog(kind: CampaignInsertContentState["kind"]) {
    if (!editor) return
    if (kind === "link") {
      const attrs = editor.getAttributes("link") as { href?: string }
      setInsertContent({ kind, selectedText: campaignEditorTextSelection(editor), url: attrs.href || "", editing: Boolean(attrs.href) })
      return
    }
    const attrs = campaignSelectedImageAttributes(editor)
    setInsertContent({ kind, selectedText: "", url: attrs?.src || "", alt: attrs?.alt || "", editing: Boolean(attrs?.src) })
  }

  function confirmInsert(value: CampaignInsertContentValue) {
    if (!editor || !insertContent) return
    const url = normalizeCampaignInsertUrl(value.url, insertContent.kind)
    if (!url) return
    if (insertContent.kind === "link") {
      const text = value.text.trim() || insertContent.selectedText || value.url.trim()
      const linkHtml = `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`
      if ((editor.state.selection.empty && !insertContent.editing) || (value.text.trim() && value.text.trim() !== insertContent.selectedText)) {
        editor.chain().focus().insertContent(linkHtml).run()
        return
      }
      editor.chain().focus().extendMarkRange("link").setLink({ href: url, target: "_blank", rel: "noopener noreferrer" }).run()
      return
    }
    if (insertContent.editing) {
      editor.chain().focus().updateAttributes("image", { src: url, alt: value.alt.trim() }).run()
      return
    }
    editor.chain().focus().setImage({ src: url, alt: value.alt.trim() }).run()
  }

  function updateRawHTML(raw: string) {
    const html = sanitizeCampaignHtml(raw)
    const text = campaignHtmlToText(html).trimEnd()
    onChange({ text, html: campaignHtmlContainsMeaningfulContent(html, text) ? html : "" })
  }

  return <div className="overflow-hidden rounded-md border bg-background focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 lg:flex lg:min-h-0 lg:flex-1 lg:flex-col">
    <Input ref={attachmentInputRef} type="file" multiple className="hidden" onChange={(event) => { onPickFiles(Array.from(event.target.files || [])); event.target.value = "" }} />
    <div className="flex h-10 items-stretch justify-between gap-2 border-b px-2">
      <div className="flex items-stretch" aria-label="群发正文视图">
        {([['content', '内容'], ['preview', '预览'], ['html', 'HTML']] as const).map(([mode, label]) => (
          <Button key={mode} type="button" variant="ghost" size="sm" className={cn("relative h-10 rounded-none px-3 font-medium text-muted-foreground hover:bg-transparent hover:text-foreground", viewMode === mode && "text-foreground after:absolute after:inset-x-2 after:bottom-0 after:h-0.5 after:bg-foreground")} aria-pressed={viewMode === mode} onMouseDown={(event) => event.preventDefault()} onClick={() => setViewMode(mode)}>{label}</Button>
        ))}
      </div>
      <div className="flex items-center gap-1">
        <Button type="button" size="icon" variant={expanded ? "secondary" : "ghost"} className="h-8 w-8 shrink-0" title={expanded ? "还原群发正文" : "放大群发正文"} aria-label={expanded ? "还原群发正文" : "放大群发正文"} aria-pressed={expanded} onMouseDown={(event) => event.preventDefault()} onClick={() => onExpandedChange(!expanded)}>
          {expanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
        </Button>
      </div>
    </div>
    {viewMode === "content" && <>
      <div className="flex min-h-10 flex-wrap items-center gap-1 border-b px-2 py-1.5" aria-label="正文插入工具栏">
        <CampaignToolbarButton label="撤销" disabled={!editor?.can().undo()} onClick={() => editor?.chain().focus().undo().run()}><Undo2 /></CampaignToolbarButton>
        <CampaignToolbarButton label="重做" disabled={!editor?.can().redo()} onClick={() => editor?.chain().focus().redo().run()}><Redo2 /></CampaignToolbarButton>
        <Separator orientation="vertical" className="mx-1 h-6" />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button" variant="ghost" size="sm" className="h-8 gap-1 rounded-md px-2 font-normal hover:bg-accent hover:shadow-sm" onMouseDown={(event) => event.preventDefault()} disabled={!editor}>
              <Plus className="h-4 w-4" />插入<ChevronDown className="h-3.5 w-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem className={campaignMenuItemClass} onSelect={() => attachmentInputRef.current?.click()}><Paperclip className="h-4 w-4" />附件</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className={campaignMenuItemClass} onSelect={() => openInsertDialog("link")}><Link className="h-4 w-4" />链接</DropdownMenuItem>
            <DropdownMenuItem className={campaignMenuItemClass} onSelect={() => openInsertDialog("image")}><ImageIcon className="h-4 w-4" />图片链接</DropdownMenuItem>
            <DropdownMenuItem className={campaignMenuItemClass} onSelect={() => editor?.chain().focus().setHorizontalRule().run()}><span className="h-4 w-4 border-t border-current" aria-hidden />分隔线</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <span className="px-1 text-xs text-muted-foreground" title={`单个附件上限 ${maxAttachmentText}`}>附件上限 {maxAttachmentText}</span>
        <span className="ml-auto whitespace-nowrap px-1 text-xs tabular-nums text-muted-foreground" aria-live="polite">{value.text.replace(/\s/g, "").length} 字</span>
      </div>
      <div className="flex min-h-10 flex-wrap items-center gap-0 border-b bg-muted/30 px-2 py-1.5" aria-label="正文格式工具栏">
        <CampaignToolbarButton label="清除格式" disabled={!editor} onClick={() => editor?.chain().focus().unsetAllMarks().clearNodes().run()}><Eraser /></CampaignToolbarButton>
        <Separator orientation="vertical" className="mx-0.5 h-6" />
        <CampaignToolbarButton label="加粗" active={editor?.isActive("bold")} disabled={!editor} onClick={() => editor?.chain().focus().toggleBold().run()}><Bold /></CampaignToolbarButton>
        <CampaignToolbarButton label="斜体" active={editor?.isActive("italic")} disabled={!editor} onClick={() => editor?.chain().focus().toggleItalic().run()}><Italic /></CampaignToolbarButton>
        <CampaignToolbarButton label="下划线" active={editor?.isActive("underline")} disabled={!editor} onClick={() => editor?.chain().focus().toggleUnderline().run()}><Underline /></CampaignToolbarButton>
        <CampaignToolbarButton label="删除线" active={editor?.isActive("strike")} disabled={!editor} onClick={() => editor?.chain().focus().toggleStrike().run()}><Strikethrough /></CampaignToolbarButton>
        <Separator orientation="vertical" className="mx-0.5 h-6" />
        <CampaignToolbarButton label="无序列表" active={editor?.isActive("bulletList")} disabled={!editor} onClick={() => editor?.chain().focus().toggleBulletList().run()}><List /></CampaignToolbarButton>
        <CampaignToolbarButton label="有序列表" active={editor?.isActive("orderedList")} disabled={!editor} onClick={() => editor?.chain().focus().toggleOrderedList().run()}><ListOrdered /></CampaignToolbarButton>
        <CampaignToolbarButton label="左对齐" active={editor?.isActive({ textAlign: "left" })} disabled={!editor} onClick={() => editor?.chain().focus().setTextAlign("left").run()}><AlignLeft /></CampaignToolbarButton>
        <CampaignToolbarButton label="居中" active={editor?.isActive({ textAlign: "center" })} disabled={!editor} onClick={() => editor?.chain().focus().setTextAlign("center").run()}><AlignCenter /></CampaignToolbarButton>
        <CampaignToolbarButton label="右对齐" active={editor?.isActive({ textAlign: "right" })} disabled={!editor} onClick={() => editor?.chain().focus().setTextAlign("right").run()}><AlignRight /></CampaignToolbarButton>
      </div>
    </>}
    <div className={cn("h-[238px] overflow-y-auto [&_.ProseMirror_p.is-editor-empty:first-child::before]:pointer-events-none [&_.ProseMirror_p.is-editor-empty:first-child::before]:float-left [&_.ProseMirror_p.is-editor-empty:first-child::before]:h-0 [&_.ProseMirror_p.is-editor-empty:first-child::before]:text-muted-foreground [&_.ProseMirror_p.is-editor-empty:first-child::before]:content-[attr(data-placeholder)] [&_.ProseMirror_a]:break-all [&_.ProseMirror_a]:text-primary [&_.ProseMirror_a]:underline [&_.ProseMirror_ol]:list-decimal [&_.ProseMirror_ol]:pl-6 [&_.ProseMirror_ul]:list-disc [&_.ProseMirror_ul]:pl-6", expanded && "h-[calc(92svh-19rem)] min-h-[360px]")}>
      <EditorContent editor={editor} className={cn(viewMode !== "content" && "hidden")} />
      {viewMode === "preview" && <div className="mail-html min-h-full px-3 py-3 text-sm leading-6 [overflow-wrap:anywhere]" aria-label="群发邮件预览" dangerouslySetInnerHTML={{ __html: sanitizeCampaignHtml(value.html || editor?.getHTML() || "") || "<p></p>" }} />}
      {viewMode === "html" && <Textarea className="min-h-full resize-none rounded-none border-0 px-3 py-3 font-mono text-xs leading-5 shadow-none focus-visible:ring-0" aria-label="群发 HTML 源码" value={value.html} onChange={(event) => updateRawHTML(event.target.value)} placeholder="<h1>标题</h1><p>正文</p><img src=&quot;https://example.com/banner.jpg&quot; alt=&quot;&quot;>" />}
    </div>
    {files.length > 0 && (
      <div className="flex flex-wrap gap-2 border-t bg-muted/20 px-3 py-2">
        {files.map((file, index) => (
          <Badge key={`${file.name}-${file.lastModified}-${index}`} variant="outline" className="max-w-full gap-1 rounded-md px-2 py-1 font-normal">
            <Paperclip className="h-3.5 w-3.5 shrink-0" />
            <span className="max-w-[220px] truncate" title={file.name}>{file.name}</span>
            <span className="text-muted-foreground">{formatBytes(file.size)}</span>
            <button type="button" className="ml-1 rounded-sm text-muted-foreground hover:text-foreground" aria-label={`移除附件 ${file.name}`} onClick={() => onRemoveFile(index)}>
              <XCircle className="h-3.5 w-3.5" />
            </button>
          </Badge>
        ))}
      </div>
    )}
    <CampaignInsertContentDialog state={insertContent} onOpenChange={(open) => { if (!open) setInsertContent(null) }} onConfirm={confirmInsert} />
  </div>
}

function CampaignToolbarButton({ label, active, disabled, onClick, children }: { label: string; active?: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode }) {
  return <Button type="button" size="icon" variant={active ? "secondary" : "ghost"} className="h-8 w-8 shrink-0 [&_svg]:h-4 [&_svg]:w-4" title={label} aria-label={label} aria-pressed={active || undefined} disabled={disabled} onMouseDown={(event) => event.preventDefault()} onClick={onClick}>{children}</Button>
}

const campaignMenuItemClass = "min-h-9 rounded-md px-3 text-sm transition-colors data-[highlighted]:bg-primary/10 data-[highlighted]:font-semibold data-[highlighted]:text-foreground hover:bg-primary/10 hover:font-semibold hover:text-foreground"

type CampaignInsertContentState = { kind: "link" | "image"; selectedText: string; url?: string; alt?: string; editing?: boolean }
type CampaignInsertContentValue = { url: string; text: string; alt: string }

function CampaignInsertContentDialog({ state, onOpenChange, onConfirm }: { state: CampaignInsertContentState | null; onOpenChange: (open: boolean) => void; onConfirm: (value: CampaignInsertContentValue) => void }) {
  const kind = state?.kind || "link"
  const [url, setUrl] = React.useState("")
  const [text, setText] = React.useState("")
  const [alt, setAlt] = React.useState("")

  React.useEffect(() => {
    if (!state) return
    setUrl(state.url || "")
    setText(state.kind === "link" ? state.selectedText : "")
    setAlt(state.alt || "")
  }, [state])

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!url.trim()) return
    onConfirm({ url, text, alt })
    onOpenChange(false)
  }

  return <Dialog open={!!state} onOpenChange={onOpenChange}>
    <DialogContent className="sm:max-w-md">
      <form className="grid gap-4" onSubmit={submit}>
        <DialogHeader><DialogTitle>{kind === "link" ? (state?.editing ? "编辑链接" : "插入链接") : (state?.editing ? "编辑图片" : "插入图片")}</DialogTitle></DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="campaign-insert-url">{kind === "link" ? "链接地址" : "图片地址"}</Label>
          <Input id="campaign-insert-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder={kind === "link" ? "https://example.com" : "https://example.com/banner.jpg"} autoFocus />
        </div>
        {kind === "link" ? (
          <div className="grid gap-2">
            <Label htmlFor="campaign-insert-text">显示文字</Label>
            <Input id="campaign-insert-text" value={text} onChange={(event) => setText(event.target.value)} placeholder="默认使用链接地址" />
          </div>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="campaign-insert-alt">替代文字</Label>
            <Input id="campaign-insert-alt" value={alt} onChange={(event) => setAlt(event.target.value)} placeholder="图片说明" />
          </div>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>取消</Button>
          <Button type="submit">{state?.editing ? "更新" : "插入"}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
}

function campaignEditorTextSelection(editor: Editor) {
  const { from, to, empty } = editor.state.selection
  if (empty) return ""
  return editor.state.doc.textBetween(from, to, " ").trim()
}

function campaignSelectedImageAttributes(editor: Editor) {
  const attrs = editor.getAttributes("image") as { src?: string; alt?: string }
  return attrs.src ? attrs : null
}

function normalizeCampaignInsertUrl(value: string, kind: CampaignInsertContentState["kind"]) {
  const trimmed = value.trim()
  if (!trimmed) return ""
  const allowed = kind === "image" ? /^(https?:|cid:|data:image\/|\/)/i : /^(https?:|mailto:|tel:|#|\/)/i
  return allowed.test(trimmed) ? trimmed : `https://${trimmed}`
}

function sanitizeCampaignHtml(value: string) {
  const raw = value || ""
  return DOMPurify.sanitize(raw, {
    ADD_ATTR: ["style", "type", "align", "valign", "bgcolor", "border", "cellpadding", "cellspacing", "width", "height", "target", "rel"],
    ADD_TAGS: ["html", "head", "body", "style", "center", "font"],
    WHOLE_DOCUMENT: /<html[\s>]/i.test(raw) || /<body[\s>]/i.test(raw),
  })
}

function campaignHtmlToText(html: string) {
  if (typeof document === "undefined") return html.replace(/<[^>]*>/g, " ")
  const div = document.createElement("div")
  div.innerHTML = sanitizeCampaignHtml(html)
  return div.textContent || div.innerText || ""
}

function campaignHtmlContainsMeaningfulContent(html: string, text = "") {
  return text.trim().length > 0 || /<(img|hr|table|ul|ol|li|blockquote|pre|div)[\s>]/i.test(html)
}

function campaignAttachmentLimitBytes(limits?: PermissionLimits) {
  const mb = limits?.maxAttachmentMb || 0
  return mb > 0 ? mb * 1024 * 1024 : 0
}

async function fileToCampaignAttachment(file: File): Promise<NonNullable<CampaignInput["attachments"]>[number]> {
  const buffer = await file.arrayBuffer()
  let binary = ""
  const bytes = new Uint8Array(buffer)
  for (let index = 0; index < bytes.length; index++) binary += String.fromCharCode(bytes[index])
  return { filename: file.name, contentType: file.type || "application/octet-stream", contentBase64: btoa(binary) }
}

function parseCampaignRecipients(raw: string): { items: { email: string }[]; duplicates: number; invalid: number } {
  if (!raw.trim()) return { items: [], duplicates: 0, invalid: 0 }
  const result = Papa.parse<string[]>(raw, { skipEmptyLines: "greedy" })
  const rows = result.data.map((row) => row.map((cell) => String(cell || "").trim())).filter((row) => row.some(Boolean))
  const emailAliases = ["email", "e-mail", "邮箱", "邮箱地址"]
  let emailColumn = -1
  if (rows[0]) {
    emailColumn = rows[0].findIndex((cell) => emailAliases.includes(cell.toLowerCase()))
    if (emailColumn >= 0) rows.shift()
  }
  const seen = new Set<string>()
  const items: { email: string }[] = []
  let duplicates = 0
  let invalid = result.errors.filter((error) => error.type === "Quotes").length
  const add = (email: string) => {
    email = email.trim().toLowerCase()
    if (!campaignEmailPattern.test(email)) { invalid += 1; return }
    if (seen.has(email)) { duplicates += 1; return }
    seen.add(email); items.push({ email })
  }
  for (const row of rows) {
    if (emailColumn >= 0) { add(row[emailColumn] || ""); continue }
    const emailCells = row.filter((cell) => campaignEmailPattern.test(cell.toLowerCase()))
    if (emailCells.length > 1 && emailCells.length === row.filter(Boolean).length) { emailCells.forEach((email) => add(email)); continue }
    const index = row.findIndex((cell) => campaignEmailPattern.test(cell.toLowerCase()))
    if (index < 0) { invalid += 1; continue }
    add(row[index])
  }
  return { items, duplicates, invalid }
}
const campaignEmailPattern = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/

function CampaignDetailDialog({ id, open, onOpenChange, canManage }: { id: string; open: boolean; onOpenChange: (open: boolean) => void; canManage: boolean }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [tab, setTab] = React.useState<RecipientTab>("sending")
  const [selected, setSelected] = React.useState<Set<string>>(() => new Set())
  const [retryAll, setRetryAll] = React.useState(false)
  const detail = useQuery({ queryKey: ["admin", "campaign", id], queryFn: () => api.campaign(id), enabled: open && !!id, refetchInterval: open ? 4000 : false })
  React.useEffect(() => { setSelected(new Set()); setRetryAll(false) }, [id, tab])
  const recipients = detail.data?.recipients || []
  const filtered = recipients.filter((recipient) => tab === "sending" ? recipient.status === "pending" || recipient.status === "queued" : tab === "failed" ? recipient.status === "failed" || recipient.status === "suppressed" : recipient.status === tab)
  const failedIDs = filtered.filter((recipient) => recipient.status === "failed").map((recipient) => recipient.id)
  const retry = useMutation({ mutationFn: () => api.retryCampaignRecipients(id, retryAll ? [] : [...selected]), onSuccess: async (result) => { setSelected(new Set()); setRetryAll(false); await Promise.all([qc.invalidateQueries({ queryKey: ["admin", "campaign", id] }), qc.invalidateQueries({ queryKey: ["admin", "campaigns"] })]); toast({ title: `已重新加入 ${result.retried} 位收件人` }) }, onError: (error) => toast({ title: "重新发送失败", description: error.message }) })
  const allSelected = retryAll || (failedIDs.length > 0 && failedIDs.every((recipientID) => selected.has(recipientID)))
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="flex max-h-[90svh] max-w-5xl flex-col overflow-hidden p-0"><DialogHeader className="border-b px-5 py-4"><DialogTitle>{detail.data?.name || "活动明细"}</DialogTitle></DialogHeader>{detail.isPending ? <div className="p-5"><Skeleton className="h-72 w-full" /></div> : detail.data && <><div className="space-y-3 border-b px-5 py-4"><div className="flex flex-wrap items-center gap-2"><CampaignStatusBadge status={detail.data.status} /><span className="text-sm text-muted-foreground">{detail.data.subject}</span><span className="ml-auto text-sm text-muted-foreground">{detail.data.ratePerMinute} 封/分钟</span></div>{detail.data.pauseReason && <div className="border-l-2 border-amber-500 bg-amber-500/5 px-3 py-2 text-sm text-amber-800">{detail.data.pauseReason}</div>}<CampaignProgress item={detail.data} /><div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">{detail.data.senders?.map((sender) => <div key={sender.mailboxId} className="rounded-md border px-3 py-2"><div className="truncate text-sm font-medium">{sender.address}</div><div className="text-xs text-muted-foreground">分配 {sender.recipientCount} 位</div></div>)}</div></div><div className="flex items-center gap-1 border-b px-5 py-2">{(["sending", "delivered", "failed"] as RecipientTab[]).map((item) => <Button key={item} type="button" size="sm" variant={tab === item ? "secondary" : "ghost"} onClick={() => setTab(item)}>{item === "sending" ? `发送中 ${detail.data!.pendingCount + detail.data!.queuedCount}` : item === "delivered" ? `发送完成 ${detail.data!.deliveredCount}` : `发送失败 ${detail.data!.failedCount + detail.data!.suppressedCount}`}</Button>)}{tab === "failed" && canManage && failedIDs.length > 0 && <Button type="button" size="sm" className="ml-auto" disabled={(!retryAll && selected.size === 0) || retry.isPending} onClick={() => retry.mutate()}><RotateCcw className="mr-2 h-4 w-4" />{retryAll ? `重新发送全部 (${detail.data.failedCount})` : `重新发送所选 (${selected.size})`}</Button>}</div><ScrollArea className="min-h-0 flex-1"><div className="p-5">{filtered.length === 0 ? <div className="grid min-h-40 place-items-center text-sm text-muted-foreground">当前没有记录</div> : <div className="overflow-hidden rounded-md border"><Table><TableHeader><TableRow>{tab === "failed" && <TableHead className="w-12"><Checkbox checked={allSelected} aria-label="全选失败收件人" onCheckedChange={(checked) => { const value = checked === true; setRetryAll(value); setSelected(value ? new Set(failedIDs) : new Set()) }} /></TableHead>}<TableHead>收件人</TableHead><TableHead>发件人</TableHead><TableHead>状态</TableHead><TableHead>时间 / 原因</TableHead></TableRow></TableHeader><TableBody>{filtered.map((recipient) => <CampaignRecipientRow key={recipient.id} recipient={recipient} sender={detail.data!.senders?.find((sender) => sender.mailboxId === recipient.mailboxId)?.address || "-"} selectable={tab === "failed" && recipient.status === "failed"} selected={retryAll || selected.has(recipient.id)} onSelected={(checked) => { setRetryAll(false); setSelected((current) => { const next = new Set(current); if (checked) next.add(recipient.id); else next.delete(recipient.id); return next }) }} />)}</TableBody></Table></div>}</div></ScrollArea></>}</DialogContent></Dialog>
}

function CampaignRecipientRow({ recipient, sender, selectable, selected, onSelected }: { recipient: CampaignRecipient; sender: string; selectable: boolean; selected: boolean; onSelected: (checked: boolean) => void }) {
  return <TableRow>{selectable ? <TableCell><Checkbox checked={selected} aria-label={`选择 ${recipient.email}`} onCheckedChange={(checked) => onSelected(checked === true)} /></TableCell> : recipient.status === "suppressed" ? <TableCell /> : null}<TableCell><div className="font-medium">{recipient.email}</div>{recipient.name && <div className="text-xs text-muted-foreground">{recipient.name}</div>}</TableCell><TableCell className="max-w-48 truncate text-xs" title={sender}>{sender}</TableCell><TableCell><Badge variant={recipient.status === "delivered" ? "default" : recipient.status === "failed" || recipient.status === "suppressed" ? "destructive" : "outline"}>{recipient.status === "delivered" ? "发送完成" : recipient.status === "suppressed" ? "已禁止发送" : recipient.status === "failed" ? "发送失败" : "发送中"}</Badge></TableCell><TableCell className="max-w-72 text-xs text-muted-foreground">{recipient.lastError || (recipient.deliveredAt ? formatDate(recipient.deliveredAt) : recipient.queuedAt ? formatDate(recipient.queuedAt) : "等待发送")}</TableCell></TableRow>
}

function CampaignSuppressions({ items, loading, canManage }: { items: CampaignSuppression[]; loading: boolean; canManage: boolean }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [email, setEmail] = React.useState("")
  const [reason, setReason] = React.useState("")
  const add = useMutation({ mutationFn: () => api.createCampaignSuppression({ email, reason }), onSuccess: async () => { setEmail(""); setReason(""); await qc.invalidateQueries({ queryKey: ["admin", "campaign-suppressions"] }); toast({ title: "已加入退订名单" }) }, onError: (error) => toast({ title: "添加失败", description: error.message }) })
  const remove = useMutation({ mutationFn: api.deleteCampaignSuppression, onSuccess: async () => { await qc.invalidateQueries({ queryKey: ["admin", "campaign-suppressions"] }); toast({ title: "已移出退订名单" }) }, onError: (error) => toast({ title: "移除失败", description: error.message }) })
  return <div className="space-y-3">{canManage && <div className="grid gap-2 rounded-lg border p-3 sm:grid-cols-[minmax(220px,1fr)_minmax(240px,1.5fr)_auto]"><Input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="邮箱地址" aria-label="退订邮箱地址" /><Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="原因（可选）" aria-label="加入退订名单的原因" /><Button type="button" disabled={!email.trim() || add.isPending} onClick={() => add.mutate()}>加入名单</Button></div>}{loading ? <Skeleton className="h-64 w-full" /> : <div className="overflow-hidden rounded-lg border"><Table><TableHeader><TableRow><TableHead>邮箱地址</TableHead><TableHead>来源</TableHead><TableHead>原因</TableHead><TableHead>加入时间</TableHead>{canManage && <TableHead className="w-16" />}</TableRow></TableHeader><TableBody>{items.map((item) => <TableRow key={item.id}><TableCell className="font-medium">{item.email}</TableCell><TableCell>{item.source === "unsubscribe" ? "主动退订" : item.source === "complaint" ? "收件人投诉" : item.source === "hard_bounce" ? "硬退信" : "手动添加"}</TableCell><TableCell>{item.reason}</TableCell><TableCell>{formatDate(item.createdAt)}</TableCell>{canManage && <TableCell><Button type="button" size="icon" variant="ghost" className="text-destructive" aria-label={`移出 ${item.email}`} title="移出名单" onClick={() => remove.mutate(item.id)}><Trash2 className="h-4 w-4" /></Button></TableCell>}</TableRow>)}{items.length === 0 && <TableRow><TableCell colSpan={canManage ? 5 : 4} className="h-36 text-center text-muted-foreground">退订名单为空</TableCell></TableRow>}</TableBody></Table></div>}</div>
}
