defmodule CredentialBreachWeb.InvestigationLive.Overview do
  @moduledoc "总览标签页：关键指标、泄露身份、来源画像与杀伤链速览。"
  use CredentialBreachWeb, :html

  alias CredentialBreach.Audit.Meta

  attr :report, :map, required: true

  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.section_panel
        id="identity-banner"
        title="泄露凭证与攻击窗口"
        icon="hero-identification"
      >
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <.kv label="泄露访问密钥" value={@report.leaked_key} mono />
          <.kv label="所属 IAM 身份" value={@report.leaked_user} />
          <.kv label="身份 ARN" value={@report.leaked_arn} mono small />
          <.kv label="攻击活跃窗口" value={window_text(@report.window_seconds)} />
        </div>
        <div class="mt-4 grid gap-4 sm:grid-cols-2">
          <div class="rounded-lg border border-base-300 bg-base-200/40 p-3">
            <p class="text-xs font-semibold uppercase tracking-wide text-base-content/50">首次被使用</p>
            <p class="mt-1 font-mono text-sm">{fmt(@report.first_seen_at)}</p>
          </div>
          <div class="rounded-lg border border-base-300 bg-base-200/40 p-3">
            <p class="text-xs font-semibold uppercase tracking-wide text-base-content/50">最后一次调用</p>
            <p class="mt-1 font-mono text-sm">{fmt(@report.last_seen_at)}</p>
          </div>
        </div>

        <div
          :if={@report.revoked_at}
          class="mt-4 flex items-start gap-3 rounded-lg border border-warning/30 bg-warning/10 p-3"
        >
          <.icon name="hero-no-symbol" class="mt-0.5 size-5 shrink-0 text-warning" />
          <div class="text-sm">
            <p class="font-semibold text-warning">密钥已于 {fmt(@report.revoked_at)} 被吊销（置为 Inactive）</p>
            <p class="mt-0.5 text-xs text-base-content/65">
              操作人：{@report.revoked_by}。吊销后仍有失败调用，见“攻击经过”阶段 7。
            </p>
          </div>
        </div>
      </.section_panel>

      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <.stat_card
          label="密钥相关调用"
          value={@report.total_events}
          icon="hero-cursor-arrow-ripple"
          tone="info"
          hint="成功 {@report.success_events} · 被拒 {@report.denied_events}"
        />
        <.stat_card label="数据外传量" icon="hero-arrow-down-tray" tone="warning">
          {human_bytes(@report.data_total_bytes)}
        </.stat_card>
        <.stat_card
          label="敏感数据命中"
          value={@report.sensitive_count}
          icon="hero-eye-slash"
          tone="danger"
          hint="PII/凭证/机密文件"
        />
        <.stat_card
          label="严重级别事件"
          value={@report.critical_count}
          icon="hero-fire"
          tone="danger"
          hint="critical 级动作"
        />
      </div>

      <div class="grid gap-6 lg:grid-cols-2">
        <.section_panel id="origin-ips" title="攻击来源画像" icon="hero-globe-alt">
          <ul class="space-y-3">
            <li :for={ip <- @report.ip_summary} class="rounded-lg border border-base-300 p-3">
              <div class="flex items-center justify-between gap-2">
                <p class="font-mono text-sm font-semibold">{ip.ip}</p>
                <span class="badge badge-sm badge-ghost">{ip.count} 次</span>
              </div>
              <p class="mt-1 text-xs font-medium text-error/90">{ip.label}</p>
              <p class="mt-0.5 text-xs text-base-content/55">{ip.note}</p>
              <p class="mt-1 text-[11px] text-base-content/45">
                活跃 {fmt(ip.first_seen)} ~ {fmt(ip.last_seen)}
              </p>
            </li>
          </ul>
        </.section_panel>

        <.section_panel id="killchain" title="杀伤链阶段速览" icon="hero-command-line">
          <ol class="space-y-2.5">
            <li :for={group <- @report.stage_groups} class="flex items-center gap-3">
              <span class={[
                "grid size-7 shrink-0 place-items-center rounded-full text-xs font-bold text-base-100",
                Meta.stage(group.stage).dot
              ]}>
                {group.stage}
              </span>
              <div class="min-w-0 flex-1">
                <div class="flex items-center justify-between gap-2">
                  <p class="truncate text-sm font-medium">{group.name}</p>
                  <span class="text-xs tabular-nums text-base-content/55">{group.count} 步</span>
                </div>
                <p class="truncate text-xs text-base-content/50">{group.desc}</p>
              </div>
            </li>
          </ol>
        </.section_panel>
      </div>

      <.section_panel
        id="ua-panel"
        title="工具指纹（User-Agent）"
        icon="hero-wrench-screwdriver"
      >
        <div class="grid gap-3 sm:grid-cols-2">
          <div :for={ua <- @report.user_agents} class="rounded-lg border border-base-300 p-3">
            <div class="flex items-center justify-between gap-2">
              <span class="badge badge-sm badge-primary">{ua.fingerprint}</span>
              <span class="text-xs tabular-nums text-base-content/55">{ua.count} 次</span>
            </div>
            <p class="mt-1.5 break-all font-mono text-[11px] text-base-content/55">{ua.user_agent}</p>
          </div>
        </div>
      </.section_panel>
    </div>
    """
  end

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :mono, :boolean, default: false
  attr :small, :boolean, default: false

  defp kv(assigns) do
    ~H"""
    <div class="min-w-0">
      <p class="text-xs font-semibold uppercase tracking-wide text-base-content/50">{@label}</p>
      <p class={[
        "mt-1 break-words font-medium",
        @mono && "font-mono",
        (@small && "text-xs") || "text-sm"
      ]}>
        {@value}
      </p>
    </div>
    """
  end

  defp window_text(nil), do: "未知"

  defp window_text(seconds) when seconds >= 3600,
    do: "#{div(seconds, 3600)} 小时 #{rem(seconds, 3600) |> div(60)} 分钟"

  defp window_text(seconds), do: "#{div(seconds, 60)} 分钟"

  defp human_bytes(n) when n >= 1_073_741_824, do: "#{Float.round(n / 1_073_741_824, 2)} GB"
  defp human_bytes(n) when n >= 1_048_576, do: "#{Float.round(n / 1_048_576, 1)} MB"
  defp human_bytes(n) when n >= 1024, do: "#{div(n, 1024)} KB"
  defp human_bytes(n), do: "#{n} B"

  defp fmt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  defp fmt(_), do: "—"
end
