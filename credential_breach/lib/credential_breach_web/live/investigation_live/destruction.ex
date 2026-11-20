defmodule CredentialBreachWeb.InvestigationLive.Destruction do
  @moduledoc "删改与规避标签页：被删除/关停的资源，以及针对审计设施的压制动作。"
  use CredentialBreachWeb, :html

  attr :report, :map, required: true

  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="grid gap-4 sm:grid-cols-2">
        <.stat_card
          label="被删改/关停资源"
          value={length(@report.destructions)}
          icon="hero-trash"
          tone="danger"
          hint="直接影响恢复能力与可用性"
        />
        <.stat_card
          label="审计规避动作"
          value={length(@report.evasions)}
          icon="hero-eye-slash"
          tone="danger"
          hint="停日志/改跟踪/删跟踪"
        />
      </div>

      <.section_panel
        id="evasion-panel"
        title="审计压制（Defense Evasion）"
        subtitle="先断监控再做破坏，是高成熟度攻击的标志性动作"
        icon="hero-eye-slash"
      >
        <.empty_state
          :if={@report.evasions == []}
          icon="hero-check-circle"
          title="未发现审计规避动作"
        />
        <ol :if={@report.evasions != []} class="relative space-y-4 border-l-2 border-error/30 pl-5">
          <li :for={ev <- @report.evasions} key={ev.event.event_id} class="relative">
            <span class="absolute -left-[27px] top-1 grid size-4 place-items-center rounded-full bg-error ring-4 ring-base-100"></span>
            <div class="flex flex-wrap items-center gap-2">
              <.severity_chip severity={ev.event.severity} />
              <p class="text-sm font-semibold">{ev.title}</p>
              <span class="font-mono text-[11px] text-base-content/45">{time(ev.event.event_time)}</span>
            </div>
            <p class="mt-1 text-xs text-base-content/60">{ev.detail}</p>
          </li>
        </ol>
      </.section_panel>

      <.section_panel
        id="destruction-panel"
        title="被删除 / 修改 / 关停的资源"
        icon="hero-trash"
      >
        <.empty_state
          :if={@report.destructions == []}
          icon="hero-check-circle"
          title="未发现破坏性操作"
        />
        <div :if={@report.destructions != []} class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-32">时间 (UTC)</th>
                <th class="w-40">动作</th>
                <th>资源</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={d <- @report.destructions} key={d.event.event_id} class="hover:bg-base-200/50">
                <td class="whitespace-nowrap font-mono text-xs">{time(d.event.event_time)}</td>
                <td><span class="badge badge-error badge-sm font-mono">{d.action}</span></td>
                <td class="break-all font-mono text-xs">{d.resource}</td>
                <td class="text-xs text-base-content/60">{d.detail}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </.section_panel>

      <.section_panel id="recovery-hint" title="恢复与处置建议" icon="hero-lifebuoy">
        <ul class="list-disc space-y-1.5 pl-5 text-sm text-base-content/75">
          <li>5 个夜间备份对象与 1 个 RDS 手动快照已删，立即检查 S3 版本控制 / 跨区复制与回收站中是否仍可恢复。</li>
          <li>
            被强制停止的实例
            <code class="rounded bg-base-300/60 px-1 font-mono text-xs">i-0c88f1a2b3d4e5f60</code>
            在重启前必须先清理被篡改的 userData，否则会重新回连 C2。
          </li>
          <li>
            CloudTrail 跟踪已被删除，需用原配置重建 <code class="rounded bg-base-300/60 px-1 font-mono text-xs">org-main-trail</code>，并开启日志文件完整性校验与多区域复制。
          </li>
          <li>停止日志到删除跟踪之间存在审计盲区，该窗口内的操作需结合 VPC Flow Logs、S3 访问日志与端点日志交叉还原。</li>
        </ul>
      </.section_panel>
    </div>
    """
  end

  defp time(%DateTime{} = dt), do: Calendar.strftime(dt, "%m-%d %H:%M:%S")
  defp time(_), do: "—"
end
