defmodule CredentialBreachWeb.InvestigationLive.DataPanel do
  @moduledoc "数据泄露标签页：被读取、下载、导出与凭证检索的全部数据对象。"
  use CredentialBreachWeb, :html

  attr :report, :map, required: true

  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="grid gap-4 sm:grid-cols-3">
        <.stat_card
          label="数据访问动作"
          value={length(@report.data_accesses)}
          icon="hero-circle-stack"
          tone="warning"
        />
        <.stat_card label="累计外传字节" icon="hero-arrow-down-tray" tone="danger">
          {human_bytes(@report.data_total_bytes)}
        </.stat_card>
        <.stat_card
          label="敏感数据命中"
          value={@report.sensitive_count}
          icon="hero-eye-slash"
          tone="danger"
          hint="需优先评估合规通报义务"
        />
      </div>

      <.section_panel
        id="data-table"
        title="被读取 / 下载 / 导出的数据"
        subtitle="按时间顺序，含对象下载、RDS 快照导出与应用日志凭证检索"
        icon="hero-table-cells"
      >
        <.empty_state
          :if={@report.data_accesses == []}
          icon="hero-check-circle"
          title="未发现数据访问动作"
        />

        <div :if={@report.data_accesses != []} class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-32">时间 (UTC)</th>
                <th class="w-28">类型</th>
                <th>目标资源</th>
                <th class="w-24 text-right">大小</th>
                <th class="w-20 text-center">敏感</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={item <- @report.data_accesses}
                key={item.event.event_id}
                class={[
                  "hover:bg-base-200/50",
                  item.sensitive && "bg-error/5"
                ]}
              >
                <td class="whitespace-nowrap font-mono text-xs">{time(item.event.event_time)}</td>
                <td>
                  <.category_badge category={item.event.category} />
                </td>
                <td class="max-w-0">
                  <p class="break-all font-mono text-xs">{item.target}</p>
                  <p class="mt-0.5 text-[11px] text-base-content/50">{item.event.title}</p>
                </td>
                <td class="whitespace-nowrap text-right font-mono text-xs tabular-nums">
                  {if(item.bytes > 0, do: human_bytes(item.bytes), else: "—")}
                </td>
                <td class="text-center">
                  <.sensitive_flag flag={item.sensitive} />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.section_panel>

      <.section_panel
        id="sensitive-summary"
        title="敏感数据风险提示"
        icon="hero-exclamation-triangle"
      >
        <ul class="list-disc space-y-1.5 pl-5 text-sm text-base-content/75">
          <li>客户 PII 库（{@report.sensitive_count} 处敏感命中）已被整库级下载，需评估《个人信息保护法》数据泄露通报义务。</li>
          <li>
            生产环境变量 <code class="rounded bg-base-300/60 px-1 font-mono text-xs">.env.production</code>
            与源代码备份被下载，应立即轮换其中可能包含的全部数据库口令、API Token 与加密密钥。
          </li>
          <li>
            攻击者在 CloudWatch Logs 中以
            <code class="rounded bg-base-300/60 px-1 font-mono text-xs">password/token/secret</code>
            关键词过滤检索，需排查应用日志是否明文记录凭证。
          </li>
          <li>
            RDS 快照被导出到 CI 制品桶的
            <code class="rounded bg-base-300/60 px-1 font-mono text-xs">tmp-export/</code>
            前缀，且该前缀随后被写入跨账号读取策略，应立即检查并删除导出文件。
          </li>
        </ul>
      </.section_panel>
    </div>
    """
  end

  defp time(%DateTime{} = dt), do: Calendar.strftime(dt, "%m-%d %H:%M:%S")
  defp time(_), do: "—"

  defp human_bytes(n) when n >= 1_073_741_824, do: "#{Float.round(n / 1_073_741_824, 2)} GB"
  defp human_bytes(n) when n >= 1_048_576, do: "#{Float.round(n / 1_048_576, 1)} MB"
  defp human_bytes(n) when n >= 1024, do: "#{div(n, 1024)} KB"
  defp human_bytes(n), do: "#{n} B"
end
