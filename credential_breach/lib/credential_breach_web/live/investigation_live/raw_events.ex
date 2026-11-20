defmodule CredentialBreachWeb.InvestigationLive.RawEvents do
  @moduledoc "原始调用标签页：泄露密钥的全部审计事件，支持类别与失败调用过滤。"
  use CredentialBreachWeb, :html

  attr :report, :map, required: true
  attr :filter_category, :string, required: true
  attr :filter_only_denied, :boolean, required: true

  def render(assigns) do
    filtered =
      filter_events(assigns.report.events, assigns.filter_category, assigns.filter_only_denied)

    assigns = assign(assigns, :filtered, filtered)

    ~H"""
    <div class="space-y-5">
      <.section_panel
        id="raw-filters"
        title="原始调用事件流"
        subtitle="该泄露密钥产生的全部 CloudTrail 事件（含被拒调用）"
        icon="hero-list-bullet"
      >
        <div class="flex flex-wrap items-center gap-2">
          <button
            :for={cat <- category_options()}
            key={cat.id}
            phx-click="filter_category"
            phx-value-category={cat.id}
            class={[
              "btn btn-xs transition-colors",
              (@filter_category == cat.id && "btn-primary") || "btn-ghost border border-base-300"
            ]}
          >
            {cat.name}
          </button>

          <div class="divider divider-horizontal mx-1"></div>

          <button
            phx-click="toggle_denied"
            class={[
              "btn btn-xs",
              (@filter_only_denied && "btn-neutral") || "btn-ghost border border-base-300"
            ]}
          >
            <.icon name="hero-no-symbol" class="size-3.5" /> 只看失败/被拒
          </button>

          <span class="ml-auto text-xs text-base-content/50">显示 {length(@filtered)} / {@report.total_events} 条</span>
        </div>
      </.section_panel>

      <.empty_state
        :if={@filtered == []}
        icon="hero-funnel"
        title="当前过滤条件下没有事件"
        note="试试切换类别或关闭“只看失败/被拒”。"
      />

      <div :if={@filtered != []} id="raw-event-list" class="space-y-2.5">
        <details
          :for={event <- @filtered}
          key={event.event_id}
          class="rounded-lg border border-base-300 bg-base-100/70 transition-colors open:border-primary/40"
        >
          <summary class="flex cursor-pointer list-none flex-wrap items-center gap-2 p-3 [&::-webkit-details-marker]:hidden">
            <.icon
              name="hero-chevron-right"
              class="size-4 shrink-0 transition-transform group-open:rotate-90"
            />
            <span class="font-mono text-[11px] tabular-nums text-base-content/50">{time(
              event.event_time
            )}</span>
            <.stage_badge stage={event.stage} />
            <.category_badge category={event.category} />
            <span :if={!event.success} class="badge badge-neutral badge-sm">被拒</span>
            <.sensitive_flag :if={event.sensitive} flag={true} />
            <span class="min-w-0 flex-1 truncate text-sm font-medium">{event.title}</span>
            <span class="hidden font-mono text-[11px] text-base-content/45 sm:block">{event.source_ip}</span>
          </summary>
          <div class="border-t border-base-300/70 px-4 py-3">
            <p class="text-sm text-base-content/70">{event.summary}</p>
            <div class="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 text-xs">
              <.meta_line label="API" value={"#{event.event_source}:#{event.event_name}"} mono />
              <.meta_line label="来源 IP" value={event.source_ip} mono />
              <.meta_line label="User-Agent" value={event.user_agent} mono />
              <.meta_line label="事件 ID" value={event.event_id} mono />
            </div>
            <pre
              phx-no-curly-interpolation
              class="mt-3 max-h-80 overflow-auto rounded-lg bg-base-300/50 p-3 text-[11px] leading-relaxed"
            ><code>{Jason.encode!(event.raw, pretty: true)}</code></pre>
          </div>
        </details>
      </div>
    </div>
    """
  end

  defp category_options do
    [
      %{id: "all", name: "全部"},
      %{id: "recon", name: "侦察"},
      %{id: "data_access", name: "数据下载"},
      %{id: "data_export", name: "DB 导出"},
      %{id: "credential_harvest", name: "凭证翻找"},
      %{id: "backdoor_identity", name: "后门身份"},
      %{id: "backdoor_permission", name: "权限后门"},
      %{id: "backdoor_network", name: "网络后门"},
      %{id: "defense_evasion", name: "审计规避"},
      %{id: "destruction", name: "破坏删除"},
      %{id: "denied", name: "被拒调用"}
    ]
  end

  defp filter_events(events, "all", only_denied?) do
    maybe_denied(events, only_denied?)
  end

  defp filter_events(events, category, only_denied?) do
    events
    |> Enum.filter(&(&1.category == String.to_existing_atom(category)))
    |> maybe_denied(only_denied?)
  end

  defp maybe_denied(events, false), do: events
  defp maybe_denied(events, true), do: Enum.filter(events, &(&1.category == :denied))

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :mono, :boolean, default: false

  defp meta_line(assigns) do
    ~H"""
    <div class="min-w-0">
      <p class="text-[10px] uppercase tracking-wide text-base-content/45">{@label}</p>
      <p class={["break-words", @mono && "font-mono"]}>{@value}</p>
    </div>
    """
  end

  defp time(%DateTime{} = dt), do: Calendar.strftime(dt, "%m-%d %H:%M:%S")
  defp time(_), do: "—"
end
