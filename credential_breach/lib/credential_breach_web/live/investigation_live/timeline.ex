defmodule CredentialBreachWeb.InvestigationLive.Timeline do
  @moduledoc "攻击经过标签页：按杀伤链阶段串联全部调用的垂直时间线。"
  use CredentialBreachWeb, :html

  alias CredentialBreach.Audit.Meta

  attr :report, :map, required: true

  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.section_panel
        id="timeline"
        title="攻击者操作经过（按泄露密钥还原）"
        subtitle="共 #{@report.total_events} 次调用，归入 7 个杀伤链阶段；点击任意一步可展开原始审计事件"
        icon="hero-clock"
      >
        <div class="space-y-8">
          <div :for={group <- @report.stage_groups} key={group.stage} class="relative">
            <div class="flex items-center gap-3">
              <span class={[
                "grid size-9 shrink-0 place-items-center rounded-full text-sm font-bold text-base-100 shadow-sm",
                Meta.stage(group.stage).dot
              ]}>
                {group.stage}
              </span>
              <div class="flex-1 border-b border-base-300/70 pb-2">
                <div class="flex flex-wrap items-center gap-2">
                  <h3 class="text-base font-bold">{group.name}</h3>
                  <span class={["badge badge-sm", group.badge]}>{group.count} 个动作</span>
                  <span class="font-mono text-[11px] text-base-content/45">
                    {time(group.started_at)} ~ {time(group.ended_at)}
                  </span>
                </div>
                <p class="mt-0.5 text-xs text-base-content/50">{group.desc}</p>
              </div>
            </div>

            <div class={["mt-3 rounded-xl border bg-base-200/30 p-4", Meta.stage(group.stage).ring]}>
              <p class="mb-4 rounded-lg bg-base-100/80 p-3 text-sm leading-relaxed text-base-content/80">
                <.icon name="hero-chat-bubble-left-right" class="mr-1 inline size-4 text-primary" />
                {group.narrative}
              </p>

              <ol class="relative space-y-3 border-l-2 border-base-300/70 pl-5">
                <li
                  :for={event <- group.events}
                  key={event.event_id}
                  id={"ev-#{event.event_id}"}
                  class="relative"
                >
                  <span class={[
                    "absolute -left-[27px] top-1.5 size-3.5 rounded-full ring-4 ring-base-100",
                    Meta.stage(group.stage).dot
                  ]}></span>

                  <details class="group rounded-lg border border-base-300 bg-base-100/70 transition-colors open:border-primary/40 open:shadow-sm">
                    <summary class="flex cursor-pointer list-none flex-wrap items-center gap-2 p-3 [&::-webkit-details-marker]:hidden">
                      <.icon
                        name="hero-chevron-right"
                        class="size-4 shrink-0 transition-transform group-open:rotate-90"
                      />
                      <span class="font-mono text-[11px] tabular-nums text-base-content/50">{time(
                        event.event_time
                      )}</span>
                      <.severity_chip severity={event.severity} />
                      <span :if={!event.success} class="badge badge-neutral badge-sm">失败</span>
                      <.sensitive_flag :if={event.sensitive} flag={true} />
                      <span class="text-sm font-medium">{event.title}</span>
                    </summary>
                    <div class="border-t border-base-300/70 px-4 py-3">
                      <p class="text-sm text-base-content/70">{event.summary}</p>
                      <div class="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 text-xs">
                        <.meta_line
                          label="服务 / API"
                          value={"#{event.event_source}:#{event.event_name}"}
                          mono
                        />
                        <.meta_line label="来源 IP" value={event.source_ip} mono />
                        <.meta_line label="区域" value={event.aws_region} mono />
                        <.meta_line label="身份" value={event.user_name} mono />
                        <.meta_line label="密钥" value={event.access_key_id} mono />
                        <.meta_line label="只读" value={if(event.read_only, do: "是", else: "否")} />
                      </div>
                      <div
                        :if={event.error_code}
                        class="mt-2 rounded-md bg-error/10 px-3 py-2 text-xs text-error"
                      >
                        {event.error_code}: {event.error_message}
                      </div>
                      <pre
                        phx-no-curly-interpolation
                        class="mt-3 max-h-72 overflow-auto rounded-lg bg-base-300/50 p-3 text-[11px] leading-relaxed"
                      ><code>{Jason.encode!(event.raw, pretty: true)}</code></pre>
                    </div>
                  </details>
                </li>
              </ol>
            </div>
          </div>
        </div>
      </.section_panel>
    </div>
    """
  end

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
